package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/ipc"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

func main() {
	usage := func() {
		fmt.Fprintln(os.Stderr, "usage: mistgate-clientd run [-fake] [-data <dir>] [-verify host:port] | install [run flags] | uninstall")
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "install", "uninstall":
		var err error
		if os.Args[1] == "install" {
			err = install(os.Args[2:])
		} else {
			err = uninstall()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "run":
	default:
		usage()
	}
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	fake := flags.Bool("fake", false, "use the in-process fake engine")
	dataDir := flags.String("data", defaultDataDir(), "subscription data directory")
	verify := flags.String("verify", "", "override the tunnel verification target (development only)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	start := func(ctx context.Context, powerEvents <-chan time.Duration) error {
		return run(ctx, *fake, *dataDir, *verify, powerEvents)
	}
	if asService, err := runAsService(start); asService {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := start(ctx, nil); err != nil {
		os.Exit(1)
	}
}

func shouldConnectAtStart(configured settings.Settings) bool {
	return configured.LastServer != "" && (configured.Autoconnect || configured.Restore && configured.LastOn)
}

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
		if runtime.GOOS == "windows" {
			base = `C:\ProgramData`
		}
	}
	return filepath.Join(base, "Mistgate")
}

// run owns the lifecycle; the context ends it (Ctrl+C in a console, a stop request as a Windows service).
func run(ctx context.Context, useFake bool, dataDir, verify string, powerEvents <-chan time.Duration) error {
	var eventMu sync.RWMutex
	var eventHub *session.Hub
	logs := ipc.NewLogStore()
	logger := ipc.NewEventLogger(func(data any) {
		eventMu.RLock()
		hub := eventHub
		eventMu.RUnlock()
		if hub != nil {
			hub.Publish("log", data)
		}
	}, logs)
	slog.SetDefault(logger.With("src", "subs"))
	store, err := subs.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the data directory:", err)
		return err
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open settings:", err)
		return err
	}
	geoStore, err := geo.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open geo cache:", err)
		return err
	}
	slog.SetDefault(logger.With("src", "engine"))
	go store.Run(ctx)
	var eng engine.Engine
	var routeState session.RouteState
	var routes func() geo.Routes
	if useFake {
		eng = engine.NewFake(engine.FakeConfig{StepDelay: 300 * time.Millisecond})
		routeState.Effective = func(settings.Settings) string { return "all" }
		routes = func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		}
	} else {
		real := engine.NewReal(store.Profiles, settingsStore.Get, geoStore, verify)
		eng = real
		routeState.Effective = real.EffectiveRoute
		routeState.Path = real.RoutePath
		routeState.Refresh = real.RefreshAutoRegion
		routes = func() geo.Routes { return real.Routes(settingsStore.Get()) }
	}
	routeState.Snapshot = func() geo.Routes { return routes() }
	manager := session.NewManager(eng, settingsStore.Get, routeState)
	defer manager.Close()
	if powerEvents != nil {
		go func() {
			for {
				select {
				case asleep, ok := <-powerEvents:
					if !ok {
						return
					}
					manager.NetworkChanged("resume", asleep)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	eventMu.Lock()
	eventHub = manager.Events()
	eventMu.Unlock()
	if configured := settingsStore.Get(); shouldConnectAtStart(configured) {
		_, _ = manager.Connect(ctx, engine.Target{Server: configured.LastServer, Protocol: "auto", Sub: configured.LastSub})
	}
	diagnostics := diag.NewRunner(diag.Config{Profiles: store.Profiles, Tunnel: func() bool {
		status, err := manager.Status(ctx)
		return err == nil && status.State == "connected"
	}, Connected: func() string {
		// the status carries the profile's name (its id when it has no name), not the id
		if status, err := manager.Status(ctx); err == nil && status.State == "connected" {
			return status.Server
		}
		return ""
	}, Logger: logger.With("src", "diag")}, func(state diag.State) {
		manager.Events().Publish("diag", state)
	})
	if err := ipc.Run(ctx, manager, logger, store, settingsStore, diagnostics, logs, geoStore, routes); err != nil {
		logger.With("src", "ipc").Error("service stopped", "error", err)
		return err
	}
	return nil
}
