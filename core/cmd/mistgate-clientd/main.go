package main

import (
	"context"
	"flag"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/ipc"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/proxy"
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

// keepCrashOutput: a service has no console, so what the runtime says when it dies (the panic and the goroutines'
// stacks) goes to crash.log in the data directory. The file is started again once it is over 256 KiB.
func keepCrashOutput(dataDir string) {
	if os.MkdirAll(dataDir, 0700) != nil {
		return
	}
	path := filepath.Join(dataDir, "crash.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > 256<<10 {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	if file, err := os.OpenFile(path, flags, 0600); err == nil {
		_ = debug.SetCrashOutput(file, debug.CrashOptions{})
		serviceStderrTo(file)
	}
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
	// before anything is written there: a folder planted by another user is not used
	if err := subs.ClaimDirectory(dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "the data directory belongs to another user and could not be moved aside")
		return err
	}
	keepCrashOutput(dataDir)
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
	var check func(string) geo.Check
	var dialVPN func(context.Context, string, uint16) (net.Conn, error)
	var homeAddr func() string
	ping := ipc.PingFunc(diag.Handshake)
	if useFake {
		fake := engine.NewFake(engine.FakeConfig{StepDelay: 300 * time.Millisecond})
		eng = fake
		dialVPN = fake.DialVPN
		homeAddr = func() string { return "" }
		routeState.Effective = func(settings.Settings) string { return "all" }
		routes = func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		}
		ping = func(_ context.Context, p profile.Profile, _ time.Duration) (time.Duration, error) {
			return time.Duration(20+crc32.ChecksumIEEE([]byte(p.ID))%180) * time.Millisecond, nil // plausible, stable per server
		}
		check = func(name string) geo.Check {
			configured := settingsStore.Get()
			region := ""
			if geo.ValidRegion(configured.RouteRegion) {
				region = configured.RouteRegion
			}
			return geoStore.CheckName(configured.RouteMode, region, name, false)
		}
	} else {
		real := engine.NewReal(store.Profiles, settingsStore.Get, geoStore, verify)
		eng = real
		real.AllowDest = proxy.AllowedAddr
		dialVPN = real.DialVPN
		homeAddr = real.HomeAddr
		routeState.Effective = real.EffectiveRoute
		routeState.Path = real.RoutePath
		routeState.Refresh = real.RefreshAutoRegion
		routes = func() geo.Routes { return real.Routes(settingsStore.Get()) }
		check = func(name string) geo.Check { return real.CheckSite(settingsStore.Get(), name) }
	}
	routeState.Snapshot = func() geo.Routes { return routes() }
	// the programs the rules already name stay in the window's list even when they are not running
	apps := func() []engine.AppInfo {
		rules := geoStore.GetRules()
		return engine.ListApps(slices.Concat(rules.Direct.Apps, rules.VPN.Apps))
	}
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
	localProxy := proxy.New(proxy.Config{
		Dir: dataDir, Settings: settingsStore.Get, Dial: dialVPN, Host: homeAddr,
		Firewall: proxy.FirewallRule, Logger: logger.With("src", "proxy"),
	})
	defer localProxy.Close()
	localProxy.Reload()
	if err := ipc.Run(ctx, manager, logger, store, settingsStore, diagnostics, logs, geoStore, routes, check, apps, ping, localProxy); err != nil {
		logger.With("src", "ipc").Error("service stopped", "error", err)
		return err
	}
	return nil
}
