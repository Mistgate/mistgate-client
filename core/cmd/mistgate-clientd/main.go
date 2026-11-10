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
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/ipc"
	"github.com/mistgate/mistgate-client/core/internal/session"
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

	start := func(ctx context.Context) error { return run(ctx, *fake, *dataDir, *verify) }
	if asService, err := runAsService(start); asService {
		if err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := start(ctx); err != nil {
		os.Exit(1)
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
func run(ctx context.Context, useFake bool, dataDir, verify string) error {
	store, err := subs.Open(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the data directory:", err)
		return err
	}
	go store.Run(ctx)
	var eng engine.Engine
	if useFake {
		eng = engine.NewFake(engine.FakeConfig{StepDelay: 300 * time.Millisecond})
	} else {
		eng = engine.NewReal(store.Profiles, verify)
	}
	manager := session.NewManager(eng)
	defer manager.Close()
	logger := ipc.NewEventLogger(func(data any) { manager.Events().Publish("log", data) })
	slog.SetDefault(logger)
	if err := ipc.Run(ctx, manager, logger, store); err != nil {
		logger.Error("service stopped", "error", err)
		return err
	}
	return nil
}
