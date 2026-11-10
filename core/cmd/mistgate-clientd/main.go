package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/ipc"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/session"
)

func main() {
	usage := func() {
		fmt.Fprintln(os.Stderr, "usage: mistgate-clientd run [-fake] [-profiles <file>] | install [run flags] | uninstall")
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
	profiles := flags.String("profiles", "", "load server profiles from a JSON file")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	start := func(ctx context.Context) error { return run(ctx, *fake, *profiles) }
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

// run owns the lifecycle; the context ends it (Ctrl+C in a console, a stop request as a Windows service).
func run(ctx context.Context, useFake bool, profilesPath string) error {
	var eng engine.Engine
	if profilesPath != "" {
		eng = engine.NewReal(func() ([]profile.Profile, error) { return profile.Load(profilesPath) })
	} else if useFake {
		eng = engine.NewFake(engine.FakeConfig{StepDelay: 300 * time.Millisecond})
	}
	manager := session.NewManager(eng)
	defer manager.Close()
	logger := ipc.NewEventLogger(func(data any) { manager.Events().Publish("log", data) })
	slog.SetDefault(logger)
	if err := ipc.Run(ctx, manager, logger); err != nil {
		logger.Error("service stopped", "error", err)
		return err
	}
	return nil
}
