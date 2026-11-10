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
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: mistgate-clientd run [-fake] [-profiles <file>]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	fake := flags.Bool("fake", false, "use the in-process fake engine")
	profiles := flags.String("profiles", "", "load server profiles from a JSON file")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *fake, *profiles); err != nil {
		os.Exit(1)
	}
}

// run owns foreground lifecycle; a future Windows service host can supply its stop context here.
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
