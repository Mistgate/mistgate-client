package session

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

type holdOrderFake struct {
	*engine.Fake
	mu            sync.Mutex
	firstStart    context.Context
	holdSawActive bool
}

func (f *holdOrderFake) Start(ctx context.Context, target engine.Target, report func(engine.Step)) (engine.Info, error) {
	info, err := f.Fake.Start(ctx, target, report)
	if err == nil {
		f.mu.Lock()
		if f.firstStart == nil {
			f.firstStart = ctx
		}
		f.mu.Unlock()
	}
	return info, err
}

func (f *holdOrderFake) Hold() bool {
	f.mu.Lock()
	if f.firstStart != nil {
		select {
		case <-f.firstStart.Done():
		default:
			f.holdSawActive = true
		}
	}
	f.mu.Unlock()
	return f.Fake.Hold()
}

func TestConnectedServerSwitchKeepsKillSwitchHold(t *testing.T) {
	store := testSettings(t, "while")
	fake := engine.NewFake(engine.FakeConfig{})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "first"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(s Status) bool { return s.State == "connected" })
	holdsBefore := fake.HoldCount()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "second"}); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, fake, 2)
	targets := fake.Targets()
	if len(targets) != 2 || !targets[1].Hold || fake.HoldCount() <= holdsBefore {
		t.Fatalf("second attempt hold=%v; Hold calls=%d -> %d", len(targets) == 2 && targets[1].Hold, holdsBefore, fake.HoldCount())
	}
}

func TestSuccessfulConnectClearsAttemptCancelBeforeHold(t *testing.T) {
	store := testSettings(t, "while")
	fake := &holdOrderFake{Fake: engine.NewFake(engine.FakeConfig{})}
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "first"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(s Status) bool { return s.State == "connected" })
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "second"}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	sawActive := fake.holdSawActive
	fake.mu.Unlock()
	if !sawActive {
		t.Fatal("the completed attempt was cancelled before the engine held the network")
	}
}

func TestServerSwitchWhileTunnelIsVerifyingKeepsKillSwitchHold(t *testing.T) {
	store := testSettings(t, "while")
	fake := engine.NewFake(engine.FakeConfig{StepDelays: map[engine.Step]time.Duration{engine.StepVerify: time.Second}})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "first"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(s Status) bool { return s.State == "connecting" && s.Step == string(engine.StepVerify) })
	holdsBefore := fake.HoldCount()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "second"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(fake.Targets()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	targets := fake.Targets()
	if len(targets) != 2 || !targets[1].Hold || fake.HoldCount() <= holdsBefore {
		t.Fatalf("second attempt hold=%v; Hold calls=%d -> %d", len(targets) == 2 && targets[1].Hold, holdsBefore, fake.HoldCount())
	}
}

func TestConnectedServerSwitchWithKillSwitchOffStaysUnheld(t *testing.T) {
	store := testSettings(t, "off")
	fake := engine.NewFake(engine.FakeConfig{})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "first"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(s Status) bool { return s.State == "connected" })
	holdsBefore := fake.HoldCount()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "second"}); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, fake, 2)
	targets := fake.Targets()
	if len(targets) != 2 || targets[1].Hold || fake.HoldCount() != holdsBefore {
		t.Fatalf("second attempt hold=%v; Hold calls=%d -> %d", len(targets) == 2 && targets[1].Hold, holdsBefore, fake.HoldCount())
	}
}
