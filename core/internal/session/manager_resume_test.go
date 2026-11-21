package session

import (
	"context"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

func resumeManager(t *testing.T, killSwitch string, fake *engine.Fake) (*Manager, *Subscription) {
	t.Helper()
	store := testSettings(t, killSwitch)
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{5 * time.Millisecond})
	t.Cleanup(manager.Close)
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subscription.Close)
	return manager, subscription
}

// A service that starts with the VPN left on holds the network at once and goes the way of a tunnel that died.
func TestResumeHoldsAndReconnects(t *testing.T) {
	for _, killSwitch := range []string{"while", "always"} {
		t.Run(killSwitch, func(t *testing.T) {
			fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
			manager, subscription := resumeManager(t, killSwitch, fake)
			holdsAtStart := fake.HoldCount() // "always" holds when the manager starts
			status, err := manager.Resume(context.Background(), engine.Target{Server: "server-a", Protocol: "auto"})
			if err != nil || status.State != "reconnecting" || status.Server != "server-a" {
				t.Fatalf("Resume() = %#v, %v; want reconnecting to server-a", status, err)
			}
			if fake.HoldCount() <= holdsAtStart {
				t.Fatal("the network was not held when the session resumed")
			}
			// ("always" may publish its start-up "blocked" before this: it is not part of the resume)
			waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
			waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
			if targets := fake.Targets(); len(targets) != 1 || !targets[0].Hold || targets[0].Server != "server-a" {
				t.Fatalf("Start targets = %#v, want one held attempt at server-a", targets)
			}
		})
	}
}

// The retries are the existing ones: reconnecting stays, the attempts go on, and a person's disconnect ends it.
func TestResumeRetriesLikeADroppedSession(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailStartCode: "offline"})
	manager, subscription := resumeManager(t, "while", fake)
	if _, err := manager.Resume(context.Background(), engine.Target{Server: "server-a"}); err != nil {
		t.Fatal(err)
	}
	failed := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Error == "offline" })
	if failed.Server != "server-a" {
		t.Fatalf("status = %#v, want the failed attempt on server-a", failed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for fake.StartCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fake.StartCount() < 3 {
		t.Fatalf("Start() calls = %d, want the retries to go on", fake.StartCount())
	}
	for _, target := range fake.Targets() {
		if !target.Hold {
			t.Fatal("a retry opened the network")
		}
	}
	fake.SetFailStartCode("")
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })

	status, err := manager.Disconnect(context.Background())
	if err != nil || status.State != "off" {
		t.Fatalf("Disconnect() = %#v, %v; want off", status, err)
	}
}

// With "always" a failed attempt retries like any dropped session; only the refusals that do not pass block.
func TestResumeAlwaysRetriesAFailedAttempt(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailStartCode: "offline"})
	manager, subscription := resumeManager(t, "always", fake)
	if _, err := manager.Resume(context.Background(), engine.Target{Server: "server-a"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Error == "offline" })
	waitForStarts(t, fake, 3)
	fake.SetFailStartCode("auth_rejected")
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "blocked" && status.Error == "auth_rejected" })
}

func TestResumeDoesNothingWithKillSwitchOff(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager, _ := resumeManager(t, "off", fake)
	status, err := manager.Resume(context.Background(), engine.Target{Server: "server-a"})
	if err != nil || status.State != "off" {
		t.Fatalf("Resume() = %#v, %v; want off", status, err)
	}
	time.Sleep(20 * time.Millisecond)
	if fake.StartCount() != 0 || fake.HoldCount() != 0 {
		t.Fatalf("Start() calls = %d, Hold() calls = %d, want none", fake.StartCount(), fake.HoldCount())
	}
}

func TestResumeLeavesARunningSessionAlone(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager, subscription := resumeManager(t, "while", fake)
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-a"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	status, err := manager.Resume(context.Background(), engine.Target{Server: "server-b"})
	if err != nil || status.State != "connected" || status.Server != "server-a" || fake.StartCount() != 1 {
		t.Fatalf("Resume() over a connected session = %#v, %v, %d starts", status, err, fake.StartCount())
	}
}
