package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

// A server may refuse an account that is fine for a few minutes. A session that was up comes back by itself when the
// refusals stop: it must not have been given up meanwhile.
func TestRefusedReconnectComesBackWhenTheRefusalsStop(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 2 * time.Millisecond
	timing.probeFailureWindow = time.Millisecond
	timing.refusalPatience = time.Hour
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{5 * time.Millisecond})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-a", Protocol: "awg"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailStartCode("auth_rejected")
	fake.SetProbeErr(errors.New("tunnel is dead"))
	for refusals := 0; refusals < 3; {
		status := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "blocked" || status.Error == "auth_rejected" })
		if status.State == "blocked" {
			t.Fatal("given up at a refusal that had lasted a moment")
		}
		refusals++
	}
	fake.SetFailStartCode("")
	fake.SetProbeErr(nil)
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
}
