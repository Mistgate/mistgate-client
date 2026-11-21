package session

import (
	"context"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

func TestSubscriptionsChangedTunnel(t *testing.T) {
	connected := func(t *testing.T) (*Manager, *engine.Fake, *Subscription) {
		fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
		manager, subscription := retryManager(t, fake, "off", 5*time.Millisecond)
		if _, err := manager.Connect(context.Background(), engine.Target{Server: "a"}); err != nil {
			t.Fatal(err)
		}
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
		return manager, fake, subscription
	}
	t.Run("a changed path rebuilds the tunnel, the network held", func(t *testing.T) {
		manager, fake, subscription := connected(t)
		fake.SetStale(true)
		manager.SubscriptionsChanged()
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
		if targets := fake.Targets(); len(targets) != 2 || !targets[1].Hold || targets[1].Server != "a" {
			t.Fatalf("attempts = %#v, want a second one on a with the network held", targets)
		}
	})
	t.Run("a sync that leaves the path alone leaves the tunnel alone", func(t *testing.T) {
		manager, fake, _ := connected(t)
		manager.SubscriptionsChanged()
		if _, err := manager.Status(context.Background()); err != nil { // the actor has taken the change
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := fake.StartCount(); got != 1 {
			t.Fatalf("attempts = %d, want the tunnel untouched", got)
		}
	})
	t.Run("a path that is gone ends in no_subscription", func(t *testing.T) {
		manager, fake, subscription := connected(t)
		fake.SetStale(true)
		fake.SetFailStartCode("no_subscription")
		manager.SubscriptionsChanged()
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "error" && status.Error == "no_subscription" })
		if got := fake.StopCount(); got != 1 {
			t.Fatalf("engine stops = %d, want 1", got)
		}
	})
}
