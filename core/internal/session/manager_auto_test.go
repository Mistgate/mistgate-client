package session

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/profile"
)

var autoTarget = engine.Target{Server: "auto", Protocol: "auto", Sub: "sub"}

func autoProfiles(ids ...string) []profile.Profile {
	profiles := make([]profile.Profile, len(ids))
	for i, id := range ids {
		profiles[i] = profile.Profile{ID: id, Sub: "sub", Protocol: "hysteria2"}
	}
	return profiles
}

// avoidedBy lists what each attempt was asked to avoid, one entry per attempt.
func avoidedBy(fake *engine.Fake) []string {
	var out []string
	for _, target := range fake.Targets() {
		out = append(out, strings.Join(target.Avoid, ","))
	}
	return out
}

func TestAutoPaths(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "first connect moves on to the next path and connects", run: testAutoFirstConnectMovesOn},
		{name: "first connect ends in an error after four failed attempts", run: testAutoFirstConnectGivesUp},
		{name: "verify_failed on a reconnect rules the path out at once", run: testAutoVerifyFailedRulesPathOut},
		{name: "a reconnect keeps off a path that failed twice until the round is done", run: testAutoRoundBeforeReturning},
		{name: "on_server_down next and fastest leave the server on auto", run: testAutoStaysAuto},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testAutoFirstConnectMovesOn(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	fake.SetFailing("p1")
	manager, subscription := retryManager(t, fake, "off", 5*time.Millisecond)
	if _, err := manager.Connect(context.Background(), autoTarget); err != nil {
		t.Fatal(err)
	}
	connected := waitForStatus(t, subscription.C, func(status Status) bool {
		if status.State == "error" || status.State == "reconnecting" {
			t.Fatalf("the person saw %#v while the first path failed", status)
		}
		return status.State == "connected"
	})
	if connected.ServerID != "p2" {
		t.Fatalf("connected to %q, want p2", connected.ServerID)
	}
	if avoided := avoidedBy(fake); len(avoided) != 2 || avoided[0] != "" || avoided[1] != "p1" {
		t.Fatalf("avoided by attempt = %q, want the second attempt to avoid p1", avoided)
	}
}

func testAutoFirstConnectGivesUp(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailAt: engine.StepHandshake})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3", "p4", "p5")...)
	manager, subscription := retryManager(t, fake, "off", 5*time.Millisecond)
	if _, err := manager.Connect(context.Background(), autoTarget); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "error" && status.Error == "no_server_answers" })
	time.Sleep(30 * time.Millisecond)
	if got := fake.StartCount(); got != 4 {
		t.Fatalf("attempts = %d, want 4", got)
	}
}

func testAutoVerifyFailedRulesPathOut(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailCode: "verify_failed"})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	manager, subscription := retryManager(t, fake, "off", 5*time.Millisecond)
	if _, err := manager.Connect(context.Background(), autoTarget); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailing("p1")
	manager.NetworkChanged("wake", time.Hour)
	connected := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if connected.ServerID != "p2" {
		t.Fatalf("reconnected to %q, want p2", connected.ServerID)
	}
	// connect, the reconnect that found p1 carrying nothing, and the very next attempt already away from it
	if avoided := avoidedBy(fake); len(avoided) != 3 || avoided[1] != "" || avoided[2] != "p1" {
		t.Fatalf("avoided by attempt = %q", avoided)
	}
}

func testAutoRoundBeforeReturning(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	manager, subscription := retryManager(t, fake, "off", 2*time.Millisecond)
	if _, err := manager.Connect(context.Background(), autoTarget); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailing("p1", "p2", "p3")
	manager.NetworkChanged("wake", time.Hour)
	waitForStarts(t, fake, 8)
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// two failures of a path put it aside; once every path has had its two, the round starts again
	want := []string{"", "", "p1", "p1", "p1,p2", "p1,p2", ""}
	if got := avoidedBy(fake)[1:8]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("avoided by attempt = %q, want %q", got, want)
	}
}

func testAutoStaysAuto(t *testing.T) {
	for _, mode := range []string{"next", "fastest"} {
		store := testSettings(t, "off")
		if _, err := store.Set(map[string]json.RawMessage{"on_server_down": json.RawMessage(`"` + mode + `"`)}); err != nil {
			t.Fatal(err)
		}
		fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
		fake.SetServers("a", "b", "c")
		fake.SetFastest("c")
		timing := defaultManagerTiming()
		timing.probeInterval = 5 * time.Millisecond
		timing.probeRetryInterval = 2 * time.Millisecond
		timing.probeFailureWindow = time.Millisecond
		manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{2 * time.Millisecond})
		subscription, err := manager.Events().Subscribe([]string{"status"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Connect(context.Background(), engine.Target{Server: "auto"}); err != nil {
			t.Fatal(err)
		}
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
		fake.SetFailStartCode("offline")
		fake.SetProbeErr(errors.New("tunnel is dead"))
		waitForStarts(t, fake, 8)
		if _, err := manager.Disconnect(context.Background()); err != nil {
			t.Fatal(err)
		}
		avoided := false
		for i, target := range fake.Targets() {
			if target.Server != "auto" {
				t.Fatalf("%s: attempt %d went to %q, want auto", mode, i, target.Server)
			}
			avoided = avoided || len(target.Avoid) != 0
		}
		if !avoided {
			t.Fatalf("%s: no attempt was told to avoid a path that failed twice", mode)
		}
		subscription.Close()
		manager.Close()
	}
}
