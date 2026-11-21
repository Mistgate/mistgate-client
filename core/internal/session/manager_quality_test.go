package session

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

// qualityManager is memoryManager with the timings of the watch squeezed: tune changes them. The clock of the memory is
// the clock of the watch too, so a test moves both by c.advance.
func qualityManager(t *testing.T, fake *engine.Fake, mem *auto.Memory, c *clock, tune func(*managerTiming)) (*Manager, *Subscription, *settings.Store) {
	t.Helper()
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	timing.proofDelayMin, timing.proofDelayMax = 30*time.Millisecond, 31*time.Millisecond
	if tune != nil {
		tune(&timing)
	}
	store := testSettings(t, "off")
	route := RouteState{Auto: AutoMemory{
		Paths:      mem,
		NetworkKey: func() (string, string) { return "net", "wifi" },
		PathIDs:    func() []string { return nil },
		Now:        c.now,
	}}
	manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{5 * time.Millisecond}, route)
	t.Cleanup(manager.Close)
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subscription.Close)
	return manager, subscription, store
}

func connected(status Status) bool { return status.State == "connected" }

// waitFor polls until cond holds, for two seconds at most.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func saved(t *testing.T, mem *auto.Memory, dir string) string {
	t.Helper()
	mem.Flush()
	data, err := os.ReadFile(filepath.Join(dir, "auto.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestProof(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"a freeze moves to the next path, marks the path and keeps it out", testProofFreezeMoves},
		{"a second freeze in a row stays where it is", testProofSecondFreezeStays},
		{"a person's connect lets a freeze move again", testProofResetByConnect},
		{"a check that passes writes the mark and resets the count", testProofOkMarks},
		{"the check is skipped when it is not needed or not wanted", testProofSkipped},
		{"Auto with no memory checks nothing", testProofNeedsMemory},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testProofFreezeMoves(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	fake.SetProof("p1", "freeze")
	fake.SetProof("p2", "ok")
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, nil)
	connectAuto(t, manager)
	if first := waitForStatus(t, subscription.C, connected); first.ServerID != "p1" {
		t.Fatalf("connected to %q, want p1", first.ServerID)
	}
	held := waitForStatus(t, subscription.C, func(s Status) bool { return s.State == "reconnecting" })
	if held.Error != "" || held.Auto || held.Reason != "" {
		t.Fatalf("while it moves: %#v", held)
	}
	back := waitForStatus(t, subscription.C, connected)
	if back.ServerID != "p2" || !back.Auto || back.Reason != "freeze" {
		t.Fatalf("status = %#v, want p2 by Auto, freeze", back)
	}
	if targets := fake.Targets(); len(targets) != 2 || strings.Join(targets[1].Avoid, ",") != "p1" || !targets[1].Hold || targets[1].Prefer != "" {
		t.Fatalf("attempts = %#v, want the second held, a race, avoiding p1", targets)
	}
	if _, ok := mem.Known("net", []auto.Path{{ID: "p1"}}, c.now()); ok {
		t.Fatal("the frozen path is still known")
	}
	if data := saved(t, mem, dir); !strings.Contains(data, `"froze"`) {
		t.Fatalf("no freeze in the memory: %s", data)
	}
}

func testProofSecondFreezeStays(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	fake.SetProof("", "freeze")
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, nil)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	if second := waitForStatus(t, subscription.C, connected); second.ServerID != "p2" || second.Reason != "freeze" {
		t.Fatalf("status = %#v, want p2 by freeze", second)
	}
	waitFor(t, "the second check", func() bool { return fake.ProofCount() >= 2 })
	time.Sleep(60 * time.Millisecond)
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "connected" || status.ServerID != "p2" || fake.StartCount() != 2 {
		t.Fatalf("after the second freeze: %#v (%d starts), %v; want to stay on p2", status, fake.StartCount(), err)
	}
	// the second path is not marked: the network or the target is at fault, not the path
	if id, ok := mem.Known("net", []auto.Path{{ID: "p2"}}, c.now()); !ok || id != "p2" || strings.Count(saved(t, mem, dir), `"froze"`) != 1 {
		t.Fatalf("p2 known %v; memory %s", ok, saved(t, mem, dir))
	}
}

func testProofResetByConnect(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	fake.SetProof("", "freeze")
	c, mem := newClock(), auto.Open("")
	manager, subscription, _ := qualityManager(t, fake, mem, c, nil)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	waitForStatus(t, subscription.C, connected) // moved once, and stays
	waitFor(t, "the second check", func() bool { return fake.ProofCount() >= 2 })
	connectAuto(t, manager) // the person connects again
	waitForStatus(t, subscription.C, func(s Status) bool { return s.State == "connecting" })
	waitForStatus(t, subscription.C, connected)
	moved := waitForStatus(t, subscription.C, connected)
	if moved.Reason != "freeze" || fake.StartCount() != 4 {
		t.Fatalf("status = %#v after %d starts, want a second move for the new connect", moved, fake.StartCount())
	}
}

func testProofOkMarks(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	fake.SetProof("", "ok")
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, nil)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	waitFor(t, "the mark of data", func() bool { return mem.Proved("net", "p1", c.now()) })
	if strings.Contains(saved(t, mem, dir), `"froze"`) || fake.StartCount() != 1 {
		t.Fatal("a check that passed moved or marked the path")
	}
}

func testProofSkipped(t *testing.T) {
	old := func(c *clock) func(*auto.Memory) {
		return func(mem *auto.Memory) { mem.Prove("net", "p1", c.now().Add(-25*time.Hour)) }
	}
	tests := []struct {
		name  string
		setup func(*clock) func(*auto.Memory)
		after func(*engine.Fake, *settings.Store) // once connected
		pin   bool
		want  uint64
	}{
		{"nothing to skip for", nil, nil, false, 1},
		{"a mark older than a day does not skip", old, nil, false, 1},
		{"a fresh mark skips", func(c *clock) func(*auto.Memory) {
			return func(mem *auto.Memory) { mem.Prove("net", "p1", c.now().Add(-23*time.Hour)) }
		}, nil, false, 0},
		{"bytes received skip", nil, func(f *engine.Fake, _ *settings.Store) { f.SetReceived(256 << 10) }, false, 0},
		{"a few bytes do not", nil, func(f *engine.Fake, _ *settings.Store) { f.SetReceived(256<<10 - 1) }, false, 1},
		{"the game mode skips", nil, func(_ *engine.Fake, s *settings.Store) {
			if _, err := s.Set(map[string]json.RawMessage{"game": json.RawMessage(`true`)}); err != nil {
				panic(err)
			}
		}, false, 0},
		{"a named server is not checked", nil, nil, true, 0},
	}
	for _, test := range tests {
		fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
		fake.SetProfiles(autoProfiles("p1", "p2")...)
		fake.SetProof("", "ok")
		c, mem := newClock(), auto.Open("")
		mem.Success("net", "p1", 20, c.now()) // the known path, which Auto goes to at once
		if test.setup != nil {
			test.setup(c)(mem)
		}
		manager, subscription, store := qualityManager(t, fake, mem, c, func(timing *managerTiming) {
			timing.proofDelayMin, timing.proofDelayMax = 150*time.Millisecond, 151*time.Millisecond
		})
		target := autoTarget
		if test.pin {
			target.Server = "p1"
		}
		if _, err := manager.Connect(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		waitForStatus(t, subscription.C, connected)
		if test.after != nil {
			test.after(fake, store)
			manager.SettingsChanged()
		}
		deadline := time.Now().Add(400 * time.Millisecond)
		for fake.ProofCount() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
		if got := fake.ProofCount(); got != test.want {
			t.Errorf("%s: %d checks, want %d", test.name, got, test.want)
		}
		manager.Close()
	}
}

func testProofNeedsMemory(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	fake.SetProof("", "freeze")
	manager, subscription, _ := qualityManager(t, fake, nil, newClock(), nil)
	connectAuto(t, manager)
	if first := waitForStatus(t, subscription.C, connected); !first.Auto {
		t.Fatalf("status = %#v", first)
	}
	time.Sleep(100 * time.Millisecond)
	if fake.ProofCount() != 0 || fake.StartCount() != 1 {
		t.Fatalf("%d checks, %d starts: Auto with no memory must leave the connection alone", fake.ProofCount(), fake.StartCount())
	}
}
