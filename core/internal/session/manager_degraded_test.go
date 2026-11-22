package session

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

// failing is n answers of the probe, by pattern: F fails, anything else passes ("FSS" is a third of them failing).
func failing(pattern string, n int) []error {
	out := make([]error, n)
	for i := range out {
		if pattern[i%len(pattern)] == 'F' {
			out[i] = errors.New("the probe failed")
		}
	}
	return out
}

// rig is a connected Auto whose probes fail a third of the time: a poor connection, on a clock the test moves.
type rig struct {
	fake    *engine.Fake
	c       *clock
	mem     *auto.Memory
	manager *Manager
	events  *Subscription
	store   *settings.Store
}

func newRig(t *testing.T, pattern string, ids ...string) *rig {
	t.Helper()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErrs: failing(pattern, 4000)})
	fake.SetProfiles(autoProfiles(ids...)...)
	c, mem := newClock(), auto.Open("")
	manager, events, store := qualityManager(t, fake, mem, c, quickProbes)
	return &rig{fake, c, mem, manager, events, store}
}

func settle() { time.Sleep(60 * time.Millisecond) } // a few ticks of the counters and probes

// searched waits until Fastest has been asked n times, and a little more for the answer to reach the actor.
func (r *rig) searched(t *testing.T, n uint64) {
	t.Helper()
	waitFor(t, "the search", func() bool { return r.fake.FastestCount() >= n })
	settle()
}

// moved waits for the connection that follows a move, which is on path to.
func (r *rig) moved(t *testing.T, to string) Status {
	t.Helper()
	status := waitForStatus(t, r.events.C, connected)
	if status.ServerID != to || !status.Auto || status.Reason != "degraded" {
		t.Fatalf("status = %#v, want %s by Auto, degraded", status, to)
	}
	return status
}

func (r *rig) setting(t *testing.T, key, value string) {
	t.Helper()
	if _, err := r.store.Set(map[string]json.RawMessage{key: json.RawMessage(value)}); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) connect(t *testing.T) Status {
	t.Helper()
	connectAuto(t, r.manager)
	return waitForStatus(t, r.events.C, connected)
}

func (r *rig) stays(t *testing.T, what string, starts uint64) {
	t.Helper()
	status, err := r.manager.Status(context.Background())
	if err != nil || status.State != "connected" || r.fake.StartCount() != starts {
		t.Fatalf("%s: status %#v, %d starts (want %d), %v", what, status, r.fake.StartCount(), starts, err)
	}
}

func TestDegradedSwitch(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"degraded: a move at a quiet moment, and the status says degraded", testSwitchAtAQuietMoment},
		{"no quiet moment: it moves at the limit of the wait", testSwitchAfterTheLimit},
		{"degraded and no replacement: it stays, and does not search again for 3 minutes", testSwitchNoReplacement},
		{"the game mode holds a degraded path and leaves a heavy one", testSwitchGame},
		{"no more than 4 moves in an hour", testSwitchLimits},
		{"a named server never moves", testSwitchPinned},
		{"auto_switch off: no move by choice, but a dead connection still goes elsewhere", testSwitchSettingOff},
		{"a connection that recovered before the quiet moment stays", testSwitchRecovered},
		{"Auto with no memory never moves by choice", testSwitchNoMemory},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testSwitchAtAQuietMoment(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3")
	r.fake.SetFastest("p2")
	if first := r.connect(t); first.ServerID != "p1" {
		t.Fatalf("connected to %q, want p1", first.ServerID)
	}
	r.searched(t, 1)
	r.c.advance(4 * time.Second) // not yet 5 s of quiet
	settle()
	r.stays(t, "after 4 quiet seconds", 1)
	r.c.advance(2 * time.Second)
	r.moved(t, "p2")
	targets := r.fake.Targets()
	if len(targets) != 2 || targets[1].Prefer != "p2" || strings.Join(targets[1].Avoid, ",") != "p1" || !targets[1].Hold {
		t.Fatalf("attempts = %#v, want the second held, to p2 at once, avoiding p1", targets)
	}
	if _, ok := r.mem.Known("net", []auto.Path{{ID: "p1"}}, r.c.now()); !ok {
		t.Fatal("a move by choice marked the path it left as failed")
	}
}

func testSwitchAfterTheLimit(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3")
	r.fake.SetFastest("p2")
	r.fake.SetTraffic(10<<20, 0) // 10 Mbit/s: never quiet
	r.connect(t)
	r.searched(t, 1)
	r.c.advance(59 * time.Second)
	settle()
	r.stays(t, "after 59 s of a busy line", 1)
	r.c.advance(2 * time.Second)
	r.moved(t, "p2")
}

func testSwitchNoReplacement(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3") // Fastest answers no one
	if first := r.connect(t); first.Reason != "fastest" {
		t.Fatalf("status = %#v", first)
	}
	r.searched(t, 1)
	r.c.advance(2 * time.Minute)
	settle()
	r.stays(t, "with no replacement", 1)
	if status, _ := r.manager.Status(context.Background()); status.Reason != "fastest" || r.fake.FastestCount() != 1 {
		t.Fatalf("status %#v, %d searches: the status must be as it was, and 3 minutes must pass between searches", status, r.fake.FastestCount())
	}
	r.c.advance(2 * time.Minute)
	waitFor(t, "the next search", func() bool { return r.fake.FastestCount() >= 2 })
	r.stays(t, "after the second search", 1)
}

func testSwitchGame(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3")
	r.fake.SetFastest("p2")
	r.setting(t, "game", "true")
	r.connect(t)
	settle()
	settle()
	if r.fake.FastestCount() != 0 {
		t.Fatal("a game was moved for a third of lost probes")
	}
	r.c.advance(3 * time.Minute) // the old probes are out of the window of the heavy loss
	r.fake.SetProbeErrs(failing("FFS", 4000)...)
	r.searched(t, 1)
	r.c.advance(6 * time.Second)
	r.moved(t, "p2")
}

func testSwitchLimits(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3", "p4", "p5", "p6")
	r.connect(t)
	for i, to := range []string{"p2", "p3", "p4", "p5"} {
		r.fake.SetFastest(to)
		r.c.advance(4 * time.Minute) // the 3 minutes between two moves
		r.searched(t, uint64(i+1))
		r.c.advance(6 * time.Second)
		r.moved(t, to)
	}
	r.fake.SetFastest("p6")
	r.c.advance(4 * time.Minute)
	settle()
	settle()
	if r.fake.FastestCount() != 4 {
		t.Fatalf("%d searches: a fifth move in an hour was looked for", r.fake.FastestCount())
	}
	r.stays(t, "after four moves", 5)
	r.c.advance(61 * time.Minute) // the hour has passed, the day has not
	r.searched(t, 5)
	r.c.advance(6 * time.Second)
	r.moved(t, "p6")
}

func testSwitchPinned(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2")
	r.fake.SetFastest("p2")
	if _, err := r.manager.Connect(context.Background(), engine.Target{Server: "p1", Protocol: "auto", Sub: "sub"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, r.events.C, connected)
	settle()
	r.c.advance(5 * time.Minute)
	settle()
	if r.fake.FastestCount() != 0 {
		t.Fatal("a named server was looked at for a replacement")
	}
	r.stays(t, "a named server", 1)
}

func testSwitchSettingOff(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2")
	r.fake.SetFastest("p2")
	r.setting(t, "auto_switch", "false")
	r.connect(t)
	settle()
	r.c.advance(4 * time.Minute)
	settle()
	if r.fake.FastestCount() != 0 {
		t.Fatal("a replacement was looked for with auto_switch off")
	}
	r.stays(t, "auto_switch off", 1)
	r.fake.SetFailing("p1")
	r.manager.NetworkChanged("wake", time.Hour) // the connection died
	back := waitForStatus(t, r.events.C, connected)
	if back.ServerID != "p2" || back.Reason != "failover" {
		t.Fatalf("status = %#v, want p2 by failover: a dead connection leaves its path whatever the setting", back)
	}
}

func testSwitchRecovered(t *testing.T) {
	r := newRig(t, "FSS", "p1", "p2", "p3")
	r.fake.SetFastest("p2")
	r.fake.SetTraffic(10<<20, 0)
	r.connect(t)
	r.searched(t, 1)
	r.fake.SetProbeErrs() // the line mends
	r.c.advance(4 * time.Minute)
	settle()
	r.stays(t, "a mended connection", 1)
	r.c.advance(5 * time.Minute)
	settle()
	if r.fake.FastestCount() != 1 {
		t.Fatalf("%d searches: a mended connection was looked at again", r.fake.FastestCount())
	}
	r.stays(t, "a mended connection, later", 1)
}

func testSwitchNoMemory(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErrs: failing("FSS", 4000)})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	fake.SetFastest("p2")
	c := newClock()
	manager, events, _ := qualityManager(t, fake, nil, c, quickProbes)
	connectAuto(t, manager)
	waitForStatus(t, events.C, connected)
	settle()
	c.advance(5 * time.Minute)
	settle()
	if fake.FastestCount() != 0 || fake.StartCount() != 1 {
		t.Fatalf("%d searches, %d starts: Auto with no memory must not move by choice", fake.FastestCount(), fake.StartCount())
	}
}
