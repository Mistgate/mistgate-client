package session

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/profile"
)

// clock is the memory's time in these tests: it stands still until a test moves it.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock { return &clock{at: time.Unix(1_700_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// memoryManager is a manager whose Auto has a memory, the network key "net" and the given clock.
func memoryManager(t *testing.T, fake *engine.Fake, mem *auto.Memory, c *clock, probe time.Duration, ids ...string) (*Manager, *Subscription) {
	t.Helper()
	timing := defaultManagerTiming()
	timing.probeInterval = probe
	route := RouteState{Auto: AutoMemory{
		Paths:      mem,
		NetworkKey: func() (string, string) { return "net", "wifi" },
		PathIDs:    func() []string { return ids },
		Now:        c.now,
	}}
	manager := newManagerWithTimings(fake, testSettings(t, "off").Get, timing, []time.Duration{5 * time.Millisecond}, route)
	t.Cleanup(manager.Close)
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subscription.Close)
	return manager, subscription
}

func noErrors(t *testing.T) func(Status) bool {
	return func(status Status) bool {
		if status.State == "error" || status.State == "reconnecting" {
			t.Fatalf("the person saw %#v", status)
		}
		return status.State == "connected"
	}
}

func prefers(fake *engine.Fake) []string {
	var out []string
	for _, target := range fake.Targets() {
		out = append(out, target.Prefer)
	}
	return out
}

func connectAuto(t *testing.T, manager *Manager) {
	t.Helper()
	if _, err := manager.Connect(context.Background(), autoTarget); err != nil {
		t.Fatal(err)
	}
}

func TestAutoMemory(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"a known path connects with no race and the status says known", testMemoryKnown},
		{"a network that is not known is a race and the status says fastest", testMemoryUnknownNetwork},
		{"a known path that fails is followed by a race, not by the same path", testMemoryKnownFails},
		{"two failures in a row put a path in quarantine and a success lifts it", testMemoryQuarantine},
		{"offline is not written down", testMemoryOfflineNotRecorded},
		{"the memory outlives a restart and holds no names", testMemoryRestart},
		{"a connection that died on one path and comes back on another is a failover", testMemoryFailover},
		{"the round trip is noted at the first good probe", testMemoryRTT},
		{"a path that left the subscriptions is forgotten", testMemoryKeep},
		{"a named server is written down but is not Auto", testMemoryPinned},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testMemoryKnown(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	c, mem := newClock(), auto.Open("")
	mem.Success("net", "p2", 40, c.now())
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	connectAuto(t, manager)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p2" || !connected.Auto || connected.Reason != "known" {
		t.Fatalf("status = %#v, want p2 by Auto, known", connected)
	}
	if got := strings.Join(prefers(fake), ","); got != "p2" || fake.StartCount() != 1 {
		t.Fatalf("prefer by attempt = %q (%d starts), want p2 at once", got, fake.StartCount())
	}
}

func testMemoryUnknownNetwork(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	c, mem := newClock(), auto.Open("")
	mem.Success("elsewhere", "p2", 40, c.now())
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	connectAuto(t, manager)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p1" || !connected.Auto || connected.Reason != "fastest" {
		t.Fatalf("status = %#v, want p1 by Auto, fastest", connected)
	}
	if got := prefers(fake); len(got) != 1 || got[0] != "" {
		t.Fatalf("prefer by attempt = %q, want a race", got)
	}
	// the one path of a subscription is no choice
	single := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	single.SetProfiles(autoProfiles("only")...)
	manager, subscription = memoryManager(t, single, auto.Open(""), c, time.Hour)
	connectAuto(t, manager)
	if only := waitForStatus(t, subscription.C, noErrors(t)); only.Reason != "only" || !only.Auto {
		t.Fatalf("status = %#v, want only", only)
	}
}

func testMemoryKnownFails(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	fake.SetFailing("p2")
	c, mem := newClock(), auto.Open("")
	mem.Success("net", "p2", 40, c.now())
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	connectAuto(t, manager)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p1" || connected.Reason != "failover" {
		t.Fatalf("status = %#v, want p1 by failover", connected)
	}
	if got := strings.Join(prefers(fake), ","); got != "p2," {
		t.Fatalf("prefer by attempt = %q, want p2 and then a race", got)
	}
	if avoided := avoidedBy(fake); len(avoided) != 2 || avoided[1] != "p2" {
		t.Fatalf("avoided by attempt = %q, want the second to avoid p2", avoided)
	}
	if _, ok := mem.Known("net", []auto.Path{{ID: "p2"}}, c.now()); ok {
		t.Fatal("a path that failed is still known")
	}
}

func testMemoryQuarantine(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	fake.SetFailing("p1", "p2")
	c, mem := newClock(), auto.Open("")
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	for range 2 { // a failed first connect is one failure of each path
		connectAuto(t, manager)
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "error" })
	}
	if got := strings.Join(mem.Avoid("net", c.now()), ","); got != "p1,p2" {
		t.Fatalf("in quarantine = %q, want p1,p2", got)
	}
	fake.SetFailing()
	connectAuto(t, manager)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	targets := fake.Targets()
	if last := targets[len(targets)-1]; strings.Join(last.Avoid, ",") != "p1,p2" || last.Prefer != "" {
		t.Fatalf("last attempt = avoid %v prefer %q, want the quarantine and no prefer", last.Avoid, last.Prefer)
	}
	// every path was aside, so the first of the order is taken, and its success lifts its quarantine
	if connected.ServerID != "p1" || strings.Join(mem.Avoid("net", c.now()), ",") != "p2" {
		t.Fatalf("connected to %q, in quarantine %v", connected.ServerID, mem.Avoid("net", c.now()))
	}
	c.advance(3 * time.Minute)
	if got := mem.Avoid("net", c.now()); len(got) != 0 {
		t.Fatalf("still in quarantine after the time: %v", got)
	}
}

func testMemoryOfflineNotRecorded(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailStartCode: "offline"})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open("")
	mem.Success("net", "p1", 40, c.now())
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	for range 3 {
		connectAuto(t, manager)
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "error" })
	}
	if id, ok := mem.Known("net", []auto.Path{{ID: "p1"}, {ID: "p2"}}, c.now()); !ok || id != "p1" || len(mem.Avoid("net", c.now())) != 0 {
		t.Fatalf("known = %q, %v; avoid %v: offline was written down", id, ok, mem.Avoid("net", c.now()))
	}
}

func testMemoryRestart(t *testing.T) {
	dir := t.TempDir()
	profiles := autoProfiles("p1", "p2", "p3")
	for i := range profiles {
		profiles[i].Name = "Secret Name " + profiles[i].ID
	}
	c := newClock()
	first := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	first.SetProfiles(profiles...)
	first.SetFailing("p1")
	mem := auto.Open(dir)
	manager, subscription := memoryManager(t, first, mem, c, time.Hour)
	connectAuto(t, manager)
	if connected := waitForStatus(t, subscription.C, noErrors(t)); connected.ServerID != "p2" {
		t.Fatalf("connected to %q, want p2", connected.ServerID)
	}
	manager.Close()
	mem.Flush()

	data, err := os.ReadFile(filepath.Join(dir, "auto.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Secret", "wifi"} {
		if strings.Contains(string(data), leak) {
			t.Fatalf("auto.json holds %q: %s", leak, data)
		}
	}

	second := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	second.SetProfiles(profiles...)
	again, subscription := memoryManager(t, second, auto.Open(dir), c, time.Hour)
	connectAuto(t, again)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p2" || connected.Reason != "known" || second.StartCount() != 1 {
		t.Fatalf("after a restart: %#v (%d starts), want p2, known, at once", connected, second.StartCount())
	}
}

func testMemoryFailover(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	c, mem := newClock(), auto.Open("")
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	connectAuto(t, manager)
	if first := waitForStatus(t, subscription.C, noErrors(t)); first.ServerID != "p1" || first.Reason != "fastest" {
		t.Fatalf("status = %#v, want p1, fastest", first)
	}
	fake.SetFailing("p1")
	manager.NetworkChanged("wake", time.Hour) // the connection died
	back := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if back.ServerID != "p2" || !back.Auto || back.Reason != "failover" {
		t.Fatalf("status = %#v, want p2 by failover", back)
	}
}

func testMemoryRTT(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open(dir)
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, noErrors(t))
	fake.SetRTT(55)                     // measured after the tunnel came up, as the real engine does
	manager.NetworkChanged("change", 0) // a probe now, instead of in an hour
	deadline := time.Now().Add(2 * time.Second)
	for {
		mem.Flush()
		if data, _ := os.ReadFile(filepath.Join(dir, "auto.json")); strings.Contains(string(data), `"rtt":55`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the round trip never reached the memory")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testMemoryKeep(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1")...)
	c, mem := newClock(), auto.Open("")
	mem.Success("net", "p1", 40, c.now())
	mem.Success("net", "gone", 10, c.now())
	manager, _ := memoryManager(t, fake, mem, c, time.Hour, "p1")
	manager.SubscriptionsChanged()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, goneKnown := mem.Known("net", []auto.Path{{ID: "gone"}}, c.now())
		if _, ok := mem.Known("net", []auto.Path{{ID: "p1"}}, c.now()); ok && !goneKnown {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the path that left the subscriptions is still remembered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testMemoryPinned(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open("")
	mem.Success("net", "p1", 40, c.now())
	manager, subscription := memoryManager(t, fake, mem, c, time.Hour)
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "p2", Protocol: "auto", Sub: "sub"}); err != nil {
		t.Fatal(err)
	}
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p2" || connected.Auto || connected.Reason != "" {
		t.Fatalf("status = %#v, want p2 and no word of Auto", connected)
	}
	if got := prefers(fake); len(got) != 1 || got[0] != "" {
		t.Fatalf("prefer by attempt = %q: a named server takes no hint", got)
	}
	if _, ok := mem.Known("net", []auto.Path{{ID: "p2"}}, c.now()); !ok {
		t.Fatal("the success of a named server was not written down")
	}
}

// Without a memory Auto is what it was: a race, and the status says how it ended.
func TestAutoWithoutMemory(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(profile.Profile{ID: "p1", Sub: "sub", Protocol: "hysteria2"}, profile.Profile{ID: "p2", Sub: "sub", Protocol: "hysteria2"})
	manager, subscription := retryManager(t, fake, "off", 5*time.Millisecond)
	connectAuto(t, manager)
	connected := waitForStatus(t, subscription.C, noErrors(t))
	if connected.ServerID != "p1" || !connected.Auto || connected.Reason != "fastest" {
		t.Fatalf("status = %#v, want p1, fastest", connected)
	}
	if got := prefers(fake); len(got) != 1 || got[0] != "" {
		t.Fatalf("prefer by attempt = %q, want none", got)
	}
	off, err := manager.Disconnect(context.Background())
	if err != nil || off.Auto || off.Reason != "" {
		t.Fatalf("after a disconnect: %#v, %v", off, err)
	}
}
