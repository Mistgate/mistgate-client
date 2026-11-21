package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
)

func TestStalled(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	window := 6 * time.Second
	base := counterSample{at: at, sent: 1000, received: 500}
	tests := []struct {
		name string
		cur  counterSample
		want bool
	}{
		{"data out, none back, a window passed", counterSample{at.Add(6 * time.Second), 1000 + stallSent, 500}, true},
		{"a long stall", counterSample{at.Add(time.Minute), 1 << 30, 500}, true},
		{"a little less than the window", counterSample{at.Add(5900 * time.Millisecond), 1 << 20, 500}, false},
		{"a little less than 32 KiB", counterSample{at.Add(7 * time.Second), 1000 + stallSent - 1, 500}, false},
		{"one byte came back", counterSample{at.Add(7 * time.Second), 1 << 20, 501}, false},
		{"nothing went out: an idle line", counterSample{at.Add(7 * time.Second), 1000, 500}, false},
		{"the counters began again", counterSample{at.Add(7 * time.Second), 10, 500}, false},
	}
	for _, test := range tests {
		if got := stalled(base, test.cur, window); got != test.want {
			t.Errorf("%s: stalled = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestStalledDead(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name     string
		failures int
		start    time.Time
		rxAtBase uint64
		rxNow    uint64
		stall    bool
		want     bool
	}{
		{"a stall and one failed probe", 1, start, 0, 0, true, true},
		{"a stall and no failed probe", 0, start, 0, 0, true, false},
		{"a failed probe and no stall", 3, start, 0, 0, false, false},
		{"a stall, but the streak has no start", 1, time.Time{}, 0, 0, true, false},
		{"bytes came since the streak began", 1, start, 0, receivedAliveThreshold, true, false},
		{"fewer bytes than that", 1, start, 0, receivedAliveThreshold - 1, true, true},
	}
	for _, test := range tests {
		if got := stalledDead(test.failures, test.start, test.rxAtBase, test.rxNow, test.stall); got != test.want {
			t.Errorf("%s: dead = %v, want %v", test.name, got, test.want)
		}
	}
}

// feedStall makes a connection go on sending and hear nothing: n times 64 KiB more sent and a second more of time.
func feedStall(fake *engine.Fake, c *clock, n int) {
	for range n {
		fake.SetSent(fake.Sent() + 64<<10)
		c.advance(time.Second)
		time.Sleep(6 * time.Millisecond) // a few ticks of the counters
	}
}

func quickProbes(timing *managerTiming) {
	timing.probeInterval, timing.probeRetryInterval, timing.trafficEvery = 3*time.Millisecond, 3*time.Millisecond, 2*time.Millisecond
}

func TestStallDeath(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"a stall and a failed probe end the connection at once and mark the path", testStallDeathAtOnce},
		{"a stall with probes that pass does not", testStallWithGoodProbes},
		{"an ordinary death marks nothing", testOrdinaryDeathMarksNothing},
		{"a named server is not watched", testStallPinned},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testStallDeathAtOnce(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, quickProbes)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	if strings.Contains(saved(t, mem, dir), `"bad"`) {
		t.Fatal("a failure before any")
	}
	fake.SetProbeErr(errors.New("the probe failed"))
	feedStall(fake, c, 10)
	waitForStatus(t, subscription.C, func(s Status) bool { return s.State == "reconnecting" })
	if data := saved(t, mem, dir); !strings.Contains(data, `"bad"`) {
		t.Fatalf("the path of a connection that died of a stall is not marked: %s", data)
	}
}

func testStallWithGoodProbes(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, quickProbes)
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	feedStall(fake, c, 10)
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "connected" || fake.StartCount() != 1 || strings.Contains(saved(t, mem, dir), `"bad"`) {
		t.Fatalf("status %#v (%d starts), %v: a stall alone is no death", status, fake.StartCount(), err)
	}
}

func testOrdinaryDeathMarksNothing(t *testing.T) {
	dir := t.TempDir()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open(dir)
	manager, subscription, _ := qualityManager(t, fake, mem, c, func(timing *managerTiming) {
		quickProbes(timing)
		timing.probeFailureWindow = 20 * time.Millisecond
	})
	connectAuto(t, manager)
	waitForStatus(t, subscription.C, connected)
	fake.SetProbeErr(errors.New("the probe failed"))
	waitForStatus(t, subscription.C, func(s Status) bool { return s.State == "reconnecting" })
	if data := saved(t, mem, dir); strings.Contains(data, `"bad"`) {
		t.Fatalf("an ordinary death marked the path: %s", data)
	}
}

func testStallPinned(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2")...)
	c, mem := newClock(), auto.Open("")
	manager, subscription, _ := qualityManager(t, fake, mem, c, quickProbes)
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "p1", Protocol: "auto", Sub: "sub"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, connected)
	fake.SetProbeErr(errors.New("the probe failed"))
	feedStall(fake, c, 10)
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "connected" || fake.StartCount() != 1 {
		t.Fatalf("status %#v (%d starts), %v: a named server keeps the window of 20 s", status, fake.StartCount(), err)
	}
}
