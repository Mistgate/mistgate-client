package session

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

func TestJitter(t *testing.T) {
	for range 1000 {
		if got := jitter(10 * time.Minute); got < 7*time.Minute || got >= 13*time.Minute {
			t.Fatalf("jitter = %v, want 70 to 130 percent of 10m", got)
		}
	}
}

// measured waits until Measure has been asked n times, and a little more for the answer to reach the actor.
func (r *rig) measured(t *testing.T, n int) {
	t.Helper()
	waitFor(t, "the background probes", func() bool { return len(r.fake.MeasureCalls()) >= n })
	settle()
}

// idle lets the clock run by d on a connection that has settled, so that exactly one round of probes falls due.
func (r *rig) idle(d time.Duration) {
	settle()
	r.c.advance(d)
	settle()
}

func TestBackgroundProbes(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"a healthy connection probes the other paths, but not more often than the limit", testMeasureHealthyLimit},
		{"a probe writes its success and its failure to the memory, a skipped path nothing", testMeasureWritesMemory},
		{"while the connection's own probes fail in a row, the other paths are not probed", testMeasureWhileFailing},
		{"a named server and Auto with no memory probe nothing", testMeasureNotForAll},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testMeasureHealthyLimit(t *testing.T) {
	r := newRig(t, "S", "p1", "p2", "p3", "p4")
	r.fake.SetMeasure(map[string]time.Duration{"p2": 40 * time.Millisecond, "p3": 50 * time.Millisecond, "p4": 60 * time.Millisecond})
	r.connect(t)
	r.idle(10 * time.Minute)
	if len(r.fake.MeasureCalls()) != 0 {
		t.Fatal("probed within 21 minutes of the connection")
	}
	r.c.advance(30 * time.Minute)
	r.measured(t, 1)
	if first := r.fake.MeasureCalls()[0]; !slices.Equal(first, []string{"p2", "p3"}) {
		t.Fatalf("first round = %v, want the two best alternatives, never the path in use", first)
	}
	r.idle(40 * time.Minute) // the hour has not passed: two probes in it are all there are
	if got := len(r.fake.MeasureCalls()); got != 1 {
		t.Fatalf("%d rounds: more than two probes in an hour", got)
	}
	r.c.advance(40 * time.Minute) // 80 minutes after the first: p2 and p3 were probed less than 2 h ago
	r.measured(t, 2)
	if second := r.fake.MeasureCalls()[1]; !slices.Equal(second, []string{"p4"}) {
		t.Fatalf("second round = %v, want the third alternative only", second)
	}
	r.stays(t, "probes", 1)
}

func testMeasureWritesMemory(t *testing.T) {
	r := newRig(t, "S", "p1", "p2", "p3")
	r.fake.SetMeasure(map[string]time.Duration{"p2": 80 * time.Millisecond}, "p3") // p3 is the live AmneziaWG key's twin
	r.connect(t)
	r.idle(40 * time.Minute)
	r.measured(t, 1)
	stats := r.mem.Stats("net")
	if p2 := stats["p2"]; p2.OK == 0 || p2.RTT != 80 || p2.Streak != 0 {
		t.Fatalf("p2 answered: %#v", p2)
	}
	if p3, found := stats["p3"]; found {
		t.Fatalf("p3 was skipped and has an entry: %#v", p3)
	}
	r.fake.SetMeasure(map[string]time.Duration{"p3": 90 * time.Millisecond}) // p2 stops answering
	r.c.advance(2*time.Hour + time.Minute)
	r.measured(t, 2)
	if p2 := r.mem.Stats("net")["p2"]; p2.Bad == 0 || p2.Streak != 1 {
		t.Fatalf("p2 did not answer: %#v", p2)
	}
	if p3 := r.mem.Stats("net")["p3"]; p3.OK == 0 || p3.RTT != 90 {
		t.Fatalf("p3 answered: %#v", p3)
	}
}

func testMeasureWhileFailing(t *testing.T) {
	r := newRig(t, "F", "p1", "p2", "p3")
	r.fake.SetMeasure(map[string]time.Duration{"p2": 40 * time.Millisecond, "p3": 50 * time.Millisecond})
	r.connect(t)
	waitFor(t, "a series of failed probes", func() bool { return r.fake.ProbeCount() >= 6 })
	r.idle(40 * time.Minute)
	if got := len(r.fake.MeasureCalls()); got != 0 {
		t.Fatalf("%d rounds while the connection's own probes fail", got)
	}
	r.fake.SetProbeErrs() // the line mends
	r.fake.SetProbeErr(nil)
	r.idle(40 * time.Minute)
	r.measured(t, 1)
}

func testMeasureNotForAll(t *testing.T) {
	r := newRig(t, "S", "p1", "p2", "p3")
	r.fake.SetMeasure(map[string]time.Duration{"p2": 40 * time.Millisecond})
	if _, err := r.manager.Connect(context.Background(), engine.Target{Server: "p1", Protocol: "auto", Sub: "sub"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, r.events.C, connected)
	r.idle(40 * time.Minute)
	r.idle(40 * time.Minute)
	if got := len(r.fake.MeasureCalls()); got != 0 {
		t.Fatalf("%d rounds for a named server", got)
	}

	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetProfiles(autoProfiles("p1", "p2", "p3")...)
	c := newClock()
	manager, events, _ := qualityManager(t, fake, nil, c, quickProbes)
	connectAuto(t, manager)
	waitForStatus(t, events.C, connected)
	settle()
	c.advance(40 * time.Minute)
	settle()
	if got := len(fake.MeasureCalls()); got != 0 {
		t.Fatalf("%d rounds for Auto with no memory", got)
	}
}
