package auto

import (
	"testing"
	"time"
)

// probes are n probes of which the first `fails` failed, spread over the span before t0 (at the end of it, the oldest first).
func probes(n, fails int, span time.Duration) []Sample {
	out := make([]Sample, n)
	for i := range out {
		out[i] = Sample{At: t0.Add(-span + span*time.Duration(i)/time.Duration(max(n-1, 1))), Fail: i < fails, Took: time.Duration(50+i) * time.Millisecond}
	}
	return out
}

func stalls(n int, age time.Duration) []Sample {
	out := make([]Sample, n)
	for i := range out {
		out[i] = Sample{At: t0.Add(-age), Stall: true}
	}
	return out
}

func TestDegraded(t *testing.T) {
	tests := []struct {
		name    string
		samples []Sample
		awg     bool
		want    bool
	}{
		{"nothing seen", nil, false, false},
		{"all well", probes(18, 0, 170*time.Second), false, false},
		{"three of nine is 30 percent", probes(9, 3, 170*time.Second), false, true},
		{"two of nine is not", probes(9, 2, 170*time.Second), false, false},
		{"too few probes to say, all failed", probes(8, 8, 170*time.Second), false, false},
		{"a third of eighteen", probes(18, 6, 170*time.Second), false, true},
		{"awg: 30 percent is noise", probes(10, 3, 170*time.Second), true, false},
		{"awg: 45 percent is not", probes(20, 9, 170*time.Second), true, true},
		{"awg: under 45 percent", probes(20, 8, 170*time.Second), true, false},
		{"old probes are not looked at", probes(12, 12, 10*time.Minute), false, false},
		{"the edge of the window is in", append(probes(8, 8, 60*time.Second), Sample{At: t0.Add(-ProbeSpan), Fail: true}), false, true},
		{"just past the edge is out", append(probes(8, 8, 60*time.Second), Sample{At: t0.Add(-ProbeSpan - time.Second), Fail: true}), false, false},
		{"three stalls", stalls(3, 4*time.Minute), false, true},
		{"two stalls", stalls(2, time.Minute), false, false},
		{"three stalls, one too old", append(stalls(2, time.Minute), stalls(1, stallSpan+time.Second)...), false, false},
		{"stalls count for awg too", stalls(3, time.Minute), true, true},
		{"stalls are not probes", append(stalls(2, time.Minute), probes(8, 0, time.Minute)...), false, false},
	}
	for _, test := range tests {
		if got := Degraded(test.samples, test.awg, t0); got != test.want {
			t.Errorf("%s: degraded = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestHeavy(t *testing.T) {
	tests := []struct {
		name    string
		samples []Sample
		want    bool
	}{
		{"nothing seen", nil, false},
		{"half of six", probes(6, 3, 100*time.Second), true},
		{"half of five is too few to say", probes(5, 3, 100*time.Second), false},
		{"a third of six", probes(6, 2, 100*time.Second), false},
		{"most of them", probes(6, 5, 100*time.Second), true},
		{"one probe is no half", probes(1, 1, 0), false},
		{"five are too few", probes(5, 5, 60*time.Second), false},
		{"the window is two minutes", probes(8, 8, 5*time.Minute), false},
		{"degraded is not heavy", probes(9, 3, 100*time.Second), false},
	}
	for _, test := range tests {
		if got := Heavy(test.samples, t0); got != test.want {
			t.Errorf("%s: heavy = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestMaySwitch(t *testing.T) {
	ago := func(from string, d time.Duration) Switch { return Switch{At: t0.Add(-d), From: from} }
	minute := time.Minute
	tests := []struct {
		name    string
		history []Switch
		to      string
		want    bool
	}{
		{"never moved", nil, "b", true},
		{"a move 2 minutes ago", []Switch{ago("a", 2*minute)}, "b", false},
		{"a move just 3 minutes ago", []Switch{ago("a", 3*minute)}, "b", true},
		{"three in the hour, the last long enough ago", []Switch{ago("a", 40*minute), ago("c", 20*minute), ago("d", 5*minute)}, "b", true},
		{"four in the hour", []Switch{ago("a", 50*minute), ago("c", 30*minute), ago("d", 10*minute), ago("e", 4*minute)}, "b", false},
		{"four, but one is more than an hour old", []Switch{ago("a", 61*minute), ago("c", 30*minute), ago("d", 10*minute), ago("e", 4*minute)}, "b", true},
		{"four an hour apart are not four in an hour", []Switch{ago("a", 61*minute), ago("c", 122*minute), ago("d", 183*minute), ago("e", 244*minute)}, "b", true},
		{"eleven in a day", spread(11, 100*minute, "x"), "b", true},
		{"twelve in a day", spread(12, 100*minute, "x"), "b", false},
		{"twelve, one a day old", append(spread(11, 100*minute, "x"), ago("x", 24*time.Hour)), "b", true},
		{"back to the path left 29 minutes ago", []Switch{ago("b", 29*minute)}, "b", false},
		{"back to the path left 30 minutes ago", []Switch{ago("b", 30*minute)}, "b", true},
		{"to another than the one left", []Switch{ago("a", 29*minute)}, "b", true},
		{"the destination is not known yet", []Switch{ago("b", 29*minute)}, "", true},
	}
	for _, test := range tests {
		if got := MaySwitch(test.history, test.to, t0); got != test.want {
			t.Errorf("%s: may = %v, want %v", test.name, got, test.want)
		}
	}
}

// spread is n moves from one path, the first d ago, and every later one 100 minutes after the one before: they are within a day.
func spread(n int, d time.Duration, from string) []Switch {
	out := make([]Switch, n)
	for i := range out {
		out[i] = Switch{At: t0.Add(-d - time.Duration(n-1-i)*100*time.Minute), From: from}
	}
	return out
}

func TestLeftAndMoved(t *testing.T) {
	var history []Switch
	history = Moved(history, t0.Add(-25*time.Hour), "old")
	history = Moved(history, t0.Add(-40*time.Minute), "a")
	history = Moved(history, t0.Add(-10*time.Minute), "b")
	history = Moved(history, t0.Add(-5*time.Minute), "b")
	if len(history) != 3 {
		t.Fatalf("history = %v: what is a day old should be forgotten by the next move", history)
	}
	if got := Left(history, t0); len(got) != 1 || got[0] != "b" {
		t.Fatalf("left = %v, want b once", got)
	}
	if got := Left(history, t0.Add(25*time.Minute)); len(got) != 0 {
		t.Fatalf("left 25 minutes later = %v, want none", got)
	}
}

func TestLookMedian(t *testing.T) {
	tests := []struct {
		name    string
		samples []Sample
		want    Window
	}{
		{"nothing", nil, Window{}},
		{"odd", []Sample{{At: t0, Took: 90 * time.Millisecond}, {At: t0, Took: 30 * time.Millisecond}, {At: t0, Took: 60 * time.Millisecond}}, Window{3, 0, 60 * time.Millisecond}},
		{"even is the middle of the two", []Sample{{At: t0, Took: 10 * time.Millisecond}, {At: t0, Took: 30 * time.Millisecond}}, Window{2, 0, 20 * time.Millisecond}},
		{"a failure is no round trip", []Sample{{At: t0, Took: 3 * time.Second, Fail: true}, {At: t0, Took: 40 * time.Millisecond}}, Window{2, 1, 40 * time.Millisecond}},
		{"all failed", []Sample{{At: t0, Fail: true}}, Window{1, 1, 0}},
		{"a stall is no probe", []Sample{{At: t0, Stall: true}, {At: t0, Took: 40 * time.Millisecond}}, Window{1, 0, 40 * time.Millisecond}},
	}
	for _, test := range tests {
		if got := Look(test.samples, time.Minute, t0); got != test.want {
			t.Errorf("%s: look = %+v, want %+v", test.name, got, test.want)
		}
	}
}
