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
		{"the edge of the window is in", append(probes(8, 8, 60*time.Second), Sample{At: t0.Add(-probeSpan), Fail: true}), false, true},
		{"just past the edge is out", append(probes(8, 8, 60*time.Second), Sample{At: t0.Add(-probeSpan - time.Second), Fail: true}), false, false},
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
		{"half of four", probes(4, 2, 100*time.Second), true},
		{"a third of six", probes(6, 2, 100*time.Second), false},
		{"most of them", probes(6, 5, 100*time.Second), true},
		{"one probe is no half", probes(1, 1, 0), false},
		{"three are too few", probes(3, 3, 60*time.Second), false},
		{"the window is two minutes", probes(8, 8, 5*time.Minute), false},
		{"degraded is not heavy", probes(9, 3, 100*time.Second), false},
	}
	for _, test := range tests {
		if got := Heavy(test.samples, t0); got != test.want {
			t.Errorf("%s: heavy = %v, want %v", test.name, got, test.want)
		}
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
