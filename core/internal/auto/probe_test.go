package auto

import (
	"maps"
	"slices"
	"testing"
	"time"
)

// rtts gives paths p1, p2, ... the round trips, best first when they rise.
func rtts(ms ...int) (paths []Path, stats map[string]Stat) {
	stats = map[string]Stat{}
	for i, rtt := range ms {
		id := "p" + string(rune('1'+i))
		paths = append(paths, Path{ID: id})
		stats[id] = Stat{OK: t0.Unix(), RTT: rtt}
	}
	return paths, stats
}

// tried is probes of the paths, each this long before t0.
func tried(ago time.Duration, ids ...string) []Probe {
	out := make([]Probe, len(ids))
	for i, id := range ids {
		out[i] = Probe{At: t0.Add(-ago), Net: "net", Path: id, RTT: 50 * time.Millisecond}
	}
	return out
}

func TestProbes(t *testing.T) {
	four, stats := rtts(40, 50, 60, 70)
	skipped := tried(time.Minute, "p1")
	skipped[0].Skipped = true
	tests := []struct {
		name    string
		mode    string
		game    bool
		history []Probe
		edit    func(map[string]Stat)
		want    []string
	}{
		{"healthy: two probes an hour, of the best", ModeHealthy, false, nil, nil, []string{"p1", "p2"}},
		{"healthy: a path probed 2 h ago is probed again", ModeHealthy, false, tried(2*time.Hour, "p1"), nil, []string{"p1", "p2"}},
		{"healthy: a path probed within 2 h is not, the next one is", ModeHealthy, false, tried(2*time.Hour-time.Second, "p1"), nil, []string{"p2", "p3"}},
		{"healthy: the fourth is out of the top", ModeHealthy, false, tried(90*time.Minute, "p1", "p2", "p3"), nil, nil},
		{"healthy: a probe within the hour leaves one", ModeHealthy, false, tried(30*time.Minute, "p9"), nil, []string{"p1"}},
		{"healthy: two probes within the hour leave none", ModeHealthy, false, tried(30*time.Minute, "p8", "p9"), nil, nil},
		{"healthy: probes of an hour ago are out of the hour", ModeHealthy, false, tried(time.Hour, "p8", "p9"), nil, []string{"p1", "p2"}},
		{"healthy: a probe not made is no probe", ModeHealthy, false, skipped, nil, []string{"p2", "p3"}},
		{"healthy: a path in quarantine is left out", ModeHealthy, false, nil, func(s map[string]Stat) {
			s["p1"] = Stat{OK: t0.Unix(), RTT: 40, Until: t0.Unix() + 1}
		}, []string{"p2", "p3"}},
		{"healthy: a quarantine that is over is not", ModeHealthy, false, nil, func(s map[string]Stat) {
			s["p1"] = Stat{OK: t0.Unix(), RTT: 40, Until: t0.Unix()}
		}, []string{"p1", "p2"}},
		{"healthy: the score, not the order of the list, ranks", ModeHealthy, false, nil, func(s map[string]Stat) {
			s["p1"] = Stat{OK: t0.Unix(), RTT: 200}
			s["p4"] = Stat{OK: t0.Unix(), RTT: 10}
		}, []string{"p4", "p2"}},
		{"healthy: a path never seen ranks by its guess", ModeHealthy, false, nil, func(s map[string]Stat) { delete(s, "p1") }, []string{"p2", "p3"}},
		{"degraded: six an hour, each path every 5 min", ModeDegraded, false, nil, nil, []string{"p1", "p2", "p3"}},
		{"degraded: 5 min is enough", ModeDegraded, false, tried(5*time.Minute, "p1"), nil, []string{"p1", "p2", "p3"}},
		{"degraded: 4 min is not", ModeDegraded, false, tried(4*time.Minute, "p1"), nil, []string{"p2", "p3"}},
		{"degraded: five in the hour leave one", ModeDegraded, false, tried(30*time.Minute, "p5", "p6", "p7", "p8", "p9"), nil, []string{"p1"}},
		{"degraded: six leave none", ModeDegraded, false, tried(30*time.Minute, "p5", "p6", "p7", "p8", "p9", "pa"), nil, nil},
		{"whitelist: the two best ordinary paths", ModeWhitelist, false, nil, nil, []string{"p1", "p2"}},
		{"whitelist: a path in quarantine is probed all the same", ModeWhitelist, false, nil, func(s map[string]Stat) {
			s["p1"] = Stat{OK: t0.Unix(), RTT: 40, Until: t0.Unix() + 3600}
		}, []string{"p1", "p2"}},
		{"whitelist: each every 5 min", ModeWhitelist, false, tried(3*time.Minute, "p1"), nil, []string{"p2"}},
		{"game: two an hour when healthy", ModeHealthy, true, tried(30*time.Minute, "p9"), nil, []string{"p1"}},
		{"game: and when degraded", ModeDegraded, true, tried(30*time.Minute, "p8", "p9"), nil, nil},
		{"game: degraded leaves two", ModeDegraded, true, nil, nil, []string{"p1", "p2"}},
		{"a day holds 48", ModeDegraded, false, dayOfProbes(47), nil, []string{"p1"}},
		{"a day of 48 leaves none", ModeDegraded, false, dayOfProbes(48), nil, nil},
		{"probes of the day before are forgotten", ModeDegraded, false, slices.Concat(dayOfProbes(47), tried(25*time.Hour, "p5")), nil, []string{"p1"}},
		{"another network's probe does not hold a path back, but counts", ModeHealthy, false, []Probe{{At: t0.Add(-time.Minute), Net: "other", Path: "p1"}}, nil, []string{"p1"}},
	}
	for _, test := range tests {
		s := maps.Clone(stats)
		if test.edit != nil {
			test.edit(s)
		}
		got := Probes(ProbeInput{Paths: four, Stats: s, History: test.history, Net: "net", Now: t0, Mode: test.mode, Game: test.game})
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: probes = %v, want %v", test.name, got, test.want)
		}
	}
}

// dayOfProbes is n probes over the last day, none within the last hour and a half.
func dayOfProbes(n int) []Probe {
	out := make([]Probe, n)
	for i := range out {
		out[i] = Probe{At: t0.Add(-90*time.Minute - time.Duration(i)*20*time.Minute), Net: "net", Path: "px"}
	}
	return out
}

func TestTrimProbes(t *testing.T) {
	history := []Probe{{At: t0.Add(-25 * time.Hour)}, {At: t0.Add(-24 * time.Hour)}, {At: t0.Add(-23 * time.Hour)}}
	if got := TrimProbes(history, t0); len(got) != 1 || !got[0].At.Equal(t0.Add(-23*time.Hour)) {
		t.Fatalf("kept %v, want only the last", got)
	}
}

func TestConfirmed(t *testing.T) {
	ok, bad := 80*time.Millisecond, time.Duration(0)
	probe := func(ago time.Duration, rtt time.Duration) Probe {
		return Probe{At: t0.Add(-ago), Net: "net", Path: "p1", RTT: rtt}
	}
	tests := []struct {
		name    string
		history []Probe
		since   time.Time
		gap     time.Duration
		want    time.Duration
	}{
		{"no probe", nil, time.Time{}, 10 * time.Minute, 0},
		{"one answer is not two", []Probe{probe(time.Minute, ok)}, time.Time{}, 10 * time.Minute, 0},
		{"two answers 10 min apart", []Probe{probe(20*time.Minute, 90*time.Millisecond), probe(10*time.Minute, ok)}, time.Time{}, 10 * time.Minute, ok},
		{"two answers 9 min apart", []Probe{probe(19*time.Minute, ok), probe(10*time.Minute, ok)}, time.Time{}, 10 * time.Minute, 0},
		{"5 min is enough for a return", []Probe{probe(10*time.Minute, ok), probe(5*time.Minute, ok)}, time.Time{}, 5 * time.Minute, ok},
		{"the last one failed", []Probe{probe(30*time.Minute, ok), probe(20*time.Minute, ok), probe(10*time.Minute, bad)}, time.Time{}, 10 * time.Minute, 0},
		{"a failure between the two", []Probe{probe(30*time.Minute, ok), probe(20*time.Minute, bad), probe(10*time.Minute, ok)}, time.Time{}, 10 * time.Minute, 0},
		{"an old failure is behind them", []Probe{probe(40*time.Minute, bad), probe(30*time.Minute, ok), probe(10*time.Minute, ok)}, time.Time{}, 10 * time.Minute, ok},
		{"the later one is 3 h old", []Probe{probe(4*time.Hour, ok), probe(3*time.Hour, ok)}, time.Time{}, 10 * time.Minute, ok},
		{"the later one is older than that", []Probe{probe(4*time.Hour, ok), probe(3*time.Hour+time.Second, ok)}, time.Time{}, 10 * time.Minute, 0},
		{"probes before since do not count", []Probe{probe(20*time.Minute, ok), probe(10*time.Minute, ok)}, t0.Add(-15 * time.Minute), 5 * time.Minute, 0},
		{"probes from since on do", []Probe{probe(20*time.Minute, ok), probe(10*time.Minute, ok)}, t0.Add(-20 * time.Minute), 5 * time.Minute, ok},
		{"another path or network is not this one", []Probe{{At: t0.Add(-20 * time.Minute), Net: "other", Path: "p1", RTT: ok}, {At: t0.Add(-10 * time.Minute), Net: "net", Path: "p2", RTT: ok}}, time.Time{}, 5 * time.Minute, 0},
		{"a probe not made is no answer", []Probe{probe(20*time.Minute, ok), {At: t0.Add(-10 * time.Minute), Net: "net", Path: "p1", Skipped: true}}, time.Time{}, 5 * time.Minute, 0},
	}
	for _, test := range tests {
		got, found := Confirmed(test.history, "net", "p1", test.since, test.gap, t0)
		if got != test.want || found != (test.want != 0) {
			t.Errorf("%s: confirmed = %v, %v; want %v", test.name, got, found, test.want)
		}
	}
}
