package auto

import (
	"testing"
	"time"
)

func TestBetter(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name      string
		cur, cand time.Duration
		want      bool
	}{
		{"much quicker", 200 * ms, 80 * ms, true},
		{"exactly 0.6 and 60 ms", 150 * ms, 90 * ms, true},
		{"a hair over 0.6", 200 * ms, 121 * ms, false},
		{"0.6 but under 60 ms quicker", 100 * ms, 60 * ms, false},
		{"59 ms quicker", 150 * ms, 91 * ms, false},
		{"slower", 80 * ms, 200 * ms, false},
		{"the path in use has no time", 0, 10 * ms, false},
		{"the candidate has none", 200 * ms, 0, false},
	}
	for _, test := range tests {
		if got := Better(test.cur, test.cand); got != test.want {
			t.Errorf("%s: Better(%v, %v) = %v, want %v", test.name, test.cur, test.cand, got, test.want)
		}
	}
}

// answered is two probes of path id that answered, at the given ages (the older first).
func answered(id string, rtt time.Duration, older, newer time.Duration) []Probe {
	return []Probe{
		{At: t0.Add(-older), Net: "net", Path: id, RTT: rtt},
		{At: t0.Add(-newer), Net: "net", Path: id, RTT: rtt},
	}
}

func TestUpgrade(t *testing.T) {
	ms := time.Millisecond
	base := func() UpgradeInput {
		return UpgradeInput{
			AutoSwitch: true, OnPath: UpgradeOnPath, MinOnPath: UpgradeOnPath, Quiet: UpgradeQuiet, Cur: 200 * ms,
			Paths:   []Path{{ID: "p2"}, {ID: "p3"}},
			Stats:   map[string]Stat{"p2": {OK: t0.Unix(), RTT: 80}, "p3": {OK: t0.Unix(), RTT: 90}},
			History: answered("p2", 80*ms, 2*time.Hour, 30*time.Minute),
			Net:     "net", Now: t0,
		}
	}
	moved := func(ago time.Duration, from string) Switch { return Switch{At: t0.Add(-ago), From: from} }
	tests := []struct {
		name string
		edit func(*UpgradeInput)
		want string
	}{
		{"every condition holds", func(*UpgradeInput) {}, "p2"},
		{"the connection is poor", func(in *UpgradeInput) { in.Poor = true }, ""},
		{"auto_switch is off", func(in *UpgradeInput) { in.AutoSwitch = false }, ""},
		{"a game is played", func(in *UpgradeInput) { in.Game = true }, ""},
		{"59 minutes on the path", func(in *UpgradeInput) { in.OnPath = UpgradeOnPath - time.Second }, ""},
		{"the minimum is another one", func(in *UpgradeInput) { in.MinOnPath = 2 * time.Hour }, ""},
		{"the line was quiet for 59 s", func(in *UpgradeInput) { in.Quiet = UpgradeQuiet - time.Second }, ""},
		{"the line is not quiet", func(in *UpgradeInput) { in.Quiet = 0 }, ""},
		{"the path in use has no round trip", func(in *UpgradeInput) { in.Cur = 0 }, ""},
		{"one answer only", func(in *UpgradeInput) { in.History = in.History[1:] }, ""},
		{"no probe at all", func(in *UpgradeInput) { in.History = nil }, ""},
		{"two answers 9 minutes apart", func(in *UpgradeInput) { in.History = answered("p2", 80*ms, 20*time.Minute, 11*time.Minute) }, ""},
		{"two answers 10 minutes apart", func(in *UpgradeInput) { in.History = answered("p2", 80*ms, 20*time.Minute, 10*time.Minute) }, "p2"},
		{"the last probe failed", func(in *UpgradeInput) {
			in.History = append(in.History, Probe{At: t0.Add(-time.Minute), Net: "net", Path: "p2"})
		}, ""},
		{"the answers are of another network", func(in *UpgradeInput) { in.History[0].Net, in.History[1].Net = "other", "other" }, ""},
		{"the answers are older than 3 hours", func(in *UpgradeInput) { in.History = answered("p2", 80*ms, 5*time.Hour, 3*time.Hour+time.Second) }, ""},
		{"a hair over 0.6 of the time", func(in *UpgradeInput) {
			in.Cur = 149 * ms
			in.History = answered("p2", 90*ms, 2*time.Hour, 30*time.Minute)
		}, ""},
		{"0.6 of the time and 60 ms", func(in *UpgradeInput) {
			in.Cur = 150 * ms
			in.History = answered("p2", 90*ms, 2*time.Hour, 30*time.Minute)
		}, "p2"},
		{"quicker by under 60 ms", func(in *UpgradeInput) {
			in.Cur = 130 * ms
			in.History = answered("p2", 71*ms, 2*time.Hour, 30*time.Minute)
		}, ""},
		{"in quarantine", func(in *UpgradeInput) { in.Stats["p2"] = Stat{OK: t0.Unix(), RTT: 80, Until: t0.Unix() + 1} }, ""},
		{"a move 2 minutes ago", func(in *UpgradeInput) { in.Switches = []Switch{moved(2*time.Minute, "p9")} }, ""},
		{"a move 3 minutes ago", func(in *UpgradeInput) { in.Switches = []Switch{moved(3*time.Minute, "p9")} }, "p2"},
		{"four moves in the hour", func(in *UpgradeInput) {
			in.Switches = []Switch{moved(10*time.Minute, "a"), moved(20*time.Minute, "b"), moved(30*time.Minute, "c"), moved(40*time.Minute, "d")}
		}, ""},
		{"the path was left 2 h - 1 s ago", func(in *UpgradeInput) { in.Switches = []Switch{moved(2*time.Hour-time.Second, "p2")} }, ""},
		{"the path was left 2 h ago", func(in *UpgradeInput) { in.Switches = []Switch{moved(2*time.Hour, "p2")} }, "p2"},
		{"another path was left lately", func(in *UpgradeInput) { in.Switches = []Switch{moved(30*time.Minute, "p9")} }, "p2"},
		{"the quickest of two confirmed", func(in *UpgradeInput) {
			in.History = append(answered("p3", 50*ms, 2*time.Hour, 30*time.Minute), in.History...)
		}, "p3"},
		{"the quickest is barred, the other goes", func(in *UpgradeInput) {
			in.History = append(answered("p3", 50*ms, 2*time.Hour, 30*time.Minute), in.History...)
			in.Switches = []Switch{moved(time.Hour, "p3")}
		}, "p2"},
	}
	for _, test := range tests {
		in := base()
		test.edit(&in)
		got, ok := Upgrade(in)
		if got != test.want || ok != (test.want != "") {
			t.Errorf("%s: Upgrade = %q, %v; want %q", test.name, got, ok, test.want)
		}
	}
}

func TestReturnTo(t *testing.T) {
	ms := time.Millisecond
	paths := []Path{{ID: "p1"}, {ID: "p2"}}
	since := t0.Add(-time.Hour)
	tests := []struct {
		name    string
		history []Probe
		stats   map[string]Stat
		since   time.Time
		want    string
	}{
		{"two answers 5 minutes apart", answered("p1", 90*ms, 20*time.Minute, 15*time.Minute), nil, since, "p1"},
		{"4 minutes apart", answered("p1", 90*ms, 20*time.Minute, 16*time.Minute), nil, since, ""},
		{"one answer", answered("p1", 90*ms, 20*time.Minute, 15*time.Minute)[1:], nil, since, ""},
		{"answers from before the path for allowlists was taken", answered("p1", 90*ms, 20*time.Minute, 15*time.Minute), nil, t0.Add(-16 * time.Minute), ""},
		{"the quicker of two", append(answered("p1", 90*ms, 20*time.Minute, 15*time.Minute), answered("p2", 40*ms, 20*time.Minute, 10*time.Minute)...), nil, since, "p2"},
		{"in quarantine", answered("p1", 90*ms, 20*time.Minute, 15*time.Minute), map[string]Stat{"p1": {Until: t0.Unix() + 60}}, since, ""},
		{"quarantine over", answered("p1", 90*ms, 20*time.Minute, 15*time.Minute), map[string]Stat{"p1": {Until: t0.Unix()}}, since, "p1"},
		{"a path that is not asked about", answered("p9", 90*ms, 20*time.Minute, 15*time.Minute), nil, since, ""},
	}
	for _, test := range tests {
		if got := ReturnTo(paths, test.stats, test.history, "net", test.since, t0); got != test.want {
			t.Errorf("%s: ReturnTo = %q, want %q", test.name, got, test.want)
		}
	}
}
