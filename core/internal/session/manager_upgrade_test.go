package session

import (
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/profile"
)

// newRigWith is newRig with the profiles named, and the timings tuned further.
func newRigWith(t *testing.T, pattern string, tune func(*managerTiming), profiles ...profile.Profile) *rig {
	t.Helper()
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErrs: failing(pattern, 4000)})
	fake.SetProfiles(profiles...)
	c, mem := newClock(), auto.Open("")
	manager, events, store := qualityManager(t, fake, mem, c, func(timing *managerTiming) {
		quickProbes(timing)
		if tune != nil {
			tune(timing)
		}
	})
	return &rig{fake, c, mem, manager, events, store}
}

// quickPath is a rig of four paths, of which p1 is slow (200 ms) and p2 to p4 answer the background probes at 80 to 100 ms.
func quickPath(t *testing.T, tune func(*managerTiming)) *rig {
	t.Helper()
	r := newRigWith(t, "S", tune, autoProfiles("p1", "p2", "p3", "p4")...)
	r.fake.SetMeasure(map[string]time.Duration{"p2": 80 * time.Millisecond, "p3": 100 * time.Millisecond, "p4": 90 * time.Millisecond})
	r.fake.SetRTT(200)
	return r
}

// confirmed runs the two rounds of probes that a healthy connection needs to confirm a path: 2 hours apart.
func (r *rig) confirmed(t *testing.T) {
	t.Helper()
	r.idle(40 * time.Minute)
	r.measured(t, 1)
	r.stays(t, "after the first round", 1)
	r.c.advance(2*time.Hour + 5*time.Minute)
	r.measured(t, 2)
}

// upgraded waits for the connection that follows a move for speed, which is on path to.
func (r *rig) upgraded(t *testing.T, to string) Status {
	t.Helper()
	status := waitForStatus(t, r.events.C, connected)
	if status.ServerID != to || !status.Auto || status.Reason != "upgrade" {
		t.Fatalf("status = %#v, want %s by Auto, upgrade", status, to)
	}
	return status
}

func TestUpgradeAtIdle(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"a confirmed quicker path: a move when idle, and the status says upgrade", testUpgradeMoves},
		{"a line that is not idle stays until it is, for a minute", testUpgradeNotIdle},
		{"less than an hour on the path: it stays", testUpgradeTooSoon},
		{"auto_switch off: it stays", testUpgradeSettingOff},
		{"the game mode: it stays", testUpgradeGame},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testUpgradeMoves(t *testing.T) {
	r := quickPath(t, nil)
	r.connect(t)
	r.confirmed(t)
	r.upgraded(t, "p2")
	targets := r.fake.Targets()
	if last := targets[len(targets)-1]; len(targets) != 2 || last.Prefer != "p2" || !last.Hold {
		t.Fatalf("attempts = %#v, want the second held, to p2 at once", targets)
	}
	if _, ok := r.mem.Known("net", []auto.Path{{ID: "p1"}}, r.c.now()); !ok {
		t.Fatal("a move for speed marked the path it left as failed")
	}
}

func testUpgradeNotIdle(t *testing.T) {
	r := quickPath(t, nil)
	r.connect(t)
	r.fake.SetTraffic(100<<10, 0) // 12.5 KB/s: busy for an upgrade (4 KB/s), though quiet enough for a move off a poor path
	r.idle(40 * time.Minute)
	r.measured(t, 1)
	r.c.advance(2*time.Hour + 5*time.Minute)
	r.measured(t, 2)
	r.stays(t, "a line in use", 1)
	r.fake.SetTraffic(10<<10, 0) // 1.25 KB/s
	settle()                     // the first quiet tick
	r.c.advance(59 * time.Second)
	settle()
	r.stays(t, "59 s of quiet", 1)
	r.c.advance(2 * time.Second)
	r.upgraded(t, "p2")
}

func testUpgradeTooSoon(t *testing.T) {
	r := quickPath(t, func(timing *managerTiming) { timing.upgradeOnPath = 4 * time.Hour })
	r.connect(t)
	r.confirmed(t)
	settle()
	r.stays(t, "under the time on the path", 1)
	r.c.advance(2 * time.Hour)
	r.upgraded(t, "p2")
}

func testUpgradeSettingOff(t *testing.T) {
	r := quickPath(t, nil)
	r.setting(t, "auto_switch", "false")
	r.connect(t)
	r.confirmed(t)
	settle()
	r.stays(t, "auto_switch off", 1)
	r.setting(t, "auto_switch", "true")
	r.upgraded(t, "p2")
}

func testUpgradeGame(t *testing.T) {
	r := quickPath(t, nil)
	r.setting(t, "game", "true")
	r.connect(t)
	r.confirmed(t)
	settle()
	r.stays(t, "the game mode", 1)
	r.setting(t, "game", "false")
	r.upgraded(t, "p2")
}

func whitelistProfiles() []profile.Profile {
	return append(autoProfiles("p1", "p2", "p3"), profile.Profile{ID: "wl", Sub: "sub", Protocol: "hysteria2", Purpose: profile.PurposeWhitelist})
}

// whitelisted is a rig whose session has gone to the path for allowlists by the rule: every ordinary path failed twice, and the
// path for allowlists took the connection. It answers the probes of p1 at 90 ms and of p2 at 120 ms.
func whitelisted(t *testing.T, tune func(*rig)) *rig {
	t.Helper()
	r := newRigWith(t, "S", nil, whitelistProfiles()...)
	r.setting(t, "whitelist_auto", "true")
	if tune != nil {
		tune(r)
	}
	r.fake.SetMeasure(map[string]time.Duration{"p1": 90 * time.Millisecond, "p2": 120 * time.Millisecond})
	r.connect(t)
	r.fake.SetFailStartCode("offline")
	r.manager.NetworkChanged("wake", time.Hour)
	waitForStatus(t, r.events.C, func(s Status) bool { return s.State == "reconnecting" && s.WhitelistByRule })
	r.fake.SetFailStartCode("")
	status := waitForStatus(t, r.events.C, connected)
	if status.ServerID != "wl" || !status.WhitelistByRule || status.Auto {
		t.Fatalf("status = %#v, want the path for allowlists, by the rule", status)
	}
	return r
}

// answeredTwice runs two rounds of probes, 14 minutes apart: each of the two best ordinary paths has answered twice.
func (r *rig) answeredTwice(t *testing.T) {
	t.Helper()
	r.idle(14 * time.Minute)
	r.measured(t, 1)
	r.c.advance(14 * time.Minute)
	r.measured(t, 2)
}

func TestWhitelistReturn(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"back to an ordinary path that came alive, at a quiet moment, and the status says upgrade", testReturnMoves},
		{"auto_switch off does not keep it on the path for allowlists", testReturnIgnoresAutoSwitch},
		{"a return that fails goes back to the path for allowlists and marks the path", testReturnFails},
		{"a return that carries nothing goes back to the path for allowlists and marks the path", testReturnFreezes},
		{"one answer is not enough, and a busy line is waited for a minute at most", testReturnNeedsTwo},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testReturnMoves(t *testing.T) {
	r := whitelisted(t, nil)
	base := r.fake.StartCount()
	r.answeredTwice(t)
	r.c.advance(4 * time.Second) // the speed was under 64 KB/s for 4 s: not yet
	settle()
	r.stays(t, "4 quiet seconds", base)
	r.c.advance(2 * time.Second)
	back := waitForStatus(t, r.events.C, connected)
	if back.ServerID != "p1" || !back.Auto || back.Reason != "upgrade" || back.Purpose != "" || back.WhitelistByRule {
		t.Fatalf("status = %#v, want p1 by Auto, upgrade, no mark of the path for allowlists", back)
	}
	targets := r.fake.Targets()
	if last := targets[len(targets)-1]; last.Server != "auto" || last.Prefer != "p1" || !last.Hold {
		t.Fatalf("the return = %#v, want a held attempt of Auto, to p1 at once", last)
	}
	if got := r.mem.Stats("net")["p1"]; got.Streak != 0 || got.Until != 0 {
		t.Fatalf("p1 is marked after a good return: %#v", got)
	}
}

func testReturnIgnoresAutoSwitch(t *testing.T) {
	r := whitelisted(t, func(r *rig) { r.setting(t, "auto_switch", "false") })
	r.answeredTwice(t)
	r.c.advance(6 * time.Second)
	if back := waitForStatus(t, r.events.C, connected); back.ServerID != "p1" || back.Reason != "upgrade" {
		t.Fatalf("status = %#v, want p1 by upgrade: the path for allowlists is not a place to stay on", back)
	}
}

func testReturnFails(t *testing.T) {
	r := whitelisted(t, nil)
	r.answeredTwice(t)
	r.fake.SetFailing("p1") // the path answers the probes, but a connection to it does not come up
	r.c.advance(6 * time.Second)
	back := waitForStatus(t, r.events.C, connected)
	if back.ServerID != "wl" || !back.WhitelistByRule || back.Purpose != profile.PurposeWhitelist || back.Auto {
		t.Fatalf("status = %#v, want the path for allowlists again, by the rule", back)
	}
	targets := r.fake.Targets()
	if n := len(targets); n < 2 || targets[n-2].Server != "auto" || targets[n-2].Prefer != "p1" || targets[n-1].Server != "wl" {
		t.Fatalf("attempts = %#v, want the one to p1, then the one to the path for allowlists", targets)
	}
	if got := r.mem.Stats("net")["p1"]; got.Streak < 2 || got.Until <= r.c.now().Unix() {
		t.Fatalf("p1 after a failed return: %#v, want two failures and a quarantine", got)
	}
	// the next return is not made on the old answers, nor before the path answers twice again
	r.c.advance(6 * time.Second)
	settle()
	r.stays(t, "after the failed return", uint64(len(targets)))
}

func testReturnFreezes(t *testing.T) {
	r := whitelisted(t, nil)
	r.answeredTwice(t)
	r.fake.SetProof("p1", "freeze")
	r.c.advance(6 * time.Second)
	if back := waitForStatus(t, r.events.C, connected); back.ServerID != "p1" || back.Reason != "upgrade" {
		t.Fatalf("status = %#v, want the return to p1", back)
	}
	back := waitForStatus(t, r.events.C, connected)
	if back.ServerID != "wl" || !back.WhitelistByRule || back.Purpose != profile.PurposeWhitelist {
		t.Fatalf("status = %#v, want the path for allowlists again, by the rule", back)
	}
	if got := r.mem.Stats("net")["p1"]; got.Froze == 0 || got.Streak < 2 || got.Until <= r.c.now().Unix() {
		t.Fatalf("p1 after a frozen return: %#v, want the freeze mark and a quarantine", got)
	}
}

func testReturnNeedsTwo(t *testing.T) {
	r := whitelisted(t, nil)
	base := r.fake.StartCount()
	r.idle(14 * time.Minute)
	r.measured(t, 1)
	r.c.advance(6 * time.Second)
	settle()
	r.stays(t, "one answer", base)
	// a busy line waits for its quiet, but not for longer than a minute
	r.fake.SetTraffic(10<<20, 0)
	r.c.advance(14 * time.Minute)
	r.measured(t, 2)
	r.c.advance(50 * time.Second)
	settle()
	r.stays(t, "a busy line for 50 s", base)
	r.c.advance(11 * time.Second)
	if back := waitForStatus(t, r.events.C, connected); back.ServerID != "p1" || back.Reason != "upgrade" {
		t.Fatalf("status = %#v, want p1 by upgrade after the limit of the wait", back)
	}
}
