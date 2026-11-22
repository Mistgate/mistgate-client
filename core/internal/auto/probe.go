package auto

import (
	"slices"
	"time"
)

// Background probes: now and then Auto makes a handshake to the other paths, outside the tunnel, to know what a move to
// one of them would be worth. The session keeps the history of the probes; these functions only judge it.

// The state of the connection that the probes are made for.
const (
	ModeHealthy   = "healthy"
	ModeDegraded  = "degraded"
	ModeWhitelist = "whitelist" // the connection is on the path for allowlists, by rule
)

const (
	probeTop          = 3                // the best alternatives that are probed
	probeTopWhite     = 2                // on the path for allowlists: the best ordinary ones
	probeEveryPath    = 2 * time.Hour    // a healthy connection: the same path is not probed more often
	probeBadEvery     = 5 * time.Minute  // a poor connection, or the path for allowlists
	probesHour        = 2                // a healthy connection: all probes in an hour
	probesHourBad     = 6                // a poor connection, or the path for allowlists
	probesHourGame    = 2                // a game, whatever the mode
	probesDay         = 48               // in 24 hours, in any mode
	probeHistory      = 24 * time.Hour   // what TrimProbes keeps
	ProbeConfirmGap   = 10 * time.Minute // two answers this far apart confirm a path for a move by choice
	ProbeReturnGap    = 5 * time.Minute  // and for a return from the path for allowlists
	probeConfirmFresh = 3 * time.Hour    // the later of the two answers is not older than this
)

// Probe is one background probe of a path outside the tunnel.
type Probe struct {
	At      time.Time
	Net     string
	Path    string
	RTT     time.Duration // 0: no answer
	Skipped bool          // not made (the key of the live AmneziaWG tunnel): only keeps the path from being picked again at once
}

// ProbeInput is what Probes decides from.
type ProbeInput struct {
	Paths   []Path          // the alternatives: every path that can be gone to, but the one in use
	Stats   map[string]Stat // of the network, from the memory
	History []Probe         // the probes of this process, oldest first, of every network
	Net     string
	Now     time.Time
	Mode    string
	Game    bool
}

// Probes names the paths to probe now: the best (by Score) of the alternatives that are not set aside, no path more
// often than the mode allows, and no more probes than its hour and the day allow. The paths come best first.
// ponytail: the top is taken before the interval is looked at, so a path outside it is never probed while the top ones
// stay good; the scores move as the probes write to the memory, and that is what brings the next one in.
func Probes(in ProbeInput) []string {
	hourCap, every, top := probesHour, probeEveryPath, probeTop
	if in.Mode != ModeHealthy {
		hourCap, every = probesHourBad, probeBadEvery
	}
	if in.Mode == ModeWhitelist {
		top = probeTopWhite
	}
	if in.Game {
		hourCap = min(hourCap, probesHourGame)
	}
	last := map[string]time.Time{}
	hour, day := 0, 0
	for _, p := range in.History {
		if p.Net == in.Net && p.At.After(last[p.Path]) {
			last[p.Path] = p.At
		}
		if age := in.Now.Sub(p.At); !p.Skipped {
			if age < time.Hour {
				hour++
			}
			if age < 24*time.Hour {
				day++
			}
		}
	}
	budget := min(hourCap-hour, probesDay-day)
	var open []Path
	for _, c := range in.Paths {
		if in.Stats[c.ID].Until <= in.Now.Unix() {
			open = append(open, c)
		}
	}
	slices.SortStableFunc(open, func(a, b Path) int {
		sa, sb := Score(in.Stats[a.ID], a.Via, in.Now), Score(in.Stats[b.ID], b.Via, in.Now)
		switch {
		case sa < sb:
			return -1
		case sa > sb:
			return 1
		}
		return 0
	})
	open = open[:min(len(open), top)]
	var out []string
	for _, c := range open {
		if len(out) >= budget {
			break
		}
		if at, ok := last[c.ID]; !ok || in.Now.Sub(at) >= every {
			out = append(out, c.ID)
		}
	}
	return out
}

// TrimProbes drops the probes that are older than a day.
func TrimProbes(history []Probe, now time.Time) []Probe {
	return slices.DeleteFunc(history, func(p Probe) bool { return now.Sub(p.At) >= probeHistory })
}

// Confirmed: the path's last two probes in the network, not counting those before since, both answered, at least gap
// apart, and the later is not older than 3 hours. rtt is the later one's.
func Confirmed(history []Probe, net, path string, since time.Time, gap time.Duration, now time.Time) (rtt time.Duration, ok bool) {
	var last []Probe
	for i := len(history) - 1; i >= 0 && len(last) < 2; i-- {
		if p := history[i]; p.Net == net && p.Path == path && !p.Skipped && !p.At.Before(since) {
			last = append(last, p)
		}
	}
	if len(last) < 2 || last[0].RTT <= 0 || last[1].RTT <= 0 {
		return 0, false
	}
	if last[0].At.Sub(last[1].At) < gap || now.Sub(last[0].At) > probeConfirmFresh {
		return 0, false
	}
	return last[0].RTT, true
}

// bestConfirmed is the quickest of the paths that are confirmed (see Confirmed), not set aside and allowed by keep (all
// are when it is nil): its id, and its round trip. "": none is.
func bestConfirmed(paths []Path, stats map[string]Stat, history []Probe, net string, since time.Time, gap time.Duration,
	now time.Time, keep func(id string) bool) (id string, best time.Duration) {
	for _, c := range paths {
		if stats[c.ID].Until > now.Unix() || keep != nil && !keep(c.ID) {
			continue
		}
		if rtt, ok := Confirmed(history, net, c.ID, since, gap, now); ok && (id == "" || rtt < best) {
			id, best = c.ID, rtt
		}
	}
	return id, best
}

// A move by choice off a connection that works, to a path that is much quicker (see Upgrade).
const (
	UpgradeOnPath   = time.Hour     // the connection has been on its path this long
	UpgradeQuiet    = time.Minute   // and the line has been quiet this long
	UpgradeQuietBPS = (4 << 10) * 8 // quiet: rx and tx together under 4 KB/s, in bits per second as Traffic has it
	upgradeGain     = 60 * time.Millisecond
	noReturnUpgrade = 2 * time.Hour // a path left by choice is not gone back to for this long (30 minutes for the other moves)
)

// Better says whether a path that answers in cand is worth a move off one that answers in cur: at most 0.6 of its time,
// and 60 ms quicker. A cur that is not known (0) is worth nothing.
func Better(cur, cand time.Duration) bool {
	return cur > 0 && cand > 0 && cand*10 <= cur*6 && cur-cand >= upgradeGain
}

// UpgradeInput is what Upgrade decides from.
type UpgradeInput struct {
	Poor, Game, AutoSwitch bool
	OnPath, MinOnPath      time.Duration // how long on the path in use, and how long it must be (UpgradeOnPath)
	Quiet                  time.Duration // how long the line has been quiet
	Cur                    time.Duration // the round trip of the path in use, the engine's; 0 when not known
	Paths                  []Path        // the alternatives
	Stats                  map[string]Stat
	History                []Probe
	Switches               []Switch
	Net                    string
	Now                    time.Time
}

// Upgrade names the path that a healthy connection that is idle may move to: only when the connection is not poor, the
// setting is on, no game is played, it has been on its path for MinOnPath and the line quiet for a minute, the path in use
// has a round trip, and an alternative is confirmed by two answered probes 10 minutes apart, is Better than the one in
// use, is not in quarantine, is allowed by MaySwitch and was not left by choice in the last 2 hours.
func Upgrade(in UpgradeInput) (to string, ok bool) {
	if in.Poor || !in.AutoSwitch || in.Game || in.OnPath < in.MinOnPath || in.Quiet < UpgradeQuiet || in.Cur <= 0 {
		return "", false
	}
	id, rtt := bestConfirmed(in.Paths, in.Stats, in.History, in.Net, time.Time{}, ProbeConfirmGap, in.Now,
		func(id string) bool { return maySwitch(in.Switches, id, in.Now, noReturnUpgrade) })
	if id == "" || !Better(in.Cur, rtt) {
		return "", false
	}
	return id, true
}

// ReturnTo names the ordinary path that the connection on the path for allowlists may go back to: the quickest that
// answered two probes made since it went there, 5 minutes apart, and is not in quarantine. "": none.
func ReturnTo(paths []Path, stats map[string]Stat, history []Probe, net string, since, now time.Time) string {
	id, _ := bestConfirmed(paths, stats, history, net, since, ProbeReturnGap, now, nil)
	return id
}
