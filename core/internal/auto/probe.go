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
