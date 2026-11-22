package auto

import (
	"slices"
	"time"
)

// What Auto makes of the way a live connection behaves. The session keeps Samples (the outcomes of its probes, and the
// starts of stalls); these functions only judge them, with no clock of their own.
const (
	ProbeSpan    = 3 * time.Minute // the window of the probes that Degraded looks at
	minProbes    = 9               // fewer probes in the window say nothing
	failShare    = 0.30            // the share of failed probes that is "degraded"
	failShareAWG = 0.45            // AmneziaWG fails single probes with no loss at all, so it takes more
	Span         = 5 * time.Minute // the longest of the windows: what a session keeps of its samples
	stallSpan    = Span            // the window of the stalls
	stallsToMove = 3               // stalls in that window that are "degraded"
	heavySpan    = 2 * time.Minute
	heavyShare   = 0.5
	minHeavy     = 6 // probes in heavySpan that a share of failures is read from; one failed probe is no "half"

	minSwitchGap  = 3 * time.Minute  // between two moves that Auto makes by itself
	switchesHour  = 4                // at most this many in an hour
	switchesDay   = 12               // and in a day
	noReturn      = 30 * time.Minute // a path that was left is not gone back to for this long
	switchHistory = 24 * time.Hour   // what Moved keeps
)

// Sample is one thing seen of a live connection: the outcome of a probe, or the start of a stall (data sent, none back).
type Sample struct {
	At    time.Time
	Stall bool          // a stall began (the rest of the fields are not used)
	Fail  bool          // the probe failed
	Took  time.Duration // how long the probe took
}

// Trim drops the samples that are older than Span.
func Trim(samples []Sample, now time.Time) []Sample {
	return slices.DeleteFunc(samples, func(s Sample) bool { return now.Sub(s.At) > Span })
}

// Window is what the probes of a span add up to.
type Window struct {
	Probes, Fails int
	Median        time.Duration // of the probes that succeeded; 0 when none did
}

// Look adds up the probes of the last span.
// ponytail: the median is only reported; a rule on a rising round trip needs field data (what is normal for a path).
func Look(samples []Sample, span time.Duration, now time.Time) Window {
	var w Window
	var took []time.Duration
	for _, s := range samples {
		if s.Stall || now.Sub(s.At) > span {
			continue
		}
		w.Probes++
		if s.Fail {
			w.Fails++
		} else {
			took = append(took, s.Took)
		}
	}
	if len(took) != 0 {
		slices.Sort(took)
		w.Median = took[len(took)/2]
		if len(took)%2 == 0 {
			w.Median = (took[len(took)/2-1] + took[len(took)/2]) / 2
		}
	}
	return w
}

// Degraded: the connection is up but poor. At least 9 probes in the last 3 minutes and 30% of them failed (45% for
// AmneziaWG), or 3 stalls in the last 5 minutes.
func Degraded(samples []Sample, awg bool, now time.Time) bool {
	share := failShare
	if awg {
		share = failShareAWG
	}
	if w := Look(samples, ProbeSpan, now); w.Probes >= minProbes && float64(w.Fails) >= share*float64(w.Probes) {
		return true
	}
	stalls := 0
	for _, s := range samples {
		if s.Stall && now.Sub(s.At) <= stallSpan {
			stalls++
		}
	}
	return stalls >= stallsToMove
}

// Heavy: half of the probes of the last 2 minutes failed. The bar for a game, which a move would interrupt.
func Heavy(samples []Sample, now time.Time) bool {
	w := Look(samples, heavySpan, now)
	return w.Probes >= minHeavy && float64(w.Fails) >= heavyShare*float64(w.Probes)
}

// Switch is a move that Auto made by itself, off a path that still worked.
type Switch struct {
	At   time.Time
	From string
}

// MaySwitch says whether Auto may move by itself now (to is the path it would go to, "" when that is not known yet): not
// within 3 minutes of the last move, not a fifth within the hour or a thirteenth within the day, and not back to a path
// it left in the last half hour.
func MaySwitch(history []Switch, to string, now time.Time) bool {
	hour, day := 0, 0
	for _, s := range history {
		age := now.Sub(s.At)
		if age < minSwitchGap || age < noReturn && to != "" && s.From == to {
			return false
		}
		if age < time.Hour {
			hour++
		}
		if age < 24*time.Hour {
			day++
		}
	}
	return hour < switchesHour && day < switchesDay
}

// Left are the paths Auto went away from within the last half hour: not to be gone back to.
func Left(history []Switch, now time.Time) []string {
	var out []string
	for _, s := range history {
		if now.Sub(s.At) < noReturn && !slices.Contains(out, s.From) {
			out = append(out, s.From)
		}
	}
	slices.Sort(out)
	return out
}

// Moved adds a move to the history and forgets what is older than a day.
func Moved(history []Switch, at time.Time, from string) []Switch {
	history = slices.DeleteFunc(history, func(s Switch) bool { return at.Sub(s.At) >= switchHistory })
	return append(history, Switch{At: at, From: from})
}
