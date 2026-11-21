package auto

import (
	"slices"
	"time"
)

// What Auto makes of the way a live connection behaves. The session keeps Samples (the outcomes of its probes, and the
// starts of stalls); these functions only judge them, with no clock of their own.
const (
	probeSpan    = 3 * time.Minute // the window of the probes that Degraded looks at
	minProbes    = 9               // fewer probes in the window say nothing
	failShare    = 0.30            // the share of failed probes that is "degraded"
	failShareAWG = 0.45            // AmneziaWG fails single probes with no loss at all, so it takes more
	Span         = 5 * time.Minute // the longest of the windows: what a session keeps of its samples
	stallSpan    = Span            // the window of the stalls
	stallsToMove = 3               // stalls in that window that are "degraded"
	heavySpan    = 2 * time.Minute
	heavyShare   = 0.5
	minHeavy     = 4 // probes in heavySpan that a share of failures is read from; one failed probe is no "half"
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
	if w := Look(samples, probeSpan, now); w.Probes >= minProbes && float64(w.Fails) >= share*float64(w.Probes) {
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
