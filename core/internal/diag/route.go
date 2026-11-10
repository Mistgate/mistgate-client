package diag

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Blocking on the route: where do packets to an address that is certainly blocked die?
//
// The idea is the panel's TSPU probe (mistgate internal/tspuprobe; references from internal/panel/countryprobe): a
// DPI box drops packets to a blocked address without a word, so the last router that still answers a TTL-limited
// probe is the hop in front of the box. A control address that is never blocked must still pass beyond that hop, or
// the method does not apply to this network.
//
// Windows gives a plain TCP socket no sign of a router's "time exceeded" (measured: every TTL-limited connect just
// times out), so the probes here are ICMP echoes through the system's ICMP interface, as tracert does. That sees
// blocking by address, which is what the references are blocked by.
//
// ponytail: the references are Russia's; elsewhere they pass and the verdict is "ok". Per-country references come
// with the panel integration.
var (
	routeBlockedRefs = []netip.Addr{
		netip.MustParseAddr("31.13.72.36"),    // Facebook
		netip.MustParseAddr("149.154.167.99"), // Telegram
		netip.MustParseAddr("108.174.10.10"),  // LinkedIn
	}
	routeControl = netip.MustParseAddr("77.88.55.88") // Yandex
)

const (
	routeMaxTTL  = 16
	routeTimeout = 700 * time.Millisecond
)

type hopAnswer int

const (
	hopSilent  hopAnswer = iota
	hopRouter            // a router on the way answered "time exceeded"
	hopReached           // the destination itself answered
)

// trace is what each TTL got back, index 0 = TTL 1.
type trace []hopAnswer

func (t trace) reached() int { // the TTL at which the destination answered, 0 if it never did
	for i, a := range t {
		if a == hopReached {
			return i + 1
		}
	}
	return 0
}

func (t trace) lastRouter() int { // the highest TTL a router answered, 0 if none did
	for i := len(t) - 1; i >= 0; i-- {
		if t[i] == hopRouter {
			return i + 1
		}
	}
	return 0
}

func (t trace) answersBeyond(ttl int) bool {
	for i := ttl; i < len(t); i++ {
		if t[i] != hopSilent {
			return true
		}
	}
	return false
}

// routeVerdict folds the traces into a verdict. ok: a blocked reference reached its end (Hop = the path's length).
// blocked: at least two references die behind the same router (a single silent one may simply not answer echoes)
// while the control passes beyond it (Hop = the first silent hop). Anything else: unknown.
func routeVerdict(refs []trace, control trace) (verdict string, hop, total int) {
	for _, t := range refs {
		if at := t.reached(); at > 0 {
			return "ok", at, at
		}
	}
	total = control.reached()
	if total == 0 {
		total = control.lastRouter()
	}
	counts := map[int]int{}
	for _, t := range refs {
		if last := t.lastRouter(); last > 0 {
			counts[last]++
		}
	}
	for last, n := range counts {
		// the neighbouring hop counts too: routers before the box may answer one reference and stay silent for another
		if n+counts[last+1] >= 2 && control.answersBeyond(last+counts[last+1]) {
			return "blocked", last + 1, max(total, last+1)
		}
	}
	return "unknown", 0, 0
}

// checkRoute traces the references and the control at once. echo is one probe (the machine's ICMP, or a test's).
func checkRoute(ctx context.Context, echo func(context.Context, netip.Addr, int, time.Duration) hopAnswer) (string, int, int) {
	targets := append(append([]netip.Addr{}, routeBlockedRefs...), routeControl)
	traces := make([]trace, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		traces[i] = make(trace, routeMaxTTL)
		for ttl := 1; ttl <= routeMaxTTL; ttl++ {
			wg.Add(1)
			go func(i, ttl int, target netip.Addr) {
				defer wg.Done()
				// a second look: routers limit how often they answer, and a lost answer reads as a block
				for try := 0; try < 2 && ctx.Err() == nil; try++ {
					if answer := echo(ctx, target, ttl, routeTimeout); answer != hopSilent {
						traces[i][ttl-1] = answer
						return
					}
				}
			}(i, ttl, target)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return "unknown", 0, 0
	}
	return routeVerdict(traces[:len(routeBlockedRefs)], traces[len(routeBlockedRefs)])
}
