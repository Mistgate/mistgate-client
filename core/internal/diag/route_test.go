package diag

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// path builds a trace: routers answer up to `routers`, then the destination at `reach` (0 = never), silence between.
func path(routers, reach int, silent ...int) trace {
	t := make(trace, routeMaxTTL)
	for i := 0; i < routers; i++ {
		t[i] = hopRouter
	}
	if reach > 0 {
		t[reach-1] = hopReached
	}
	for _, ttl := range silent {
		t[ttl-1] = hopSilent
	}
	return t
}

func TestRouteVerdict(t *testing.T) {
	control := path(10, 11)
	cases := []struct {
		name       string
		refs       []trace
		control    trace
		verdict    string
		hop, total int
	}{
		{"a reference reaches its end", []trace{path(12, 13), path(5, 0), path(5, 0)}, control, "ok", 13, 13},
		{"two references die behind hop 5", []trace{path(5, 0), path(5, 0), path(3, 0)}, control, "blocked", 6, 11},
		{"neighbouring hops agree", []trace{path(5, 0), path(6, 0), path(0, 0)}, control, "blocked", 6, 11},
		{"a router that never answers does not move the box", []trace{path(5, 0, 2), path(5, 0, 2), path(5, 0)}, control, "blocked", 6, 11},
		{"one silent reference is not a block", []trace{path(5, 0), path(0, 0), path(0, 0)}, control, "unknown", 0, 0},
		{"the control dies at the same hop: the method does not apply", []trace{path(5, 0), path(5, 0), path(5, 0)}, path(5, 0), "unknown", 0, 0},
		{"nothing answers at all", []trace{path(0, 0), path(0, 0), path(0, 0)}, path(0, 0), "unknown", 0, 0},
	}
	for _, c := range cases {
		verdict, hop, total := routeVerdict(c.refs, c.control)
		if verdict != c.verdict || hop != c.hop || total != c.total {
			t.Errorf("%s: got %s hop %d of %d, want %s hop %d of %d", c.name, verdict, hop, total, c.verdict, c.hop, c.total)
		}
	}
}

func TestCheckRouteFindsTheBox(t *testing.T) {
	// routers answer up to hop 6; the references are dropped behind it, the control ends at hop 9
	echo := func(_ context.Context, target netip.Addr, ttl int, _ time.Duration) hopAnswer {
		switch {
		case ttl <= 6:
			return hopRouter
		case target == routeControl && ttl < 9:
			return hopRouter
		case target == routeControl && ttl == 9:
			return hopReached
		}
		return hopSilent
	}
	if verdict, hop, total := checkRoute(context.Background(), echo); verdict != "blocked" || hop != 7 || total != 9 {
		t.Fatalf("got %s hop %d of %d", verdict, hop, total)
	}
}

func TestCheckRouteStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if verdict, _, _ := checkRoute(ctx, func(context.Context, netip.Addr, int, time.Duration) hopAnswer { return hopReached }); verdict != "unknown" {
		t.Fatalf("got %s", verdict)
	}
}
