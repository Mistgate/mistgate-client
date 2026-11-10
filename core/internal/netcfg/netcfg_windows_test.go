//go:build windows

package netcfg

import (
	"net/netip"
	"testing"
)

func TestChooseRoute(t *testing.T) {
	destination := netip.MustParseAddr("198.51.100.7")
	candidates := []routeCandidate{
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 1, interfaceMetric: 1},
		{prefix: netip.MustParsePrefix("198.51.100.0/25"), metric: 500, interfaceMetric: 500},
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 5, interfaceMetric: 2},
	}
	got, ok := chooseRoute(destination, candidates)
	if !ok || got.prefix.String() != "198.51.100.0/25" {
		t.Fatalf("chooseRoute() = %#v, %v; want longest prefix", got, ok)
	}

	candidates = []routeCandidate{
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 8, interfaceMetric: 4},
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 5, interfaceMetric: 2},
	}
	got, ok = chooseRoute(destination, candidates)
	if !ok || got.metric != 5 || got.interfaceMetric != 2 {
		t.Fatalf("chooseRoute() = %#v, %v; want lowest combined metric", got, ok)
	}
}
