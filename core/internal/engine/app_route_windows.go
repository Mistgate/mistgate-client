//go:build windows

package engine

import "net/netip"

// appOwners says which program owns the socket a flow comes from.
type appOwners interface {
	// Cached answers from memory only; ok is false when the owner is not known yet.
	Cached(udp bool, src netip.AddrPort) (path string, ok bool)
	// Owner may wait for a table snapshot (tens of milliseconds); "" when nobody is found.
	Owner(udp bool, src netip.AddrPort) string
}

// appRouter is the bridge's view of the per-program rules.
type appRouter struct {
	owners appOwners
	listed func() bool                  // some program is named for the current mode: without one no flow is looked up
	rule   func(path string) appVerdict // what the rules say about a program
	plain  func(netip.Addr) bool        // addresses that always follow the plain rules (the tunnel check's)
	blocks func() bool                  // some name is blocked: such flows are still read for their name
}

// appQuick gives the verdict for a flow if it is known without reading the table; ready is false when the caller
// must go on with appResolve. Flows that no verdict can change are not looked up: the DNS port, and addresses that
// never go direct (the VPN takes them anyway).
func (b *gvisorBridge) appQuick(udp bool, src, target netip.AddrPort) (v appVerdict, ready bool) {
	a := b.apps
	if a == nil || target.Port() == 53 || !directAddressAllowed(target.Addr()) || !a.listed() || a.plain != nil && a.plain(target.Addr()) {
		return appNone, true
	}
	path, ok := a.owners.Cached(udp, src)
	if !ok {
		return appNone, false
	}
	return a.rule(path), true
}

// appResolve is the slow half of appQuick; it may wait for a table snapshot.
func (b *gvisorBridge) appResolve(udp bool, src netip.AddrPort) appVerdict {
	return b.apps.rule(b.apps.owners.Owner(udp, src))
}

// appWait is both halves in a row, for callers that may wait (TCP flows run on their own goroutine).
func (b *gvisorBridge) appWait(udp bool, src, target netip.AddrPort) appVerdict {
	if v, ready := b.appQuick(udp, src, target); ready {
		return v
	}
	return b.appResolve(udp, src)
}
