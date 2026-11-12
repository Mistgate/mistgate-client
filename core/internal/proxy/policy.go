package proxy

import (
	"net/netip"
	"strings"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

// Not worth reaching through a VPN, and some of them reach the VPN server's own network or this machine.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, also the tailnets
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // the Hysteria2 adapter lives here
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 and 6to4 carry an IPv4 address of anyone's choosing
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"),
}

// AllowedAddr is whether the proxy may connect to an address: a public unicast one. Loopback, unspecified, multicast,
// link-local and private addresses are refused, so the proxy cannot be used to walk into the VPN server's network or
// back into this machine.
func AllowedAddr(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range reserved {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// Names that only mean something on a private network.
var privateSuffixes = []string{".local", ".localhost", ".localdomain", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet", ".private"}

// cleanTarget vets what a client asked for before anything is dialled, and returns the host in the form that is
// dialled. A name is resolved on the tunnel's side, where it cannot be checked, so only its shape is: a real name has a
// dot and a top-level domain of letters, which also shuts out the numeric spellings of an address ("2130706433",
// "0x7f.1") that some resolvers would accept.
func cleanTarget(host string, port uint16) (string, error) {
	if port == 0 {
		return "", engine.ErrBlockedDest
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if address, err := netip.ParseAddr(host); err == nil {
		if !AllowedAddr(address) {
			return "", engine.ErrBlockedDest
		}
		return address.Unmap().String(), nil
	}
	if !validName(host) {
		return "", engine.ErrBlockedDest
	}
	for _, suffix := range privateSuffixes {
		if strings.HasSuffix(host, suffix) {
			return "", engine.ErrBlockedDest
		}
	}
	return host, nil
}

func validName(name string) bool {
	if len(name) < 4 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		return len(tld) > 4
	}
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}

// lanAddr: where a client may come from when the home network is allowed in.
func lanAddr(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()
}
