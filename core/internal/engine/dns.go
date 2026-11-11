package engine

import (
	"net/netip"
	"slices"

	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/profile"
)

const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsTypeHTTPS = 65
)

// dnsQuestion reads the name of the one question of a plain query for A, AAAA or HTTPS in class IN: lower case, no
// trailing dot, letters, digits and hyphens only. end is where the question section ends. Anything else is !ok and
// travels as it always did. The only allocation is the name; it never appears in an error or a log.
func dnsQuestion(msg []byte) (name string, end int, ok bool) {
	// QR and opcode zero; one question; no answer or authority records (an additional OPT record is fine)
	if len(msg) < 12+1+4 || msg[2]&0xF8 != 0 || msg[4] != 0 || msg[5] != 1 || msg[6]|msg[7]|msg[8]|msg[9] != 0 {
		return "", 0, false
	}
	var buf [253]byte
	n, i := 0, 12
	for {
		if i >= len(msg) {
			return "", 0, false
		}
		length := int(msg[i])
		i++
		if length == 0 {
			break
		}
		// 0x40 and above is a compression pointer or a reserved form: not in the first question of a query
		if length > 63 || i+length > len(msg) || n+length+1 > len(buf) || msg[i] == '-' || msg[i+length-1] == '-' {
			return "", 0, false
		}
		if n > 0 {
			buf[n] = '.'
			n++
		}
		for _, c := range msg[i : i+length] {
			switch {
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			default:
				return "", 0, false
			}
			buf[n] = c
			n++
		}
		i += length
	}
	if n == 0 || i+4 > len(msg) {
		return "", 0, false
	}
	qtype, qclass := int(msg[i])<<8|int(msg[i+1]), int(msg[i+2])<<8|int(msg[i+3])
	if qclass != 1 || qtype != dnsTypeA && qtype != dnsTypeAAAA && qtype != dnsTypeHTTPS {
		return "", 0, false
	}
	return string(buf[:n]), i + 4, true
}

// nxdomain turns a query into its answer in place and returns it: the id, the question and RD stay, QR and RA are
// set, RCODE is 3 and there are no records.
func nxdomain(msg []byte, end int) []byte {
	msg[2] = 0x80 | msg[2]&0x01
	msg[3] = 0x83
	clear(msg[6:12])
	return msg[:end]
}

// regionResolver is where a question of the region goes directly: the panel's split entry for the region, else the
// table. The zero value says there is none, and the question goes through the VPN. ponytail: the first resolver only;
// when it is down the question falls back to the VPN, and a second one would save that detour.
func regionResolver(region string, split []profile.DNSSplit) netip.AddrPort {
	if region == "" {
		return netip.AddrPort{}
	}
	for _, entry := range split {
		if len(entry.Servers) != 0 && slices.Contains(entry.Geo, region) {
			return netip.AddrPortFrom(entry.Servers[0], 53)
		}
	}
	if table := geo.RegionResolvers(region); len(table) != 0 {
		return netip.AddrPortFrom(table[0], 53)
	}
	return netip.AddrPort{}
}

var defaultTunnelDNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}

// tunnelDNS is a copy of the first non-empty list, in the order of authority: the user's, the profile's own, the
// panel's, the default.
func tunnelDNS(lists ...[]netip.Addr) []netip.Addr {
	for _, list := range lists {
		if len(list) != 0 {
			return slices.Clone(list)
		}
	}
	return nil
}
