//go:build !windows

package diag

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

type interfaceInfo struct {
	Index uint32
	Kind  string
	DNS   []netip.Addr
}

// ponytail: non-Windows checks return offline; upgrade = add the platform's physical-route socket binding.
func physicalNetwork() (interfaceInfo, error) { return interfaceInfo{}, errors.New("offline") }

func interfaceFor(_ netip.Addr, fallback interfaceInfo) interfaceInfo { return fallback }

func listenPacketBound(context.Context, interfaceInfo) (net.PacketConn, error) {
	return nil, errors.New("physical interface binding is unavailable")
}

func dialBound(ctx context.Context, network, address string, _ interfaceInfo) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func resolveHost(_ context.Context, host string, _ interfaceInfo, _ Config) (netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, errors.New("offline")
	}
	return ip, nil
}

func dnsExchange(context.Context, netip.Addr, []byte, interfaceInfo) ([]byte, error) {
	return nil, errors.New("physical interface binding is unavailable")
}

func dohRequest(context.Context, string, interfaceInfo) ([]byte, error) {
	return nil, errors.New("physical interface binding is unavailable")
}

func attemptProfile(context.Context, profile.Profile, netip.AddrPort, interfaceInfo, Config) (time.Duration, error) {
	return 0, errNoAnswer
}

func tlsProbe(context.Context, string, interfaceInfo, Config) bool { return false }
