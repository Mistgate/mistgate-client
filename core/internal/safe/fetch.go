package safe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrLinkLocal: the address a fetch was about to reach is a link-local one.
var ErrLinkLocal = errors.New("link-local address refused")

// FetchClient is for requests to an address somebody else chose: a subscription link, a list by its link. The service
// runs as SYSTEM, and such a link can name anything the machine reaches. Link-local addresses are refused at connect
// time, after the name is resolved: nothing a person adds lives there, and a cloud machine's metadata service does.
// ponytail: private and loopback addresses stay open, a panel at home or on this PC is a real case. Upgrade = refuse
// them for a link that came from outside (mistgate://), which the service would have to be told.
func FetchClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = fetchDial
	return &http.Client{Timeout: timeout, Transport: transport}
}

// The two ways to resolve a name. The system one asks Windows' DNS service, from another process: a held kill switch
// lets only this service's sockets out, so there it gets no answer. The own one asks the network's resolvers from this
// process (as the engine's ownResolver does). The system one goes first because with a tunnel up it is the tunnel's
// resolver; asking the adapters' resolvers first would take the name past the tunnel.
var (
	systemLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	ownLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return (&net.Resolver{PreferGo: true}).LookupNetIP(ctx, "ip", host)
	}
	systemLookupLimit = 3 * time.Second
)

// fetchDial resolves the name itself and dials the addresses in order until one connects; noLinkLocal checks each one.
func fetchDial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: noLinkLocal}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return dialer.DialContext(ctx, network, address)
	}
	addresses, err := lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		if err = dialErr; ctx.Err() != nil {
			break
		}
	}
	return nil, err
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	limited, cancel := context.WithTimeout(ctx, systemLookupLimit)
	addresses, err := systemLookup(limited, host)
	cancel()
	if err == nil && len(addresses) != 0 {
		return addresses, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err = ownLookup(ctx, host)
	if err == nil && len(addresses) == 0 {
		err = errors.New("no address")
	}
	return addresses, err
}

func noLinkLocal(_, address string, _ syscall.RawConn) error {
	if target, err := netip.ParseAddrPort(address); err == nil && target.Addr().Unmap().IsLinkLocalUnicast() {
		return ErrLinkLocal
	}
	return nil
}
