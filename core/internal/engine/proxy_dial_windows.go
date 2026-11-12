//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// vpnDialer opens a TCP connection through the tunnel of one run. A name is resolved on the tunnel's side, never
// here: a lookup on this machine would tell the provider where the user goes.
type vpnDialer func(ctx context.Context, host string, port uint16) (net.Conn, error)

// DialVPN is the local proxy's way out: a connection through the tunnel that is up now, and only through it. With no
// tunnel (not connected, held, still connecting) it fails; nothing goes out directly. A connection ends with its run,
// so a disconnect or a reconnect cuts everything the proxy had open. The lock is not held while connecting.
// ponytail: the route rules (smart, selected, blocked names) do not apply to the proxy; upgrade = ask r.routeDirect.
func (r *Real) DialVPN(ctx context.Context, host string, port uint16) (net.Conn, error) {
	r.mu.Lock()
	run := r.current
	var dial vpnDialer
	if run != nil && run.probeIP.IsValid() {
		dial = run.dial
	}
	r.mu.Unlock()
	if dial == nil || run.ctx.Err() != nil {
		return nil, ErrNoTunnel
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopDial := context.AfterFunc(run.ctx, cancel)
	conn, err := dial(dialCtx, host, port)
	stopDial()
	if err != nil {
		if run.ctx.Err() != nil {
			return nil, ErrNoTunnel
		}
		return nil, err
	}
	return &runConn{Conn: conn, stop: context.AfterFunc(run.ctx, func() { _ = conn.Close() })}, nil
}

// runConn is a connection that the end of its run closes.
type runConn struct {
	net.Conn
	stop func() bool
}

func (c *runConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// CloseWrite is the half-close the relay uses when the tunnel's connection has one (a Hysteria2 stream has none).
func (c *runConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}

// HomeAddr is this machine's IPv4 address on the home network: the interface the internet is reached through when
// the tunnel is left out. Empty when that address is not a private one (nobody at home could use it).
func (r *Real) HomeAddr() string {
	address, err := netcfg.PhysicalAddr4()
	if err != nil || !address.IsPrivate() {
		return ""
	}
	return address.String()
}

func hy2Dialer(o hy2Outbound) vpnDialer {
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return o.dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
}

func awgStackDialer(tnet *netstack.Net, allow func(netip.Addr) bool) vpnDialer {
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if tnet == nil {
			return nil, ErrNoTunnel
		}
		return dialNamed(ctx, host, port, allow, func(ctx context.Context, name string) ([]netip.Addr, error) {
			names, err := tnet.LookupContextHost(ctx, name)
			var out []netip.Addr
			for _, text := range names {
				if address, parseErr := netip.ParseAddr(text); parseErr == nil {
					out = append(out, address.Unmap())
				}
			}
			return out, err
		}, func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
			return tnet.DialContextTCPAddrPort(ctx, target)
		})
	}
}

// awgPlainDialer is for AmneziaWG with no userspace stack of its own: the adapter carries the traffic through
// Windows' routing, so the sockets are bound to the adapter and its address (a route that vanished then fails the
// connect instead of leaving by the physical interface), and the names are asked of the tunnel's DNS server.
func awgPlainDialer(local netip.Addr, adapter *netcfg.Adapter, dns []netip.Addr, allow func(netip.Addr) bool) vpnDialer {
	var server netip.Addr
	for _, address := range dns {
		if address.Is4() {
			server = address
			break
		}
	}
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if adapter == nil || !local.IsValid() {
			return nil, ErrNoTunnel
		}
		iface, err := winipcfg.LUID(adapter.LUID()).IPInterface(windows.AF_INET)
		if err != nil || iface.InterfaceIndex == 0 {
			return nil, ErrNoTunnel
		}
		dialBound := func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Control: netcfg.SocketControl(iface.InterfaceIndex)}
			if network == "udp" || network == "udp4" {
				dialer.LocalAddr = &net.UDPAddr{IP: net.IP(local.AsSlice())}
			} else {
				dialer.LocalAddr = &net.TCPAddr{IP: net.IP(local.AsSlice())}
			}
			return dialer.DialContext(ctx, network, address)
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialBound(ctx, network, net.JoinHostPort(server.String(), "53"))
		}}
		return dialNamed(ctx, host, port, allow, func(ctx context.Context, name string) ([]netip.Addr, error) {
			if !server.IsValid() {
				return nil, errors.New("no IPv4 DNS server in the tunnel")
			}
			return resolver.LookupNetIP(ctx, "ip4", name)
		}, func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
			return dialBound(ctx, "tcp4", target.String())
		})
	}
}

// dialNamed turns host into addresses (itself when it is one), drops the ones the proxy may not reach and tries up
// to three of them, IPv4 first.
func dialNamed(ctx context.Context, host string, port uint16, allow func(netip.Addr) bool,
	lookup func(context.Context, string) ([]netip.Addr, error),
	dial func(context.Context, netip.AddrPort) (net.Conn, error)) (net.Conn, error) {
	var found []netip.Addr
	if address, err := netip.ParseAddr(host); err == nil {
		found = []netip.Addr{address.Unmap()}
	} else {
		var lookupErr error
		found, lookupErr = lookup(ctx, host)
		if len(found) == 0 {
			if lookupErr == nil {
				lookupErr = errors.New("name did not resolve")
			}
			return nil, lookupErr
		}
	}
	var candidates []netip.Addr
	for _, wantV4 := range []bool{true, false} {
		for _, address := range found {
			if address.Is4() == wantV4 && (allow == nil || allow(address)) {
				candidates = append(candidates, address)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, ErrBlockedDest
	}
	var lastErr error
	for _, address := range candidates[:min(len(candidates), 3)] {
		attempt, cancel := context.WithTimeout(ctx, 6*time.Second)
		conn, err := dial(attempt, netip.AddrPortFrom(address, port))
		cancel()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lastErr = err
	}
	return nil, lastErr
}
