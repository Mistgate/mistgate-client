//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
)

type outbound interface {
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	ListenUDP(context.Context) (packetFlow, error)
}

type packetFlow interface {
	WriteTo([]byte, netip.AddrPort) error
	ReadFrom() ([]byte, netip.AddrPort, error)
	Close() error
}

type hy2Outbound struct{ client client.Client }

func (o hy2Outbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	var mu sync.Mutex
	canceled := false
	go func() {
		conn, err := o.client.TCP(target.String())
		mu.Lock()
		if canceled {
			mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		done <- result{conn: conn, err: err}
		mu.Unlock()
	}()
	select {
	case result := <-done:
		return result.conn, result.err
	case <-ctx.Done():
		mu.Lock()
		canceled = true
		mu.Unlock()
		select {
		case result := <-done:
			if result.conn != nil {
				_ = result.conn.Close()
			}
		default:
		}
		return nil, ctx.Err()
	}
}

func (o hy2Outbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := o.client.UDP()
	if err != nil {
		return nil, err
	}
	return &hy2PacketFlow{conn: conn}, nil
}

type hy2PacketFlow struct{ conn client.HyUDPConn }

func (f *hy2PacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	return f.conn.Send(payload, target.String())
}

func (f *hy2PacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	payload, address, err := f.conn.Receive()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	target, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, netip.AddrPort{}, errors.New("invalid Hysteria2 UDP source")
	}
	return payload, target, nil
}

func (f *hy2PacketFlow) Close() error { return f.conn.Close() }

type awgOutbound struct{ net *netstack.Net }

func (o awgOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	return o.net.DialContextTCPAddrPort(ctx, target)
}

func (o awgOutbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &awgPacketFlow{ctx: ctx, net: o.net, ready: make(chan struct{})}, nil
}

type awgPacketFlow struct {
	ctx    context.Context
	net    *netstack.Net
	mu     sync.Mutex
	conn   net.Conn
	target netip.AddrPort
	ready  chan struct{}
	closed bool
	once   sync.Once
}

func (f *awgPacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	if f.conn == nil {
		conn, err := f.net.DialUDPAddrPort(netip.AddrPort{}, target)
		if err != nil {
			f.mu.Unlock()
			return err
		}
		f.conn, f.target = conn, target
		f.once.Do(func() { close(f.ready) })
	} else if target != f.target {
		f.mu.Unlock()
		return errors.New("UDP flow target changed")
	}
	conn := f.conn
	f.mu.Unlock()
	if err := f.ctx.Err(); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func (f *awgPacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	select {
	case <-f.ready:
	case <-f.ctx.Done():
		return nil, netip.AddrPort{}, f.ctx.Err()
	}
	f.mu.Lock()
	conn, target, closed := f.conn, f.target, f.closed
	f.mu.Unlock()
	if closed || conn == nil {
		return nil, netip.AddrPort{}, net.ErrClosed
	}
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	return buffer[:n], target, err
}

func (f *awgPacketFlow) Close() error {
	f.mu.Lock()
	f.closed = true
	conn := f.conn
	f.once.Do(func() { close(f.ready) })
	f.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

type directOutbound struct{}

func (directOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	index, err := netcfg.PhysicalInterfaceIndexFor(target.Addr())
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Control: netcfg.SocketControl(index)}).DialContext(ctx, "tcp4", target.String())
}

func (directOutbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &directPacketFlow{ctx: ctx, ready: make(chan struct{})}, nil
}

type directPacketFlow struct {
	ctx    context.Context
	mu     sync.Mutex
	conn   net.PacketConn
	target netip.AddrPort
	ready  chan struct{}
	closed bool
	once   sync.Once
}

func (f *directPacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	if f.conn == nil {
		index, err := netcfg.PhysicalInterfaceIndexFor(target.Addr())
		if err != nil {
			f.mu.Unlock()
			return err
		}
		var listen net.ListenConfig
		listen.Control = netcfg.SocketControl(index)
		conn, err := listen.ListenPacket(f.ctx, "udp4", ":0")
		if err != nil {
			f.mu.Unlock()
			return err
		}
		f.conn, f.target = conn, target
		f.once.Do(func() { close(f.ready) })
	} else if target != f.target {
		f.mu.Unlock()
		return errors.New("UDP flow target changed")
	}
	conn := f.conn
	f.mu.Unlock()
	if err := f.ctx.Err(); err != nil {
		return err
	}
	_, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.IP(target.Addr().AsSlice()), Port: int(target.Port())})
	return err
}

func (f *directPacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	select {
	case <-f.ready:
	case <-f.ctx.Done():
		return nil, netip.AddrPort{}, f.ctx.Err()
	}
	f.mu.Lock()
	conn, target, closed := f.conn, f.target, f.closed
	f.mu.Unlock()
	if closed || conn == nil {
		return nil, netip.AddrPort{}, net.ErrClosed
	}
	for {
		buffer := make([]byte, 65535)
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok {
			return nil, netip.AddrPort{}, errors.New("invalid direct UDP source")
		}
		address := udpSource.AddrPort()
		if address != target {
			continue
		}
		return buffer[:n], address, nil
	}
}

func (f *directPacketFlow) Close() error {
	f.mu.Lock()
	f.closed = true
	conn := f.conn
	f.once.Do(func() { close(f.ready) })
	f.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}
