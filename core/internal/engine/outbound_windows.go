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
	"github.com/mistgate/mistgate-client/core/internal/xray"
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
	return o.dial(ctx, target.String())
}

// dial takes a host:port; the server resolves a name.
func (o hy2Outbound) dial(ctx context.Context, address string) (net.Conn, error) {
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
		conn, err := o.client.TCP(address)
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
	buf    []byte // the read buffer: one reader per flow, made at the first read
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
	if f.buf == nil {
		f.buf = make([]byte, 65535)
	}
	n, err := conn.Read(f.buf)
	// A copy of the datagram's size: a 64 KiB buffer per datagram is what this replaces.
	return append([]byte(nil), f.buf[:n]...), target, err
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

// vlessOutbound is a run's Xray instance. A name is left to the server to resolve.
type vlessOutbound struct{ x *xray.Instance }

// DialTCP returns at once: VLESS gets no answer before the target speaks, so an unreachable target shows as a closed
// connection after it, not as an error here.
func (o vlessOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	return o.x.DialTCP(ctx, target.Addr().String(), target.Port())
}

func (o vlessOutbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &vlessPacketFlow{ctx: ctx, x: o.x, conns: make(map[netip.AddrPort]net.Conn), in: make(chan vlessDatagram, 16), done: make(chan struct{})}, nil
}

// vlessPacketFlow keeps one Xray UDP stream per destination: a stream names its destination once, so a flow that
// writes to several gets several streams, and what any of them returns is read from one place. The engine's flows
// have one destination each. ponytail: one stream that ends (idle, refused) ends the whole flow; per-destination
// recovery if a flow ever needs more than one.
type vlessPacketFlow struct {
	ctx   context.Context
	x     *xray.Instance
	mu    sync.Mutex
	conns map[netip.AddrPort]net.Conn
	in    chan vlessDatagram
	done  chan struct{}
	once  sync.Once
	err   error
}

type vlessDatagram struct {
	payload []byte
	from    netip.AddrPort
}

func (f *vlessPacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	f.mu.Lock()
	select {
	case <-f.done:
		f.mu.Unlock()
		return net.ErrClosed
	default:
	}
	conn := f.conns[target]
	if conn == nil {
		var err error
		if conn, err = f.x.DialUDP(f.ctx, target); err != nil {
			f.mu.Unlock()
			return err
		}
		f.conns[target] = conn
		go f.pump(conn, target)
	}
	f.mu.Unlock()
	_, err := conn.Write(payload)
	return err
}

func (f *vlessPacketFlow) pump(conn net.Conn, target netip.AddrPort) {
	buffer := make([]byte, 65535)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			f.end(err)
			return
		}
		select {
		case f.in <- vlessDatagram{append([]byte(nil), buffer[:n]...), target}:
		case <-f.done:
			return
		}
	}
}

func (f *vlessPacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	select {
	case d := <-f.in:
		return d.payload, d.from, nil
	case <-f.done:
		return nil, netip.AddrPort{}, f.err
	case <-f.ctx.Done():
		return nil, netip.AddrPort{}, f.ctx.Err()
	}
}

// end closes the flow; the first reason stays.
func (f *vlessPacketFlow) end(reason error) {
	f.once.Do(func() {
		f.mu.Lock()
		f.err = reason
		close(f.done) // under the lock: a write that comes after sees it and dials nothing
		for _, conn := range f.conns {
			_ = conn.Close()
		}
		f.mu.Unlock()
	})
}

func (f *vlessPacketFlow) Close() error {
	f.end(net.ErrClosed)
	return nil
}

type directOutbound struct{}

func (directOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	index, err := netcfg.CachedPhysicalInterfaceIndexFor(target.Addr())
	if err != nil {
		return nil, err
	}
	network := "tcp6"
	if target.Addr().Is4() {
		network = "tcp4"
	}
	return (&net.Dialer{Control: netcfg.SocketControl(index)}).DialContext(ctx, network, target.String())
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
	buf    []byte // the read buffer: one reader per flow, made at the first read
}

func (f *directPacketFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	if f.conn == nil {
		index, err := netcfg.CachedPhysicalInterfaceIndexFor(target.Addr())
		if err != nil {
			f.mu.Unlock()
			return err
		}
		var listen net.ListenConfig
		listen.Control = netcfg.SocketControl(index)
		network := "udp6"
		if target.Addr().Is4() {
			network = "udp4"
		}
		conn, err := listen.ListenPacket(f.ctx, network, ":0")
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
	_, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.IP(target.Addr().AsSlice()), Port: int(target.Port()), Zone: target.Addr().Zone()})
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
	if f.buf == nil {
		f.buf = make([]byte, 65535)
	}
	for {
		n, source, err := conn.ReadFrom(f.buf)
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
		return append([]byte(nil), f.buf[:n]...), address, nil
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
