//go:build windows

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const hy2UDPIdleTimeout = 60 * time.Second

type gvisorBridge struct {
	tun          tun.Device
	vpn          outbound
	direct       outbound
	shouldDirect func(netip.Addr, string) bool
	hasSiteRules func() bool
	track        *geo.Tracker // nil: flows are not watched for "doesn't open?"
	dns          *dnsMemory
	stack        *stack.Stack
	link         *channel.Endpoint
	ctx          context.Context
	cancel       context.CancelFunc

	// names says, for a host name, whether it is blocked and which resolver (zero: none) its DNS question is sent to
	// directly. nil: DNS questions and TLS names are left alone.
	names   func(name string) (block bool, resolver netip.AddrPort)
	dnsDown atomic.Int64 // unix nanoseconds until which regional resolvers are not tried, after one was silent

	mu     sync.Mutex
	closed bool
	flows  map[*udpFlow]struct{}
	wg     sync.WaitGroup
}

func newGvisorBridge(parent context.Context, tunDevice tun.Device, mtu int, vpn, direct outbound, shouldDirect func(netip.Addr, string) bool, hasSiteRules func() bool, track *geo.Tracker, names func(string) (bool, netip.AddrPort)) (*gvisorBridge, error) {
	if vpn == nil {
		return nil, errors.New("VPN outbound is unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	link := channel.New(1024, uint32(mtu), "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	fail := func() {
		cancel()
		link.Close()
		st.Close()
	}
	if err := st.CreateNIC(1, link); err != nil {
		fail()
		return nil, errors.New("attach gVisor stack to Wintun")
	}
	if err := st.SetPromiscuousMode(1, true); err != nil {
		fail()
		return nil, errors.New("enable gVisor promiscuous mode")
	}
	if err := st.SetSpoofing(1, true); err != nil {
		fail()
		return nil, errors.New("enable gVisor address spoofing")
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	bridge := &gvisorBridge{
		tun:          tunDevice,
		vpn:          vpn,
		direct:       direct,
		shouldDirect: shouldDirect,
		hasSiteRules: hasSiteRules,
		track:        track,
		names:        names,
		dns:          &dnsMemory{entries: make(map[netip.Addr]dnsEntry)},
		stack:        st,
		link:         link,
		ctx:          ctx,
		cancel:       cancel,
		flows:        make(map[*udpFlow]struct{}),
	}
	tcpForwarder := tcp.NewForwarder(st, 0, 1024, bridge.forwardTCP)
	udpForwarder := udp.NewForwarder(st, bridge.forwardUDP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	bridge.wg.Add(2)
	go bridge.readTun()
	go bridge.writeTun()
	return bridge, nil
}

func (b *gvisorBridge) readTun() {
	defer b.wg.Done()
	const batch = 16
	buffers := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range buffers {
		buffers[i] = make([]byte, 65536)
	}
	for {
		n, err := b.tun.Read(buffers, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			size := sizes[i]
			if size <= 0 || size > len(buffers[i]) {
				continue
			}
			data := append([]byte(nil), buffers[i][:size]...)
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			switch data[0] >> 4 {
			case 4:
				b.link.InjectInbound(ipv4.ProtocolNumber, packet)
			case 6:
				b.link.InjectInbound(ipv6.ProtocolNumber, packet)
			}
			packet.DecRef()
		}
	}
}

func (b *gvisorBridge) writeTun() {
	defer b.wg.Done()
	for {
		packet := b.link.ReadContext(b.ctx)
		if packet.IsNil() {
			return
		}
		view := packet.ToView()
		data := view.AsSlice()
		_, _ = b.tun.Write([][]byte{data}, 0)
		view.Release()
		packet.DecRef()
	}
}

func (b *gvisorBridge) startForward(fn func()) bool {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return false
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		fn()
	}()
	return true
}

func (b *gvisorBridge) forwardTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	address, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		req.Complete(true)
		return
	}
	target := netip.AddrPortFrom(address.Unmap(), id.LocalPort)
	// Watching a TLS flow needs its name, so port 443 is read first even without site rules.
	watching := b.track != nil && target.Port() == 443
	needsName := b.hasSiteRules != nil && b.hasSiteRules() || watching
	var remote net.Conn
	var local *gonet.TCPConn
	var sniffed []byte
	var watch *flowWatch
	if needsName {
		var queue waiter.Queue
		endpoint, endpointErr := req.CreateEndpoint(&queue)
		if endpointErr != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		local = gonet.NewTCPConn(&queue, endpoint)
		name := ""
		if target.Port() == 443 || target.Port() == 80 {
			name, sniffed = sniffTCPName(local, target.Port())
		}
		if name != "" && b.names != nil {
			if block, _ := b.names(name); block {
				_ = local.Close()
				return
			}
		}
		watching = watching && name != ""
		var err error
		var route geo.Route
		remote, route, err = b.dialTCPName(b.ctx, target, name)
		if err != nil {
			// A cancelled context is the app closing, not the site failing.
			if watching && b.ctx.Err() == nil {
				b.track.Fail(route, name, time.Now())
			}
			// We cannot send a RST after accepting the local endpoint, so close it.
			_ = local.Close()
			return
		}
		for len(sniffed) > 0 {
			n, writeErr := remote.Write(sniffed)
			if n > 0 {
				sniffed = sniffed[n:]
			}
			if writeErr != nil || n == 0 {
				if watching && b.ctx.Err() == nil {
					b.track.Fail(route, name, time.Now())
				}
				_ = local.Close()
				_ = remote.Close()
				return
			}
		}
		if watching {
			watch = &flowWatch{track: b.track, route: route, name: name}
		}
	} else {
		var err error
		remote, err = b.dialTCP(b.ctx, target)
		if err != nil {
			req.Complete(true)
			return
		}
	}
	if local == nil {
		var queue waiter.Queue
		endpoint, endpointErr := req.CreateEndpoint(&queue)
		if endpointErr != nil {
			_ = remote.Close()
			req.Complete(true)
			return
		}
		req.Complete(false)
		local = gonet.NewTCPConn(&queue, endpoint)
	}
	if !b.startForward(func() { proxyTCP(local, remote, watch) }) {
		_ = local.Close()
		_ = remote.Close()
	}
}

var noAnswerAfter = 10 * time.Second // a variable for the test

// flowWatch reads the answers of one TLS flow for the tracker: the first byte is a success; a close, a reset or
// 10 s of silence before it is a failure. Read runs on the one goroutine that copies remote -> local.
type flowWatch struct {
	track   *geo.Tracker
	route   geo.Route
	name    string
	remote  net.Conn
	closing atomic.Bool // proxyTCP is ending the flow itself (the app went away), so a read error is not the site's
	started bool
	got     bool
	silent  bool // the 10 s ran out and the failure is counted
}

func (w *flowWatch) Read(p []byte) (int, error) {
	if !w.started {
		w.started = true
		_ = w.remote.SetReadDeadline(time.Now().Add(noAnswerAfter))
	}
	for {
		n, err := w.remote.Read(p)
		if w.got || err == nil && n == 0 {
			return n, err
		}
		if n > 0 {
			w.got = true
			if !w.silent {
				_ = w.remote.SetReadDeadline(time.Time{})
			}
			w.track.OK(w.route, w.name, time.Now())
			return n, err
		}
		var timeout net.Error
		if !w.silent && errors.As(err, &timeout) && timeout.Timeout() {
			w.silent = true
			w.track.Fail(w.route, w.name, time.Now())
			_ = w.remote.SetReadDeadline(time.Time{})
			continue
		}
		// ponytail: a reset first noticed by a write (A side) is not counted, TLS clients do not write before the reply.
		if !w.silent && !w.closing.Load() {
			w.track.Fail(w.route, w.name, time.Now())
		}
		return n, err
	}
}

func proxyTCP(local, remote net.Conn, watch *flowWatch) {
	var answers io.Reader = remote
	if watch != nil {
		watch.remote = remote
		answers = watch
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, local)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, answers)
		done <- struct{}{}
	}()
	<-done
	if watch != nil {
		watch.closing.Store(true)
	}
	_ = local.Close()
	_ = remote.Close()
	<-done
}

func (b *gvisorBridge) forwardUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	address, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return
	}
	target := netip.AddrPortFrom(address.Unmap(), id.LocalPort)
	flowCtx, cancel := context.WithCancel(b.ctx)
	remote, dialErr := b.listenUDP(flowCtx, target)
	if dialErr != nil {
		cancel()
		return
	}
	var queue waiter.Queue
	endpoint, err := req.CreateEndpoint(&queue)
	if err != nil {
		_ = remote.Close()
		cancel()
		return
	}
	local := gonet.NewUDPConn(b.stack, &queue, endpoint)
	flow := &udpFlow{
		local:  local,
		remote: remote,
		target: target,
		ctx:    flowCtx,
		cancel: cancel,
		dns:    b.dns,
	}
	if target.Port() == 53 {
		flow.names, flow.direct, flow.down = b.names, b.direct, &b.dnsDown
	}
	flow.lastActivity.Store(time.Now().UnixNano())
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		flow.close()
		return
	}
	b.flows[flow] = struct{}{}
	b.mu.Unlock()
	if !b.startForward(func() {
		defer b.removeFlow(flow)
		flow.run()
	}) {
		b.removeFlow(flow)
		flow.close()
	}
}

func (b *gvisorBridge) removeFlow(flow *udpFlow) {
	b.mu.Lock()
	delete(b.flows, flow)
	b.mu.Unlock()
}

type udpFlow struct {
	local        net.Conn // the app's side; a *gonet.UDPConn
	remote       packetFlow
	target       netip.AddrPort
	ctx          context.Context
	cancel       context.CancelFunc
	lastActivity atomic.Int64
	dns          *dnsMemory
	once         sync.Once

	// Set for port 53 only; names == nil leaves every packet alone.
	names  func(string) (bool, netip.AddrPort)
	direct outbound
	down   *atomic.Int64

	sendMu  sync.Mutex // the VPN flow takes one writer at a time (Hysteria2 reuses one send buffer)
	mu      sync.Mutex // guards the fields below; never held across a send
	dflow   packetFlow // the flow to the regional resolver, made at the first direct question
	dtarget netip.AddrPort
	pending map[uint16]*dnsAsk
	closed  bool
}

// dnsAsk is a question sent to a regional resolver and not yet answered.
type dnsAsk struct {
	payload []byte
	end     int // where its question section ends
	timer   *time.Timer
}

var (
	dnsDirectWait  = 2 * time.Second  // silence after which the question goes through the VPN as before
	dnsDirectPause = 30 * time.Second // after one such silence, regional resolvers rest this long (a blocked one would cost every question 2 s)
)

// dnsPacket handles a DNS question on its way out and says whether it did: a blocked name is answered here, and a
// name that goes direct is sent to the regional resolver. Everything else, and every failure, returns false and the
// packet goes through the VPN.
func (f *udpFlow) dnsPacket(payload []byte) bool {
	name, end, ok := dnsQuestion(payload)
	if !ok {
		return false
	}
	block, resolver := f.names(name)
	if block {
		_, _ = f.local.Write(nxdomain(payload, end))
		return true
	}
	if !resolver.IsValid() || f.direct == nil || time.Now().UnixNano() < f.down.Load() {
		return false
	}
	return f.askDirect(payload, end, resolver)
}

func (f *udpFlow) askDirect(payload []byte, end int, resolver netip.AddrPort) bool {
	f.mu.Lock()
	flow, target, closed := f.dflow, f.dtarget, f.closed
	f.mu.Unlock()
	if closed || flow != nil && target != resolver {
		return false
	}
	if flow == nil {
		var err error
		if flow, err = f.direct.ListenUDP(f.ctx); err != nil {
			return false
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			_ = flow.Close()
			return false
		}
		f.dflow, f.dtarget = flow, resolver
		f.mu.Unlock()
		go f.readDirect(flow, resolver)
	}
	id := uint16(payload[0])<<8 | uint16(payload[1])
	ask := &dnsAsk{payload: payload, end: end}
	f.mu.Lock()
	if f.pending == nil {
		f.pending = make(map[uint16]*dnsAsk)
	}
	f.pending[id] = ask
	f.mu.Unlock()
	if err := flow.WriteTo(payload, resolver); err != nil {
		f.settle(id, ask)
		f.down.Store(time.Now().Add(dnsDirectPause).UnixNano())
		return false
	}
	timer := time.AfterFunc(dnsDirectWait, func() { f.fallback(id, ask) })
	f.mu.Lock()
	if f.pending[id] == ask {
		ask.timer = timer
		timer = nil
	}
	f.mu.Unlock()
	if timer != nil { // answered, or the flow closed, before the timer existed
		timer.Stop()
	}
	return true
}

// settle takes a question off the pending list, if it is still the one for id.
func (f *udpFlow) settle(id uint16, ask *dnsAsk) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending[id] != ask {
		return false
	}
	delete(f.pending, id)
	if ask.timer != nil {
		ask.timer.Stop()
	}
	return true
}

// fallback asks through the VPN a question the regional resolver left unanswered.
func (f *udpFlow) fallback(id uint16, ask *dnsAsk) {
	if !f.settle(id, ask) {
		return
	}
	f.down.Store(time.Now().Add(dnsDirectPause).UnixNano())
	_ = f.send(ask.payload)
}

func (f *udpFlow) send(payload []byte) error {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	return f.remote.WriteTo(payload, f.target)
}

// readDirect hands the app the answers of the regional resolver. An answer counts only for a pending question: same
// id and same question section.
func (f *udpFlow) readDirect(flow packetFlow, resolver netip.AddrPort) {
	for {
		payload, source, err := flow.ReadFrom()
		if err != nil {
			return
		}
		if source != resolver || len(payload) < 2 {
			continue
		}
		id := uint16(payload[0])<<8 | uint16(payload[1])
		f.mu.Lock()
		ask := f.pending[id]
		f.mu.Unlock()
		if ask == nil || len(payload) < ask.end || !bytes.Equal(payload[12:ask.end], ask.payload[12:ask.end]) || !f.settle(id, ask) {
			continue
		}
		if f.dns != nil {
			f.dns.remember(payload)
		}
		f.lastActivity.Store(time.Now().UnixNano())
		if _, err := f.local.Write(payload); err != nil {
			f.close()
			return
		}
	}
}

func (f *udpFlow) run() {
	defer f.close()
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = f.local.SetReadDeadline(time.Now().Add(time.Second))
			n, err := f.local.Read(buf)
			if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
				select {
				case <-f.ctx.Done():
					done <- struct{}{}
					return
				default:
					continue
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
			f.lastActivity.Store(time.Now().UnixNano())
			payload := append([]byte(nil), buf[:n]...)
			if f.names != nil && f.dnsPacket(payload) {
				continue
			}
			if err := f.send(payload); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		for {
			payload, source, err := f.remote.ReadFrom()
			if err != nil {
				done <- struct{}{}
				return
			}
			if source != f.target {
				continue
			}
			if f.target.Port() == 53 && f.dns != nil {
				f.dns.remember(payload)
			}
			f.lastActivity.Store(time.Now().UnixNano())
			if _, err := f.local.Write(payload); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	ctxDone := f.ctx.Done()
	completed := 0
	for completed < 2 {
		select {
		case <-done:
			completed++
			f.close()
			ctxDone = nil
		case <-ctxDone:
			f.close()
			ctxDone = nil
		case <-ticker.C:
			if time.Since(time.Unix(0, f.lastActivity.Load())) >= hy2UDPIdleTimeout {
				f.close()
				ctxDone = nil
			}
		}
	}
}

func (f *udpFlow) close() {
	f.once.Do(func() {
		f.cancel()
		f.mu.Lock()
		f.closed = true
		dflow := f.dflow
		for _, ask := range f.pending {
			if ask.timer != nil {
				ask.timer.Stop()
			}
		}
		clear(f.pending)
		f.mu.Unlock()
		_ = f.remote.Close()
		if dflow != nil {
			_ = dflow.Close()
		}
		_ = f.local.Close()
	})
}

func (b *gvisorBridge) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	flows := make([]*udpFlow, 0, len(b.flows))
	for flow := range b.flows {
		flows = append(flows, flow)
	}
	b.mu.Unlock()

	b.cancel()
	for _, flow := range flows {
		flow.close()
	}
	b.link.Close()
	b.stack.Close()
	_ = b.tun.Close()
	b.wg.Wait()
}

func (b *gvisorBridge) dialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	conn, _, err := b.dialTCPName(ctx, target, "")
	return conn, err
}

// dialTCPName also says which route the flow was given, even when the dial fails.
func (b *gvisorBridge) dialTCPName(ctx context.Context, target netip.AddrPort, name string) (net.Conn, geo.Route, error) {
	if name == "" && b.hasSiteRules != nil && b.hasSiteRules() && b.dns != nil {
		name = b.dns.lookup(target.Addr())
	}
	out, route := selectOutbound(target, name, b.shouldDirect, b.vpn, b.direct)
	conn, err := out.DialTCP(ctx, target)
	return conn, route, err
}

func (b *gvisorBridge) listenUDP(ctx context.Context, target netip.AddrPort) (packetFlow, error) {
	name := ""
	if target.Port() != 53 && b.hasSiteRules != nil && b.hasSiteRules() && b.dns != nil {
		name = b.dns.lookup(target.Addr())
	}
	out, _ := selectOutbound(target, name, b.shouldDirect, b.vpn, b.direct)
	return out.ListenUDP(ctx)
}

func selectOutbound(target netip.AddrPort, name string, shouldDirect func(netip.Addr, string) bool, vpn, direct outbound) (outbound, geo.Route) {
	address := target.Addr()
	// Keep the adapter's configured DNS resolver on the VPN.
	if direct != nil && target.Port() != 53 && directAddressAllowed(address) && shouldDirect != nil && shouldDirect(address, name) {
		return direct, geo.ViaDirect
	}
	return vpn, geo.ViaVPN
}

func directAddressAllowed(address netip.Addr) bool {
	return address.IsValid() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}
