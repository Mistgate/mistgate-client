//go:build windows

package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
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
	vpnRx        atomic.Uint64 // bytes that arrived from the VPN side: the link guard's sign of a live server
	direct       outbound
	shouldDirect func(netip.Addr, string) bool
	hasSiteRules func() bool
	apps         *appRouter   // nil: no program has a rule of its own
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
	// noVPN6: the VPN carries no IPv6 (an AmneziaWG server that hands out an address and routes nothing, a Hysteria2
	// server without IPv6). Asked once when the tunnel comes up. Names that go through the VPN then get no IPv6
	// addresses and IPv6 connections are refused at once, so every app uses IPv4 instead of waiting on a dead path.
	noVPN6 atomic.Bool

	mu     sync.Mutex
	closed bool
	flows  map[*udpFlow]struct{}
	wg     sync.WaitGroup
}

func newGvisorBridge(parent context.Context, tunDevice tun.Device, mtu int, vpn, direct outbound, shouldDirect func(netip.Addr, string) bool, hasSiteRules func() bool, track *geo.Tracker, names func(string) (bool, netip.AddrPort), apps *appRouter) (*gvisorBridge, error) {
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
		apps:         apps,
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
	udpForwarder := udp.NewForwarder(st, func(req *udp.ForwarderRequest) bool {
		bridge.forwardUDP(req)
		return true // every UDP flow is ours; an unhandled one would get an ICMP unreachable
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	bridge.wg.Add(2)
	go bridge.readTun()
	go bridge.writeTun()
	bridge.vpn = countedOutbound{vpn, &bridge.vpnRx}
	go bridge.checkVPN6()
	return bridge, nil
}

// vpn6Probes are public IPv6 resolvers' HTTPS ports: one answer through the VPN means IPv6 works there.
var vpn6Probes = []netip.AddrPort{netip.MustParseAddrPort("[2606:4700:4700::1111]:443"), netip.MustParseAddrPort("[2001:4860:4860::8888]:443")}

func isVLESS(o outbound) bool {
	if counted, ok := o.(countedOutbound); ok {
		o = counted.outbound
	}
	_, ok := o.(vlessOutbound)
	return ok
}

func (b *gvisorBridge) checkVPN6() {
	ctx, cancel := context.WithTimeout(b.ctx, 3*time.Second)
	defer cancel()
	answers := make(chan bool, len(vpn6Probes))
	lazy := isVLESS(b.vpn)
	for _, target := range vpn6Probes {
		go func() {
			conn, err := b.vpn.DialTCP(ctx, target)
			if err == nil {
				if lazy { // a VLESS dial is only a request in flight; a handshake that comes back proves the way
					err = tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).HandshakeContext(ctx)
				}
				_ = conn.Close()
			}
			answers <- err == nil
		}()
	}
	for range vpn6Probes {
		if <-answers {
			return
		}
	}
	if b.ctx.Err() == nil {
		b.noVPN6.Store(true)
	}
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
		if packet == nil {
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
	// No IPv6 through the VPN and none beside it: refuse before accepting, so the app turns to IPv4 at once. (Accepted
	// first, to read the name, the connection would hang on a path that carries nothing.)
	if target.Addr().Is6() && b.noVPN6.Load() && !directIPv6() {
		req.Complete(true)
		return
	}
	// This goroutine is the flow's own, so waiting here for the owner of the socket stalls nothing else.
	srcAddr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	app := b.appWait(false, netip.AddrPortFrom(srcAddr.Unmap(), id.RemotePort), target)
	// A program kept on the VPN cannot use a VPN without IPv6: refuse as above.
	if app == appVPN && target.Addr().Is6() && b.noVPN6.Load() {
		req.Complete(true)
		return
	}
	needsName, watching := b.readsName(app, target.Port())
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
		remote, route, err = b.dialTCPName(b.ctx, target, name, app)
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
		remote, _, err = b.dialTCPName(b.ctx, target, "", app)
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

// readsName says whether a TCP flow is accepted first and read for its name before it is dialed, and whether the
// tracker watches it. Watching a TLS flow needs its name, so port 443 is read even without site rules. A flow decided by
// its program is not the site's doing: it is not watched, and needs a name only to be blocked by it.
func (b *gvisorBridge) readsName(app appVerdict, port uint16) (needsName, watching bool) {
	if app != appNone {
		return (port == 443 || port == 80) && b.apps.blocks(), false
	}
	watching = b.track != nil && port == 443
	return b.hasSiteRules != nil && b.hasSiteRules() || watching, watching
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
	srcAddr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	src := netip.AddrPortFrom(srcAddr.Unmap(), id.RemotePort)
	app, ready := b.appQuick(true, src, target)
	if !ready {
		// Finding the owner of the socket may wait for a table snapshot, and this runs on the packet pump, which must not
		// wait. The endpoint is made first so the flow's next packets queue on it instead of starting new requests.
		var queue waiter.Queue
		endpoint, err := req.CreateEndpoint(&queue)
		if err != nil {
			return
		}
		local := gonet.NewUDPConn(&queue, endpoint)
		if !b.startForward(func() { b.runUDP(local, target, b.appResolve(true, src)) }) {
			_ = local.Close()
		}
		return
	}
	flowCtx, cancel := context.WithCancel(b.ctx)
	remote, dialErr := b.listenUDP(flowCtx, target, app)
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
	b.serveUDP(gonet.NewUDPConn(&queue, endpoint), remote, target, flowCtx, cancel)
}

// runUDP gives an accepted flow its outbound once the program is known.
func (b *gvisorBridge) runUDP(local net.Conn, target netip.AddrPort, app appVerdict) {
	flowCtx, cancel := context.WithCancel(b.ctx)
	remote, err := b.listenUDP(flowCtx, target, app)
	if err != nil {
		cancel()
		_ = local.Close()
		return
	}
	b.serveUDP(local, remote, target, flowCtx, cancel)
}

func (b *gvisorBridge) serveUDP(local net.Conn, remote packetFlow, target netip.AddrPort, flowCtx context.Context, cancel context.CancelFunc) {
	flow := &udpFlow{
		local:  local,
		remote: remote,
		target: target,
		ctx:    flowCtx,
		cancel: cancel,
		dns:    b.dns,
	}
	if target.Port() == 53 {
		flow.names, flow.direct, flow.down, flow.noVPN6 = b.names, b.direct, &b.dnsDown, b.noVPN6.Load
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
	noVPN6 func() bool // port 53 only: the VPN carries no IPv6

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
	block, resolver := false, netip.AddrPort{}
	if f.names != nil {
		block, resolver = f.names(name)
	}
	if block {
		_, _ = f.local.Write(blockedAnswer(payload, end))
		return true
	}
	// A name that goes through a VPN without IPv6 gets no IPv6 addresses (see noVPN6).
	if !resolver.IsValid() && payload[end-4] == 0 && payload[end-3] == dnsTypeAAAA && f.noVPN6 != nil && f.noVPN6() {
		_, _ = f.local.Write(noData(payload, end))
		return true
	}
	if !resolver.IsValid() || f.direct == nil || time.Now().UnixNano() < f.down.Load() {
		return false
	}
	// A name that goes direct on a machine without IPv6 beside the tunnel must not get IPv6 addresses: the app would
	// connect to one, the flow could not leave, and the app would not fall back to IPv4.
	if payload[end-4] == 0 && payload[end-3] == dnsTypeAAAA && !directIPv6() {
		_, _ = f.local.Write(noData(payload, end))
		return true
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
			if (f.names != nil || f.noVPN6 != nil) && f.dnsPacket(payload) {
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
	conn, _, err := b.dialTCPName(ctx, target, "", appNone)
	return conn, err
}

// dialTCPName also says which route the flow was given, even when the dial fails.
func (b *gvisorBridge) dialTCPName(ctx context.Context, target netip.AddrPort, name string, app appVerdict) (net.Conn, geo.Route, error) {
	if app == appNone && name == "" && b.hasSiteRules != nil && b.hasSiteRules() && b.dns != nil {
		name = b.dns.lookup(target.Addr())
	}
	out, route := selectOutbound(target, name, b.shouldDirect, app, b.vpn, b.direct)
	conn, err := out.DialTCP(ctx, target)
	return conn, route, err
}

func (b *gvisorBridge) listenUDP(ctx context.Context, target netip.AddrPort, app appVerdict) (packetFlow, error) {
	name := ""
	if app == appNone && target.Port() != 53 && b.hasSiteRules != nil && b.hasSiteRules() && b.dns != nil {
		name = b.dns.lookup(target.Addr())
	}
	out, _ := selectOutbound(target, name, b.shouldDirect, app, b.vpn, b.direct)
	return out.ListenUDP(ctx)
}

// selectOutbound: the program's verdict replaces the site and address rules in its own direction. The DNS port, the
// addresses that cannot go direct and IPv6 without a direct path stay as they are (block works before this, by name).
func selectOutbound(target netip.AddrPort, name string, shouldDirect func(netip.Addr, string) bool, app appVerdict, vpn, direct outbound) (outbound, geo.Route) {
	address := target.Addr()
	if app == appVPN {
		return vpn, geo.ViaVPN
	}
	// Keep the adapter's configured DNS resolver on the VPN.
	if direct != nil && target.Port() != 53 && directAddressAllowed(address) && (app == appDirect || shouldDirect != nil && shouldDirect(address, name)) && (address.Is4() || directIPv6()) {
		return direct, geo.ViaDirect
	}
	return vpn, geo.ViaVPN
}

// countedOutbound counts what arrives through the VPN. The adapter's own counter will not do here: in the forwarder
// modes it also counts the answers of direct flows, and a busy machine would hide a dead server for ever.
type countedOutbound struct {
	outbound
	rx *atomic.Uint64
}

func (o countedOutbound) DialTCP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	conn, err := o.outbound.DialTCP(ctx, target)
	if err != nil {
		return nil, err
	}
	return countedConn{conn, o.rx}, nil
}

func (o countedOutbound) ListenUDP(ctx context.Context) (packetFlow, error) {
	flow, err := o.outbound.ListenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return countedFlow{flow, o.rx}, nil
}

type countedConn struct {
	net.Conn
	rx *atomic.Uint64
}

func (c countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rx.Add(uint64(n))
	return n, err
}

type countedFlow struct {
	packetFlow
	rx *atomic.Uint64
}

func (f countedFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	payload, source, err := f.packetFlow.ReadFrom()
	f.rx.Add(uint64(len(payload)))
	return payload, source, err
}

var direct6 struct{ at, ok atomic.Int64 }

// directIPv6 says whether this machine reaches IPv6 beside the tunnel; the routing table is asked at most once in 30 s.
var directIPv6 = func() bool { // a variable for the tests
	now := time.Now().Unix()
	if now-direct6.at.Load() < 30 {
		return direct6.ok.Load() == 1
	}
	var ok int64
	if _, err := netcfg.PhysicalInterfaceIndexFor(netip.MustParseAddr("2001:4860:4860::8888")); err == nil {
		ok = 1
	}
	direct6.ok.Store(ok)
	direct6.at.Store(now)
	return ok == 1
}

func directAddressAllowed(address netip.Addr) bool {
	return address.IsValid() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}
