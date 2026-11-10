//go:build windows

package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
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
	shouldDirect func(netip.Addr) bool
	stack        *stack.Stack
	link         *channel.Endpoint
	ctx          context.Context
	cancel       context.CancelFunc

	mu     sync.Mutex
	closed bool
	flows  map[*udpFlow]struct{}
	wg     sync.WaitGroup
}

func newGvisorBridge(parent context.Context, tunDevice tun.Device, mtu int, vpn, direct outbound, shouldDirect func(netip.Addr) bool) (*gvisorBridge, error) {
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
	remote, err := b.dialTCP(b.ctx, target)
	if err != nil {
		req.Complete(true)
		return
	}
	var queue waiter.Queue
	endpoint, endpointErr := req.CreateEndpoint(&queue)
	if endpointErr != nil {
		_ = remote.Close()
		req.Complete(true)
		return
	}
	req.Complete(false)
	local := gonet.NewTCPConn(&queue, endpoint)
	if !b.startForward(func() { proxyTCP(local, remote) }) {
		_ = local.Close()
		_ = remote.Close()
	}
}

func proxyTCP(local, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, local)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		done <- struct{}{}
	}()
	<-done
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
	local        *gonet.UDPConn
	remote       packetFlow
	target       netip.AddrPort
	ctx          context.Context
	cancel       context.CancelFunc
	lastActivity atomic.Int64
	once         sync.Once
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
			if err := f.remote.WriteTo(payload, f.target); err != nil {
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
		_ = f.remote.Close()
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
	return selectOutbound(target, b.shouldDirect, b.vpn, b.direct).DialTCP(ctx, target)
}

func (b *gvisorBridge) listenUDP(ctx context.Context, target netip.AddrPort) (packetFlow, error) {
	return selectOutbound(target, b.shouldDirect, b.vpn, b.direct).ListenUDP(ctx)
}

func selectOutbound(target netip.AddrPort, shouldDirect func(netip.Addr) bool, vpn, direct outbound) outbound {
	address := target.Addr()
	// Keep the adapter's configured DNS resolver on the VPN.
	inRegion := shouldDirect != nil && shouldDirect(address)
	if direct != nil && target.Port() != 53 && directAddressAllowed(address) && inRegion {
		return direct
	}
	return vpn
}

func directAddressAllowed(address netip.Addr) bool {
	return address.Is4() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}
