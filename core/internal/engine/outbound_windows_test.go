//go:build windows

package engine

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type countOutbound struct {
	tcp  atomic.Int32
	udp  atomic.Int32
	flow packetFlow
}

func (o *countOutbound) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	o.tcp.Add(1)
	return nil, nil
}

func (o *countOutbound) ListenUDP(context.Context) (packetFlow, error) {
	o.udp.Add(1)
	return o.flow, nil
}

type countPacketFlow struct{ writes atomic.Int32 }

func (f *countPacketFlow) WriteTo([]byte, netip.AddrPort) error {
	f.writes.Add(1)
	return nil
}

func (*countPacketFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, net.ErrClosed
}

func (*countPacketFlow) Close() error { return nil }

func TestBridgeSelectsExitForNewTCPAndUDPFlows(t *testing.T) {
	vpnFlow, directFlow := &countPacketFlow{}, &countPacketFlow{}
	vpn := &countOutbound{flow: vpnFlow}
	direct := &countOutbound{flow: directFlow}
	bridge := &gvisorBridge{
		vpn:    vpn,
		direct: direct,
		shouldDirect: func(netip.Addr, string) bool {
			return true
		},
	}
	target := netip.MustParseAddrPort("203.0.113.7:8443")
	if _, err := bridge.dialTCP(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	flow, err := bridge.listenUDP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := flow.WriteTo([]byte("packet"), target); err != nil {
		t.Fatal(err)
	}
	if direct.tcp.Load() != 1 || direct.udp.Load() != 1 || directFlow.writes.Load() != 1 || vpn.tcp.Load() != 0 || vpn.udp.Load() != 0 {
		t.Fatalf("direct counts tcp=%d udp=%d writes=%d; vpn tcp=%d udp=%d", direct.tcp.Load(), direct.udp.Load(), directFlow.writes.Load(), vpn.tcp.Load(), vpn.udp.Load())
	}
}

func TestPrivateAndDNSDestinationsNeverUseDirectExit(t *testing.T) {
	vpn := &countOutbound{}
	direct := &countOutbound{}
	bridge := &gvisorBridge{vpn: vpn, direct: direct, shouldDirect: func(netip.Addr, string) bool { return true }}
	addresses := []string{"10.1.2.3:443", "127.0.0.1:443", "169.254.1.2:443", "224.0.0.1:443", "203.0.113.7:53", "[::1]:443", "[fd00::1]:443", "[fe80::1]:443", "[ff02::1]:443"}
	for _, address := range addresses {
		if _, err := bridge.dialTCP(context.Background(), netip.MustParseAddrPort(address)); err != nil {
			t.Fatal(err)
		}
		if _, err := bridge.listenUDP(context.Background(), netip.MustParseAddrPort(address)); err != nil {
			t.Fatal(err)
		}
	}
	if direct.tcp.Load() != 0 || direct.udp.Load() != 0 || vpn.tcp.Load() != int32(len(addresses)) || vpn.udp.Load() != int32(len(addresses)) {
		t.Fatalf("direct tcp=%d udp=%d, VPN tcp=%d udp=%d", direct.tcp.Load(), direct.udp.Load(), vpn.tcp.Load(), vpn.udp.Load())
	}
}

func TestPublicIPv6CanUseDirectExit(t *testing.T) {
	// with IPv6 beside the tunnel; without it the same flows take the VPN
	real := directIPv6
	defer func() { directIPv6 = real }()
	for _, has := range []bool{false, true} {
		directIPv6 = func() bool { return has }
		out, _ := selectOutbound(netip.MustParseAddrPort("[2001:4860:4860::8888]:443"), "", func(netip.Addr, string) bool { return true }, hy2Outbound{}, directOutbound{})
		if _, direct := out.(directOutbound); direct != has {
			t.Fatalf("direct IPv6 available = %v, flow direct = %v", has, direct)
		}
	}
	vpn := &countOutbound{}
	direct := &countOutbound{}
	bridge := &gvisorBridge{vpn: vpn, direct: direct, shouldDirect: func(netip.Addr, string) bool { return true }}
	target := netip.MustParseAddrPort("[2001:4860:4860::8888]:443")
	if _, err := bridge.dialTCP(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.listenUDP(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if direct.tcp.Load() != 1 || direct.udp.Load() != 1 || vpn.tcp.Load() != 0 || vpn.udp.Load() != 0 {
		t.Fatalf("public IPv6 exits: direct tcp=%d udp=%d; VPN tcp=%d udp=%d", direct.tcp.Load(), direct.udp.Load(), vpn.tcp.Load(), vpn.udp.Load())
	}
}

func TestDirectOutboundUsesLocalTCPAndUDPEchoListeners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	tcpTarget := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(tcpListener.Addr().(*net.TCPAddr).Port))
	conn, err := (directOutbound{}).DialTCP(ctx, tcpTarget)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	go func() {
		buf := make([]byte, 64)
		n, source, err := udpListener.ReadFrom(buf)
		if err == nil {
			_, _ = udpListener.WriteTo(buf[:n], source)
		}
	}()
	udpAddress := udpListener.LocalAddr().(*net.UDPAddr)
	udpTarget := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udpAddress.Port))
	flow, err := (directOutbound{}).ListenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if err := flow.WriteTo([]byte("echo"), udpTarget); err != nil {
		t.Fatal(err)
	}
	payload, _, err := flow.ReadFrom()
	if err != nil || string(payload) != "echo" {
		t.Fatalf("UDP echo = %q, %v", payload, err)
	}
}
