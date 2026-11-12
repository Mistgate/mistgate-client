//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/xray"
	"github.com/mistgate/mistgate-client/core/internal/xray/xraytest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// packetTun is a tun.Device the test feeds packets into.
type packetTun struct {
	in   chan []byte
	done chan struct{}
	once sync.Once
}

func newPacketTun() *packetTun {
	return &packetTun{in: make(chan []byte, 16), done: make(chan struct{})}
}

func (p *packetTun) File() *os.File { return nil }
func (p *packetTun) Read(bufs [][]byte, sizes []int, _ int) (int, error) {
	select {
	case packet := <-p.in:
		sizes[0] = copy(bufs[0], packet)
		return 1, nil
	case <-p.done:
		return 0, os.ErrClosed
	}
}
func (p *packetTun) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (p *packetTun) MTU() (int, error)                       { return 1500, nil }
func (p *packetTun) Name() (string, error)                   { return "test", nil }
func (p *packetTun) Events() <-chan tun.Event                { return nil }
func (p *packetTun) Close() error                            { p.once.Do(func() { close(p.done) }); return nil }
func (p *packetTun) BatchSize() int                          { return 1 }

// udpPacket is an IPv4 datagram from src to dst (the UDP checksum is left zero: "none" for IPv4).
func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(udp.ProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.Addr().As4()), DstAddr: tcpip.AddrFrom4(dst.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(packet[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(u.Payload(), payload)
	return packet
}

// hangingOutbound: ListenUDP waits for release, like a Hysteria2 client redialing a dead QUIC session; TCP is refused.
type hangingOutbound struct {
	entered atomic.Int32
	release chan struct{}
}

func (*hangingOutbound) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("refused")
}

func (o *hangingOutbound) ListenUDP(context.Context) (packetFlow, error) {
	o.entered.Add(1)
	<-o.release
	return nil, errors.New("gone")
}

// The packet pump must not wait for an outbound: a UDP flow whose ListenUDP hangs must not stop the next packets.
func TestSlowUDPOutboundDoesNotStopThePacketPump(t *testing.T) {
	device := newPacketTun()
	vpn := &hangingOutbound{release: make(chan struct{})}
	bridge, err := newGvisorBridge(context.Background(), device, 1500, vpn, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	defer close(vpn.release) // runs first: lets the hanging calls return so Close can finish
	target := netip.MustParseAddrPort("203.0.113.7:4000")
	for port := uint16(50000); port < 50003; port++ {
		device.in <- udpPacket(netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), port), target, []byte("x"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for vpn.entered.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 3 flows reached the outbound: the packet pump is stuck", vpn.entered.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// failingOutbound can neither dial nor listen.
type failingOutbound struct{}

func (failingOutbound) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("dead")
}
func (failingOutbound) ListenUDP(context.Context) (packetFlow, error) { return nil, errors.New("dead") }

// The tunnel check goes to the VPN's exit: whatever the bridge's stack would accept first, a dead exit means no link.
func TestBridgeProbeNeedsTheVPNToAnswer(t *testing.T) {
	var rx atomic.Uint64
	target := netip.MustParseAddrPort("1.1.1.1:443")
	dead := &gvisorBridge{vpn: countedOutbound{failingOutbound{}, &rx}}
	if _, err := dead.probe(context.Background(), []netip.AddrPort{target}, time.Second); err == nil {
		t.Fatal("a dead exit passed the check")
	}
}

// pipeOutbound dials into a net.Pipe whose other end is dropped on the floor.
type pipeOutbound struct{ failingOutbound }

func (pipeOutbound) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return a, nil
}

func TestBridgeProbeAcceptsAConnectedExit(t *testing.T) {
	var rx atomic.Uint64
	bridge := &gvisorBridge{vpn: countedOutbound{pipeOutbound{}, &rx}}
	if _, err := bridge.probe(context.Background(), []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:443")}, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeProbeTargets(t *testing.T) {
	var rx atomic.Uint64
	plain := &gvisorBridge{vpn: countedOutbound{pipeOutbound{}, &rx}}
	if got := plain.probeTargets("9.9.9.9:80"); len(got) != 1 || got[0].String() != "9.9.9.9:80" {
		t.Fatalf("plain targets = %v", got)
	}
	if got := plain.probeTargets("example.test:443"); len(got) != 0 {
		t.Fatalf("a host name cannot be dialed through the VPN: %v", got)
	}
	vless := &gvisorBridge{vpn: countedOutbound{vlessOutbound{}, &rx}}
	if got := vless.probeTargets("9.9.9.9:80"); len(got) != 2 {
		t.Fatalf("a VLESS check needs a TLS port, so the default targets stand in: %v", got)
	}
	if got := vless.probeTargets("9.9.9.9:443"); len(got) != 1 {
		t.Fatalf("VLESS targets = %v", got)
	}
}

// VLESS dials lazily, so only a handshake through the server proves the path: a stopped server must fail the check.
func TestBridgeProbeOverVLESSNeedsTheServer(t *testing.T) {
	p := vlessPaths(t)["reality+raw+vision"]
	mask := netip.MustParseAddrPort(xraytest.MaskSite(t))
	var rx atomic.Uint64
	probe := func(p2 *profile.VLESS) error {
		x, err := xray.Start(p2, netip.MustParseAddr(p2.Host), "")
		if err != nil {
			t.Fatal(err)
		}
		defer x.Close()
		bridge := &gvisorBridge{vpn: countedOutbound{vlessOutbound{x: x}, &rx}}
		_, err = bridge.probe(context.Background(), []netip.AddrPort{mask}, 5*time.Second)
		return err
	}
	if err := probe(p); err != nil {
		t.Fatalf("live server: %v", err)
	}
	dead := *p
	dead.Port = xraytest.Port(t)
	if err := probe(&dead); err == nil {
		t.Fatal("a stopped server passed the check")
	}
}

// In "selected" with programs on the VPN list a program's DNS question comes from the system's DNS service, so no
// name may go to a regional resolver in the clear; blocking still works.
func TestNameRouteSelectedWithProgramsKeepsDNSInTheTunnel(t *testing.T) {
	store, err := geo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Real{geo: store, getSettings: func() settings.Settings {
		s := settings.Defaults()
		s.RouteMode, s.RouteRegion = "selected", "ru"
		return s
	}}
	if _, _, err := store.SetRules(geo.Rules{VPN: geo.Selection{Sites: []string{"vpn.example"}}, Block: geo.Selection{Sites: []string{"ads.example"}}}); err != nil {
		t.Fatal(err)
	}
	if block, resolver := r.nameRoute("plain.example"); block || !resolver.IsValid() {
		t.Fatalf("without programs: block=%t resolver=%v; want the regional resolver", block, resolver)
	}
	if _, _, err := store.SetRules(geo.Rules{VPN: geo.Selection{Apps: []string{`c:\tools\app.exe`}}, Block: geo.Selection{Sites: []string{"ads.example"}}}); err != nil {
		t.Fatal(err)
	}
	if block, resolver := r.nameRoute("plain.example"); block || resolver.IsValid() {
		t.Fatalf("with a program on the list: block=%t resolver=%v; want the tunnel", block, resolver)
	}
	if block, _ := r.nameRoute("ads.example"); !block {
		t.Fatal("a blocked name was not blocked")
	}
}

func TestAutoRegionNeedsNoLock(t *testing.T) {
	r := &Real{}
	r.mu.Lock() // setFirewall holds this for a whole firewall transaction
	defer r.mu.Unlock()
	if got := r.routeRegion(settings.Settings{RouteRegion: "auto"}); got != "" {
		t.Fatalf("unset auto region = %q", got)
	}
	r.setAutoRegion("ru")
	if got := r.routeRegion(settings.Settings{RouteRegion: "auto"}); got != "ru" {
		t.Fatalf("auto region = %q", got)
	}
}

// idleFlow runs a udpFlow between a pipe (the app) and a recording exit; the channel closes when run returns.
func idleFlow(t *testing.T, target netip.AddrPort) (net.Conn, *scriptFlow, <-chan struct{}) {
	t.Helper()
	app, local := net.Pipe()
	remote := newScriptFlow()
	ctx, cancel := context.WithCancel(context.Background())
	flow := &udpFlow{local: local, remote: remote, target: target, ctx: ctx, cancel: cancel}
	flow.lastActivity.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() { flow.run(); close(done) }()
	t.Cleanup(func() { flow.close(); _ = app.Close(); <-done })
	return app, remote, done
}

// A silent flow ends after its idle time, a DNS one sooner; a packet postpones the end by a whole idle time.
func TestUDPFlowEndsWhenIdle(t *testing.T) {
	oldFlow, oldDNS := hy2UDPIdleTimeout, dnsUDPIdleTimeout
	hy2UDPIdleTimeout, dnsUDPIdleTimeout = 600*time.Millisecond, 100*time.Millisecond
	defer func() { hy2UDPIdleTimeout, dnsUDPIdleTimeout = oldFlow, oldDNS }()

	_, _, dnsDone := idleFlow(t, netip.MustParseAddrPort("203.0.113.7:53"))
	app, remote, done := idleFlow(t, netip.MustParseAddrPort("203.0.113.7:4000"))
	select {
	case <-dnsDone:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("a silent DNS flow did not end within its short idle time")
	}
	started := time.Now()
	time.Sleep(400 * time.Millisecond)
	if _, err := app.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	recvPacket(t, remote)
	select {
	case <-done:
		t.Fatal("a flow with traffic ended early")
	case <-time.After(400 * time.Millisecond): // past its first idle time, inside the one the packet gave
	}
	select {
	case <-done:
		if time.Since(started) < 900*time.Millisecond {
			t.Fatalf("flow ended %s after the packet; want a whole idle time", time.Since(started))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an idle flow did not end")
	}
}
