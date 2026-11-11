//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// scriptFlow is a packetFlow the test drives: it records what is written and hands out what the test queues.
type scriptFlow struct {
	sent    chan []byte
	targets chan netip.AddrPort
	recv    chan scriptPacket
	closed  chan struct{}
	once    sync.Once
	fail    atomic.Bool // WriteTo fails
}

type scriptPacket struct {
	payload []byte
	source  netip.AddrPort
}

func newScriptFlow() *scriptFlow {
	return &scriptFlow{sent: make(chan []byte, 8), targets: make(chan netip.AddrPort, 8), recv: make(chan scriptPacket, 8), closed: make(chan struct{})}
}

func (f *scriptFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	if f.fail.Load() {
		return errors.New("blocked")
	}
	f.sent <- append([]byte(nil), payload...)
	f.targets <- target
	return nil
}

func (f *scriptFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	select {
	case p := <-f.recv:
		return p.payload, p.source, nil
	case <-f.closed:
		return nil, netip.AddrPort{}, net.ErrClosed
	}
}

func (f *scriptFlow) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

var (
	testResolver = netip.MustParseAddrPort("77.88.8.8:53")
	testTarget   = netip.MustParseAddrPort("1.1.1.1:53")
)

type dnsRig struct {
	flow   *udpFlow
	app    net.Conn
	vpn    *scriptFlow
	direct *scriptFlow
	out    *countOutbound
	asked  atomic.Int32
}

// newDNSRig runs a udpFlow to 1.1.1.1:53 between a pipe (the app) and two fake exits. names gets every name asked.
func newDNSRig(t *testing.T, names func(string) (bool, netip.AddrPort)) *dnsRig {
	t.Helper()
	rig := &dnsRig{vpn: newScriptFlow(), direct: newScriptFlow()}
	rig.out = &countOutbound{flow: rig.direct}
	app, local := net.Pipe()
	rig.app = app
	ctx, cancel := context.WithCancel(context.Background())
	rig.flow = &udpFlow{
		local: local, remote: rig.vpn, target: testTarget, ctx: ctx, cancel: cancel, dns: &dnsMemory{},
		names: func(name string) (bool, netip.AddrPort) {
			rig.asked.Add(1)
			return names(name)
		},
		direct: rig.out, down: new(atomic.Int64),
	}
	rig.flow.lastActivity.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() { rig.flow.run(); close(done) }()
	t.Cleanup(func() {
		rig.flow.close()
		_ = app.Close()
		<-done
	})
	return rig
}

func (r *dnsRig) ask(t *testing.T, packet []byte) {
	t.Helper()
	_ = r.app.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.app.Write(packet); err != nil {
		t.Fatal(err)
	}
}

func (r *dnsRig) heard(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	_ = r.app.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := r.app.Read(buf)
	if err != nil {
		t.Fatalf("the app heard nothing: %v", err)
	}
	return buf[:n]
}

func (r *dnsRig) silent(t *testing.T) {
	t.Helper()
	buf := make([]byte, 4096)
	_ = r.app.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, err := r.app.Read(buf); err == nil {
		t.Fatalf("the app heard %d bytes; want silence", n)
	}
}

func recvPacket(t *testing.T, f *scriptFlow) ([]byte, netip.AddrPort) {
	t.Helper()
	select {
	case p := <-f.sent:
		return p, <-f.targets
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was sent")
		return nil, netip.AddrPort{}
	}
}

func nothingSent(t *testing.T, f *scriptFlow) {
	t.Helper()
	select {
	case p := <-f.sent:
		t.Fatalf("an unexpected packet of %d bytes", len(p))
	case <-time.After(100 * time.Millisecond):
	}
}

// replyFor is the answer to query: the given id, the same question, one A record.
func replyFor(t *testing.T, query []byte, id uint16, address [4]byte) []byte {
	t.Helper()
	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		t.Fatal(err)
	}
	q, err := parser.Question()
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true})
	_ = builder.StartQuestions()
	_ = builder.Question(q)
	_ = builder.StartAnswers()
	if err := builder.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: address}); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestUDPFlowAnswersBlockedNamesItself(t *testing.T) {
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return name == "ads.example", testResolver })
	query := dnsQuery(t, 0x0102, "ads.example", dnsmessage.TypeAAAA, dnsmessage.ClassINET)
	rig.ask(t, query)
	var parser dnsmessage.Parser
	header, err := parser.Start(rig.heard(t))
	if err != nil || header.ID != 0x0102 || !header.Response || header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("answer header = %+v, %v", header, err)
	}
	nothingSent(t, rig.vpn)
	nothingSent(t, rig.direct)
	if rig.out.udp.Load() != 0 {
		t.Fatal("a blocked name opened a direct flow")
	}
}

func TestUDPFlowSendsDirectNamesToTheRegionalResolver(t *testing.T) {
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return false, testResolver })
	query := dnsQuery(t, 0x0A0B, "yandex.ru", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, query)
	got, target := recvPacket(t, rig.direct)
	if string(got) != string(query) || target != testResolver {
		t.Fatalf("direct write = %d bytes to %v", len(got), target)
	}
	nothingSent(t, rig.vpn)

	// not the id, not the question, not the resolver: none of these is the answer
	other := dnsQuery(t, 0x0A0B, "other.example", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.direct.recv <- scriptPacket{replyFor(t, query, 0x0A0C, [4]byte{5, 255, 255, 5}), testResolver}
	rig.direct.recv <- scriptPacket{replyFor(t, other, 0x0A0B, [4]byte{5, 255, 255, 5}), testResolver}
	rig.direct.recv <- scriptPacket{replyFor(t, query, 0x0A0B, [4]byte{5, 255, 255, 5}), netip.MustParseAddrPort("203.0.113.9:53")}
	rig.direct.recv <- scriptPacket{[]byte{1}, testResolver}
	rig.silent(t)

	answer := replyFor(t, query, 0x0A0B, [4]byte{5, 255, 255, 5})
	rig.direct.recv <- scriptPacket{answer, testResolver}
	if string(rig.heard(t)) != string(answer) {
		t.Fatal("the app got another answer")
	}
	if name := rig.flow.dns.lookup(netip.MustParseAddr("5.255.255.5")); name != "yandex.ru" {
		t.Fatalf("the address was remembered as %q", name)
	}
	// the same answer again is a late duplicate
	rig.direct.recv <- scriptPacket{answer, testResolver}
	rig.silent(t)
	nothingSent(t, rig.vpn)
}

func TestUDPFlowFallsBackToTheVPNAndPausesTheRegionalResolver(t *testing.T) {
	oldWait := dnsDirectWait
	dnsDirectWait = 60 * time.Millisecond
	t.Cleanup(func() { dnsDirectWait = oldWait })
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return false, testResolver })

	query := dnsQuery(t, 1, "slow.ru", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, query)
	if got, _ := recvPacket(t, rig.direct); string(got) != string(query) {
		t.Fatal("the question did not go direct first")
	}
	got, target := recvPacket(t, rig.vpn)
	if string(got) != string(query) || target != testTarget {
		t.Fatalf("fallback = %d bytes to %v; want the same question to the app's resolver", len(got), target)
	}
	// the resolver answers too late: the app already has its answer from the VPN
	rig.direct.recv <- scriptPacket{replyFor(t, query, 1, [4]byte{5, 255, 255, 5}), testResolver}
	rig.silent(t)

	// it is resting now: the next question does not wait for it
	next := dnsQuery(t, 2, "next.ru", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, next)
	if got, _ := recvPacket(t, rig.vpn); string(got) != string(next) {
		t.Fatal("the next question did not go through the VPN")
	}
	nothingSent(t, rig.direct)

	// and when the rest is over it is tried again
	rig.flow.down.Store(0)
	again := dnsQuery(t, 3, "again.ru", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, again)
	if got, _ := recvPacket(t, rig.direct); string(got) != string(again) {
		t.Fatal("the resolver was not tried again")
	}
}

func TestUDPFlowSendFailureGoesStraightToTheVPN(t *testing.T) {
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return false, testResolver })
	rig.direct.fail.Store(true)
	query := dnsQuery(t, 9, "blocked-network.ru", dnsmessage.TypeA, dnsmessage.ClassINET)
	rig.ask(t, query)
	if got, target := recvPacket(t, rig.vpn); string(got) != string(query) || target != testTarget {
		t.Fatalf("VPN write = %d bytes to %v", len(got), target)
	}
	if rig.flow.down.Load() <= time.Now().UnixNano() {
		t.Fatal("a failed direct send did not pause the regional resolver")
	}
}

func TestUDPFlowLeavesOtherPacketsAlone(t *testing.T) {
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return true, testResolver })
	for i, packet := range [][]byte{
		dnsQuery(t, 1, "a.example", dnsmessage.TypeTXT, dnsmessage.ClassINET), // a type this code does not take
		dnsQuery(t, 2, "a.example", dnsmessage.TypeA, dnsmessage.ClassCHAOS),
		{0x12, 0x34, 0x01}, // junk
	} {
		rig.ask(t, packet)
		if got, target := recvPacket(t, rig.vpn); string(got) != string(packet) || target != testTarget {
			t.Fatalf("packet %d: VPN write = %d bytes to %v", i, len(got), target)
		}
	}
	if rig.asked.Load() != 0 {
		t.Fatalf("names was asked %d times about packets that are not questions", rig.asked.Load())
	}
	nothingSent(t, rig.direct)
}

func TestUDPFlowWithoutRegionalResolverUsesTheVPN(t *testing.T) {
	rig := newDNSRig(t, func(name string) (bool, netip.AddrPort) { return false, netip.AddrPort{} })
	query := dnsQuery(t, 5, "nobody.example", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
	rig.ask(t, query)
	if got, target := recvPacket(t, rig.vpn); string(got) != string(query) || target != testTarget {
		t.Fatalf("VPN write = %d bytes to %v", len(got), target)
	}
	if rig.out.udp.Load() != 0 {
		t.Fatal("a direct flow was opened without a resolver")
	}
}
