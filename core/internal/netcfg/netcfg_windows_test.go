//go:build windows

package netcfg

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func TestChooseRoute(t *testing.T) {
	destination := netip.MustParseAddr("198.51.100.7")
	candidates := []routeCandidate{
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 1, interfaceMetric: 1},
		{prefix: netip.MustParsePrefix("198.51.100.0/25"), metric: 500, interfaceMetric: 500},
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 5, interfaceMetric: 2},
	}
	got, ok := chooseRoute(destination, candidates)
	if !ok || got.prefix.String() != "198.51.100.0/25" {
		t.Fatalf("chooseRoute() = %#v, %v; want longest prefix", got, ok)
	}

	candidates = []routeCandidate{
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 8, interfaceMetric: 4},
		{prefix: netip.MustParsePrefix("198.51.100.0/24"), metric: 5, interfaceMetric: 2},
	}
	got, ok = chooseRoute(destination, candidates)
	if !ok || got.metric != 5 || got.interfaceMetric != 2 {
		t.Fatalf("chooseRoute() = %#v, %v; want lowest combined metric", got, ok)
	}
}

func TestSessionReadsPacketsInOrderWithOffset(t *testing.T) {
	pump, fake := startFakePump(t)
	session := pump.newSession(1280)
	t.Cleanup(func() { _ = session.Close() })

	for _, want := range [][]byte{[]byte("first"), []byte("second")} {
		sendFakePacket(t, fake, want)
		buffer := bytes.Repeat([]byte{0xff}, 32)
		sizes := []int{0}
		n, err := session.Read([][]byte{buffer}, sizes, 5)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if n != 1 || sizes[0] != len(want) {
			t.Fatalf("Read() = %d packets, size %d; want 1 packet, size %d", n, sizes[0], len(want))
		}
		if !bytes.Equal(buffer[:5], bytes.Repeat([]byte{0xff}, 5)) || !bytes.Equal(buffer[5:5+len(want)], want) {
			t.Fatalf("Read() buffer = %v; want offset data %q", buffer[:5+len(want)], want)
		}
	}
}

func TestSessionCloseUnblocksRead(t *testing.T) {
	pump, _ := startFakePump(t)
	session := pump.newSession(1500)
	if mtu, err := session.MTU(); err != nil || mtu != 1500 {
		t.Fatalf("MTU() = %d, %v; want 1500", mtu, err)
	}
	if event, ok := <-session.Events(); !ok || event != tun.EventUp {
		t.Fatalf("first Events() value = %v, %v; want EventUp", event, ok)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := session.Read([][]byte{make([]byte, 16)}, make([]int, 1), 0)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		t.Fatalf("Read() returned before close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := session.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, ok := <-session.Events(); ok {
		t.Fatal("Events() remained open after Close()")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read() after Close() returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not unblock Read() promptly")
	}
	if _, err := session.Read([][]byte{make([]byte, 16)}, make([]int, 1), 0); err == nil {
		t.Fatal("Read() after Close() returned no error")
	}
	if _, err := session.Write([][]byte{[]byte("packet")}, 0); err == nil {
		t.Fatal("Write() after Close() returned no error")
	}
}

func TestPumpDropsPacketsWithoutSession(t *testing.T) {
	pump, fake := startFakePump(t)
	sendFakePacket(t, fake, []byte("drop"))
	waitFakeRead(t, fake)
	session := pump.newSession(1500)
	t.Cleanup(func() { _ = session.Close() })

	sendFakePacket(t, fake, []byte("keep"))
	buffer := make([]byte, 16)
	sizes := []int{0}
	n, err := session.Read([][]byte{buffer}, sizes, 0)
	if err != nil || n != 1 || string(buffer[:sizes[0]]) != "keep" {
		t.Fatalf("Read() = %d, %q, %v; want one packet 'keep'", n, buffer[:sizes[0]], err)
	}
}

func TestPumpHoldsPacketUntilReaderReturns(t *testing.T) {
	pump, fake := startFakePump(t)
	session := pump.newSession(1500)
	t.Cleanup(func() { _ = session.Close() })
	read := func() string {
		buffer := make([]byte, 16)
		sizes := []int{0}
		n, err := session.Read([][]byte{buffer}, sizes, 0)
		if err != nil || n != 1 {
			t.Fatalf("Read() = %d, %v; want one packet", n, err)
		}
		return string(buffer[:sizes[0]])
	}

	sendFakePacket(t, fake, []byte("first"))
	if got := read(); got != "first" {
		t.Fatalf("first Read() = %q; want first", got)
	}
	waitFakeRead(t, fake)
	sendFakePacket(t, fake, []byte("while-busy"))
	waitPacketPending(t, session)
	if got := read(); got != "while-busy" {
		t.Fatalf("second Read() = %q; want while-busy", got)
	}
}

type fakeTun struct {
	packets     chan []byte
	readStarted chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{
		packets:     make(chan []byte),
		readStarted: make(chan struct{}, 8),
		done:        make(chan struct{}),
	}
}

func startFakePump(t *testing.T) (*devicePump, *fakeTun) {
	t.Helper()
	fake := newFakeTun()
	pump := newDevicePump(fake)
	t.Cleanup(func() { _ = fake.Close() })
	waitFakeRead(t, fake)
	return pump, fake
}

func waitFakeRead(t *testing.T, fake *fakeTun) {
	t.Helper()
	select {
	case <-fake.readStarted:
	case <-time.After(time.Second):
		t.Fatal("pump did not call fake Read()")
	}
}

func sendFakePacket(t *testing.T, fake *fakeTun, packet []byte) {
	t.Helper()
	select {
	case fake.packets <- packet:
	case <-time.After(time.Second):
		t.Fatal("pump did not receive fake packet")
	}
}

func waitPacketPending(t *testing.T, session *sessionDevice) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(session.packet) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pump did not hold the packet for the next Read()")
}

func (f *fakeTun) File() *os.File { return nil }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case f.readStarted <- struct{}{}:
	default:
	}
	select {
	case <-f.done:
		return 0, errors.New("fake tun closed")
	case packet := <-f.packets:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func (f *fakeTun) MTU() (int, error) { return 1500, nil }

func (f *fakeTun) Name() (string, error) { return "fake", nil }

func (f *fakeTun) Events() <-chan tun.Event { return nil }

func (f *fakeTun) Close() error {
	f.closeOnce.Do(func() { close(f.done) })
	return nil
}

func (f *fakeTun) BatchSize() int { return 1 }

// Direct flows read the routes from a cache; a route change throws it away, and each destination still gets its own route.
func TestCachedPhysicalInterfaceIndexUsesAndDropsTheCache(t *testing.T) {
	defer InvalidateRoutes()
	routeCache.Lock()
	routeCache.rows[0] = []routeCandidate{
		{prefix: netip.MustParsePrefix("0.0.0.0/0"), index: 7},
		{prefix: netip.MustParsePrefix("203.0.113.0/24"), index: 9},
	}
	routeCache.at[0] = time.Now()
	routeCache.Unlock()
	for destination, want := range map[string]uint32{"1.1.1.1": 7, "203.0.113.5": 9} {
		if got, err := CachedPhysicalInterfaceIndexFor(netip.MustParseAddr(destination)); err != nil || got != want {
			t.Fatalf("index for %s = %d, %v; want %d", destination, got, err, want)
		}
	}
	InvalidateRoutes()
	routeCache.Lock()
	dropped := routeCache.at[0].IsZero()
	routeCache.Unlock()
	if !dropped {
		t.Fatal("InvalidateRoutes kept the cache")
	}
}

// The cached answer is the uncached one (read-only: both only read the routing table).
func TestCachedPhysicalInterfaceIndexAgreesWithTheTable(t *testing.T) {
	defer InvalidateRoutes()
	InvalidateRoutes()
	for _, text := range []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"} {
		destination := netip.MustParseAddr(text)
		want, wantErr := PhysicalInterfaceIndexFor(destination)
		got, gotErr := CachedPhysicalInterfaceIndexFor(destination)
		if (wantErr == nil) != (gotErr == nil) || got != want {
			t.Fatalf("%s: cached %d, %v; table %d, %v", text, got, gotErr, want, wantErr)
		}
	}
}
