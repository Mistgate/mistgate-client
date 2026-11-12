package xray_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/xray"
	"github.com/mistgate/mistgate-client/core/internal/xray/xraytest"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	if os.Getenv("XRAY_TEST_LOG") != "" { // for looking into a failure; the library is silent otherwise
		xlog.ReplaceWithSeverityLogger(xlog.Severity_Debug)
	}
}

func start(t *testing.T, p *profile.VLESS) *xray.Instance {
	t.Helper()
	x, err := xray.Start(p, netip.MustParseAddr(p.Host), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	return x
}

func roundTripTCP(t *testing.T, x *xray.Instance, host string, port uint16, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := x.DialTCP(ctx, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	written := make(chan error, 1)
	go func() { _, err := conn.Write(payload); written <- err }()
	got := make([]byte, size)
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(conn, got); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("echo did not come back")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echoed bytes differ")
	}
}

func roundTripUDP(t *testing.T, x *xray.Instance, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := x.DialUDP(ctx, netip.MustParseAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ { // each datagram on its own
		msg := []byte("ping-" + strconv.Itoa(i))
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make(chan string, 1)
		go func() {
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)
			if err != nil {
				got <- "error: " + err.Error()
				return
			}
			got <- string(buf[:n])
		}()
		select {
		case reply := <-got:
			if reply != "echo:"+string(msg) {
				t.Fatalf("UDP reply = %q", reply)
			}
		case <-ctx.Done():
			t.Fatal("no UDP reply")
		}
	}
}

func TestRealityRawVision(t *testing.T) {
	p := xraytest.Server(t, xraytest.RealityProfile("raw", profile.VLESSFlowVision, ""), "")
	x := start(t, p)
	echo := netip.MustParseAddrPort(xraytest.TCPEcho(t))
	roundTripTCP(t, x, echo.Addr().String(), echo.Port(), 1<<20)
	if udp, ok := xraytest.UDPEcho(t, "127.0.0.1:0"); ok {
		roundTripUDP(t, x, udp) // Vision sends every UDP flow as XUDP
	}
	if udp, ok := xraytest.UDPEcho(t, "127.0.0.1:443"); ok {
		roundTripUDP(t, x, udp) // "-udp443": QUIC is not refused
	} else {
		t.Log("UDP 443 is taken here: QUIC over Vision not exercised")
	}
	if err := x.Check(context.Background(), xraytest.MaskSite(t)); err != nil {
		t.Fatalf("Check against a TLS target: %v", err)
	}
}

func TestRealityXHTTPModes(t *testing.T) {
	for _, mode := range []string{"auto", "packet-up", "stream-up"} {
		t.Run(mode, func(t *testing.T) {
			p := xraytest.Server(t, xraytest.RealityProfile("xhttp", "", mode), "")
			x := start(t, p)
			echo := netip.MustParseAddrPort(xraytest.TCPEcho(t))
			roundTripTCP(t, x, echo.Addr().String(), echo.Port(), 1<<20)
			if udp, ok := xraytest.UDPEcho(t, "127.0.0.1:0"); ok {
				roundTripUDP(t, x, udp)
			}
			if udp, ok := xraytest.UDPEcho(t, "127.0.0.1:443"); ok {
				roundTripUDP(t, x, udp)
			}
		})
	}
}

func TestRealityXHTTPWithPaddingAndHost(t *testing.T) {
	q := xraytest.RealityProfile("xhttp", "", "packet-up")
	q.XPadding, q.HTTPHost = [2]int32{200, 400}, "cdn.example"
	p := xraytest.Server(t, q, "")
	echo := netip.MustParseAddrPort(xraytest.TCPEcho(t))
	roundTripTCP(t, start(t, p), echo.Addr().String(), echo.Port(), 64<<10)
}

func TestNameIsLeftToTheServer(t *testing.T) {
	echo := xraytest.TCPEcho(t)
	p := xraytest.Server(t, xraytest.RealityProfile("raw", profile.VLESSFlowVision, ""), echo)
	// No resolver anywhere knows this name: only the server's override makes it reach the echo, so the client sent
	// the name as it was.
	roundTripTCP(t, start(t, p), "no-such-host.invalid", 4242, 4096)
}

func TestCheckClassifiesFailures(t *testing.T) {
	p := xraytest.Server(t, xraytest.RealityProfile("raw", profile.VLESSFlowVision, ""), "")
	target := xraytest.MaskSite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := start(t, p).Check(ctx, target); err != nil {
		t.Fatalf("good profile: %v", err)
	}
	wrongUser := *p
	wrongUser.UUID = "00000000-0000-4000-8000-000000000001"
	if err := start(t, &wrongUser).Check(ctx, target); !errors.Is(err, xray.ErrRejected) {
		t.Errorf("unknown user: %v", err)
	}
	wrongKey := *p
	wrongKey.PublicKey = xraytest.OtherKey()
	if err := start(t, &wrongKey).Check(ctx, target); !errors.Is(err, xray.ErrRejected) {
		t.Errorf("wrong REALITY key: %v", err)
	}
	dead := *p
	dead.Port = xraytest.Port(t)
	if err := start(t, &dead).Check(ctx, target); !errors.Is(err, xray.ErrNoAnswer) {
		t.Errorf("closed port: %v", err)
	}
}

// The library may write nothing, and its own sockets may go to the server only: no resolver, no other address.
func TestStaysQuietAndTalksToTheServerOnly(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	recording := true
	_ = internet.RegisterDialerController(func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		if recording {
			dialed = append(dialed, address)
		}
		mu.Unlock()
		return nil
	})
	echoText := xraytest.TCPEcho(t)
	echo := netip.MustParseAddrPort(echoText)
	p := xraytest.Server(t, xraytest.RealityProfile("xhttp", "", "auto"), echoText)

	// a name looked up on this machine would come through the default resolver
	var lookups atomic.Int32
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("no resolver in tests")
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	if _, _ = net.LookupHost("hook-check.invalid"); lookups.Swap(0) == 0 {
		t.Fatal("the resolver hook does not see lookups")
	}

	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout, os.Stderr = w, w
	captured := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); captured <- b }()

	mu.Lock()
	dialed = nil
	mu.Unlock()
	x, err := xray.Start(p, netip.MustParseAddr(p.Host), "")
	if err == nil {
		roundTripTCP(t, x, "some.name.test", 80, 64<<10)
		roundTripTCP(t, x, echo.Addr().String(), echo.Port(), 1024)
		wrong := *p
		wrong.UUID = "00000000-0000-4000-8000-000000000001"
		var bad *xray.Instance
		if bad, err = xray.Start(&wrong, netip.MustParseAddr(p.Host), ""); err == nil {
			_ = bad.Check(context.Background(), echo.String()) // fails on purpose: errors must stay silent too
			_ = bad.Close()
		}
		_ = x.Close()
	}
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	mu.Lock()
	recording = false
	seen := append([]string(nil), dialed...)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if out := <-captured; len(out) != 0 {
		t.Errorf("Xray wrote %d bytes to stdout/stderr: %q", len(out), out)
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("%d lookups went to the system resolver", n)
	}
	for _, address := range seen {
		// the client's socket to the server, the server's to the echo and to the site it imitates: all on loopback
		if host, _, err := net.SplitHostPort(address); err != nil || host != "127.0.0.1" {
			t.Errorf("a socket went to %q", address)
		}
	}
	if len(seen) == 0 {
		t.Error("the controller saw no socket at all")
	}
}

func TestCloseEndsItsGoroutines(t *testing.T) {
	p := xraytest.Server(t, xraytest.RealityProfile("raw", profile.VLESSFlowVision, ""), "")
	echo := netip.MustParseAddrPort(xraytest.TCPEcho(t))
	udp, haveUDP := xraytest.UDPEcho(t, "127.0.0.1:0")
	cycle := func() {
		x, err := xray.Start(p, netip.MustParseAddr(p.Host), "")
		if err != nil {
			t.Fatal(err)
		}
		roundTripTCP(t, x, echo.Addr().String(), echo.Port(), 16<<10)
		if haveUDP {
			roundTripUDP(t, x, udp)
		}
		_ = x.Close()
	}
	cycle() // globals and the server's own goroutines exist from here on
	time.Sleep(time.Second)
	base := runtime.NumGoroutine()
	for i := 0; i < 8; i++ {
		cycle()
	}
	deadline := time.Now().Add(10 * time.Second)
	n := runtime.NumGoroutine()
	for n > base+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	if n > base+4 {
		t.Errorf("goroutines: %d before, %d after 8 started and closed instances", base, n)
	}
}
