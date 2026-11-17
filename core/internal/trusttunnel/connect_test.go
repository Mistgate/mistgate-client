package trusttunnel

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// pairStub is a node: HTTP/2 on a TCP port and HTTP/3 on the UDP port of the same number, one certificate.
type pairStub struct {
	der      []byte
	addr     string
	requests atomic.Int64 // what the HTTP/2 side was asked, every CONNECT including _check
	h3       *h3TestServer
}

// statusHandler answers every request of a known account with code.
func statusHandler(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if checkAuth(w, r) {
			w.WriteHeader(code)
		}
	}
}

// newPairStub starts both sides; a nil h2 leaves the TCP port closed. What Connect remembers is cleared before and
// after the test.
func newPairStub(t *testing.T, h2, h3 http.HandlerFunc) *pairStub {
	t.Helper()
	ForgetHTTP3()
	t.Cleanup(ForgetHTTP3)
	der, certificate := endpointCertificate(t)
	s := &pairStub{der: der}
	if h2 == nil {
		server, err := startH3TestServer(t, certificate, h3, "127.0.0.1:0", 0)
		if err != nil {
			t.Fatal(err)
		}
		s.h3, s.addr = server, server.addr
		return s
	}
	counted := func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		h2(w, r)
	}
	// A port of the same number for both. Windows hands out the next free port in turn, and its excluded UDP ranges are
	// hundreds of ports long, so the port is drawn at random below the dynamic range.
	for range 100 {
		address := "127.0.0.1:" + strconv.Itoa(20000+rand.IntN(28000))
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		server, err := startH3TestServer(t, certificate, h3, address, 0)
		if err != nil {
			_ = listener.Close()
			continue
		}
		serveHTTPTest(t, listener, true, certificate, counted, 0)
		s.h3, s.addr = server, address
		return s
	}
	t.Fatal("no port is free for both TCP and UDP")
	return nil
}

func (s *pairStub) config() Config {
	return Config{
		Host: "example.test", SNI: "example.test", Addresses: []string{s.addr}, Username: "user", Password: "password",
		Certs: [][]byte{s.der}, H3: true,
	}
}

// slowTCP and slowUDP hold the start of one handshake back, so the other one finishes first on loopback every time.
func slowTCP(config *Config, delay time.Duration) {
	config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func slowUDP(config *Config, delay time.Duration) {
	config.ListenPacket = func(ctx context.Context, target netip.AddrPort) (net.PacketConn, error) {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return listenUDP(ctx, target)
	}
}

func setVar[T any](t *testing.T, variable *T, value T) {
	t.Helper()
	old := *variable
	*variable = value
	t.Cleanup(func() { *variable = old })
}

func connectWithin(t *testing.T, config Config) (*Client, error, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	client, err := Connect(ctx, config)
	if client != nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err, time.Since(start)
}

// Where QUIC is quicker, it takes the connection; HTTP/2 was not authorised, so its server saw no request; and the
// session lives on after the caller's context ends.
func TestConnectTakesHTTP3WhenItIsFirst(t *testing.T) {
	stub := newPairStub(t, statusHandler(200), statusHandler(200))
	config := stub.config()
	slowTCP(&config, 400*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	client, err := Connect(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cancel()
	if client.Protocol() != "h3" {
		t.Fatalf("Protocol = %q, want h3", client.Protocol())
	}
	time.Sleep(600 * time.Millisecond) // the HTTP/2 dial has been cancelled or has finished and been closed by now
	if got := stub.requests.Load(); got != 0 {
		t.Fatalf("the HTTP/2 server was asked %d times, want none", got)
	}
	if err := client.Check(context.Background()); err != nil {
		t.Fatalf("session after the caller's context ended: %v", err)
	}
	if !h3Recent(config.Host) {
		t.Fatal("the choice of HTTP/3 was not remembered")
	}
}

// Where UDP is cut without a word, the connection is HTTP/2 and takes as long as it would without HTTP/3.
func TestConnectUDPBlackHoleIsHTTP2(t *testing.T) {
	stub := newPairStub(t, statusHandler(200), statusHandler(200))
	_ = stub.h3.server.Close() // the port stays bound and answers nothing
	client, err, took := connectWithin(t, stub.config())
	if err != nil {
		t.Fatal(err)
	}
	if client.Protocol() != "h2" || took > time.Second {
		t.Fatalf("Protocol = %q after %v, want h2 in under a second", client.Protocol(), took)
	}
	if h3Recent("example.test") {
		t.Fatal("HTTP/3 was remembered for a connection that went over HTTP/2")
	}
}

// A QUIC _check that hangs costs h3CheckTimeout and the answer is HTTP/2's.
func TestConnectHungH3CheckFallsBackToHTTP2(t *testing.T) {
	setVar(t, &h3CheckTimeout, 400*time.Millisecond)
	stub := newPairStub(t, statusHandler(200), func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	config := stub.config()
	slowTCP(&config, 150*time.Millisecond)
	client, err, took := connectWithin(t, config)
	if err != nil {
		t.Fatal(err)
	}
	if client.Protocol() != "h2" || took < 350*time.Millisecond || took > 5*time.Second {
		t.Fatalf("Protocol = %q after %v, want h2 after about h3CheckTimeout", client.Protocol(), took)
	}
}

// HTTP/3 is never the one to turn an account away: HTTP/2's word counts.
func TestConnectRefusalComesFromHTTP2(t *testing.T) {
	stub := newPairStub(t, statusHandler(200), statusHandler(404))
	config := stub.config()
	slowTCP(&config, 150*time.Millisecond)
	client, err, _ := connectWithin(t, config)
	if err != nil || client.Protocol() != "h2" {
		t.Fatalf("h3 refused, h2 accepted: %v, %v", client, err)
	}

	both := newPairStub(t, statusHandler(404), statusHandler(404))
	config = both.config()
	slowTCP(&config, 150*time.Millisecond)
	if client, err, _ := connectWithin(t, config); client != nil || !IsRefusal(err) {
		t.Fatalf("both refused: %v, %v", client, err)
	}
	if got := both.requests.Load(); got != 1 {
		t.Fatalf("the HTTP/2 server was asked %d times, want the one _check", got)
	}
}

// A server that TCP does not reach at all is served over QUIC, which then has the last word.
func TestConnectTCPClosedUsesHTTP3(t *testing.T) {
	stub := newPairStub(t, nil, statusHandler(200))
	client, err, _ := connectWithin(t, stub.config())
	if err != nil || client.Protocol() != "h3" {
		t.Fatalf("TCP closed: %v, %v", client, err)
	}

	refusing := newPairStub(t, nil, statusHandler(404))
	if client, err, _ := connectWithin(t, refusing.config()); client != nil || !IsRefusal(err) {
		t.Fatalf("TCP closed, QUIC refused: %v, %v", client, err)
	}
}

// With nothing reachable the error is HTTP/2's.
func TestConnectNothingReachableReportsHTTP2(t *testing.T) {
	ForgetHTTP3()
	t.Cleanup(ForgetHTTP3)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	config := Config{Host: "example.test", Addresses: []string{address}, Username: "user", Password: "password", Insecure: true, H3: true}
	config.ListenPacket = func(context.Context, netip.AddrPort) (net.PacketConn, error) { return nil, errors.New("no socket") }
	client, err, _ := connectWithin(t, config)
	if client != nil || err != ErrEndpoint {
		t.Fatalf("nothing reachable: %v, %v; want ErrEndpoint", client, err)
	}
}

// After HTTP/3 was taken, the host goes over HTTP/2 alone for h3Retry, and then tries HTTP/3 again.
func TestConnectRemembersHTTP3ForTheRetryTime(t *testing.T) {
	setVar(t, &h3Retry, 1500*time.Millisecond)
	stub := newPairStub(t, statusHandler(200), statusHandler(200))
	config := stub.config()
	slowTCP(&config, 300*time.Millisecond)
	first, err, _ := connectWithin(t, config)
	if err != nil || first.Protocol() != "h3" {
		t.Fatalf("first connection: %v, %v", first, err)
	}
	// Were HTTP/3 tried, it would win again: the slow TCP dial would have lost.
	second, err, _ := connectWithin(t, config)
	if err != nil || second.Protocol() != "h2" {
		t.Fatalf("second connection: %v, %v; want h2", second, err)
	}
	if got := stub.h3.conns.Load(); got != 1 {
		t.Fatalf("the HTTP/3 server saw %d connections, want only the first", got)
	}
	time.Sleep(1600 * time.Millisecond)
	third, err, _ := connectWithin(t, config)
	if err != nil || third.Protocol() != "h3" {
		t.Fatalf("connection after h3Retry: %v, %v; want h3", third, err)
	}
}

// Without H3 the QUIC side is not touched.
func TestConnectWithoutH3IsHTTP2Only(t *testing.T) {
	stub := newPairStub(t, statusHandler(200), statusHandler(200))
	config := stub.config()
	config.H3 = false
	config.ListenPacket = func(context.Context, netip.AddrPort) (net.PacketConn, error) {
		t.Error("a UDP socket was asked for without H3")
		return nil, errors.New("unexpected")
	}
	client, err, _ := connectWithin(t, config)
	if err != nil || client.Protocol() != "h2" {
		t.Fatalf("H3 off: %v, %v", client, err)
	}
	if got := stub.h3.conns.Load(); got != 0 {
		t.Fatalf("the HTTP/3 server saw %d connections, want none", got)
	}
}
