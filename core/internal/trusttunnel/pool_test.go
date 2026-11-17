package trusttunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPoolExpandsAndReapsIdleExtras(t *testing.T) {
	der, certificate := endpointCertificate(t)
	server := newHTTPTestServerWithMaxConcurrentStreams(t, certificate, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		if r.Host == "_check" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}, 4)
	config := Config{
		Host: "example.test", SNI: "example.test", Addresses: []string{server.Addr()},
		Username: "user", Password: "password", Certs: [][]byte{der},
	}
	primary, err := Dial(context.Background(), config)
	if err != nil {
		t.Fatalf("primary dial failed: %v", err)
	}
	if err := primary.Check(context.Background()); err != nil {
		_ = primary.Close()
		t.Fatalf("primary check failed: %v", err)
	}
	_, limit := primary.Load()
	if limit != 4 {
		_ = primary.Close()
		t.Fatalf("server stream limit = %d, want 4", limit)
	}
	pool, err := NewPool(context.Background(), primary, config, 200*time.Millisecond)
	if err != nil {
		_ = primary.Close()
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const streamCount = 20
	conns := make([]net.Conn, streamCount)
	errs := make(chan error, streamCount)
	var group sync.WaitGroup
	for index := range conns {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			conn, err := pool.DialTCP(ctx, "example.test:443")
			if err == nil {
				conns[index] = conn
			}
			errs <- err
		}(index)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("opening concurrent stream: %v", err)
		}
	}
	if count := pool.ConnectionCount(); count < 2 || count > maxPoolConnections {
		t.Fatalf("pool connection count = %d, want 2 through %d", count, maxPoolConnections)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for pool.ConnectionCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if count := pool.ConnectionCount(); count != 1 {
		t.Fatalf("idle extras remained in the pool: %d connections", count)
	}

	// The device-wide stream cap: with every slot taken a dial waits, and goes through once one is given back.
	if len(pool.slots) != 0 {
		t.Fatalf("closed streams still hold %d slots", len(pool.slots))
	}
	for range maxStreams {
		pool.slots <- struct{}{}
	}
	short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	if _, err := pool.DialTCP(short, "example.test:443"); err != context.DeadlineExceeded {
		t.Fatalf("dial past the stream cap = %v, want a wait until the deadline", err)
	}
	stop()
	<-pool.slots
	conn, err := pool.DialTCP(ctx, "example.test:443")
	if err != nil {
		t.Fatalf("dial after a slot was freed: %v", err)
	}
	_ = conn.Close()
	if len(pool.slots) != maxStreams-1 {
		t.Fatalf("slots after close = %d, want %d", len(pool.slots), maxStreams-1)
	}
}

func TestUDPFramePayloadLimit(t *testing.T) {
	target := netip.MustParseAddrPort("203.0.113.7:443")
	frame, err := encodeOutgoingFrame(1234, target, make([]byte, maxUDPPayload))
	if err != nil {
		t.Fatalf("maximum UDP payload was rejected: %v", err)
	}
	if got := binary.BigEndian.Uint32(frame[:4]); got != maxUDPPayload+37 {
		t.Fatalf("outgoing frame length = %d, want %d", got, maxUDPPayload+37)
	}
	if _, err := encodeOutgoingFrame(1234, target, make([]byte, maxUDPPayload+1)); err == nil {
		t.Fatal("accepted a UDP payload above the server limit")
	}
}

// poolOn builds a pool whose first connection is on server.
func poolOn(t *testing.T, server *httptestServer, der []byte) *Pool {
	t.Helper()
	config := Config{Host: "example.test", SNI: "example.test", Addresses: []string{server.Addr()}, Username: "user", Password: "password", Certs: [][]byte{der}}
	primary, err := Dial(context.Background(), config)
	if err != nil {
		t.Fatalf("primary dial failed: %v", err)
	}
	if err := primary.Check(context.Background()); err != nil {
		_ = primary.Close()
		t.Fatalf("primary check failed: %v", err)
	}
	pool, err := NewPool(context.Background(), primary, config, 0)
	if err != nil {
		_ = primary.Close()
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// echoPool is a pool on a stub that tunnels every CONNECT to a local echo listener; limit is the stub's stream limit.
func echoPool(t *testing.T, limit uint32) (*Pool, string) {
	t.Helper()
	target := startEchoListener(t)
	der, certificate := endpointCertificate(t)
	server := newHTTPTestServerWithMaxConcurrentStreams(t, certificate, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		if r.Host == "_check" {
			w.WriteHeader(http.StatusOK)
			return
		}
		serveTCPTunnel(w, r, target.Addr().String())
	}, limit)
	return poolOn(t, server, der), target.Addr().String()
}

// With every place taken a dial waits only so long, and the service's own dials do not wait at all.
func TestPoolStreamCapWaitIsBoundedAndServiceDialsSkipIt(t *testing.T) {
	old := slotWait
	slotWait = 150 * time.Millisecond
	t.Cleanup(func() { slotWait = old })
	pool, target := echoPool(t, 0)
	for range maxStreams {
		pool.slots <- struct{}{}
	}
	done := make(chan error, 1)
	go func() {
		conn, err := pool.DialTCP(context.Background(), target)
		if err == nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrStreamCap) {
			t.Fatalf("dial past the cap with no deadline = %v, want ErrStreamCap", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a dial past the cap waits for ever")
	}
	conn, err := pool.DialTCP(ServiceDial(context.Background()), target)
	if err != nil {
		t.Fatalf("service dial with every place taken: %v", err)
	}
	if err := echoRound(conn, "check"); err != nil {
		t.Fatalf("service stream: %v", err)
	}
	_ = conn.Close()
	if len(pool.slots) != maxStreams {
		t.Fatalf("places taken = %d after a service dial closed, want %d", len(pool.slots), maxStreams)
	}
}

// An extra connection that cannot be opened is no reason to fail a stream that a live connection can carry.
func TestPoolFallsBackWhenAnExtraConnectionFails(t *testing.T) {
	der, certificate := endpointCertificate(t)
	var mu sync.Mutex
	var first string
	var refusedChecks int
	server := newHTTPTestServerWithMaxConcurrentStreams(t, certificate, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		mu.Lock()
		if first == "" {
			first = r.RemoteAddr
		}
		onFirst := r.RemoteAddr == first
		if r.Host == "_check" && !onFirst {
			refusedChecks++
		}
		mu.Unlock()
		if r.Host == "_check" && !onFirst {
			w.WriteHeader(http.StatusNotFound) // the site, as at the account's connection limit
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if r.Host != "_check" {
			<-r.Context().Done()
		}
	}, 4) // the first connection keeps primaryReserve of the 4 back: one stream fits, the next wants an extra connection
	pool := poolOn(t, server, der)
	for i := range 3 {
		conn, err := pool.DialTCP(context.Background(), "example.test:443")
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		defer conn.Close()
	}
	if count := pool.ConnectionCount(); count != 1 {
		t.Fatalf("connections = %d, want only the first", count)
	}
	mu.Lock()
	defer mu.Unlock()
	if refusedChecks != 1 {
		t.Fatalf("extra connections tried = %d, want one (the failed dial is not repeated for every stream)", refusedChecks)
	}
}
