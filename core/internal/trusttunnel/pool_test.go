package trusttunnel

import (
	"context"
	"encoding/binary"
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
