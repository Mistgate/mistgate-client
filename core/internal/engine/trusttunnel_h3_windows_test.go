//go:build windows

package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	ttclient "github.com/mistgate/mistgate-client/core/internal/trusttunnel"
)

// ttDualStub is a TrustTunnel endpoint that echoes every CONNECT over HTTP/2 on a TCP port and over HTTP/3 on the UDP
// port of the same number, with one certificate. conns counts the QUIC connections it accepted.
func ttDualStub(t *testing.T) (endpoint netip.AddrPort, h3 *http3.Server, conns *atomic.Int64) {
	t.Helper()
	var refuse atomic.Int32
	// A port of the same number for both. Windows hands out the next free port in turn and its excluded UDP ranges are hundreds
	// of ports long, so the port is drawn at random below the dynamic range.
	for range 100 {
		address := "127.0.0.1:" + strconv.Itoa(20000+rand.IntN(28000))
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		packetConn, err := net.ListenPacket("udp4", address)
		if err != nil {
			_ = listener.Close()
			continue
		}
		server := httptest.NewUnstartedServer(ttEchoHandler(&refuse))
		_ = server.Listener.Close()
		server.Listener = listener
		server.EnableHTTP2 = true
		server.StartTLS()
		conns = new(atomic.Int64)
		h3 = &http3.Server{
			Handler:   ttEchoHandler(&refuse),
			TLSConfig: &tls.Config{Certificates: server.TLS.Certificates, MinVersion: tls.VersionTLS13},
			ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
				conns.Add(1)
				return ctx
			},
		}
		go func() { _ = h3.Serve(packetConn) }()
		t.Cleanup(func() {
			_ = h3.Close()
			_ = packetConn.Close()
			server.Close()
		})
		return netip.MustParseAddrPort(server.Listener.Addr().String()), h3, conns
	}
	t.Fatal("no port is free for both TCP and UDP")
	return
}

// A tunnel on HTTP/3 whose QUIC connection is closed by the server comes back on HTTP/2 at once and stays there: the host
// just had HTTP/3, so the redial does not try it again, and the traffic goes on.
func TestTTHTTP3SessionLossFallsBackToHTTP2(t *testing.T) {
	endpoint, h3, conns := ttDualStub(t)
	config := ttclient.Config{
		// The memory of Connect is per host and lives for the process: this test has a host of its own.
		Host: fmt.Sprintf("h3-fallback-%d.example.test", time.Now().UnixNano()), Addresses: []string{endpoint.String()},
		Username: "user", Password: "password", Insecure: true, H3: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			select { // the TCP handshake starts late, so on loopback QUIC is first
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	out := ttOutboundWith(t, config)
	if got := out.pool.Primary().Protocol(); got != "h3" {
		t.Fatalf("first connection = %s, want h3", got)
	}
	if err := ttEchoOnce(out); err != nil {
		t.Fatalf("echo over HTTP/3: %v", err)
	}

	go func() { _ = h3.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for out.pool.Primary().Protocol() != "h2" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := out.pool.Primary().Protocol(); got != "h2" {
		t.Fatalf("primary connection 5 s after the QUIC close = %s, want h2", got)
	}
	if err := ttEchoOnce(out); err != nil {
		t.Fatalf("echo over HTTP/2 after the fall back: %v", err)
	}
	if out.isFatal() {
		t.Fatal("losing HTTP/3 ended the tunnel")
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("the stub accepted %d QUIC connections, want only the first", got)
	}
}
