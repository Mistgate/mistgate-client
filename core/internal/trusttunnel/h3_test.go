package trusttunnel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// h3TestServer serves handler over HTTP/3 on a UDP port of loopback, with the library the node is built on.
type h3TestServer struct {
	server *http3.Server
	conn   net.PacketConn
	addr   string
	conns  atomic.Int64 // QUIC connections accepted
}

// startH3TestServer listens on address; streams is the stream limit of a connection, 0 for the default. It returns the
// listen error, so a caller that needs the TCP port's twin can try another.
func startH3TestServer(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc, address string, streams int64) (*h3TestServer, error) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", address)
	if err != nil {
		return nil, err
	}
	s := &h3TestServer{conn: conn, addr: conn.LocalAddr().String()}
	s.server = &http3.Server{
		Handler:    handler,
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		QUICConfig: &quic.Config{MaxIncomingStreams: streams},
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			s.conns.Add(1)
			return ctx
		},
	}
	go func() { _ = s.server.Serve(conn) }()
	t.Cleanup(func() {
		_ = s.server.Close()
		_ = conn.Close()
	})
	return s, nil
}

// quicStub is a QUIC server that answers no HTTP: it speaks the one ALPN protocol it is given.
type quicStub struct {
	addr string
	der  []byte
}

func startQUICStub(t *testing.T, alpn string) *quicStub {
	t.Helper()
	der, certificate := endpointCertificate(t)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.Listen(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}, &quic.Config{})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	go func() {
		for {
			accepted, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			_ = accepted.CloseWithError(0, "")
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		_ = conn.Close()
	})
	return &quicStub{addr: conn.LocalAddr().String(), der: der}
}

func (s *quicStub) config() Config {
	return Config{Host: "example.test", SNI: "example.test", Addresses: []string{s.addr}, Username: "user", Password: "password", Certs: [][]byte{s.der}}
}

// A server that closes the QUIC connection ends the session at once, and that is no refusal of the account.
func TestH3ServerCloseEndsTheSession(t *testing.T) {
	stub := newTransportEndpoint(t, true, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	client := stub.dial(t, "user", "password")
	defer client.Close()
	if err := client.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() { _ = stub.h3.server.Close() }()
	select {
	case <-client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close after the server closed the connection")
	}
	if client.Err() != ErrSession || IsRefusal(client.Err()) {
		t.Fatalf("client error = %v, want ErrSession and no refusal", client.Err())
	}
	if _, err := client.DialTCP(context.Background(), "example.test:443"); err != ErrSession {
		t.Fatalf("DialTCP on a closed session = %v, want ErrSession", err)
	}
}

// Closing the client ends the connection on the server's side too, and the socket under it is closed.
func TestH3ClientCloseReleasesTheSocket(t *testing.T) {
	stub := newTransportEndpoint(t, true, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	config := stub.config()
	var socket *trackedPacketConn
	var target netip.AddrPort
	config.ListenPacket = func(_ context.Context, to netip.AddrPort) (net.PacketConn, error) {
		udp, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, err
		}
		target, socket = to, &trackedPacketConn{UDPConn: udp}
		return socket, nil
	}
	client, err := stub.open(config)
	if err != nil {
		t.Fatal(err)
	}
	if target != netip.MustParseAddrPort(stub.h3.addr) {
		t.Fatalf("the socket was asked for another endpoint than the server's")
	}
	if err := client.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if socket.closed.Load() {
		t.Fatal("the socket was closed while the session was up")
	}
	_ = client.Close()
	if !socket.closed.Load() {
		t.Fatal("the session's UDP socket was left open")
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("Done is not closed after Close")
	}

	// A socket that cannot be made is an endpoint that cannot be reached.
	config.ListenPacket = func(context.Context, netip.AddrPort) (net.PacketConn, error) { return nil, net.ErrClosed }
	if _, err := stub.open(config); err != ErrEndpoint {
		t.Fatalf("dial without a socket = %v, want ErrEndpoint", err)
	}
}

type trackedPacketConn struct {
	*net.UDPConn
	closed atomic.Bool
}

func (c *trackedPacketConn) Close() error {
	c.closed.Store(true)
	return c.UDPConn.Close()
}

// One QUIC connection carries all the pool's streams: the second connection HTTP/2 needs is never opened.
func TestH3PoolKeepsOneConnection(t *testing.T) {
	stub := newTransportEndpoint(t, true, 0, func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if r.Host != "_check" {
			<-r.Context().Done()
		}
	})
	pool := poolOn(t, stub)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conns := make([]net.Conn, maxStreams)
	errs := make(chan error, maxStreams)
	var group sync.WaitGroup
	for index := range conns {
		group.Add(1)
		go func() {
			defer group.Done()
			conn, err := pool.DialTCP(ctx, "example.test:443")
			conns[index] = conn
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("opening a stream of %d: %v", maxStreams, err)
		}
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	if count := pool.ConnectionCount(); count != 1 {
		t.Fatalf("pool connections = %d, want 1", count)
	}
	if accepted := stub.h3.conns.Load(); accepted != 1 {
		t.Fatalf("the server accepted %d QUIC connections, want 1", accepted)
	}
}
