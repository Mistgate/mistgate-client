package trusttunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestFrameEncodingMatchesWireBytes(t *testing.T) {
	target := netip.MustParseAddrPort("203.0.113.7:443")
	got, err := encodeOutgoingFrame(0x1234, target, []byte{0xaa, 0xbb})
	if err != nil {
		t.Fatal(err)
	}
	const want = "00000027" +
		"000000000000000000000000c6120001" +
		"1234" +
		"000000000000000000000000cb007107" +
		"01bb00aabb"
	if hex.EncodeToString(got) != want {
		t.Fatalf("frame bytes = %x, want %s", got, want)
	}

	incoming, err := hex.DecodeString("00000026" +
		"000000000000000000000000cb007107" +
		"01bb" +
		"000000000000000000000000c6120001" +
		"1234aabb")
	if err != nil {
		t.Fatal(err)
	}
	body, err := readIncomingFrame(bytes.NewReader(incoming))
	if err != nil {
		t.Fatal(err)
	}
	remote, destination, payload, err := decodeIncomingBody(body)
	if err != nil || remote != netip.MustParseAddrPort("203.0.113.7:443") || destination != 0x1234 || string(payload) != "\xaa\xbb" {
		t.Fatalf("decoded frame = %v %x %x, %v", remote, destination, payload, err)
	}
}

func TestClientTCPUDPAndHalfClose(t *testing.T) { eachTransport(t, testClientTCPUDPAndHalfClose) }

func testClientTCPUDPAndHalfClose(t *testing.T, h3 bool) {
	target := startEchoListener(t)
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) {
		wantAgent := userAgentTCP
		if r.Host == "_udp2" {
			wantAgent = userAgentUDP
		} else if r.Host == "_check" {
			wantAgent = userAgentCheck
		}
		if r.UserAgent() != wantAgent {
			t.Errorf("User-Agent for %s = %q, want %q", r.Host, r.UserAgent(), wantAgent)
		}
		if !checkAuth(w, r) {
			return
		}
		switch r.Host {
		case "_check":
			w.WriteHeader(http.StatusOK)
		case "_udp2":
			serveUDPEcho(w, r)
		default:
			serveTCPTunnel(w, r, target.Addr().String())
		}
	})
	client := stub.dial(t, "user", "password")
	defer client.Close()
	if want := map[bool]string{false: "h2", true: "h3"}[h3]; client.Protocol() != want {
		t.Fatalf("Protocol = %q, want %q", client.Protocol(), want)
	}
	if err := client.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(context.Background(), target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	const size = 3 << 20
	sent := make([]byte, size)
	for i := range sent {
		sent[i] = byte(i * 31)
	}
	received := make([]byte, size)
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(sent)
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		writeDone <- err
	}()
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write echo: %v", err)
	}
	if string(received) != string(sent) {
		t.Fatal("TCP echo did not match")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after half-close = %v, want EOF", err)
	}
	_ = conn.Close()

	first, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer second.Close()
	firstTarget := netip.MustParseAddrPort("203.0.113.53:53")
	secondTarget := netip.MustParseAddrPort("203.0.113.54:53")
	ipv6Target := netip.MustParseAddrPort("[2001:db8::53]:53")
	if err := first.WriteTo([]byte("first"), firstTarget); err != nil {
		t.Fatal(err)
	}
	if err := second.WriteTo([]byte("second"), secondTarget); err != nil {
		t.Fatal(err)
	}
	if err := first.WriteTo([]byte("six"), ipv6Target); err != nil {
		t.Fatal(err)
	}
	readUDP := func(flow PacketFlow, want string, target netip.AddrPort) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := make(chan udpReadResult, 1)
		go func() {
			payload, source, err := flow.ReadFrom()
			result <- udpReadResult{payload: payload, source: source, err: err}
		}()
		select {
		case got := <-result:
			if got.err != nil || string(got.payload) != want || got.source != target {
				t.Fatalf("UDP reply = %q, %v", got.payload, got.err)
			}
		case <-ctx.Done():
			t.Fatal("UDP reply timed out")
		}
	}
	readUDP(first, "first", firstTarget)
	readUDP(second, "second", secondTarget)
	readUDP(first, "six", ipv6Target)
	select {
	case got := <-udpIPv6Notice:
		if !got {
			t.Fatal("IPv6 destination was not encoded as IPv6")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint did not receive IPv6 destination")
	}
}

func TestClientAuthenticationClosesSession(t *testing.T) {
	eachTransport(t, testClientAuthenticationClosesSession)
}

func testClientAuthenticationClosesSession(t *testing.T, h3 bool) {
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) {
		checkAuth(w, r)
	})
	client := stub.dial(t, "wrong", "password")
	_, err := client.DialTCP(context.Background(), "example.test:443")
	if err != ErrAuth {
		t.Fatalf("DialTCP error = %v, want ErrAuth", err)
	}
	select {
	case <-client.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not close after 407")
	}
	if client.Err() != ErrAuth {
		t.Fatalf("client error = %v", client.Err())
	}
	_ = client.Close()
}

func TestClientOtherStatusCarriesOnlyStatus(t *testing.T) {
	eachTransport(t, testClientOtherStatusCarriesOnlyStatus)
}

func testClientOtherStatusCarriesOnlyStatus(t *testing.T, h3 bool) {
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	client := stub.dial(t, "user", "password")
	defer client.Close()
	_, err := client.DialTCP(context.Background(), "example.test:443")
	var status StatusError
	if !errors.As(err, &status) || status.Code != http.StatusNotFound || err.Error() != "TrustTunnel endpoint returned HTTP status 404" {
		t.Fatalf("status error = %v", err)
	}
}

func TestClientCheckStatusIsARefusal(t *testing.T) { eachTransport(t, testClientCheckStatusIsARefusal) }

func testClientCheckStatusIsARefusal(t *testing.T, h3 bool) {
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	client := stub.dial(t, "user", "password")
	defer client.Close()
	err := client.Check(context.Background())
	var status StatusError
	if !errors.As(err, &status) || status.Code != http.StatusNotFound {
		t.Fatalf("Check error = %v, want status 404 refusal", err)
	}
}

func TestClientCertificatePinChecksOnlyLeafHash(t *testing.T) {
	eachTransport(t, testClientCertificatePinChecksOnlyLeafHash)
}

func testClientCertificatePinChecksOnlyLeafHash(t *testing.T, h3 bool) {
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	config := stub.config()
	config.Host, config.SNI = "relay.example.test", "relay.example.test"
	config.Certs = nil
	config.PinSHA256 = sha256.Sum256(stub.der)
	config.HasPin = true
	client, err := stub.open(config)
	if err != nil {
		t.Fatalf("matching pin was rejected: %v", err)
	}
	_ = client.Close()

	config.PinSHA256[0] ^= 0xff
	if _, err := stub.open(config); err != ErrCertificate {
		t.Fatalf("wrong pin error = %v, want ErrCertificate", err)
	}
}

func TestClientCertificateAndALPN(t *testing.T) { eachTransport(t, testClientCertificateAndALPN) }

func testClientCertificateAndALPN(t *testing.T, h3 bool) {
	stub := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	wrong := newTransportEndpoint(t, h3, 0, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	config := stub.config()
	config.Certs = [][]byte{wrong.der}
	if _, err := stub.open(config); err != ErrCertificate {
		t.Fatalf("wrong certificate error = %v", err)
	}
	config.Insecure = true
	client, err := stub.open(config)
	if err != nil {
		t.Fatalf("insecure TLS dial: %v", err)
	}
	_ = client.Close()

	if h3 {
		other := startQUICStub(t, "not-h3")
		if _, err := dialH3(context.Background(), other.config()); err != ErrALPN {
			t.Fatalf("a QUIC server that does not speak h3: error = %v", err)
		}
		return
	}
	h1 := newEndpoint(t, false, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if _, err := Dial(context.Background(), h1.config()); err != ErrALPN {
		t.Fatalf("HTTP/1.1 only error = %v", err)
	}
}

// eachTransport runs a test of the session's behaviour on HTTP/2 and on HTTP/3: the streams, the framing and the errors
// must be the same.
func eachTransport(t *testing.T, run func(t *testing.T, h3 bool)) {
	t.Run("h2", func(t *testing.T) { run(t, false) })
	t.Run("h3", func(t *testing.T) { run(t, true) })
}

// endpointStub is a server on loopback: HTTP/2 over TCP (server) or HTTP/3 over UDP (h3).
type endpointStub struct {
	server *httptestServer
	h3     *h3TestServer
	der    []byte
}

// newTransportEndpoint is a stub on the transport under test. limit is the stub's stream limit per connection, 0 for the
// default.
func newTransportEndpoint(t *testing.T, h3 bool, limit uint32, handler http.HandlerFunc) *endpointStub {
	t.Helper()
	der, keyPair := endpointCertificate(t)
	if !h3 {
		return &endpointStub{server: newHTTPTestServerWithMaxConcurrentStreams(t, keyPair, handler, limit), der: der}
	}
	server, err := startH3TestServer(t, keyPair, handler, "127.0.0.1:0", int64(limit))
	if err != nil {
		t.Fatal(err)
	}
	return &endpointStub{h3: server, der: der}
}

func (s *endpointStub) address() string {
	if s.h3 != nil {
		return s.h3.addr
	}
	return s.server.Addr()
}

// open is Dial or dialH3, as the stub is.
func (s *endpointStub) open(config Config) (*Client, error) {
	if s.h3 != nil {
		return dialH3(context.Background(), config)
	}
	return Dial(context.Background(), config)
}

func newEndpoint(t *testing.T, h2 bool, handler http.HandlerFunc) *endpointStub {
	t.Helper()
	der, keyPair := endpointCertificate(t)
	server := newHTTPTestServer(t, h2, keyPair, handler)
	return &endpointStub{server: server, der: der}
}

func (s *endpointStub) config() Config {
	return Config{Host: "example.test", SNI: "example.test", Addresses: []string{s.address()}, Username: "user", Password: "password", Certs: [][]byte{s.der}}
}

func (s *endpointStub) dial(t *testing.T, username, password string) *Client {
	t.Helper()
	config := s.config()
	config.Username, config.Password = username, password
	client, err := s.open(config)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	return client
}

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNzd29yZA==" {
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}
	return true
}

func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
				if half, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
			}(conn)
		}
	}()
	return listener
}

func serveTCPTunnel(w http.ResponseWriter, r *http.Request, target string) {
	conn, err := net.Dial("tcp4", target)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer conn.Close()
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	go func() {
		_, _ = io.Copy(conn, r.Body)
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	}()
	_, _ = io.Copy(flushWriter{w}, conn)
}

// flushWriter sends every write at once, so a short answer does not wait in the response buffer.
type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(payload []byte) (int, error) {
	n, err := w.ResponseWriter.Write(payload)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func serveUDPEcho(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	echoUDPFrames(w, r)
}

// echoUDPFrames answers every frame of the request body with the same datagram from the destination back to the source.
func echoUDPFrames(w http.ResponseWriter, r *http.Request) {
	for {
		body, err := readOutgoingBody(r.Body)
		if err != nil {
			return
		}
		if len(body) < 37 {
			return
		}
		source := append([]byte(nil), body[:16]...)
		sourcePort := binary.BigEndian.Uint16(body[16:18])
		destination := append([]byte(nil), body[18:34]...)
		destinationPort := binary.BigEndian.Uint16(body[34:36])
		appLen := int(body[36])
		if 37+appLen > len(body) {
			return
		}
		payload := body[37+appLen:]
		isIPv6 := destination[0] != 0 || destination[1] != 0 || destination[2] != 0 || destination[3] != 0 || destination[4] != 0 || destination[5] != 0 || destination[6] != 0 || destination[7] != 0 || destination[8] != 0 || destination[9] != 0 || destination[10] != 0 || destination[11] != 0
		if isIPv6 {
			select {
			case udpIPv6Notice <- true:
			default:
			}
		}
		frame := make([]byte, 4+36+len(payload))
		binary.BigEndian.PutUint32(frame[:4], uint32(36+len(payload)))
		copy(frame[4:20], destination)
		binary.BigEndian.PutUint16(frame[20:22], destinationPort)
		copy(frame[22:38], source)
		binary.BigEndian.PutUint16(frame[38:40], sourcePort)
		copy(frame[40:], payload)
		if _, err := w.Write(frame); err != nil {
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

var udpIPv6Notice = make(chan bool, 32)

func readOutgoingBody(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length < 37 || length > maxUDPPayload+37 {
		return nil, ErrStream
	}
	body := make([]byte, int(length))
	_, err := io.ReadFull(reader, body)
	return body, err
}

func endpointCertificate(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"example.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pemCertificate(der), pemPrivateKey(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	return der, cert
}

func pemCertificate(der []byte) []byte { return pemEncode("CERTIFICATE", der) }
func pemPrivateKey(der []byte) []byte  { return pemEncode("PRIVATE KEY", der) }

func newHTTPTestServer(t *testing.T, h2 bool, certificate tls.Certificate, handler http.HandlerFunc) *httptestServer {
	t.Helper()
	return startHTTPTestServer(t, h2, certificate, handler)
}

func newHTTPTestServerWithMaxConcurrentStreams(t *testing.T, certificate tls.Certificate, handler http.HandlerFunc, max uint32) *httptestServer {
	t.Helper()
	return startHTTPTestServerWithMaxConcurrentStreams(t, true, certificate, handler, max)
}

type httptestServer struct {
	listener net.Listener
	server   *http.Server
	addr     string
}

func (s *httptestServer) Addr() string { return s.addr }

func startHTTPTestServer(t *testing.T, h2 bool, certificate tls.Certificate, handler http.HandlerFunc) *httptestServer {
	return startHTTPTestServerWithMaxConcurrentStreams(t, h2, certificate, handler, 0)
}

func startHTTPTestServerWithMaxConcurrentStreams(t *testing.T, h2 bool, certificate tls.Certificate, handler http.HandlerFunc, max uint32) *httptestServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveHTTPTest(t, listener, h2, certificate, handler, max)
}

// serveHTTPTest serves handler on an open TCP listener, which the stub closes with the test.
func serveHTTPTest(t *testing.T, listener net.Listener, h2 bool, certificate tls.Certificate, handler http.HandlerFunc, max uint32) *httptestServer {
	t.Helper()
	server := &http.Server{Handler: handler}
	if h2 {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}
		h2Server := &http2.Server{MaxConcurrentStreams: max}
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
			"h2": func(server *http.Server, conn *tls.Conn, handler http.Handler) {
				h2Server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler, BaseConfig: server})
			},
		}
	} else {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	}
	tlsListener := tls.NewListener(listener, server.TLSConfig)
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	return &httptestServer{listener: listener, server: server, addr: listener.Addr().String()}
}

type udpReadResult struct {
	payload []byte
	source  netip.AddrPort
	err     error
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func TestShortIncomingFrameIsSkipped(t *testing.T) {
	good := append([]byte{0, 0, 0, 37}, make([]byte, 37)...)
	stream := append([]byte{0, 0, 0, 3, 1, 2, 3}, good...)
	body, err := readIncomingFrame(bytes.NewReader(stream))
	if err != nil || len(body) != 37 {
		t.Fatalf("frame after a short one: %d bytes, %v", len(body), err)
	}
}

// Only the account turned away is a refusal; a server that fails or a destination that cannot be reached is not.
func TestIsRefusalIsAboutTheAccount(t *testing.T) {
	for code, refusal := range map[int]bool{400: true, 404: true, 403: true, 407: true, 429: true, 499: true, 200: false, 302: false, 500: false, 502: false, 503: false, 504: false} {
		if got := IsRefusal(fmt.Errorf("dial: %w", StatusError{Code: code})); got != refusal {
			t.Errorf("status %d: refusal = %v, want %v", code, got, refusal)
		}
	}
	if !IsRefusal(ErrAuth) || IsRefusal(ErrStream) || IsRefusal(ErrSession) || IsRefusal(context.DeadlineExceeded) || IsRefusal(nil) {
		t.Error("among the plain errors only the authentication error is a refusal")
	}
}
