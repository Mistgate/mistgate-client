package trusttunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	userAgentTCP      = "Windows Mistgate"
	userAgentUDP      = "Windows _udp2"
	userAgentCheck    = "Windows"
	connectTimeout    = 30 * time.Second
	checkTimeout      = 7 * time.Second
	maxUDPPayload     = 65471 - 37 // The frame header is 37 bytes when the app name is empty.
	maxUDPFrame       = maxUDPPayload + udpIncomingHeader
	udpIncomingHeader = 16 + 2 + 16 + 2
	udpQueueSize      = 32
)

var (
	ErrAuth        = errors.New("TrustTunnel authentication rejected")
	ErrCertificate = errors.New("TrustTunnel certificate rejected")
	ErrALPN        = errors.New("TrustTunnel endpoint did not negotiate HTTP/2")
	ErrConfig      = errors.New("invalid TrustTunnel configuration")
	ErrEndpoint    = errors.New("TrustTunnel endpoint connection failed")
	ErrSession     = errors.New("TrustTunnel session closed")
	ErrStream      = errors.New("TrustTunnel stream closed")
)

// Config contains the static link fields and the network hooks for one endpoint.
type Config struct {
	Host        string
	Addresses   []string
	SNI         string
	Username    string
	Password    string
	HasIPv6     bool
	Insecure    bool
	PinSHA256   [32]byte
	HasPin      bool
	Certs       [][]byte
	Name        string
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Resolve     func(ctx context.Context, host string) ([]netip.Addr, error)
}

type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      net.Conn
	transport *http2.Transport
	h2        *http2.ClientConn
	endpoint  netip.AddrPort
	config    Config

	mu       sync.Mutex
	err      error
	dead     chan struct{}
	deadOnce sync.Once

	udpMu     sync.Mutex
	udpStream *udpStream
	flowMu    sync.Mutex
	udpFlows  map[uint16]*udpFlow
	udpNext   uint32
}

// Dial opens one TLS session and requires the server to select HTTP/2.
func Dial(ctx context.Context, config Config) (*Client, error) {
	if ctx == nil || !validConfig(config) {
		return nil, ErrConfig
	}
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	addresses, err := resolveEndpoints(dialCtx, config)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrEndpoint
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: connectTimeout}
		dial = dialer.DialContext
	}
	sni := config.SNI
	if sni == "" {
		sni = config.Host
	}
	roots, err := trustRoots(config.Certs)
	if err != nil {
		return nil, ErrCertificate
	}
	var lastErr error = ErrEndpoint
	for _, endpoint := range addresses {
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		network := "tcp6"
		if endpoint.Addr().Is4() {
			network = "tcp4"
		}
		raw, err := dial(dialCtx, network, endpoint.String())
		if err != nil {
			continue
		}
		tlsConfig := &utls.Config{
			ServerName: sni, NextProtos: []string{"h2"}, MinVersion: utls.VersionTLS12, InsecureSkipVerify: true,
		}
		if config.HasPin {
			pin := config.PinSHA256
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return ErrCertificate
				}
				sum := sha256.Sum256(rawCerts[0])
				if subtle.ConstantTimeCompare(sum[:], pin[:]) != 1 {
					return ErrCertificate
				}
				return nil
			}
		} else if !config.Insecure {
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if err := verifyServer(rawCerts, roots, config.Host); err != nil {
					return ErrCertificate
				}
				return nil
			}
		}
		tlsConn := utls.UClient(raw, tlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = raw.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, ErrCertificate) {
				lastErr = ErrCertificate
			}
			continue
		}
		if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
			_ = tlsConn.Close()
			lastErr = ErrALPN
			continue
		}

		clientCtx, clientCancel := context.WithCancel(context.Background())
		// ponytail: Go's HTTP/2 settings differ from Chrome's; the 131072-byte window is cosmetic. Upgrade = write the SETTINGS frames.
		transport := &http2.Transport{ReadIdleTimeout: 20 * time.Second, PingTimeout: 10 * time.Second}
		h2Client, err := transport.NewClientConn(tlsConn)
		if err != nil {
			clientCancel()
			_ = tlsConn.Close()
			continue
		}
		client := &Client{
			ctx: clientCtx, cancel: clientCancel, conn: tlsConn, transport: transport, h2: h2Client,
			endpoint: endpoint, config: config, dead: make(chan struct{}), udpFlows: make(map[uint16]*udpFlow), udpNext: 49152,
		}
		go client.watchSession()
		return client, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, lastErr
}

func validConfig(config Config) bool {
	if !validTLSName(config.Host) || len(config.Addresses) == 0 || len(config.Addresses) > 64 ||
		!validCredential(config.Username) || strings.ContainsRune(config.Username, ':') || !validCredential(config.Password) {
		return false
	}
	if config.SNI != "" && !validTLSName(config.SNI) {
		return false
	}
	for _, address := range config.Addresses {
		host, port, err := net.SplitHostPort(address)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || portNumber == 0 || !validEndpointHost(host) {
			return false
		}
	}
	return true
}

func validCredential(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validTLSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	for i := range value {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func validEndpointHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	return validTLSName(value)
}

func validAuthority(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	return err == nil && portErr == nil && port != 0 && validEndpointHost(host)
}

func resolveEndpoints(ctx context.Context, config Config) ([]netip.AddrPort, error) {
	resolve := config.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addresses := make([]netip.AddrPort, 0, len(config.Addresses))
	for _, text := range config.Addresses {
		host, portText, err := net.SplitHostPort(text)
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			continue
		}
		if address, err := netip.ParseAddr(host); err == nil {
			addresses = append(addresses, netip.AddrPortFrom(address.Unmap(), uint16(port)))
			continue
		}
		resolved, err := resolve(ctx, host)
		if err != nil {
			continue
		}
		for _, address := range resolved {
			if address.IsValid() && address.Zone() == "" && len(addresses) < 128 {
				addresses = append(addresses, netip.AddrPortFrom(address.Unmap(), uint16(port)))
			}
		}
		if len(addresses) >= 128 {
			break
		}
	}
	if len(addresses) == 0 {
		return nil, ErrEndpoint
	}
	return addresses, nil
}

func trustRoots(certs [][]byte) (*x509.CertPool, error) {
	if len(certs) == 0 {
		return nil, nil
	}
	roots := x509.NewCertPool()
	for _, der := range certs {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrCertificate
		}
		roots.AddCert(certificate)
	}
	return roots, nil
}

func verifyServer(rawCerts [][]byte, roots *x509.CertPool, host string) error {
	if len(rawCerts) == 0 {
		return ErrCertificate
	}
	certificates := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return ErrCertificate
		}
		certificates = append(certificates, certificate)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: host})
	if err != nil {
		return ErrCertificate
	}
	return nil
}

// Endpoint is the numeric address selected from Config.Addresses.
func (c *Client) Endpoint() netip.AddrPort { return c.endpoint }

// Load reports active, reserved and queued HTTP/2 streams, plus the peer's stream limit.
func (c *Client) Load() (active, limit int) {
	state := c.h2.State()
	return state.StreamsActive + state.StreamsReserved + state.StreamsPending, int(state.MaxConcurrentStreams)
}

// Done closes when this session can no longer carry streams.
func (c *Client) Done() <-chan struct{} { return c.dead }

// Err returns the safe, content-free reason the session ended.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// DialTCP opens one HTTP/2 CONNECT stream to authority.
func (c *Client) DialTCP(ctx context.Context, authority string) (net.Conn, error) {
	if ctx == nil || authority == "" || len(authority) > 320 {
		return nil, ErrConfig
	}
	requestCtx, cancel := context.WithCancel(ctx)
	pipeReader, pipeWriter := io.Pipe()
	response, err := c.connect(requestCtx, authority, userAgentTCP, pipeReader)
	if err != nil {
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		cancel()
		return nil, err
	}
	return &streamConn{
		reader: response.body, writer: pipeWriter, cancel: cancel,
		local: tunnelAddr{value: "trusttunnel"}, remote: tunnelAddr{value: authority},
	}, nil
}

// Check opens the reserved health-check stream.
func (c *Client) Check(ctx context.Context) error {
	if ctx == nil {
		return ErrConfig
	}
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	response, err := c.connect(checkCtx, "_check", userAgentCheck, nil)
	if err != nil {
		return err
	}
	_ = response.body.Close()
	return nil
}

func (c *Client) connect(ctx context.Context, authority, userAgent string, body io.ReadCloser) (*httpResponse, error) {
	if authority != "_check" && authority != "_udp2" && !validAuthority(authority) {
		return nil, ErrConfig
	}
	select {
	case <-c.dead:
		return nil, c.Err()
	default:
	}
	request := &httpRequest{ctx: ctx, authority: authority, userAgent: userAgent, body: body,
		authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(c.config.Username+":"+c.config.Password))}
	response, err := c.roundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.status == 407 {
		_ = response.body.Close()
		c.markDead(ErrAuth)
		return nil, ErrAuth
	}
	if response.status != 200 {
		_ = response.body.Close()
		return nil, StatusError{Code: response.status, Warning: response.warning}
	}
	return response, nil
}

// The narrow request/response wrappers keep credentials and authorities out of transport errors.
type httpRequest struct {
	ctx           context.Context
	authority     string
	userAgent     string
	body          io.ReadCloser
	authorization string
}

type httpResponse struct {
	status  int
	warning int // the number that leads the server's X-Warning header, 0 without one
	body    io.ReadCloser
}

// StatusError is an answer other than 200. Warning is the server's own code for a destination it could not serve (the
// number in X-Warning: 301 unavailable, 302 timed out, 310 blocked, 300 other); the header's text and the host the
// server may name beside it are not kept.
type StatusError struct{ Code, Warning int }

func (e StatusError) Error() string {
	return "TrustTunnel endpoint returned HTTP status " + strconv.Itoa(e.Code)
}
func (e StatusError) StatusCode() int { return e.Code }

func (c *Client) roundTrip(input *httpRequest) (*httpResponse, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: input.authority},
		Host:   input.authority,
		Header: make(http.Header),
		Body:   input.body,
	}
	request = request.WithContext(input.ctx)
	request.Header.Set("Proxy-Authorization", input.authorization)
	request.Header.Set("User-Agent", input.userAgent)
	response, err := c.h2.RoundTrip(request)
	if err != nil {
		if input.ctx.Err() != nil {
			return nil, input.ctx.Err()
		}
		if !c.h2.CanTakeNewRequest() {
			c.markDead(ErrSession)
			return nil, ErrSession
		}
		return nil, ErrStream
	}
	warning := 0
	if digits, _, _ := strings.Cut(response.Header.Get("X-Warning"), " "); len(digits) == 3 {
		warning, _ = strconv.Atoi(digits)
	}
	return &httpResponse{status: response.StatusCode, warning: warning, body: response.Body}, nil
}

func (c *Client) watchSession() {
	// HTTP/2 PINGs from ReadIdleTimeout detect an idle dead peer without a separate health request.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.dead:
			return
		case <-ticker.C:
			if !c.h2.CanTakeNewRequest() {
				c.markDead(ErrSession)
				return
			}
		}
	}
}

func (c *Client) markDead(err error) {
	if err == nil {
		err = ErrSession
	}
	c.deadOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.dead)
		c.cancel()
		_ = c.h2.Close()
		_ = c.conn.Close()
	})
}

// Close ends the session and all of its streams.
func (c *Client) Close() error {
	c.markDead(ErrSession)
	return nil
}

type streamConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	closed     bool
	readTimer  *time.Timer
	writeTimer *time.Timer
	closeOnce  sync.Once
}

func (c *streamConn) Read(payload []byte) (int, error) {
	n, err := c.reader.Read(payload)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, ErrStream
	}
	return n, err
}

func (c *streamConn) Write(payload []byte) (int, error) {
	n, err := c.writer.Write(payload)
	if err != nil {
		return n, ErrStream
	}
	return n, nil
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.mu.Unlock()
		_ = c.writer.Close()
		_ = c.reader.Close()
		c.cancel()
	})
	return nil
}

func (c *streamConn) CloseWrite() error    { return c.writer.Close() }
func (c *streamConn) CloseRead() error     { return c.reader.Close() }
func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }
func (c *streamConn) SetDeadline(deadline time.Time) error {
	c.setTimer(&c.readTimer, deadline)
	c.setTimer(&c.writeTimer, deadline)
	return nil
}
func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	c.setTimer(&c.readTimer, deadline)
	return nil
}
func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	c.setTimer(&c.writeTimer, deadline)
	return nil
}

func (c *streamConn) setTimer(current **time.Timer, deadline time.Time) {
	c.mu.Lock()
	if *current != nil {
		(*current).Stop()
		*current = nil
	}
	if !deadline.IsZero() && !c.closed {
		delay := time.Until(deadline)
		if delay < 0 {
			delay = 0
		}
		*current = time.AfterFunc(delay, func() { _ = c.Close() })
	}
	c.mu.Unlock()
}

type tunnelAddr struct{ value string }

func (a tunnelAddr) Network() string { return "tcp" }
func (a tunnelAddr) String() string  { return a.value }

// PacketFlow is a source-port-scoped view of the shared UDP stream.
type PacketFlow interface {
	WriteTo([]byte, netip.AddrPort) error
	ReadFrom() ([]byte, netip.AddrPort, error)
	Close() error
}

type udpStream struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
}

func (s *udpStream) close() {
	s.once.Do(func() {
		_ = s.writer.Close()
		_ = s.reader.Close()
		s.cancel()
	})
}

type udpFlow struct {
	client *Client
	port   uint16
	queue  chan udpDatagram
	reset  chan error
	done   chan struct{}
	close  sync.Once
	stop   func() bool
}

type udpDatagram struct {
	data   []byte
	remote netip.AddrPort
}

// ListenUDP registers a flow. The shared _udp2 HTTP stream opens on its first WriteTo.
func (c *Client) ListenUDP(ctx context.Context) (PacketFlow, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return nil, ctx.Err()
		}
		return nil, ErrConfig
	}
	select {
	case <-c.dead:
		return nil, c.Err()
	default:
	}
	c.flowMu.Lock()
	defer c.flowMu.Unlock()
	var port uint16
	for i := 0; i < 16384; i++ {
		port = uint16(49152 + (c.udpNext-49152)%16384)
		c.udpNext++
		if _, exists := c.udpFlows[port]; !exists {
			break
		}
		port = 0
	}
	if port == 0 {
		return nil, ErrStream
	}
	flow := &udpFlow{client: c, port: port, queue: make(chan udpDatagram, udpQueueSize), reset: make(chan error, 1), done: make(chan struct{})}
	c.udpFlows[port] = flow
	flow.stop = context.AfterFunc(ctx, func() { _ = flow.Close() })
	return flow, nil
}

func (f *udpFlow) WriteTo(payload []byte, target netip.AddrPort) error {
	if !target.IsValid() || target.Port() == 0 || len(payload) > maxUDPPayload {
		return ErrConfig
	}
	select {
	case <-f.done:
		return net.ErrClosed
	case <-f.client.dead:
		return f.client.Err()
	default:
	}
	return f.client.writeUDP(f, payload, target)
}

func (f *udpFlow) ReadFrom() ([]byte, netip.AddrPort, error) {
	select {
	case <-f.done:
		return nil, netip.AddrPort{}, net.ErrClosed
	case <-f.client.dead:
		return nil, netip.AddrPort{}, f.client.Err()
	case err := <-f.reset:
		return nil, netip.AddrPort{}, err
	case datagram := <-f.queue:
		return datagram.data, datagram.remote, nil
	}
}

func (f *udpFlow) Close() error {
	f.close.Do(func() {
		if f.stop != nil {
			f.stop()
		}
		close(f.done)
		f.client.flowMu.Lock()
		delete(f.client.udpFlows, f.port)
		f.client.flowMu.Unlock()
	})
	return nil
}

func (c *Client) writeUDP(flow *udpFlow, payload []byte, target netip.AddrPort) error {
	frame, err := encodeOutgoingFrame(flow.port, target, payload)
	if err != nil {
		return err
	}
	c.udpMu.Lock()
	stream := c.udpStream
	if stream == nil {
		stream, err = c.openUDPStreamLocked()
		if err == nil {
			c.udpStream = stream
			go c.readUDPStream(stream)
		}
	}
	if err == nil {
		_, err = stream.writer.Write(frame)
	}
	if err != nil && stream == nil {
		c.udpMu.Unlock()
		if errors.Is(err, ErrAuth) {
			c.markDead(ErrAuth)
		}
		return err
	}
	if err != nil && stream != nil && c.udpStream == stream {
		c.udpStream = nil
		stream.close()
	}
	c.udpMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrAuth) {
			c.markDead(ErrAuth)
		} else {
			c.notifyFlows(ErrStream)
		}
		return ErrStream
	}
	return nil
}

func (c *Client) openUDPStreamLocked() (*udpStream, error) {
	requestCtx, cancel := context.WithCancel(c.ctx)
	pipeReader, pipeWriter := io.Pipe()
	response, err := c.connect(requestCtx, "_udp2", userAgentUDP, pipeReader)
	if err != nil {
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		cancel()
		return nil, err
	}
	return &udpStream{reader: response.body, writer: pipeWriter, cancel: cancel}, nil
}

func (c *Client) readUDPStream(stream *udpStream) {
	for {
		frame, err := readIncomingFrame(stream.reader)
		if err != nil {
			c.udpMu.Lock()
			if c.udpStream == stream {
				c.udpStream = nil
				stream.close()
			}
			c.udpMu.Unlock()
			c.notifyFlows(ErrStream)
			if !c.h2.CanTakeNewRequest() {
				c.markDead(ErrSession)
			}
			return
		}
		remote, destinationPort, payload, err := decodeIncomingBody(frame)
		if err != nil {
			c.udpMu.Lock()
			if c.udpStream == stream {
				c.udpStream = nil
				stream.close()
			}
			c.udpMu.Unlock()
			c.notifyFlows(ErrStream)
			return
		}
		c.flowMu.Lock()
		flow := c.udpFlows[destinationPort]
		c.flowMu.Unlock()
		if flow == nil {
			continue
		}
		select {
		case <-flow.done:
		case flow.queue <- udpDatagram{data: payload, remote: remote}:
		default:
		}
	}
}

func (c *Client) notifyFlows(err error) {
	c.flowMu.Lock()
	defer c.flowMu.Unlock()
	for _, flow := range c.udpFlows {
		select {
		case flow.reset <- err:
		default:
		}
	}
}

func encodeOutgoingFrame(sourcePort uint16, target netip.AddrPort, payload []byte) ([]byte, error) {
	if sourcePort == 0 || !target.IsValid() || target.Port() == 0 || len(payload) > maxUDPPayload {
		return nil, ErrConfig
	}
	targetAddr := target.Addr().Unmap()
	sourceAddr := netip.MustParseAddr("198.18.0.1")
	if targetAddr.Is6() {
		sourceAddr = netip.MustParseAddr("fd00::1")
	}
	bodyLength := 16 + 2 + 16 + 2 + 1 + len(payload)
	frame := make([]byte, 4+bodyLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(bodyLength))
	writePaddedAddress(frame[4:20], sourceAddr)
	binary.BigEndian.PutUint16(frame[20:22], sourcePort)
	writePaddedAddress(frame[22:38], targetAddr)
	binary.BigEndian.PutUint16(frame[38:40], target.Port())
	frame[40] = 0
	copy(frame[41:], payload)
	return frame, nil
}

func readIncomingFrame(reader io.Reader) ([]byte, error) {
	for {
		var prefix [4]byte
		if _, err := io.ReadFull(reader, prefix[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(prefix[:])
		if length > maxUDPFrame {
			return nil, ErrStream
		}
		if length < udpIncomingHeader {
			// A frame too short to carry its addresses is skipped whole: the stream stays in step and the other
			// flows live.
			if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
				return nil, ErrStream
			}
			continue
		}
		frame := make([]byte, int(length))
		if _, err := io.ReadFull(reader, frame); err != nil {
			return nil, ErrStream
		}
		return frame, nil
	}
}

func decodeIncomingBody(frame []byte) (netip.AddrPort, uint16, []byte, error) {
	if len(frame) < udpIncomingHeader {
		return netip.AddrPort{}, 0, nil, ErrStream
	}
	source := readPaddedAddress(frame[:16])
	sourcePort := binary.BigEndian.Uint16(frame[16:18])
	destinationPort := binary.BigEndian.Uint16(frame[34:36])
	if !source.IsValid() || sourcePort == 0 || destinationPort == 0 {
		return netip.AddrPort{}, 0, nil, ErrStream
	}
	return netip.AddrPortFrom(source, sourcePort), destinationPort, append([]byte(nil), frame[36:]...), nil
}

func writePaddedAddress(target []byte, address netip.Addr) {
	if address.Is4() {
		copy(target[12:], address.AsSlice())
		return
	}
	bytes := address.As16()
	copy(target, bytes[:])
}

func readPaddedAddress(value []byte) netip.Addr {
	var bytes [16]byte
	copy(bytes[:], value)
	address := netip.AddrFrom16(bytes)
	zeroPrefix := true
	for _, part := range bytes[:12] {
		zeroPrefix = zeroPrefix && part == 0
	}
	if address != netip.IPv6Loopback() && zeroPrefix {
		var ipv4 [4]byte
		copy(ipv4[:], bytes[12:])
		return netip.AddrFrom4(ipv4)
	}
	return address
}
