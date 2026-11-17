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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
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
	udpSendQueue      = 256     // Frames one _udp2 stream holds for its writer; a full queue drops the datagram.
	maxSkippedFrame   = 1 << 20 // A longer incoming frame means the framing is lost, not that one datagram is odd.
)

// headerTimeout bounds the wait for a stream's response headers: the server's own connect timeout is 30 s. A variable
// for the test.
var headerTimeout = 35 * time.Second

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
	// ListenPacket opens the UDP socket of one HTTP/3 session to target, so the caller can keep it off the tunnel like its
	// TCP sockets. Without it the session binds a plain wildcard socket.
	ListenPacket func(ctx context.Context, target netip.AddrPort) (net.PacketConn, error)
	// H3 asks Connect to try HTTP/3 beside HTTP/2. Dial is always HTTP/2.
	H3 bool
}

// Client is one session to the endpoint: HTTP/2 over TCP, or HTTP/3 over QUIC when h3 is set. The streams, the UDP framing
// and the rest of the API are the same on both; only opening, one round trip, the load figures and the end differ.
type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      net.Conn
	transport *http2.Transport
	h2        *http2.ClientConn
	h3        *http3.ClientConn
	quic      *quic.Conn
	closeUDP  func() // closes the QUIC transport and the UDP socket under it, which quic-go leaves to us
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

	plan, err := planDial(ctx, dialCtx, config)
	if err != nil {
		return nil, err
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: connectTimeout}
		dial = dialer.DialContext
	}
	var lastErr error = ErrEndpoint
	for _, endpoint := range plan.addresses {
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
			ServerName: plan.sni, NextProtos: []string{"h2"}, MinVersion: utls.VersionTLS12, InsecureSkipVerify: true,
			VerifyPeerCertificate: plan.verify,
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

// dialPlan is what both transports settle before the first socket: the endpoints to try, the TLS server name and the
// certificate check (nil when the link asks for none).
type dialPlan struct {
	addresses []netip.AddrPort
	sni       string
	verify    func(rawCerts [][]byte, _ [][]*x509.Certificate) error
}

// planDial resolves the endpoints on dialCtx; ctx is the caller's, to tell its cancel from a failed resolve.
func planDial(ctx, dialCtx context.Context, config Config) (dialPlan, error) {
	addresses, err := resolveEndpoints(dialCtx, config)
	if err != nil {
		if ctx.Err() != nil {
			return dialPlan{}, ctx.Err()
		}
		return dialPlan{}, ErrEndpoint
	}
	sni := config.SNI
	if sni == "" {
		sni = config.Host
	}
	roots, err := trustRoots(config.Certs)
	if err != nil {
		return dialPlan{}, ErrCertificate
	}
	return dialPlan{addresses: addresses, sni: sni, verify: verifyPeer(config, roots)}, nil
}

// verifyPeer is the certificate check of both transports: the pinned leaf if the link has a pin, else the chain against
// roots for the host, else none for a link that turns the check off.
func verifyPeer(config Config, roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	if config.HasPin {
		pin := config.PinSHA256
		return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrCertificate
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], pin[:]) != 1 {
				return ErrCertificate
			}
			return nil
		}
	}
	if config.Insecure {
		return nil
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if err := verifyServer(rawCerts, roots, config.Host); err != nil {
			return ErrCertificate
		}
		return nil
	}
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

// Protocol names the session's HTTP version for the log: "h3" or "h2".
func (c *Client) Protocol() string {
	if c.h3 != nil {
		return "h3"
	}
	return "h2"
}

// Load reports active, reserved and queued HTTP/2 streams, plus the peer's stream limit.
func (c *Client) Load() (active, limit int) {
	if c.h3 != nil {
		// ponytail: quic-go does not count streams; one QUIC connection holds the pool's 64 + 4 streams and the node grants 250, so the
		// pool never opens a second one. A server with fewer than 68 streams per connection = count them in roundTrip.
		return 0, h3StreamLimit
	}
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

// DialTCP opens one HTTP/2 CONNECT stream to authority. As with net.Dialer, ctx bounds the dial only: the stream goes on
// after it is cancelled and ends with Close or with the session.
func (c *Client) DialTCP(ctx context.Context, authority string) (net.Conn, error) {
	if ctx == nil || authority == "" || len(authority) > 320 {
		return nil, ErrConfig
	}
	response, writer, cancel, err := c.openStream(ctx, authority, userAgentTCP)
	if err != nil {
		return nil, err
	}
	return &streamConn{
		reader: response.body, writer: writer, cancel: cancel,
		local: tunnelAddr{value: "trusttunnel"}, remote: tunnelAddr{value: authority},
	}, nil
}

// openStream sends the CONNECT and waits for the response headers. In x/net a request's context lives as long as its
// stream, so the stream is made on the client's own context; ctx and headerTimeout only cancel it while the headers are
// awaited, and a stream whose bound has fired is not handed out.
func (c *Client) openStream(ctx context.Context, authority, userAgent string) (*httpResponse, *io.PipeWriter, context.CancelFunc, error) {
	streamCtx, cancel := context.WithCancel(c.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(headerTimeout, cancel)
	pipeReader, pipeWriter := io.Pipe()
	response, err := c.connect(streamCtx, authority, userAgent, pipeReader)
	callerGone, timedOut := !stopCaller(), !timer.Stop()
	if err == nil || errors.Is(err, context.Canceled) {
		switch {
		case callerGone:
			err = ctx.Err()
		case timedOut:
			err = context.DeadlineExceeded
		}
	}
	if err != nil {
		if response != nil {
			_ = response.body.Close()
		}
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		cancel()
		return nil, nil, nil, err
	}
	return response, pipeWriter, cancel, nil
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

// IsRefusal says whether err is the endpoint turning this account away: the authentication error or any 4xx (the
// reference server answers 407, ours shows its site, 404, to a wrong, switched-off or over-limit account). A 5xx is about
// one destination or the server's health and says nothing about the account.
func IsRefusal(err error) bool {
	if errors.Is(err, ErrAuth) {
		return true
	}
	var status StatusError
	return errors.As(err, &status) && status.Code >= 400 && status.Code < 500
}

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
	// Both are http.RoundTrippers that end a request with its context. The request must not carry a Proto: with one,
	// HTTP/3 sends an extended CONNECT.
	var response *http.Response
	var err error
	if c.h3 != nil {
		response, err = c.h3.RoundTrip(request)
	} else {
		response, err = c.h2.RoundTrip(request)
	}
	if err != nil {
		if input.ctx.Err() != nil {
			return nil, input.ctx.Err()
		}
		if c.sessionGone() {
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

// sessionGone says whether the HTTP/2 connection is closed or closing (a GOAWAY). CanTakeNewRequest is no test of
// that: it is false as well while the connection is merely at the server's stream limit. A QUIC connection is gone once
// its context is.
// ponytail: an HTTP/3 GOAWAY is not seen; its new streams fail with ErrStream until the old ones end and the server
// closes the connection. Our node sends none.
func (c *Client) sessionGone() bool {
	if c.h3 != nil {
		return c.quic.Context().Err() != nil
	}
	state := c.h2.State()
	return state.Closed || state.Closing
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
			if c.sessionGone() {
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
		if c.h3 != nil {
			// quic-go closes neither the transport nor our socket under it, and a transport closed first sends no CONNECTION_CLOSE.
			_ = c.quic.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			c.closeUDP()
			return
		}
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

	mu           sync.Mutex
	closed       bool
	readDeadline time.Time
	readChanged  chan struct{} // closed when readDeadline changes, to wake a Read that waits on it
	pending      *pendingRead
	spare        []byte // the buffer of the last finished pending read
	writeTimer   *time.Timer
	closeOnce    sync.Once
}

// pendingRead is a read of the stream that a deadline left running: the next Read takes its result. Its bytes go
// through an own buffer because the caller's may be reused once Read has returned.
type pendingRead struct {
	buf  []byte
	off  int // bytes of buf[:n] already handed out
	n    int
	err  error
	done chan struct{}
}

// Read is a plain read of the stream while no read deadline is set. With one, the read runs in a goroutine and a
// deadline that passes returns os.ErrDeadlineExceeded with the stream still usable: the result goes to the next Read.
// One reader at a time, as everywhere here.
// ponytail: a deadline set while a Read without one is blocked does not wake it; upgrade = always read through the
// goroutine (a goroutine and a copy for every read of the stream).
func (c *streamConn) Read(payload []byte) (int, error) {
	c.mu.Lock()
	timed := c.pending != nil || !c.readDeadline.IsZero()
	c.mu.Unlock()
	if !timed || len(payload) == 0 {
		n, err := c.reader.Read(payload)
		return n, streamError(err)
	}
	c.mu.Lock()
	pending := c.pending
	if pending == nil {
		buf := c.spare
		if cap(buf) < len(payload) {
			buf = make([]byte, len(payload))
		}
		pending = &pendingRead{buf: buf[:len(payload)], done: make(chan struct{})}
		c.pending, c.spare = pending, nil
		go func() {
			pending.n, pending.err = c.reader.Read(pending.buf)
			close(pending.done)
		}()
	}
	c.mu.Unlock()
	for {
		c.mu.Lock()
		deadline := c.readDeadline
		if c.readChanged == nil {
			c.readChanged = make(chan struct{})
		}
		changed := c.readChanged
		c.mu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case <-pending.done:
			if timer != nil {
				timer.Stop()
			}
			n := copy(payload, pending.buf[pending.off:pending.n])
			pending.off += n
			if pending.off < pending.n {
				return n, nil // the rest waits for the next Read
			}
			c.mu.Lock()
			c.pending, c.spare = nil, pending.buf
			c.mu.Unlock()
			return n, streamError(pending.err)
		case <-expired:
			c.mu.Lock()
			late := !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline)
			c.mu.Unlock()
			if late {
				return 0, os.ErrDeadlineExceeded
			}
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func streamError(err error) error {
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrStream
	}
	return err
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
	_ = c.SetReadDeadline(deadline)
	return c.SetWriteDeadline(deadline)
}

func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	if c.readChanged != nil {
		close(c.readChanged)
		c.readChanged = nil
	}
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline closes the stream when the time comes: an HTTP/2 write cannot be interrupted any other way.
// ponytail: a write deadline ends the stream; upgrade = write through a goroutine as Read does with its deadline.
func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if !deadline.IsZero() && !c.closed {
		c.writeTimer = time.AfterFunc(max(time.Until(deadline), 0), func() { _ = c.Close() })
	}
	c.mu.Unlock()
	return nil
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
	out    chan []byte // encoded frames for the stream's one writer
	done   chan struct{}
	once   sync.Once
}

func (s *udpStream) close() {
	s.once.Do(func() {
		close(s.done)
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
			go c.writeUDPStream(stream)
		}
	}
	c.udpMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrAuth) {
			c.markDead(ErrAuth)
		}
		return err
	}
	// The stream's pipe waits for HTTP/2 flow control, which the server opens at the account's rate limit, so nothing
	// here may wait for it: a full queue drops the datagram, as UDP allows, and the other flows go on.
	select {
	case stream.out <- frame:
	default:
	}
	return nil
}

// writeUDPStream is the one writer of a stream's pipe, so the frames of a flow keep their order.
func (c *Client) writeUDPStream(stream *udpStream) {
	for {
		select {
		case <-stream.done:
			return
		case frame := <-stream.out:
			if _, err := stream.writer.Write(frame); err != nil {
				c.endUDPStream(stream)
				return
			}
		}
	}
}

// endUDPStream drops a stream that failed; the next datagram opens a new one and the flows are told.
func (c *Client) endUDPStream(stream *udpStream) {
	c.udpMu.Lock()
	if c.udpStream == stream {
		c.udpStream = nil
	}
	c.udpMu.Unlock()
	stream.close()
	c.notifyFlows(ErrStream)
}

func (c *Client) openUDPStreamLocked() (*udpStream, error) {
	response, writer, cancel, err := c.openStream(c.ctx, "_udp2", userAgentUDP)
	if err != nil {
		return nil, err
	}
	return &udpStream{
		reader: response.body, writer: writer, cancel: cancel,
		out: make(chan []byte, udpSendQueue), done: make(chan struct{}),
	}, nil
}

func (c *Client) readUDPStream(stream *udpStream) {
	for {
		frame, err := readIncomingFrame(stream.reader)
		if err != nil {
			c.endUDPStream(stream)
			if c.sessionGone() {
				c.markDead(ErrSession)
			}
			return
		}
		remote, destinationPort, payload, err := decodeIncomingBody(frame)
		if err != nil {
			continue // a frame with no usable addresses is skipped whole, like a short one: the stream stays in step
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
		if length > maxSkippedFrame {
			return nil, ErrStream
		}
		if length < udpIncomingHeader || length > maxUDPFrame {
			// A frame too short to carry its addresses, or longer than any datagram, is skipped whole: the stream stays
			// in step and the other flows live.
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
