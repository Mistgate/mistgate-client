package trusttunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	h3StreamLimit  = 250                                  // Streams the node grants one QUIC connection.
	h3KeepAlive    = 10 * time.Second                     // As Hysteria2's: a quiet tunnel is not ended by a NAT or by the 30 s idle time.
	alpnRejectedAt = quic.TransportErrorCode(0x100 + 120) // The TLS alert no_application_protocol, as a QUIC crypto error.
)

// dialH3 opens one HTTP/3 session: the QUIC handshake of Chrome (the same Hysteria2 uses) on a socket from
// config.ListenPacket, then the HTTP/3 layer. As Dial does for HTTP/2, it asks the server nothing.
func dialH3(ctx context.Context, config Config) (*Client, error) {
	if ctx == nil || !validConfig(config) {
		return nil, ErrConfig
	}
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	plan, err := planDial(ctx, dialCtx, config)
	if err != nil {
		return nil, err
	}
	listen := config.ListenPacket
	if listen == nil {
		listen = listenUDP
	}
	var lastErr error = ErrEndpoint
	for _, endpoint := range plan.addresses {
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		pc, err := listen(dialCtx, endpoint)
		if err != nil {
			continue
		}
		// The transport is the one connection's own: Chrome's zero-length connection ID routes by address alone.
		transport := &quic.Transport{Conn: pc, ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{}}
		closeUDP := func() {
			_ = transport.Close()
			_ = pc.Close()
		}
		// The handshake reports a failed check only as a TLS alert, so the check says what failed itself.
		var certRejected atomic.Bool
		verify := plan.verify
		if verify != nil {
			check := verify
			verify = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
				err := check(rawCerts, chains)
				certRejected.Store(err != nil)
				return err
			}
		}
		// quic-go does not fill the server name in from the address (the fork has it commented out), so it is set here.
		tlsConfig := &tls.Config{
			ServerName: plan.sni, NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
			VerifyPeerCertificate: verify,
		}
		conn, err := transport.Dial(dialCtx, net.UDPAddrFromAddrPort(endpoint), tlsConfig, &quic.Config{ChromeParrot: true, KeepAlivePeriod: h3KeepAlive})
		if err != nil {
			closeUDP()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var transportErr *quic.TransportError
			switch {
			case certRejected.Load():
				lastErr = ErrCertificate
			case errors.As(err, &transportErr) && transportErr.ErrorCode == alpnRejectedAt:
				lastErr = ErrALPN
			}
			continue
		}
		if conn.ConnectionState().TLS.NegotiatedProtocol != http3.NextProtoH3 {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			closeUDP()
			lastErr = ErrALPN
			continue
		}

		clientCtx, clientCancel := context.WithCancel(context.Background())
		// Gzip would only add a header to a CONNECT whose body is the tunnel's bytes.
		h3Client := (&http3.Transport{DisableCompression: true}).NewClientConn(conn)
		client := &Client{
			ctx: clientCtx, cancel: clientCancel, h3: h3Client, quic: conn, closeUDP: closeUDP,
			endpoint: endpoint, config: config, dead: make(chan struct{}), udpFlows: make(map[uint16]*udpFlow), udpNext: 49152,
		}
		// The connection ends by the server's close, by the idle time or by an error of the socket; any of them is the
		// end of the session. This is also what keeps watchSession's poll away from HTTP/3.
		context.AfterFunc(conn.Context(), func() { client.markDead(ErrSession) })
		return client, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, lastErr
}

// listenUDP is the socket of a session whose caller gave no ListenPacket.
func listenUDP(_ context.Context, target netip.AddrPort) (net.PacketConn, error) {
	network := "udp6"
	if target.Addr().Is4() {
		network = "udp4"
	}
	return net.ListenUDP(network, nil)
}

// h3CheckTimeout bounds the _check that decides for HTTP/3 while HTTP/2 is still a way out; h3Retry is how long a host that
// got HTTP/3 is left to HTTP/2. Variables for the test.
var (
	h3CheckTimeout = 3 * time.Second
	h3Retry        = 10 * time.Minute
)

// h3Chosen is when HTTP/3 was last chosen for a host.
// ponytail: per host, 10 minutes, in this process, and not cleared when the network changes. It cuts the loop of a network
// that lets the QUIC handshake through and drops the flow after it (each turn would cost the 30 s idle time of the dead
// session); upgrade = clear it on a network change, or a pause that grows with each loss.
var h3Chosen = struct {
	sync.Mutex
	at map[string]time.Time
}{at: make(map[string]time.Time)}

func h3Recent(host string) bool {
	h3Chosen.Lock()
	defer h3Chosen.Unlock()
	at, ok := h3Chosen.at[host]
	return ok && time.Since(at) < h3Retry
}

func rememberH3(host string) {
	h3Chosen.Lock()
	h3Chosen.at[host] = time.Now()
	h3Chosen.Unlock()
}

type dialResult struct {
	client *Client
	err    error
}

// Connect opens a session and checks it. Without config.H3 that is Dial and Check. With it, the HTTP/3 and the HTTP/2
// handshakes start together and the first to finish leads: HTTP/3 (one round trip against two) wins only if its QUIC
// handshake ends before the TLS one and its _check passes within h3CheckTimeout. HTTP/2 is not authorised until then, so
// the loser is closed unused and takes none of the account's connections. Where UDP is cut nothing waits for it; where
// it works the connection is about one round trip quicker.
//
// HTTP/3 decides no failure: a refusal or a silent server is what HTTP/2 answers. The one exception is a server that TCP
// does not reach at all, which HTTP/3 alone can still serve. A host that got HTTP/3 within h3Retry is dialled over HTTP/2
// alone, so a session that was lost goes to HTTP/2 at once.
func Connect(ctx context.Context, config Config) (*Client, error) {
	if ctx == nil {
		return nil, ErrConfig
	}
	if !config.H3 || h3Recent(config.Host) {
		return connectH2(ctx, config)
	}
	h2Ctx, h2Cancel := context.WithCancel(ctx)
	h3Ctx, h3Cancel := context.WithCancel(ctx)
	defer h2Cancel()
	defer h3Cancel()
	h2Result, h3Result := make(chan dialResult, 1), make(chan dialResult, 1)
	go func() {
		client, err := Dial(h2Ctx, config)
		h2Result <- dialResult{client, err}
	}()
	go func() {
		client, err := dialH3(h3Ctx, config)
		h3Result <- dialResult{client, err}
	}()

	select {
	case h2 := <-h2Result:
		if h2.err != nil {
			// TCP does not reach the server. If QUIC does, its _check has the last word.
			h3 := <-h3Result
			if h3.err != nil {
				return nil, h2.err
			}
			if err := h3.client.Check(ctx); err != nil {
				_ = h3.client.Close()
				return nil, err
			}
			rememberH3(config.Host)
			return h3.client, nil
		}
		h3Cancel()
		discard(h3Result)
		return checked(ctx, h2.client)
	case h3 := <-h3Result:
		if h3.err == nil {
			checkCtx, cancel := context.WithTimeout(ctx, h3CheckTimeout)
			err := h3.client.Check(checkCtx)
			cancel()
			if err == nil {
				h2Cancel()
				discard(h2Result)
				rememberH3(config.Host)
				return h3.client, nil
			}
			_ = h3.client.Close()
		}
		h2 := <-h2Result
		if h2.err != nil {
			return nil, h2.err
		}
		return checked(ctx, h2.client)
	}
}

func connectH2(ctx context.Context, config Config) (*Client, error) {
	client, err := Dial(ctx, config)
	if err != nil {
		return nil, err
	}
	return checked(ctx, client)
}

// checked runs the health check of a session and closes the session that fails it.
func checked(ctx context.Context, client *Client) (*Client, error) {
	if err := client.Check(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// discard closes the session of a dial that lost the race, whenever the dial ends (its context is already cancelled).
func discard(result <-chan dialResult) {
	go func() {
		if r := <-result; r.client != nil {
			_ = r.client.Close()
		}
	}()
}
