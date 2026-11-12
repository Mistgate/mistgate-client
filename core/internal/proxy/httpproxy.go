package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

type sessionKey struct{}

// newHTTPServer is net/http's server and ReverseProxy for the plain requests (they strip the hop-by-hop headers, the
// proxy login among them, keep the body streaming and handle an Upgrade), and a hijack for CONNECT.
// ponytail: only the destination of each request is vetted, nothing is cached or rewritten; that is all a proxy for
// browsers and TVs needs.
func (p *Proxy) newHTTPServer(ctx context.Context) (*http.Server, *http.Transport) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, engine.ErrBlockedDest
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return nil, engine.ErrBlockedDest
			}
			conn, err := p.dial(ctx, host, uint16(port))
			if err != nil {
				return nil, err
			}
			return idleConn{Conn: conn, idle: p.idle}, nil
		},
		DisableCompression:  true, // the client's own Accept-Encoding goes through untouched
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	forward := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Header.Del("Proxy-Authorization") // already gone with the other hop-by-hop headers; the login must not leave
			r.Out.URL.User = nil
		},
		Transport:    transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) { httpFailure(w, err) },
		ErrorLog:     quietLog,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := r.Context().Value(sessionKey{}).(*session)
		if !ok || !p.httpAuth(w, r, s) {
			return
		}
		switch {
		case r.Method == http.MethodConnect:
			p.httpConnect(w, r, s)
		case r.URL.IsAbs() && r.URL.Scheme == "http" && r.URL.Host != "":
			forward.ServeHTTP(w, r)
		default:
			// a request to the proxy itself: it is not a web server
			http.Error(w, "this is a proxy", http.StatusBadRequest)
		}
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: p.handshake,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          quietLog,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, sessionKey{}, c)
		},
	}
	return srv, transport
}

// httpAuth lets a request through or answers it. This machine needs no login (one that is sent is checked all the
// same); anyone else must have one, and a missing login costs nothing, a wrong one a delay and a mark against the address.
func (p *Proxy) httpAuth(w http.ResponseWriter, r *http.Request, s *session) bool {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" && s.local {
		return true
	}
	if header != "" {
		if user, password, ok := parseBasic(header); ok && p.credsOK(user, password) {
			if !s.local {
				p.fails.clear(s.remote)
			}
			return true
		}
		p.authFailed(s)
		if !s.local {
			// a guesser gets one try a connection: the block on its address is checked when a connection comes in
			w.Header().Set("Connection", "close")
		}
	}
	w.Header().Set("Proxy-Authenticate", `Basic realm="Mistgate"`)
	http.Error(w, "proxy login required", http.StatusProxyAuthRequired)
	return false
}

func parseBasic(header string) (user, password string, ok bool) {
	scheme, encoded, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	user, password, ok = strings.Cut(string(raw), ":")
	return user, password, ok
}

func (p *Proxy) httpConnect(w http.ResponseWriter, r *http.Request, s *session) {
	host, portText, err := net.SplitHostPort(r.Host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	up, err := p.dial(r.Context(), host, uint16(port))
	if err != nil {
		httpFailure(w, err)
		return
	}
	defer up.Close()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{}) // the server's header timeout is not the tunnel's
	if !s.setUpstream(up) {
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// whatever the client sent right behind the request line is already in the server's buffer
	if n := buffered.Reader.Buffered(); n > 0 {
		early, _ := buffered.Reader.Peek(n)
		if _, err := up.Write(early); err != nil {
			return
		}
	}
	p.relay(s, up)
}

// httpFailure names the trouble without naming the destination.
func httpFailure(w http.ResponseWriter, err error) {
	status, text := http.StatusBadGateway, "bad gateway"
	switch {
	case errors.Is(err, engine.ErrNoTunnel):
		status, text = http.StatusServiceUnavailable, "the VPN is not connected"
	case errors.Is(err, engine.ErrBlockedDest):
		status, text = http.StatusForbidden, "destination not allowed"
	case errors.Is(err, context.DeadlineExceeded):
		status, text = http.StatusGatewayTimeout, "gateway timeout"
	}
	http.Error(w, text, status)
}
