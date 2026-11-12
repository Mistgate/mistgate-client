package xray

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/session"
)

// What a failed Check says about the path. Anything else Check returns is the same as ErrNoAnswer to the caller.
var (
	ErrNoAnswer = errors.New("the server did not answer")
	// ErrRejected: the server took the connection but not the client: an unknown user, a key or short id REALITY does
	// not recognise. VLESS gives no reason, so a server whose own way out is shut looks the same.
	ErrRejected = errors.New("the server rejected the client")
)

// firstError keeps what Xray's outbound reports for one connection; the connection itself only ever sees it close.
type firstError struct {
	mu  sync.Mutex
	err error
}

func (f *firstError) SubmitError(err error) {
	f.mu.Lock()
	if f.err == nil {
		f.err = err
	}
	f.mu.Unlock()
}

func (f *firstError) text() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		return ""
	}
	return f.err.Error()
}

// CheckTargets are public TLS servers on well-known addresses, tried in turn by CheckAny. Tests point it at loopback.
var CheckTargets = []string{"1.1.1.1:443", "8.8.8.8:443"}

// CheckAny is Check against the first of two well-known TLS servers that answers; the last error is returned.
func (i *Instance) CheckAny(ctx context.Context) error {
	err := ErrNoAnswer
	for _, target := range CheckTargets {
		if err = i.Check(ctx, target); err == nil || ctx.Err() != nil {
			break
		}
	}
	return err
}

// Check proves the path end to end: a TLS handshake with target (host:port, an address) through the server. It
// needs the transport security, the user and the server's own way out all to work, and it checks nothing about the
// target's certificate; the bytes only have to come back.
func (i *Instance) Check(ctx context.Context, target string) error {
	host, portText, err := net.SplitHostPort(target)
	port, perr := strconv.ParseUint(portText, 10, 16)
	if err != nil || perr != nil {
		return ErrNoAnswer
	}
	var reason firstError
	conn, err := i.dial(ctx, session.TrackedConnectionError(i.ctx, &reason), tcpDest(host, uint16(port)))
	if err != nil {
		return ErrNoAnswer
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	err = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).HandshakeContext(ctx)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil { // out of time (or told to stop: the caller knows which); silence is no answer
		return ErrNoAnswer
	}
	// Xray tells a connection's failure only to the tracker, and says nothing when the server just hangs up. A key or
	// short id the server does not know shows as REALITY's or the certificate check's error (the server then plays the
	// site it imitates); an unknown user, or a server whose own way out is shut, shows as that silent hang-up. A
	// refused, reset or silent connection has an error of its own and is no answer.
	text := reason.text()
	if strings.Contains(text, "REALITY") || strings.Contains(text, "x509:") ||
		text == "" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)) {
		return ErrRejected
	}
	return ErrNoAnswer
}
