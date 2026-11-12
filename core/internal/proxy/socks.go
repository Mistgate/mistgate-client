package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

// SOCKS5 reply codes (RFC 1928).
const (
	socksFailure         = 0x01
	socksNotAllowed      = 0x02
	socksNetUnreachable  = 0x03
	socksHostUnreachable = 0x04
	socksBadCommand      = 0x07
	socksBadAddress      = 0x08
)

func (p *Proxy) acceptSocks(l *admitListener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || l.ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond) // a temporary failure (out of handles): do not spin
			continue
		}
		go p.serveSocks(conn.(*session))
	}
}

func (p *Proxy) serveSocks(s *session) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(p.handshake))
	host, port, ok := p.socksHandshake(s)
	if !ok {
		return
	}
	_ = s.SetDeadline(time.Time{}) // the dial has its own limit
	up, err := p.dial(s.ctx, host, port)
	if err != nil {
		_ = socksReply(s, socksCode(err))
		return
	}
	defer up.Close()
	if !s.setUpstream(up) {
		return
	}
	if socksReply(s, 0) != nil {
		return
	}
	p.relay(s, up)
}

// socksHandshake reads the greeting, the login and the request; ok is false when the connection is to be dropped (the
// answer has been sent already when there is one).
func (p *Proxy) socksHandshake(s *session) (host string, port uint16, ok bool) {
	var head [2]byte
	if _, err := io.ReadFull(s, head[:]); err != nil || head[0] != 5 {
		return "", 0, false
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(s, methods); err != nil {
		return "", 0, false
	}
	// A login that is offered is checked even on this machine, so a client with an old password is told so.
	switch {
	case slices.Contains(methods, 2):
		if _, err := s.Write([]byte{5, 2}); err != nil || !p.socksLogin(s) {
			return "", 0, false
		}
	case slices.Contains(methods, 0) && s.local:
		if _, err := s.Write([]byte{5, 0}); err != nil {
			return "", 0, false
		}
	default:
		_, _ = s.Write([]byte{5, 0xFF})
		return "", 0, false
	}

	var request [4]byte
	if _, err := io.ReadFull(s, request[:]); err != nil || request[0] != 5 {
		return "", 0, false
	}
	switch request[3] {
	case 1:
		var raw [4]byte
		if _, err := io.ReadFull(s, raw[:]); err != nil {
			return "", 0, false
		}
		host = netip.AddrFrom4(raw).String()
	case 4:
		var raw [16]byte
		if _, err := io.ReadFull(s, raw[:]); err != nil {
			return "", 0, false
		}
		host = netip.AddrFrom16(raw).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(s, size[:]); err != nil || size[0] == 0 {
			_ = socksReply(s, socksBadAddress)
			return "", 0, false
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(s, name); err != nil {
			return "", 0, false
		}
		host = string(name)
	default:
		_ = socksReply(s, socksBadAddress)
		return "", 0, false
	}
	var raw [2]byte
	if _, err := io.ReadFull(s, raw[:]); err != nil {
		return "", 0, false
	}
	// The whole request is read before it is refused: closing on unread bytes makes Windows reset the connection and
	// the client never sees the answer.
	// ponytail: UDP for console games is added when it is needed (ASSOCIATE needs a UDP relay through the tunnel); BIND never.
	if request[1] != 1 {
		_ = socksReply(s, socksBadCommand)
		return "", 0, false
	}
	return host, uint16(raw[0])<<8 | uint16(raw[1]), true
}

// socksLogin is RFC 1929.
func (p *Proxy) socksLogin(s *session) bool {
	var head [2]byte
	if _, err := io.ReadFull(s, head[:]); err != nil || head[0] != 1 {
		return false
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(s, user); err != nil {
		return false
	}
	var size [1]byte
	if _, err := io.ReadFull(s, size[:]); err != nil {
		return false
	}
	password := make([]byte, size[0])
	if _, err := io.ReadFull(s, password); err != nil {
		return false
	}
	if !p.credsOK(string(user), string(password)) {
		p.authFailed(s)
		_, _ = s.Write([]byte{1, 1})
		return false
	}
	if !s.local {
		p.fails.clear(s.remote)
	}
	_, err := s.Write([]byte{1, 0})
	return err == nil
}

// socksReply answers with the bound address left empty: the connection to the target is the tunnel's, not a socket
// whose address means anything to the client.
func socksReply(s *session, code byte) error {
	_, err := s.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func socksCode(err error) byte {
	switch {
	case errors.Is(err, engine.ErrNoTunnel):
		return socksNetUnreachable
	case errors.Is(err, engine.ErrBlockedDest):
		return socksNotAllowed
	case errors.Is(err, context.DeadlineExceeded):
		return socksHostUnreachable
	default:
		return socksFailure
	}
}
