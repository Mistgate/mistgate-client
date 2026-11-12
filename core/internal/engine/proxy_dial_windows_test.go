//go:build windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDialVPNNeedsAVerifiedRun(t *testing.T) {
	r := &Real{}
	if _, err := r.DialVPN(context.Background(), "example.com", 443); !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("no run: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	r.current = &realRun{ctx: ctx, dial: func(context.Context, string, uint16) (net.Conn, error) { called = true; return nil, nil }}
	// connecting or held: the run exists, the tunnel is not verified
	if _, err := r.DialVPN(context.Background(), "example.com", 443); !errors.Is(err, ErrNoTunnel) || called {
		t.Fatalf("unverified run: %v, called=%v", err, called)
	}
}

func TestDialVPNConnectionsEndWithTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Real{}
	client, target := net.Pipe()
	defer target.Close()
	run := &realRun{ctx: ctx, probeIP: netip.MustParseAddr("10.0.0.2")}
	run.dial = func(_ context.Context, host string, port uint16) (net.Conn, error) {
		if host != "example.com" || port != 443 {
			t.Errorf("dialled %s:%d", host, port)
		}
		// the lock is not held while the tunnel connects
		if !r.mu.TryLock() {
			t.Error("r.mu held during the dial")
		} else {
			r.mu.Unlock()
		}
		return client, nil
	}
	r.current = run
	conn, err := r.DialVPN(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		t.Fatal("no CloseWrite on the connection")
	}
	cancel() // a disconnect, or a reconnect that replaces the run
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read after the run ended: %v", err)
	}
	if _, err := r.DialVPN(context.Background(), "example.com", 443); !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("dial after the run ended: %v", err)
	}
}

func TestDialNamed(t *testing.T) {
	allow := func(address netip.Addr) bool { return !address.IsPrivate() }
	var tried []netip.AddrPort
	dial := func(_ context.Context, target netip.AddrPort) (net.Conn, error) {
		tried = append(tried, target)
		if target.Addr() == netip.MustParseAddr("93.184.216.34") {
			return nil, errors.New("down")
		}
		client, _ := net.Pipe()
		return client, nil
	}
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1"), netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("1.2.3.4")}, nil
	}
	conn, err := dialNamed(context.Background(), "example.com", 443, allow, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// IPv4 first, the private answer never tried, a failure moves on to the next
	want := []string{"93.184.216.34:443", "1.2.3.4:443"}
	if len(tried) != len(want) || tried[0].String() != want[0] || tried[1].String() != want[1] {
		t.Fatalf("tried %v, want %v", tried, want)
	}
	// a name whose every answer is private is refused
	onlyPrivate := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.0.9")}, nil
	}
	if _, err := dialNamed(context.Background(), "evil.example", 80, allow, onlyPrivate, dial); !errors.Is(err, ErrBlockedDest) {
		t.Fatalf("private answer: %v", err)
	}
	// so is an address given as it is
	if _, err := dialNamed(context.Background(), "192.168.0.9", 80, allow, lookup, dial); !errors.Is(err, ErrBlockedDest) {
		t.Fatalf("private literal: %v", err)
	}
}
