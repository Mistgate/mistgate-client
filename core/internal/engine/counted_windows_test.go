//go:build windows

package engine

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
)

// The bridge counts what goes to the VPN side and what comes back, apart; a nil counter is not counted.
func TestCountedConnCountsBothWays(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	go func() {
		_, _ = far.Write(make([]byte, 7))
		_, _ = io.CopyN(io.Discard, far, 5)
	}()
	var rx, tx atomic.Uint64
	conn := countedConn{near, &rx, &tx}
	if _, err := io.ReadFull(conn, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if rx.Load() != 7 || tx.Load() != 5 {
		t.Fatalf("rx %d, tx %d, want 7 and 5", rx.Load(), tx.Load())
	}
	go func() { _, _ = io.CopyN(io.Discard, far, 2) }()
	if _, err := (countedConn{near, &rx, nil}).Write(make([]byte, 2)); err != nil || tx.Load() != 5 {
		t.Fatalf("a nil counter: %v, tx %d", err, tx.Load())
	}
}
