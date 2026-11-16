//go:build windows

package engine

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answeringResolver is a resolver that asks a DNS server on this machine's loopback, like ownResolver asks the
// network's, and counts the questions that reach it.
func answeringResolver(t *testing.T, answer netip.Addr) (*net.Resolver, *atomic.Int64) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var questions atomic.Int64
	go func() {
		buffer := make([]byte, 512)
		for {
			count, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:count]) != nil || len(query.Questions) != 1 {
				continue
			}
			questions.Add(1)
			question := query.Questions[0]
			reply := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true},
				Questions: query.Questions,
			}
			if question.Type == dnsmessage.TypeA {
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: answer.As4()},
				}}
			}
			if packed, err := reply.Pack(); err == nil {
				_, _ = conn.WriteTo(packed, from)
			}
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	return resolver, &questions
}

// Under a hold the engine resolves a server it has never connected to by asking from the service's own sockets
// (ownResolver), which the kill switch's rules let through; a server it knows is answered from memory.
// This pins the decision; that the real firewall lets those sockets out is not tested here (see firewall/rules.go).
func TestHeldRunResolvesAServerItHasNotSeen(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.77")
	resolver, questions := answeringResolver(t, want)
	previous := ownResolver
	ownResolver = resolver
	t.Cleanup(func() { ownResolver = previous })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &Real{resolved: map[string]netip.Addr{}}
	run := &realRun{ctx: ctx, hold: true}
	r.current = run

	// ".invalid" never resolves anywhere else, so an answer can only have come from ownResolver
	got, err := r.resolveServer(ctx, run, "Moved.Server.invalid.", true)
	if err != nil || got != want {
		t.Fatalf("held resolve of a name that was never cached = %v, %v; want %v", got, err, want)
	}
	asked := questions.Load()
	if asked == 0 {
		t.Fatal("the name was not asked of the own resolver")
	}
	if r.resolved["moved.server.invalid"] != want {
		t.Fatal("the answer was not remembered under the lower-cased name")
	}

	// the second time the cache answers and nobody is asked
	again, err := r.resolveServer(ctx, run, "moved.server.invalid", true)
	if err != nil || again != want {
		t.Fatalf("held resolve of a cached name = %v, %v; want %v", again, err, want)
	}
	if questions.Load() != asked {
		t.Fatal("a cached name was asked of the resolver again")
	}

	// an address needs no resolver at all
	literal, err := r.resolveServer(ctx, run, "203.0.113.5", true)
	if err != nil || literal != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("held resolve of an address = %v, %v", literal, err)
	}
}
