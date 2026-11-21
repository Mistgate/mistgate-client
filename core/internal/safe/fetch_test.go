package safe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// lookups swaps the two resolvers for the test and counts how often each was asked.
func lookups(t *testing.T, system, own func(context.Context, string) ([]netip.Addr, error)) (systemCalls, ownCalls *int) {
	t.Helper()
	previousSystem, previousOwn, previousLimit := systemLookup, ownLookup, systemLookupLimit
	t.Cleanup(func() { systemLookup, ownLookup, systemLookupLimit = previousSystem, previousOwn, previousLimit })
	systemCalls, ownCalls = new(int), new(int)
	systemLookup = func(ctx context.Context, host string) ([]netip.Addr, error) { *systemCalls++; return system(ctx, host) }
	ownLookup = func(ctx context.Context, host string) ([]netip.Addr, error) { *ownCalls++; return own(ctx, host) }
	systemLookupLimit = 50 * time.Millisecond
	return systemCalls, ownCalls
}

func TestFetchClientResolvesWithTheOwnResolverWhenTheSystemOneFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	port := server.URL[len("http://127.0.0.1:"):]
	loopback := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	fails := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no answer") }
	silent := func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }
	answers := func(context.Context, string) ([]netip.Addr, error) { return loopback, nil }
	// ".invalid" never resolves anywhere, so an answer can only have come from one of the swapped resolvers
	url := "http://fetch.invalid:" + port
	for name, c := range map[string]struct {
		system           func(context.Context, string) ([]netip.Addr, error)
		wantSys, wantOwn int
	}{
		"the system resolver fails":           {fails, 1, 1},
		"the system resolver does not answer": {silent, 1, 1},
		"the system resolver answers":         {answers, 1, 0},
	} {
		systemCalls, ownCalls := lookups(t, c.system, answers)
		response, err := FetchClient(3 * time.Second).Get(url)
		if err != nil || response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: %v", name, err)
		}
		_ = response.Body.Close()
		if *systemCalls != c.wantSys || *ownCalls != c.wantOwn {
			t.Errorf("%s: lookups system %d own %d, want %d and %d", name, *systemCalls, *ownCalls, c.wantSys, c.wantOwn)
		}
	}
}

// Every address the name leads to is checked, and the next one is tried when one does not connect.
func TestFetchClientChecksEachResolvedAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	port := server.URL[len("http://127.0.0.1:"):]
	linkLocal, loopback := netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("127.0.0.1")
	lookups(t, func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{linkLocal, loopback}, nil }, nil)
	response, err := FetchClient(3 * time.Second).Get("http://fetch.invalid:" + port)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("link-local first, loopback second: %v", err)
	}
	_ = response.Body.Close()
	lookups(t, func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{linkLocal}, nil }, nil)
	if _, err := FetchClient(3 * time.Second).Get("http://fetch.invalid:" + port); !errors.Is(err, ErrLinkLocal) {
		t.Fatalf("only a link-local address: %v, want the refusal", err)
	}
}

func TestFetchClientRefusesLinkLocal(t *testing.T) {
	for address, refused := range map[string]bool{
		"169.254.169.254:80": true, "[fe80::1%1]:443": true, "[::ffff:169.254.1.1]:80": true,
		"127.0.0.1:80": false, "192.168.1.10:443": false, "[2001:db8::1]:443": false, "203.0.113.5:443": false,
	} {
		if got := noLinkLocal("tcp", address, nil) != nil; got != refused {
			t.Errorf("%s: refused = %v, want %v", address, got, refused)
		}
	}
	// through the client itself: the refusal reaches the caller, and a loopback server still answers
	client := FetchClient(3 * time.Second)
	if _, err := client.Get("http://169.254.169.254/latest/"); !errors.Is(err, ErrLinkLocal) {
		t.Errorf("metadata address: %v, want the refusal", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	response, err := client.Get(server.URL)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("loopback server: %v", err)
	}
	_ = response.Body.Close()
}
