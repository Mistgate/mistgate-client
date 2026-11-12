package geo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseCommentsIPv6GarbageAndMergeEdges(t *testing.T) {
	var body strings.Builder
	body.WriteString("# country list\n\n2001:db8::/32\n")
	body.WriteString("192.0.2.0/25\n192.0.2.128/25\n")
	for i := 0; i < minPrefixes-2; i++ {
		fmt.Fprintf(&body, "198.18.0.%d/32\n", i*2)
	}
	set, err := parse([]byte(body.String()))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != minPrefixes-1 {
		t.Fatalf("merged range count = %d, want %d", set.Len(), minPrefixes-1)
	}
	for _, address := range []string{"192.0.2.0", "192.0.2.127", "192.0.2.128", "192.0.2.255"} {
		if !set.Contains(netip.MustParseAddr(address)) {
			t.Errorf("set does not contain edge %s", address)
		}
	}
	if set.Contains(netip.MustParseAddr("192.0.3.0")) || set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("set accepted an address outside its IPv4 ranges")
	}
	if _, err := parse([]byte(body.String() + "not-a-prefix\n")); err == nil {
		t.Fatal("accepted garbage CIDR")
	}
	if _, err := parse([]byte("192.0.2.0/24\n")); err == nil {
		t.Fatal("accepted fewer than 100 IPv4 prefixes")
	}
}

func TestFetchFallbackCapAndMinimum(t *testing.T) {
	valid := listBody("203.0.113.7/32")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fallback/ru", "/fallback/cap":
			_, _ = w.Write([]byte(valid))
		case "/primary/cap":
			_, _ = w.Write([]byte(strings.Repeat("x", maxFileBytes+1)))
		case "/primary/small", "/fallback/small":
			_, _ = w.Write([]byte(strings.Repeat("192.0.2.1/32\n", minPrefixes-1)))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()
	store, err := Open(t.TempDir(), Options{
		HTTPClient:          server.Client(),
		PrimaryURLTemplate:  server.URL + "/primary/%s",
		FallbackURLTemplate: server.URL + "/fallback/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, cc := range []string{"ru", "cap"} {
		data, set, err := store.fetch(context.Background(), cc)
		if err != nil || len(data) == 0 || set == nil {
			t.Fatalf("fetch %s = %d bytes, %v", cc, len(data), err)
		}
	}
	if _, _, err := store.fetch(context.Background(), "small"); err == nil {
		t.Fatal("accepted a region with fewer than 100 IPv4 prefixes")
	}
}

func TestFailedStaleRefreshKeepsCachedFile(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	dataDir := t.TempDir()
	store, err := Open(dataDir, Options{
		HTTPClient:          server.Client(),
		PrimaryURLTemplate:  server.URL + "/primary/%s",
		FallbackURLTemplate: server.URL + "/fallback/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "geo", "ru.list")
	want := []byte(listBody("203.0.113.7/32"))
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if set, ok := store.Region("ru"); !ok || !set.Contains(netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("stale cache was not served")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		refreshing := store.refreshing["ru"]
		store.mu.Unlock()
		if !refreshing {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("failed refresh changed the stale file: err=%v", err)
	}
}

func TestRegionRefreshSignalsAndAdvancesVersion(t *testing.T) {
	var fetch atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first := "203.0.113.7/32"
		if fetch.Add(1) > 1 {
			first = "203.0.113.8/32"
		}
		_, _ = w.Write([]byte(listBody(first)))
	}))
	defer server.Close()
	dataDir := t.TempDir()
	store, err := Open(dataDir, Options{
		HTTPClient:          server.Client(),
		PrimaryURLTemplate:  server.URL + "/primary/%s",
		FallbackURLTemplate: server.URL + "/fallback/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if routes := store.Routes("smart", "ru", ""); routes.Available {
		t.Fatal("missing region was available before its fetch")
	}
	waitForChange(t, store.Changes())
	if routes := store.Routes("smart", "ru", ""); !routes.Available || routes.Version != 1 {
		t.Fatalf("first route snapshot = %#v, want available version 1", routes)
	}
	path := filepath.Join(dataDir, "geo", "ru.list")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	// the file's age is looked at once a minute; this was looked at a moment ago
	if _, ok := store.Region("ru"); !ok {
		t.Fatal("region was lost")
	}
	select {
	case <-store.Changes():
		t.Fatal("the file's age was asked again within a minute")
	case <-time.After(100 * time.Millisecond):
	}
	store.mu.Lock()
	clear(store.staleChecked)
	store.mu.Unlock()
	if _, ok := store.Region("ru"); !ok {
		t.Fatal("stale region was not kept during refresh")
	}
	waitForChange(t, store.Changes())
	if routes := store.Routes("smart", "ru", ""); !routes.Available || routes.Version != 2 {
		t.Fatalf("refreshed route snapshot = %#v, want available version 2", routes)
	}
}

func waitForChange(t *testing.T, changes <-chan struct{}) {
	t.Helper()
	select {
	case <-changes:
	case <-time.After(3 * time.Second):
		t.Fatal("geo refresh did not signal a change")
	}
}

func TestDetectUsesCandidateOrder(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, cc := range []string{"by", "ru"} {
		if err := os.WriteFile(filepath.Join(store.dir, cc+".list"), []byte(listBody("203.0.113.9/32")), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got := store.Detect(netip.MustParseAddr("203.0.113.9"), []string{"ru", "by"})
	if got != "ru" {
		t.Fatalf("Detect = %q, want first candidate ru", got)
	}
	if got := store.Detect(netip.MustParseAddr("2001:db8::1"), []string{"ru"}); got != "" {
		t.Fatalf("Detect IPv6 = %q, want empty", got)
	}
}

func listBody(first string) string {
	var body strings.Builder
	body.WriteString(first + "\n")
	for i := 0; i < minPrefixes-1; i++ {
		fmt.Fprintf(&body, "10.%d.%d.0/24\n", i/256, i%256)
	}
	return body.String()
}
