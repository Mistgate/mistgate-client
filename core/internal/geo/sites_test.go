package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseSiteLinesAndSuffixMatching(t *testing.T) {
	set, err := parseSites([]byte("+.Example.com\n.example.org\n*.example.net\nexample.io.\n.ua\nПример.РФ\n# comment\n// comment\n\n spaced.example\ntrailing.example \nbad/path\nbad:port\nbad domain\n+bad.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 6 {
		t.Fatalf("site entries = %d; want 6", set.Len())
	}
	for _, name := range []string{"example.com", "a.example.com", "a.b.example.org", "example.net", "example.io", "ua", "co.ua", "поддомен.пример.рф"} {
		if !set.Match(name) {
			t.Errorf("Match(%q) = false", name)
		}
	}
	for _, name := range []string{"notexample.com", "other.org", "example.invalid", "https://example.com/path", "bad_name.example", "spaced.example", "trailing.example"} {
		if set.Match(name) {
			t.Errorf("Match(%q) = true", name)
		}
	}
	if _, err := parseSites([]byte("# comment\n// comment\nnot/a/site\nexample.com:443\n")); err == nil {
		t.Fatal("accepted a site list with no valid domains")
	}
}

func TestSiteFetchFallbackAndCaps(t *testing.T) {
	oversized := []byte(strings.Repeat("x", maxFileBytes+1))
	var mu sync.Mutex
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/primary/youtube":
			w.WriteHeader(http.StatusBadGateway)
		case "/fallback/youtube", "/custom":
			_, _ = w.Write([]byte("+.youtube.com\n"))
		case "/primary/oversize", "/fallback/oversize", "/custom-oversize":
			_, _ = w.Write(oversized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	store, err := Open(t.TempDir(), Options{
		HTTPClient:              server.Client(),
		SitePrimaryURLTemplate:  server.URL + "/primary/%s",
		SiteFallbackURLTemplate: server.URL + "/fallback/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, set, err := store.fetchSites(context.Background(), "geosite:youtube"); err != nil || !set.Match("www.youtube.com") {
		t.Fatalf("GeoSite fallback = %#v, %v", set, err)
	}
	mu.Lock()
	gotRequests := append([]string(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 || gotRequests[0] != "/primary/youtube" || gotRequests[1] != "/fallback/youtube" {
		t.Fatalf("GeoSite request order = %v", gotRequests)
	}
	if _, set, err := store.fetchSites(context.Background(), "list:"+server.URL+"/custom"); err != nil || !set.Match("www.youtube.com") {
		t.Fatalf("custom list fetch = %#v, %v", set, err)
	}
	if _, _, err := store.fetchSites(context.Background(), "geosite:oversize"); err == nil {
		t.Fatal("accepted an oversized GeoSite from both mirrors")
	}
	if _, _, err := store.fetchSites(context.Background(), "list:"+server.URL+"/custom-oversize"); err == nil {
		t.Fatal("accepted an oversized custom list")
	}
}

func TestSiteCacheServesStaleWhileRefreshing(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("new.example\n"))
	}))
	defer server.Close()
	dataDir := t.TempDir()
	cachePath := filepath.Join(dataDir, "geo", "site-youtube.list")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("old.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dataDir, Options{
		HTTPClient:              server.Client(),
		SitePrimaryURLTemplate:  server.URL + "/%s",
		SiteFallbackURLTemplate: server.URL + "/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetRules(Rules{Direct: Selection{Collections: []string{"geosite:youtube"}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.Changes():
	case <-time.After(time.Second):
		t.Fatal("setting route rules did not signal a change")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stale site list did not start a background refresh")
	}
	active := store.ActiveSiteRules()
	if active == nil || !active.Direct.Match("old.example") || active.Direct.Match("new.example") {
		t.Fatal("stale site list was not used while refresh was blocked")
	}
	close(release)
	waitForChange(t, store.Changes())
	active = store.ActiveSiteRules()
	if active == nil || !active.Direct.Match("new.example") || active.Direct.Match("old.example") {
		t.Fatal("refreshed site list was not swapped into the active rule set")
	}
}

func TestRejectsInvalidCollectionsAndPersistsRules(t *testing.T) {
	for _, collection := range []string{
		"list:http://example.com/list",
		"list:https://user:password@example.com/list",
		"list:https://example.com/" + strings.Repeat("x", 510),
	} {
		if _, _, ok := siteCachePath("", collection); ok {
			t.Errorf("accepted collection %q", collection)
		}
	}
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, rules := range []Rules{
		{Direct: Selection{Collections: []string{"geosite:Bad"}}},
		{VPN: Selection{Sites: []string{"example.com/path"}}},
		{Direct: Selection{Collections: make([]string, 201)}},
		{VPN: Selection{Sites: make([]string, 501)}},
	} {
		if _, _, err := store.SetRules(rules); err != ErrBadRules {
			t.Errorf("SetRules(%#v) error = %v; want ErrBadRules", rules, err)
		}
	}
	want := Rules{
		Direct: Selection{Sites: []string{"https://Example.com/x"}},
		VPN:    Selection{Sites: []string{"VPN.Example"}},
	}
	if got, changed, err := store.SetRules(want); err != nil || !changed || got.Direct.Sites[0] != "example.com" || got.VPN.Sites[0] != "vpn.example" {
		t.Fatalf("SetRules = %#v, %t, %v", got, changed, err)
	}
	reopened, err := Open(filepath.Dir(store.routesPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.GetRules(); !sameRules(got, store.GetRules()) {
		t.Fatalf("reopened rules = %#v; want %#v", got, store.GetRules())
	}
}
