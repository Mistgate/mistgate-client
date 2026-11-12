package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestUpdateReplacesFreshListsAndListsReportThem(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/geoip/ru":
			_, _ = w.Write([]byte(listBody("203.0.113.8/32")))
		case "/site/youtube":
			_, _ = w.Write([]byte("+.youtube.com\n+.googlevideo.com\n"))
		case "/custom":
			_, _ = w.Write([]byte("youtube.com\nexample.org\n"))
		case "/site/bad":
			_, _ = w.Write([]byte("# no domains here\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	dataDir := t.TempDir()
	store, err := Open(dataDir, Options{
		HTTPClient:              server.Client(),
		PrimaryURLTemplate:      server.URL + "/geoip/%s",
		FallbackURLTemplate:     server.URL + "/geoip/%s",
		SitePrimaryURLTemplate:  server.URL + "/site/%s",
		SiteFallbackURLTemplate: server.URL + "/site/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	custom := "list:" + server.URL + "/custom"
	// every list is a day-fresh copy of old content: only Update replaces it
	hourAgo := time.Now().Add(-time.Hour)
	for name, body := range map[string]string{
		"ru.list":           listBody("203.0.113.7/32"),
		"site-youtube.list": "old.example\n",
		"site-bad.list":     "old.example\n",
		"site-gone.list":    "old.example\n",
	} {
		path := filepath.Join(store.dir, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, hourAgo, hourAgo); err != nil {
			t.Fatal(err)
		}
	}
	path, _, _ := siteCachePath(store.dir, custom)
	if err := os.WriteFile(path, []byte("old.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, hourAgo, hourAgo); err != nil {
		t.Fatal(err)
	}
	rules := Rules{
		Direct: Selection{Collections: []string{"geosite:youtube", "geosite:bad", "geosite:gone"}},
		VPN:    Selection{Collections: []string{custom}},
	}
	if _, _, err := store.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	store.Routes("smart", "ru", "")
	<-store.Changes() // SetRules
	if before := store.Lists(); before.Unique != 1 || before.Duplicates != 3 {
		t.Fatalf("lists before = %#v; want one entry shared by four collections", before)
	}

	start := time.Now()
	store.Update(context.Background(), "ru")
	waitForChange(t, store.Changes())

	lists := store.Lists()
	want := map[string]struct {
		entries int
		fresh   bool
		err     string
	}{
		"region:ru":       {minPrefixes, true, ""},
		"geosite:youtube": {2, true, ""},
		"geosite:bad":     {1, false, "bad_list"},
		"geosite:gone":    {1, false, "fetch_failed"},
		custom:            {2, true, ""},
	}
	if len(lists.Lists) != len(want) {
		t.Fatalf("lists = %#v", lists)
	}
	for _, row := range lists.Lists {
		w, ok := want[row.ID]
		if !ok || row.Entries != w.entries || row.Error != w.err || (row.UpdatedUnix >= start.Unix()) != w.fresh {
			t.Errorf("row %#v; want %+v", row, w)
		}
	}
	// youtube.com is in two collections; old.example in the failed ones
	if lists.Unique != 4 || lists.Duplicates != 2 {
		t.Errorf("unique/duplicates = %d/%d; want 4/2", lists.Unique, lists.Duplicates)
	}
	// a failed list keeps working from its old copy
	if active := store.ActiveSiteRules(); !active.Direct.Match("old.example") || !active.Direct.Match("www.youtube.com") || !active.VPN.Match("example.org") {
		t.Error("active rules lost a list after Update")
	}
	if set, ok := store.Region("ru"); !ok || !set.Contains(netip.MustParseAddr("203.0.113.8")) {
		t.Error("region list was not replaced")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/geoip/ru"] != 1 || hits["/site/youtube"] != 1 || hits["/custom"] != 1 {
		t.Errorf("downloads = %v", hits)
	}
}

func TestUpdateRunsOnceAtATime(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte(listBody("203.0.113.7/32")))
	}))
	defer server.Close()
	store, err := Open(t.TempDir(), Options{HTTPClient: server.Client(), PrimaryURLTemplate: server.URL + "/%s", FallbackURLTemplate: server.URL + "/%s"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		store.Update(context.Background(), "ru")
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("update did not start downloading")
	}
	time.AfterFunc(100*time.Millisecond, func() { close(release) })
	store.Update(context.Background(), "ru") // the first still holds the download: this one only waits
	<-done
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("two overlapping updates downloaded %d times; want 1", hits)
	}
}
