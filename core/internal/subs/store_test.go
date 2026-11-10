package subs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreviewURLBodyAndHeaders(t *testing.T) {
	body := "hy2://auth@one.example:443#first"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-hwid") == "" || r.Header.Get("x-device-os") != "Windows" || !strings.HasPrefix(r.UserAgent(), "Mistgate/") {
			t.Errorf("missing fetch headers: %#v", r.Header)
		}
		w.Header().Set("subscription-userinfo", "upload=12; download=34; total=1000; expire=1700000000")
		w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Panel title")))
		w.Header().Set("profile-update-interval", "4")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := openTestStore(t, t.TempDir(), server)
	preview, err := store.Preview(context.Background(), server.URL+"/sub?token=private-token")
	if err != nil {
		t.Fatal(err)
	}
	if preview.ID != "" || preview.Kind != "url" || preview.Name != "Panel title" || preview.Host != strings.TrimPrefix(server.URL, "https://") {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	if preview.UsedBytes != 46 || preview.TotalBytes != 1000 || preview.ExpireUnix != 1700000000 {
		t.Fatalf("subscription headers not parsed: %#v", preview)
	}
	if len(preview.Servers) != 1 || preview.Servers[0].Name != "first" || preview.Servers[0].Protocol != "hysteria2" {
		t.Fatalf("subscription body not parsed: %#v", preview.Servers)
	}
	if parseInterval("0") != 1 || parseInterval("3") != 3 || parseInterval("") != 12 {
		t.Fatal("refresh interval parsing failed")
	}
}

func TestPreviewBase64AndUnsupportedEntries(t *testing.T) {
	plain := "hysteria2://auth@one.example:443#First\nhy2://auth@two.example:443#Second"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(plain))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(encoded))
	}))
	defer server.Close()
	store := openTestStore(t, t.TempDir(), server)
	preview, err := store.Preview(context.Background(), server.URL+"/sub")
	if err != nil || len(preview.Servers) != 2 {
		t.Fatalf("base64 preview = %#v, %v", preview, err)
	}

	entries := "vless://unsupported\nhy2://broken\nnot a link\nhy2://auth@ok.example:443#Working"
	preview, err = store.Preview(context.Background(), entries)
	if err != nil || preview.Unsupported != 2 || len(preview.Servers) != 1 {
		t.Fatalf("mixed links preview = %#v, %v", preview, err)
	}
	if _, err := store.Preview(context.Background(), "vless://unsupported\nhy2://broken"); errorCode(err) != "no_servers" {
		t.Fatalf("unsupported-only error = %v", err)
	}
	if _, _, _, err := parseURLBody("{\"proxies\": []}", ""); errorCode(err) != "unsupported_format" {
		t.Fatalf("JSON error = %v", err)
	}
}

func TestPreviewRejectsHTTPAndFetch404(t *testing.T) {
	store := openTestStore(t, t.TempDir(), nil)
	if _, err := store.Preview(context.Background(), "http://panel.example/sub/token"); errorCode(err) != "insecure_link" {
		t.Fatalf("HTTP preview error = %v", err)
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	store.client = server.Client()
	if _, err := store.Preview(context.Background(), server.URL+"/sub"); errorCode(err) != "bad_link" {
		t.Fatalf("404 preview error = %v", err)
	}
}

func TestAddRefreshKeepsIDsAndSecretsPrivate(t *testing.T) {
	var reordered atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reordered.Load() {
			_, _ = fmt.Fprint(w, "hy2://auth-b@two.example:443#Renamed%20Two\nhy2://auth-a@one.example:443#Renamed%20One")
			return
		}
		_, _ = fmt.Fprint(w, "hy2://auth-a@one.example:443#One\nhy2://auth-b@two.example:443#Two")
	}))
	defer server.Close()
	store := openTestStore(t, t.TempDir(), server)
	url := server.URL + "/sub?token=private-token"
	added, err := store.Add(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if len(added.Servers) != 2 {
		t.Fatalf("add returned %d servers", len(added.Servers))
	}
	initial := make(map[string]string)
	for _, item := range added.Servers {
		initial[item.Name] = item.ID
	}
	readded, err := store.Add(context.Background(), url)
	if err != nil || readded.ID != added.ID {
		t.Fatalf("re-add id = %q, %v; want %q", readded.ID, err, added.ID)
	}
	reordered.Store(true)
	refreshed, err := store.Refresh(context.Background(), added.ID)
	if err != nil || len(refreshed.Servers) != 2 {
		t.Fatalf("refresh = %#v, %v", refreshed, err)
	}
	for _, item := range refreshed.Servers {
		want := ""
		switch item.Name {
		case "Renamed Two":
			want = initial["Two"]
		case "Renamed One":
			want = initial["One"]
		}
		if item.ID != want {
			t.Errorf("renamed server id = %q, want %q", item.ID, want)
		}
	}
	encoded, err := json.Marshal(store.List())
	if err != nil {
		t.Fatal(err)
	}
	public := string(encoded)
	for _, secret := range []string{"private-token", "auth-a", "auth-b"} {
		if strings.Contains(public, secret) {
			t.Errorf("List JSON leaked %q: %s", secret, public)
		}
	}
}

func TestStoreRoundTripAndFailedRefresh(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, "hysteria2://private-auth@node.example:443#Node")
	}))
	defer server.Close()
	dir := t.TempDir()
	store := openTestStore(t, dir, server)
	added, err := store.Add(context.Background(), server.URL+"/sub?token=secret-token")
	if err != nil {
		t.Fatal(err)
	}
	before := store.state.InstallID
	reopened, err := openStore(dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	reopened.client = server.Client()
	if reopened.state.InstallID != before || len(reopened.List()) != 1 {
		t.Fatalf("store round trip lost state: %#v", reopened.List())
	}
	profiles, err := reopened.Profiles()
	if err != nil || len(profiles) != 1 || profiles[0].Sub != added.ID || profiles[0].Hy2.Auth != "private-auth" {
		t.Fatalf("profiles from reopened store = %#v, %v", profiles, err)
	}
	fail.Store(true)
	failed, err := reopened.Refresh(context.Background(), added.ID)
	if errorCode(err) != "bad_link" || failed.Error != "bad_link" || len(failed.Servers) != 1 {
		t.Fatalf("failed refresh = %#v, %v", failed, err)
	}
	if list := reopened.List(); len(list) != 1 || list[0].Servers[0].ID != added.Servers[0].ID || list[0].Error != "bad_link" {
		t.Fatalf("failed refresh changed or lost stored servers: %#v", list)
	}
}

func TestChangesAndRemove(t *testing.T) {
	store := openTestStore(t, t.TempDir(), nil)
	added, err := store.Add(context.Background(), "hy2://auth@node.example:443#Node")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.Changes():
	case <-time.After(time.Second):
		t.Fatal("Add did not signal a change")
	}
	if err := store.Remove(added.ID); err != nil {
		t.Fatal(err)
	}
	if got := store.List(); len(got) != 0 {
		t.Fatalf("Remove left subscriptions: %#v", got)
	}
}

func TestPreviewAWGAndProfiles(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	conf := "[Interface]\nAddress = 10.66.4.3/32\nPrivateKey = " + key + "\n[Peer]\nPublicKey = " + key + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820"
	store := openTestStore(t, t.TempDir(), nil)
	preview, err := store.Preview(context.Background(), conf)
	if err != nil || preview.ID != "" || preview.Name != "AmneziaWG" || preview.Servers[0].Protocol != "awg" {
		t.Fatalf("AWG preview = %#v, %v", preview, err)
	}
	added, err := store.Add(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := store.Profiles()
	if err != nil || len(profiles) != 1 || profiles[0].Sub != added.ID || profiles[0].AWG == nil {
		t.Fatalf("AWG profiles = %#v, %v", profiles, err)
	}
}

func TestOpenQuarantinesUnparseableStore(t *testing.T) {
	dir := t.TempDir()
	bad := []byte("not a subscription store")
	if err := os.WriteFile(filepath.Join(dir, fileName), bad, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := openStore(dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil || len(store.List()) != 0 {
		t.Fatalf("recovered store = %#v, %v", store, err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "subscriptions.bad")); err != nil || string(got) != string(bad) {
		t.Fatalf("quarantined file = %q, %v", got, err)
	}
}

func openTestStore(t *testing.T, dir string, server *httptest.Server) *Store {
	t.Helper()
	store, err := openStore(dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if server != nil {
		store.client = server.Client()
	}
	return store
}

func identityProtection(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }

func TestLinksOnOneLine(t *testing.T) {
	text := "hysteria2://a@203.0.113.5:443/?insecure=1#One two hy2://b@203.0.113.6:443/?insecure=1#Three\tvless://x@example.com:443#other"
	servers, _, unsupported, err := parseEntries(text, "sub")
	if err != nil || len(servers) != 2 || unsupported != 1 {
		t.Fatalf("got %d servers, %d unsupported, err %v", len(servers), unsupported, err)
	}
	if servers[0].Name != "One two" || servers[1].Name != "Three" {
		t.Fatalf("names: %q, %q", servers[0].Name, servers[1].Name)
	}
}
