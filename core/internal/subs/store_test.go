package subs

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

func TestPreviewURLBodyAndHeaders(t *testing.T) {
	body := "hy2://auth@one.example:443#first"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-hwid") == "" || r.Header.Get("x-device-os") != "Windows" || r.UserAgent() != "mihomo/1.19.33 Mistgate/0.0.1 (Windows)" {
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
	if _, _, _, _, err := parseURLBody("{\"proxies\": []}", ""); errorCode(err) != "unsupported_format" {
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

func TestLink(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hy2://auth@one.example:443#first"))
	}))
	defer server.Close()
	store := openTestStore(t, t.TempDir(), server)
	link := server.URL + "/sub?token=private-token"
	added, err := store.Add(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.Link(added.ID); err != nil || got != link {
		t.Fatalf("Link(url) = %q, %v", got, err)
	}
	links, err := store.Add(context.Background(), "hy2://auth@two.example:443#second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Link(links.ID); errorCode(err) != "no_link" {
		t.Fatalf("Link(links) = %v", err)
	}
	if _, err := store.Link("missing"); errorCode(err) != "unknown_subscription" {
		t.Fatalf("Link(missing) = %v", err)
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
	servers, _, unsupported, _, err := parseEntries(text, "sub")
	if err != nil || len(servers) != 2 || unsupported != 1 {
		t.Fatalf("got %d servers, %d unsupported, err %v", len(servers), unsupported, err)
	}
	if servers[0].Name != "One two" || servers[1].Name != "Three" {
		t.Fatalf("names: %q, %q", servers[0].Name, servers[1].Name)
	}
}

func TestParseEntriesHysteriaPortHoppingLinks(t *testing.T) {
	for _, link := range []string{
		"hy2://auth@hop.example:443?mport=20000-20100#Mport",
		"hy2://auth@hop.example:20000-20100#PortRange",
	} {
		servers, entries, _, _, err := parseEntries(link, "sub")
		if err != nil || len(servers) != 1 || len(entries) != 1 {
			t.Errorf("parseEntries(%q) = %#v, %v", link, servers, err)
			continue
		}
		parsed, err := profile.ParseHy2(entries[0].Raw)
		if err != nil || parsed.Ports != "20000-20100" {
			t.Errorf("parsed profile from %q = %#v, %v", link, parsed, err)
		}
	}
}

func TestMihomoProfileSubscription(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := mihomoProfileFixture(key)
	var renamed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-hwid") == "" || r.Header.Get("x-device-os") != "Windows" || r.UserAgent() != "mihomo/1.19.33 Mistgate/0.0.1 (Windows)" {
			t.Errorf("unexpected subscription headers: %#v", r.Header)
		}
		responseBody := body
		if renamed.Load() {
			responseBody = strings.Replace(body, "name: Hysteria Gecko", "name: Renamed Hysteria Gecko", 1)
		}
		_, _ = fmt.Fprint(w, responseBody)
	}))
	defer server.Close()
	store := openTestStore(t, t.TempDir(), server)
	added, err := store.Add(context.Background(), server.URL+"/sub")
	if err != nil || len(added.Servers) != 5 || added.Unsupported != 2 {
		t.Fatalf("Mihomo subscription = %#v, %v", added, err)
	}
	wantNames := []string{"Hysteria Gecko", "Hysteria Hop", "AWG 2", "AWG 3", "Plain WG"}
	for i, name := range wantNames {
		if added.Servers[i].Name != name {
			t.Fatalf("server %d name = %q, want %q", i, added.Servers[i].Name, name)
		}
	}
	if added.Servers[0].Protocol != "hysteria2" || added.Servers[1].Protocol != "hysteria2" ||
		added.Servers[2].Protocol != "awg" || added.Servers[3].Protocol != "awg" || added.Servers[4].Protocol != "awg" {
		t.Fatalf("unexpected protocols: %#v", added.Servers)
	}
	profiles, err := store.Profiles()
	if err != nil || len(profiles) != 5 {
		t.Fatalf("Mihomo profiles = %d, %v", len(profiles), err)
	}
	gecko := profiles[0].Hy2
	if gecko == nil || gecko.Auth != "h2-gecko-auth" || gecko.Host != "gecko.example" || gecko.Port != 443 ||
		gecko.ServerName != "sni.gecko.example" || gecko.Obfs != "gecko" || gecko.ObfsPassword != "gecko-password" || !gecko.Insecure || len(gecko.ALPN) != 1 || gecko.ALPN[0] != "h3" {
		t.Fatalf("Hysteria2 Gecko profile = %#v", gecko)
	}
	hop := profiles[1].Hy2
	if hop == nil || hop.Obfs != "salamander" || hop.Ports != "20000-20100" || hop.HopInterval != 45*time.Second || !hop.HasPin {
		t.Fatalf("Hysteria2 hopping profile = %#v", hop)
	}
	if profiles[2].AWG == nil || profiles[3].AWG == nil || profiles[4].AWG == nil {
		t.Fatal("WireGuard profiles did not round-trip")
	}
	for _, line := range []string{"jc=5\n", "h1=1-2\n", "h2=3-4\n", "allowed_ip=0.0.0.0/0\n", "endpoint=198.51.100.20:51820\n"} {
		if !strings.Contains(profiles[2].AWG.UAPI(netip.MustParseAddrPort("198.51.100.20:51820")), line) {
			t.Errorf("AWG 2 UAPI missing %q", line)
		}
	}
	for _, line := range []string{
		"header_protection_key=" + strings.Repeat("00", 32) + "\n", "content_padding_addition=20-63\n",
		"rekey_after_time=124-145\n", "rekey_timeout=6-8\n", "reject_after_time=190-207\n",
		"keepalive_timeout=14-20\n", "max_handshake_attempts=16-20\n", "random_trailers=true\n", "disable_cookies=false\n",
		"endpoint=198.51.100.21:51821\n",
	} {
		if !strings.Contains(profiles[3].AWG.UAPI(netip.MustParseAddrPort("198.51.100.21:51821")), line) {
			t.Errorf("AWG 3 UAPI missing %q", line)
		}
	}
	plainUAPI := profiles[4].AWG.UAPI(netip.MustParseAddrPort("198.51.100.22:51822"))
	if strings.Contains(plainUAPI, "jc=") || !strings.Contains(plainUAPI, "endpoint=198.51.100.22:51822\n") {
		t.Fatalf("plain WireGuard UAPI = %q", plainUAPI)
	}
	encoded, err := json.Marshal(store.List())
	if err != nil {
		t.Fatal(err)
	}
	public := string(encoded)
	for _, secret := range []string{"h2-gecko-auth", "gecko-password", "h2-hop-auth", "salamander-password", key} {
		if strings.Contains(public, secret) {
			t.Errorf("List JSON leaked %q", secret)
		}
	}
	renamed.Store(true)
	refreshed, err := store.Refresh(context.Background(), added.ID)
	if err != nil || len(refreshed.Servers) != len(added.Servers) || refreshed.Servers[0].Name != "Renamed Hysteria Gecko" {
		t.Fatalf("renamed Mihomo refresh = %#v, %v", refreshed, err)
	}
	for i := range added.Servers {
		if refreshed.Servers[i].ID != added.Servers[i].ID {
			t.Errorf("proxy %q changed id after rename", added.Servers[i].Name)
		}
	}
}

func TestMihomoRequiresValidYAMLProxies(t *testing.T) {
	for _, body := range []string{"name: Missing proxies", "proxies: ["} {
		if _, _, _, _, err := parseURLBody(body, "sub"); errorCode(err) != "unsupported_format" {
			t.Errorf("parseURLBody(%q) error = %v", body, err)
		}
	}
}

func TestHy2ProxyHopIntervalNumberAndString(t *testing.T) {
	for _, value := range []any{45, "45"} {
		got, err := parseHy2Proxy(map[string]any{
			"server": "hop.example", "port": 443, "password": "auth", "hop-interval": value,
		})
		if err != nil || got.HopInterval != 45*time.Second {
			t.Errorf("hop interval %v = %#v, %v", value, got, err)
		}
	}
}

func TestAnnounceNoticeAndRefusal(t *testing.T) {
	var refuse atomic.Bool
	var encodedAnnounce atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			w.Header().Set("Announce", "Maintenance window")
			_, _ = fmt.Fprint(w, "proxies:\n  - name: This device was turned off by the owner\n    type: hysteria2\n    server: 127.0.0.1\n    port: 443\n")
			return
		}
		if encodedAnnounce.Load() {
			w.Header().Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte("Encoded notice")))
		} else {
			w.Header().Set("Announce", "Welcome to Mistgate")
		}
		_, _ = fmt.Fprint(w, "hy2://private-auth@node.example:443#Node")
	}))
	defer server.Close()
	store := openTestStore(t, t.TempDir(), server)
	added, err := store.Add(context.Background(), server.URL+"/sub")
	if err != nil || added.Notice != "Welcome to Mistgate" {
		t.Fatalf("plain Announce = %#v, %v", added, err)
	}
	encodedAnnounce.Store(true)
	updated, err := store.Refresh(context.Background(), added.ID)
	if err != nil || updated.Notice != "Encoded notice" {
		t.Fatalf("base64 Announce = %#v, %v", updated, err)
	}
	refuse.Store(true)
	failed, err := store.Refresh(context.Background(), added.ID)
	if errorCode(err) != "refused" || failed.Error != "refused" || failed.Notice != "This device was turned off by the owner" || len(failed.Servers) != 1 {
		t.Fatalf("refused refresh = %#v, %v", failed, err)
	}
	if list := store.List(); len(list) != 1 || list[0].Servers[0].ID != added.Servers[0].ID || list[0].Notice != failed.Notice {
		t.Fatalf("refused refresh lost stored servers or notice: %#v", list)
	}

	firstStore := openTestStore(t, t.TempDir(), server)
	first, err := firstStore.Add(context.Background(), server.URL+"/sub")
	if errorCode(err) != "refused" || first.Notice != "This device was turned off by the owner" {
		t.Fatalf("first refused add = %#v, %v", first, err)
	}
}

func mihomoProfileFixture(key string) string {
	return "proxies:\n" +
		"  - name: Hysteria Gecko\n    type: hysteria2\n    server: gecko.example\n    port: 443\n    password: h2-gecko-auth\n    sni: sni.gecko.example\n    skip-cert-verify: true\n    obfs: gecko\n    obfs-password: gecko-password\n    alpn: [h3]\n" +
		"  - name: Hysteria Hop\n    type: hysteria2\n    server: hop.example\n    port: 8443\n    password: h2-hop-auth\n    obfs: salamander\n    obfs-password: salamander-password\n    ports: 20000-20100\n    hop-interval: \"45\"\n    fingerprint: \"" + strings.Repeat("ab:", 31) + "ab\"\n" +
		"  - name: Unsupported VLESS\n    type: vless\n    server: vless.example\n    port: 443\n" +
		"  - name: AWG 2\n    type: wireguard\n    server: awg2.example\n    port: 51820\n    ip: 10.66.4.2/32\n    ipv6: fd66:66::2/128\n    private-key: " + key + "\n    public-key: " + key + "\n    pre-shared-key: " + key + "\n    allowed-ips: [0.0.0.0/0, \"::/0\"]\n    mtu: 1280\n    persistent-keepalive: 25\n    dns: [1.1.1.1, \"2001:4860:4860::8888\"]\n    amnezia-wg-option:\n      version: \"2.0\"\n      jc: 5\n      jmin: 10\n      jmax: 20\n      h1: \"1-2\"\n      h2: \"3-4\"\n" +
		"  - name: AWG 3\n    type: wireguard\n    server: awg3.example\n    port: 51821\n    ip: 10.66.4.3/32\n    private-key: " + key + "\n    public-key: " + key + "\n    allowed-ips: [0.0.0.0/0]\n    amnezia-wg-option:\n      version: 3\n      header-protection-key: " + key + "\n      content-padding-addition: \"20-63\"\n      rekey-after-time: \"124-145\"\n      rekey-timeout: \"6-8\"\n      reject-after-time: \"190-207\"\n      keepalive-timeout: \"14-20\"\n      max-handshake-attempts: \"16-20\"\n      random-trailers: true\n      disable-cookies: false\n" +
		"  - name: Plain WG\n    type: wireguard\n    server: awg4.example\n    port: 51822\n    ip: 10.66.4.4/32\n    private-key: " + key + "\n    public-key: " + key + "\n    allowed-ips: [0.0.0.0/0]\n" +
		"  - name: Broken proxy\n    type: hysteria2\n    server: broken.example\n    port: 443\n"
}
