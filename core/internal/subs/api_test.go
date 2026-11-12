package subs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePanel plays a Mistgate panel: the plain subscription, enrol, sync and leave.
type fakePanel struct {
	mu     sync.Mutex
	t      *testing.T
	store  *Store
	server *httptest.Server

	discover bool   // announce the Client API on the plain answer
	plain    string // the plain subscription body

	enrolFail  int    // enrol requests recorded and then answered with a broken page
	enrolCode  string // answer enrol with this error code
	enrolKeys  []string
	enrolAuth  []string
	enrolHwids []string
	keyOnDisk  []bool // the key was in the store file when the request arrived
	plainHwids []string

	syncStatus  int // 0 = 200
	syncBody    string
	errBody     string // the body of a syncStatus answer
	syncRetry   string
	etag        string
	syncAuth    []string
	syncINM     []string
	leaves      int
	leaveStatus int
	leaveAuth   []string
}

func newPanel(t *testing.T, discover bool) *fakePanel {
	p := &fakePanel{t: t, discover: discover, plain: "hy2://auth@plain.example:443#Plain", syncBody: syncDoc("active")}
	p.server = httptest.NewTLSServer(p)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakePanel) link(token string) string { return p.server.URL + "/sub/" + token }

func (p *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Header.Get("X-Mistgate-Caps") != capsHeader {
		p.t.Errorf("caps header = %q", r.Header.Get("X-Mistgate-Caps"))
	}
	api := strings.Contains(r.URL.Path, "/client/")
	if api && r.UserAgent() != "Mistgate/0.0.1 (Windows)" {
		p.t.Errorf("API user agent = %q", r.UserAgent())
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/client/enrol"):
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req) != 5 || req["platform"] != "windows" || req["model"] != "" {
			p.t.Errorf("enrol body = %v, %v", req, err)
		}
		for _, key := range []string{"hwid", "platform", "model", "os_version", "device_key"} {
			if _, ok := req[key]; !ok {
				p.t.Errorf("enrol body lacks %q", key)
			}
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Method != http.MethodPost {
			p.t.Errorf("enrol request: %s %q", r.Method, r.Header.Get("Content-Type"))
		}
		data, _ := os.ReadFile(p.store.path)
		p.enrolKeys = append(p.enrolKeys, req["device_key"])
		p.enrolHwids = append(p.enrolHwids, req["hwid"])
		p.enrolAuth = append(p.enrolAuth, r.Header.Get("Authorization"))
		p.keyOnDisk = append(p.keyOnDisk, bytes.Contains(data, []byte(req["device_key"])))
		switch {
		case p.enrolFail > 0:
			p.enrolFail--
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		case p.enrolCode != "":
			w.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, p.enrolCode)
		default:
			_, _ = fmt.Fprintf(w, `{"device_id":"dev_1","base":%q,"sync_every_s":3600}`, p.server.URL+"/client")
		}
	case strings.HasSuffix(r.URL.Path, "/client/sync"):
		p.syncAuth = append(p.syncAuth, r.Header.Get("Authorization"))
		p.syncINM = append(p.syncINM, r.Header.Get("If-None-Match"))
		if p.syncStatus != 0 {
			if p.syncRetry != "" {
				w.Header().Set("Retry-After", p.syncRetry)
			}
			w.WriteHeader(p.syncStatus)
			_, _ = w.Write([]byte(p.errBody))
			return
		}
		if p.etag != "" {
			if r.Header.Get("If-None-Match") == p.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", p.etag)
		}
		_, _ = w.Write([]byte(p.syncBody))
	case strings.HasSuffix(r.URL.Path, "/client/leave"):
		p.leaves++
		p.leaveAuth = append(p.leaveAuth, r.Header.Get("Authorization"))
		if p.leaveStatus != 0 {
			w.WriteHeader(p.leaveStatus)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		p.plainHwids = append(p.plainHwids, r.Header.Get("X-HWID"))
		if p.discover {
			w.Header().Set("Mistgate-Client-Api", "1")
		}
		_, _ = w.Write([]byte(p.plain))
	}
}

func (p *fakePanel) set(change func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change()
}

func (p *fakePanel) openStore(t *testing.T) *Store {
	store := openTestStore(t, t.TempDir(), p.server)
	p.store = store
	return store
}

const apiTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes

func syncDoc(status string, servers ...map[string]any) string {
	doc := map[string]any{
		"v": 1, "device_id": "dev_1", "status": status, "sync_every_s": 3600,
		"brand":   map[string]any{"parts": []string{"Mist", "gate"}},
		"plan":    map[string]any{"expires_unix": 1700000000, "quota_bytes": 100, "used_bytes": 7},
		"servers": append([]map[string]any{}, servers...),
	}
	data, _ := json.Marshal(doc)
	return string(data)
}

func apiServer(city, country string, paths ...map[string]any) map[string]any {
	return map[string]any{"id": "srv_" + city + country, "city": city, "country": country, "paths": paths}
}

func apiPath(id, protocol, via string, ipv6 bool, settings map[string]any) map[string]any {
	return map[string]any{"id": id, "protocol": protocol, "via": via, "ipv6": ipv6, "settings": settings}
}

func awgSettings(host string, port int, params map[string]any) map[string]any {
	return map[string]any{
		"version": "2.0", "endpoint": map[string]any{"host": host, "port": port},
		"public_key": apiTestKey, "private_key": apiTestKey, "preshared_key": apiTestKey,
		"address_v4": "10.66.4.2/32", "address_v6": "fd66:66::2/128", "allowed_ips": []string{"0.0.0.0/0", "::/0"},
		"dns": []string{"1.1.1.1"}, "mtu": 1280, "keepalive_s": 25, "params": params,
	}
}

func mappingDoc() string {
	pin := strings.Repeat("ab", 32)
	return syncDoc("active",
		apiServer("Frankfurt", "DE",
			apiPath("pth_gecko", "hysteria2", "direct", false, map[string]any{
				"server": "gecko.example", "port": 443, "ports": "20000-30000", "hop_interval_s": 30, "auth": "api-auth-gecko",
				"tls": "ca", "sni": "sni.example", "alpn": []string{"h3"}, "obfs": map[string]any{"type": "gecko", "password": "api-obfs-pass"},
			}),
			apiPath("pth_pin", "hysteria2", "relay", false, map[string]any{
				"server": "pin.example", "port": 8443, "auth": "api-auth-pin", "tls": "pin", "pin_sha256": pin,
			}),
			apiPath("pth_ca6", "hysteria2", "direct", true, map[string]any{
				"server": "2001:db8::9", "port": 443, "auth": "api-auth-ca6", "tls": "ca",
			}),
			apiPath("pth_broken", "hysteria2", "direct", false, map[string]any{
				"server": "x.example", "port": 443, "auth": "a", "tls": "insecure",
			}),
		),
		apiServer("", "NL", apiPath("pth_awg2", "awg", "warp", false, awgSettings("awg2.example", 51820, map[string]any{
			"jc": 5, "jmin": 10, "jmax": 20, "s1": 15, "s2": 18, "h1": "1-2", "h2": "3-4", "h3": "5", "h4": "6", "i1": "<b 0xdead>",
		}))),
		apiServer("Tokyo", "JP", apiPath("pth_awg31", "awg", "direct", false, awgSettings("2001:db8::7", 51821, map[string]any{
			"jc": 4, "header_protection_key": apiTestKey, "random_trailers": true, "disable_cookies": false,
			"content_padding_addition": "20-63", "rekey_after_time": "124-145", "rekey_timeout": "6-8",
			"reject_after_time": "190-207", "keepalive_timeout": "14-20", "max_handshake_attempts": "16-20",
		}))),
	)
}

func TestClientAPIEnrolSyncAndMapping(t *testing.T) {
	panel := newPanel(t, true)
	store := panel.openStore(t)
	ctx := context.Background()

	if _, err := store.Preview(ctx, panel.link("tok")); err != nil || len(panel.enrolKeys) != 0 {
		t.Fatalf("preview must not enrol: %v, %d enrols", err, len(panel.enrolKeys))
	}
	panel.set(func() { panel.enrolFail = 1 })
	added, err := store.Add(ctx, panel.link("tok"))
	if err != nil || added.Managed || added.Error != "fetch_failed" || len(added.Servers) != 1 || added.Servers[0].Name != "Plain" {
		t.Fatalf("add with a lost enrol answer = %#v, %v", added, err)
	}
	if len(panel.enrolKeys) != 1 || !panel.keyOnDisk[0] || panel.enrolAuth[0] != "" {
		t.Fatalf("the key must be on disk before the request: %v %v %q", panel.enrolKeys, panel.keyOnDisk, panel.enrolAuth)
	}
	if panel.enrolHwids[0] != store.state.InstallID || panel.plainHwids[0] != store.state.InstallID {
		t.Fatalf("first enrol must take over the device the plain fetch made: %v %v", panel.enrolHwids, panel.plainHwids)
	}

	panel.set(func() { panel.syncBody = mappingDoc() })
	refreshed, err := store.Refresh(ctx, added.ID)
	if err != nil || !refreshed.Managed || refreshed.Error != "" || refreshed.Name != "Mistgate" {
		t.Fatalf("refresh after the lost answer = %#v, %v", refreshed, err)
	}
	if len(panel.enrolKeys) != 2 || panel.enrolKeys[1] != panel.enrolKeys[0] || panel.enrolAuth[1] != "" {
		t.Fatalf("a repeated enrol must send the same key: %v %v", panel.enrolKeys, panel.enrolAuth)
	}
	key := panel.enrolKeys[0]
	if raw, err := base64.RawURLEncoding.DecodeString(key); err != nil || len(raw) != 32 {
		t.Fatalf("device key is not 32 bytes of base64url: %q", key)
	}
	if panel.syncAuth[0] != "Bearer "+key || panel.syncINM[0] != "" {
		t.Fatalf("sync request: %v %v", panel.syncAuth, panel.syncINM)
	}
	if len(store.state.Pending) != 0 {
		t.Fatal("the pending key was not dropped after the first sync")
	}
	if refreshed.UsedBytes != 7 || refreshed.TotalBytes != 100 || refreshed.ExpireUnix != 1700000000 || refreshed.Unsupported != 1 {
		t.Fatalf("plan or unsupported not mapped: %#v", refreshed)
	}
	wantNames := []string{"Frankfurt", "Frankfurt · relay", "Frankfurt · IPv6", "NL · warp", "Tokyo"}
	wantIDs := []string{"pth_gecko", "pth_pin", "pth_ca6", "pth_awg2", "pth_awg31"}
	if len(refreshed.Servers) != 5 {
		t.Fatalf("servers = %#v", refreshed.Servers)
	}
	for i, server := range refreshed.Servers {
		if server.Name != wantNames[i] || server.ID != wantIDs[i] {
			t.Errorf("server %d = %#v, want %q %q", i, server, wantIDs[i], wantNames[i])
		}
	}

	profiles, err := store.Profiles()
	if err != nil || len(profiles) != 5 {
		t.Fatalf("profiles = %d, %v", len(profiles), err)
	}
	gecko := profiles[0].Hy2
	if gecko == nil || gecko.Host != "gecko.example" || gecko.Port != 443 || gecko.Auth != "api-auth-gecko" || gecko.Ports != "20000-30000" ||
		gecko.HopInterval != 30*time.Second || gecko.ServerName != "sni.example" || gecko.Obfs != "gecko" || gecko.ObfsPassword != "api-obfs-pass" ||
		gecko.HasPin || gecko.Insecure || len(gecko.ALPN) != 1 {
		t.Fatalf("gecko profile = %#v", gecko)
	}
	pin := profiles[1].Hy2
	if pin == nil || !pin.HasPin || pin.Insecure || pin.PinSHA256[0] != 0xab || pin.Port != 8443 || pin.Obfs != "none" || pin.ServerName != "pin.example" {
		t.Fatalf("pinned profile = %#v", pin)
	}
	ca := profiles[2].Hy2
	if ca == nil || ca.Host != "2001:db8::9" || ca.ServerName != "2001:db8::9" || ca.HasPin || ca.Insecure {
		t.Fatalf("CA profile without sni = %#v", ca)
	}
	awg2 := profiles[3].AWG.UAPI(netip.MustParseAddrPort("198.51.100.20:51820"))
	for _, line := range []string{"jc=5\n", "jmin=10\n", "jmax=20\n", "s1=15\n", "s2=18\n", "h1=1-2\n", "h2=3-4\n", "h3=5\n", "h4=6\n", "i1=<b 0xdead>\n",
		"persistent_keepalive_interval=25\n", "allowed_ip=::/0\n", "endpoint=198.51.100.20:51820\n"} {
		if !strings.Contains(awg2, line) {
			t.Errorf("AWG 2.0 UAPI lacks %q", line)
		}
	}
	if profiles[3].AWG.MTU != 1280 || len(profiles[3].AWG.Addresses) != 2 || len(profiles[3].AWG.DNS) != 1 {
		t.Errorf("AWG 2.0 interface = %#v", profiles[3].AWG)
	}
	awg31 := profiles[4].AWG
	if awg31.EndpointHost != "2001:db8::7" || awg31.EndpointPort != 51821 {
		t.Fatalf("bare IPv6 endpoint = %q %d", awg31.EndpointHost, awg31.EndpointPort)
	}
	uapi := awg31.UAPI(netip.MustParseAddrPort("[2001:db8::7]:51821"))
	for _, line := range []string{"jc=4\n", "header_protection_key=" + strings.Repeat("00", 32) + "\n", "content_padding_addition=20-63\n",
		"rekey_after_time=124-145\n", "rekey_timeout=6-8\n", "reject_after_time=190-207\n", "keepalive_timeout=14-20\n",
		"max_handshake_attempts=16-20\n", "random_trailers=true\n", "disable_cookies=false\n", "endpoint=[2001:db8::7]:51821\n"} {
		if !strings.Contains(uapi, line) {
			t.Errorf("AWG 3.1 UAPI lacks %q", line)
		}
	}

	encoded, _ := json.Marshal(store.List())
	for _, secret := range []string{key, "api-auth-gecko", "api-auth-pin", "api-obfs-pass", apiTestKey, "/tok", "pth_broken\"", "10.66.4.2"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("List JSON leaked %q", secret)
		}
	}
	if len(store.due(time.Now().Unix())) != 0 || len(store.due(time.Now().Unix()+3600+400)) != 1 {
		t.Errorf("managed subscription is due at the wrong time: %v", store.state.Subscriptions[0].NextUnix-time.Now().Unix())
	}
}

func TestClientAPIPlainWithoutHeaderAndHwidPerOrigin(t *testing.T) {
	ctx := context.Background()
	plain := newPanel(t, false)
	store := plain.openStore(t)
	added, err := store.Add(ctx, plain.link("tok"))
	if err != nil || added.Managed || added.Error != "" || len(plain.enrolKeys) != 0 || plain.plainHwids[0] != store.state.InstallID {
		t.Fatalf("panel without the header: %#v, %v, %d enrols", added, err, len(plain.enrolKeys))
	}
	if len(store.state.Hwids) != 1 || len(store.state.Pending) != 0 {
		t.Fatalf("only the origin's hwid should be remembered: %#v %#v", store.state.Hwids, store.state.Pending)
	}

	one, two := newPanel(t, true), newPanel(t, true)
	one.store, two.store = store, store
	store.client = one.server.Client()
	two.set(func() { two.enrolFail = 1 })
	if _, err := store.Add(ctx, one.link("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(ctx, one.link("b")); err != nil {
		t.Fatal(err)
	}
	second, err := store.Add(ctx, two.link("a"))
	if err != nil || second.Managed {
		t.Fatalf("second panel = %#v, %v", second, err)
	}
	if one.enrolHwids[0] != one.enrolHwids[1] || one.enrolHwids[0] == two.enrolHwids[0] || two.enrolHwids[0] == "" {
		t.Fatalf("hwid per origin: %v %v", one.enrolHwids, two.enrolHwids)
	}
	if _, err := store.Refresh(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if two.plainHwids[0] == store.state.InstallID || two.plainHwids[0] != two.enrolHwids[0] || two.plainHwids[1] != two.enrolHwids[0] || two.enrolHwids[1] != two.enrolHwids[0] {
		t.Fatalf("the plain fetch and enrol must send the origin's own hwid from the first contact: %v %v", two.plainHwids, two.enrolHwids)
	}
}

func managedStore(t *testing.T) (*fakePanel, *Store, Subscription) {
	panel := newPanel(t, true)
	store := panel.openStore(t)
	panel.set(func() {
		panel.syncBody = syncDoc("active", apiServer("Oslo", "NO", apiPath("pth_1", "hysteria2", "direct", false, map[string]any{
			"server": "oslo.example", "port": 443, "auth": "api-auth-oslo", "tls": "ca",
		})))
	})
	added, err := store.Add(context.Background(), panel.link("tok"))
	if err != nil || !added.Managed || len(added.Servers) != 1 {
		t.Fatalf("managed add = %#v, %v", added, err)
	}
	return panel, store, added
}

func TestClientAPISyncAnswers(t *testing.T) {
	ctx := context.Background()

	t.Run("decoy and retry-after keep everything", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		key := store.state.Subscriptions[0].Key
		panel.set(func() { panel.syncStatus, panel.errBody = 404, "<html>not found</html>" })
		got, err := store.Refresh(ctx, sub.ID)
		if errorCode(err) != "fetch_failed" || got.Error != "fetch_failed" || !got.Managed || len(got.Servers) != 1 || store.state.Subscriptions[0].Key != key {
			t.Fatalf("decoy = %#v, %v", got, err)
		}
		panel.set(func() { panel.syncStatus, panel.errBody, panel.syncRetry = 429, `{"error":"too_many_requests"}`, "120" })
		if _, err = store.Refresh(ctx, sub.ID); errorCode(err) != "fetch_failed" {
			t.Fatal(err)
		}
		if wait := store.state.Subscriptions[0].NextUnix - time.Now().Unix(); wait < 118 || wait > 121 {
			t.Fatalf("Retry-After not honoured: next sync in %d s", wait)
		}
		panel.set(func() { panel.syncStatus = 0 })
		if got, err = store.Refresh(ctx, sub.ID); err != nil || got.Error != "" || len(got.Servers) != 1 {
			t.Fatalf("recovery = %#v, %v", got, err)
		}
	})

	t.Run("etag, not modified, unsupported version, expired", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		panel.set(func() { panel.etag = `"v1"` })
		if _, err := store.Refresh(ctx, sub.ID); err != nil {
			t.Fatal(err)
		}
		got, err := store.Refresh(ctx, sub.ID)
		if err != nil || len(got.Servers) != 1 || panel.syncINM[len(panel.syncINM)-1] != `"v1"` {
			t.Fatalf("304 = %#v, %v, %v", got, err, panel.syncINM)
		}
		panel.set(func() { panel.etag, panel.syncBody = "", strings.Replace(panel.syncBody, `"v":1`, `"v":2`, 1) })
		got, err = store.Refresh(ctx, sub.ID)
		if errorCode(err) != "unsupported_format" || got.Error != "unsupported_format" || len(got.Servers) != 1 {
			t.Fatalf("v 2 = %#v, %v", got, err)
		}
		key := store.state.Subscriptions[0].Key
		panel.set(func() {
			panel.syncBody = strings.Replace(syncDoc("active"), `"v":1`, `"v":1,"reason":"app_disabled"`, 1)
		})
		got, err = store.Refresh(ctx, sub.ID)
		if st := store.state.Subscriptions[0]; err != nil || got.Error != "app_disabled" || len(got.Servers) != 0 || !got.Managed || st.Key != key || st.Halt {
			t.Fatalf("app off = %#v, %v", got, err)
		}
		panel.set(func() { panel.syncBody = syncDoc("expired") })
		got, err = store.Refresh(ctx, sub.ID)
		if err != nil || got.Error != "inactive" || got.Notice != "expired" || len(got.Servers) != 0 || !got.Managed {
			t.Fatalf("expired = %#v, %v", got, err)
		}
	})

	t.Run("telegram, devices, labels, relay country, ipv6 egress", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		var doc map[string]any
		if err := json.Unmarshal([]byte(panel.syncBody), &doc); err != nil {
			t.Fatal(err)
		}
		server := doc["servers"].([]any)[0].(map[string]any)
		server["label"] = "Fast	one"
		path := server["paths"].([]any)[0].(map[string]any)
		path["label"], path["via_country"], path["ipv6_egress"] = "Home profile", "fi", false
		doc["devices"] = map[string]any{"used": 2, "limit": 5}
		doc["telegram"] = []any{
			map[string]any{"server_id": "srv_1", "country": "de", "via": "relay", "via_country": "FI", "link": "tg://proxy?server=h&port=443&secret=s"},
			map[string]any{"server_id": "srv_1", "link": "https://evil.example/proxy"},
			map[string]any{"server_id": "srv_1", "link": "tg://proxy?a b"},
		}
		body, _ := json.Marshal(doc)
		panel.set(func() { panel.syncBody = string(body) })
		got, err := store.Refresh(ctx, sub.ID)
		if err != nil || len(got.Servers) != 1 || got.DevicesUsed != 2 || got.DevicesLimit != 5 || len(got.Telegram) != 1 {
			t.Fatalf("sync = %#v, %v", got, err)
		}
		entry, proxy := got.Servers[0], got.Telegram[0]
		if entry.Label != "Home profile" || entry.NodeLabel != "Fast one" || entry.ViaCountry != "FI" || entry.IPv6Egress == nil || *entry.IPv6Egress {
			t.Fatalf("server = %#v", entry)
		}
		if proxy.Node != "srv_1" || proxy.Country != "DE" || proxy.ViaCountry != "FI" || proxy.Via != "relay" || !strings.HasPrefix(proxy.Link, "tg://proxy?") {
			t.Fatalf("telegram = %#v", proxy)
		}
		panel.set(func() { panel.syncBody = syncDoc("expired") })
		if got, err = store.Refresh(ctx, sub.ID); err != nil || len(got.Telegram) != 0 || got.DevicesLimit != 0 {
			t.Fatalf("expired keeps = %#v, %v", got, err)
		}
	})

	t.Run("device removed", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		oldKey := store.state.Subscriptions[0].Key
		panel.set(func() { panel.syncStatus, panel.errBody = 401, `{"error":"device_removed"}` })
		got, err := store.Refresh(ctx, sub.ID)
		if errorCode(err) != "device_removed" || got.Error != "device_removed" || got.Managed || len(got.Servers) != 0 || len(store.List()) != 1 {
			t.Fatalf("device_removed = %#v, %v", got, err)
		}
		if stored := store.state.Subscriptions[0]; stored.Key != "" || stored.Base != "" || len(stored.Entries) != 0 || len(store.due(1<<40)) != 0 {
			t.Fatalf("key and servers must go and automatic refresh must stop: %#v", stored)
		}
		panel.set(func() { panel.syncStatus = 0 })
		got, err = store.Refresh(ctx, sub.ID) // by hand: the panel serves the plain subscription and enrols again
		if err != nil || !got.Managed || got.Error != "" || store.state.Subscriptions[0].Key == oldKey {
			t.Fatalf("refresh by hand after removal = %#v, %v", got, err)
		}
	})

	t.Run("device blocked", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		key := store.state.Subscriptions[0].Key
		panel.set(func() { panel.syncStatus, panel.errBody = 401, `{"error":"device_blocked"}` })
		got, err := store.Refresh(ctx, sub.ID)
		if errorCode(err) != "device_blocked" || got.Error != "device_blocked" || !got.Managed || len(got.Servers) != 0 || store.state.Subscriptions[0].Key != key || len(store.due(1<<40)) != 0 {
			t.Fatalf("device_blocked = %#v, %v", got, err)
		}
	})

	t.Run("link changed then add the new link", func(t *testing.T) {
		panel, store, sub := managedStore(t)
		oldKey := store.state.Subscriptions[0].Key
		panel.set(func() { panel.syncStatus, panel.errBody = 401, `{"error":"link_changed"}` })
		got, err := store.Refresh(ctx, sub.ID)
		if errorCode(err) != "link_changed" || got.Error != "link_changed" || !got.Managed || len(got.Servers) != 1 || len(store.due(1<<40)) != 0 {
			t.Fatalf("link_changed = %#v, %v", got, err)
		}
		if _, err = store.Refresh(ctx, sub.ID); errorCode(err) != "link_changed" { // still stopped after another try
			t.Fatal(err)
		}
		panel.set(func() { panel.syncStatus = 0 })
		moved, err := store.Add(ctx, panel.link("new-token"))
		list := store.List()
		if err != nil || moved.ID != sub.ID || len(list) != 1 || !list[0].Managed || list[0].Error != "" || len(list[0].Servers) != 1 {
			t.Fatalf("re-enrol to the new link = %#v, %v, %d subscriptions", moved, err, len(list))
		}
		newKey := store.state.Subscriptions[0].Key
		if n := len(panel.enrolKeys); n != 2 || panel.enrolAuth[1] != "Bearer "+oldKey || panel.enrolKeys[1] == oldKey || newKey != panel.enrolKeys[1] {
			t.Fatalf("re-enrol: keys %v auth %v", panel.enrolKeys, panel.enrolAuth)
		}
		if panel.syncAuth[len(panel.syncAuth)-1] != "Bearer "+newKey || store.state.Subscriptions[0].URL != panel.link("new-token") || store.state.Subscriptions[0].Halt {
			t.Fatalf("sync after re-enrol: %v", panel.syncAuth)
		}
		// the same link added again is a refresh of the managed subscription, not a second enrolment
		if _, err = store.Add(ctx, panel.link("new-token")); err != nil || len(store.List()) != 1 || len(panel.enrolKeys) != 2 {
			t.Fatalf("re-add of a managed link: %v, %d enrols", err, len(panel.enrolKeys))
		}
	})
}

func TestClientAPIRemoveLeaves(t *testing.T) {
	panel, store, sub := managedStore(t)
	key := store.state.Subscriptions[0].Key
	panel.set(func() { panel.leaveStatus = 500 })
	if err := store.Remove(sub.ID); err != nil {
		t.Fatal(err)
	}
	if panel.leaves != 1 || panel.leaveAuth[0] != "Bearer "+key || len(store.List()) != 0 {
		t.Fatalf("leave: %d calls %v, %d subscriptions left", panel.leaves, panel.leaveAuth, len(store.List()))
	}

	plain := newPanel(t, false)
	other := plain.openStore(t)
	added, err := other.Add(context.Background(), plain.link("tok"))
	if err != nil || other.Remove(added.ID) != nil || plain.leaves != 0 {
		t.Fatalf("an unmanaged subscription must not call leave: %v, %d", err, plain.leaves)
	}
}

func TestClientAPIEnrolDoNotRetry(t *testing.T) {
	ctx := context.Background()
	panel := newPanel(t, true)
	store := panel.openStore(t)
	panel.set(func() { panel.enrolCode = "device_limit" })
	added, err := store.Add(ctx, panel.link("tok"))
	if err != nil || added.Managed || added.Error != "device_limit" || len(added.Servers) != 1 || added.Servers[0].Name != "Plain" {
		t.Fatalf("device_limit = %#v, %v", added, err)
	}
	if len(store.state.Pending) != 0 || !store.state.Subscriptions[0].Halt || len(store.due(1<<40)) != 0 {
		t.Fatalf("the pending key must be dropped and the automatic refresh stopped: %#v", store.state)
	}
	panel.set(func() { panel.enrolCode = "" })
	got, err := store.Refresh(ctx, added.ID)
	if err != nil || !got.Managed || got.Error != "" || len(panel.enrolKeys) != 2 || panel.enrolKeys[1] == panel.enrolKeys[0] {
		t.Fatalf("refresh by hand = %#v, %v, keys %v", got, err, panel.enrolKeys)
	}
}

func TestClientAPIStoreSurvivesReopen(t *testing.T) {
	panel, store, sub := managedStore(t)
	reopened, err := openStore(store.dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	reopened.client = panel.server.Client()
	panel.store = reopened
	if list := reopened.List(); len(list) != 1 || !list[0].Managed || len(reopened.state.Hwids) != 1 {
		t.Fatalf("reopened store = %#v", list)
	}
	if got, err := reopened.Refresh(context.Background(), sub.ID); err != nil || !got.Managed || len(panel.enrolKeys) != 1 {
		t.Fatalf("managed refresh after reopen = %#v, %v", got, err)
	}
}

func vlessPathSettings(change map[string]any) map[string]any {
	settings := map[string]any{
		"server": "vless.example", "port": 443, "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5", "flow": "xtls-rprx-vision", "transport": "raw",
		"security": "reality", "sni": "www.example.com", "fingerprint": "chrome", "spider_x": "/",
		"public_key": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM", "short_id": "0123456789abcdef",
	}
	for k, v := range change {
		if v == nil {
			delete(settings, k)
		} else {
			settings[k] = v
		}
	}
	return settings
}

func TestClientAPIVLESSPaths(t *testing.T) {
	if !strings.Contains(capsHeader, "vless=1") {
		t.Fatalf("caps %q do not announce vless", capsHeader)
	}
	panel, store, sub := managedStore(t)
	panel.set(func() {
		panel.syncBody = syncDoc("active",
			apiServer("Berlin", "DE",
				apiPath("pth_vless_raw", "vless", "direct", false, vlessPathSettings(nil)),
				apiPath("pth_vless_xhttp", "vless", "relay", false, vlessPathSettings(map[string]any{"flow": nil, "transport": "xhttp", "path": "/xh", "mode": "packet-up", "x_padding_bytes": "100-1000"})),
				apiPath("pth_vless_grpc", "vless", "direct", false, vlessPathSettings(map[string]any{"flow": nil, "transport": "grpc"})),
				apiPath("pth_vless_flow", "vless", "direct", false, vlessPathSettings(map[string]any{"flow": "xtls-rprx-direct"})),
				apiPath("pth_vless_sec", "vless", "direct", false, vlessPathSettings(map[string]any{"security": "none"})),
				apiPath("pth_vless_port", "vless", "direct", false, vlessPathSettings(map[string]any{"port": 70000})),
				apiPath("pth_other", "shadowsocks", "direct", false, map[string]any{"server": "x"}),
			))
	})
	got, err := store.Refresh(context.Background(), sub.ID)
	if err != nil || got.Error != "" || len(got.Servers) != 2 || got.Unsupported != 5 {
		t.Fatalf("refresh = %#v, %v (unknown transport, flow, security, port and protocol are unsupported paths, not errors)", got, err)
	}
	if got.Servers[0].ID != "pth_vless_raw" || got.Servers[0].Protocol != "vless" || got.Servers[1].Name != "Berlin · relay" {
		t.Fatalf("servers = %#v", got.Servers)
	}
	profiles, err := store.Profiles()
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles = %d, %v", len(profiles), err)
	}
	raw, xhttp := profiles[0], profiles[1]
	if raw.Protocol != "vless" || raw.VLESS == nil || raw.Hy2 != nil || raw.AWG != nil || raw.VLESS.Host != "vless.example" ||
		raw.VLESS.Flow != "xtls-rprx-vision" || raw.VLESS.Security != "reality" {
		t.Fatalf("raw profile = %#v", raw)
	}
	if xhttp.VLESS == nil || xhttp.VLESS.Transport != "xhttp" || xhttp.VLESS.Mode != "packet-up" || xhttp.Via != "relay" {
		t.Fatalf("xhttp profile = %#v", xhttp)
	}
	// nothing the window or a log could show carries the user, the key or the server
	encoded, _ := json.Marshal(store.List())
	for _, secret := range []string{"5783a3e7", "E59Wjnv", "0123456789abcdef", "vless.example", "www.example.com"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("List JSON leaked %q", secret)
		}
	}
}
