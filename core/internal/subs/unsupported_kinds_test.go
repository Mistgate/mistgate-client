package subs

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const kindID = "8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b"

// checkKinds: the counts add up to unsupported, every name is a kind, and nothing of the servers is in them.
func checkKinds(t *testing.T, unsupported int, kinds map[string]int) {
	t.Helper()
	sum := 0
	for name, n := range kinds {
		sum += n
		if !kindName.MatchString(name) || len(kinds) > maxKinds {
			t.Errorf("kind %q (of %d)", name, len(kinds))
		}
		for _, leak := range []string{"example", kindID, "203.0.113", "secret", "svc", "/", "@", ":", "="} {
			if strings.Contains(name, leak) {
				t.Errorf("kind %q holds %q", name, leak)
			}
		}
	}
	if sum != unsupported {
		t.Errorf("kinds %v add up to %d, unsupported is %d", kinds, sum, unsupported)
	}
}

func TestUnsupportedKindsOfLinks(t *testing.T) {
	vless := "vless://" + kindID + "@edge.example.net:443?security=tls&sni=cdn.example.net&"
	text := strings.Join([]string{
		"trojan://secret@a.example:443#One", "trojan://secret@b.example:443#Two", "TROJAN://secret@c.example:443#Three",
		"ss://YWVzOnNlY3JldA@d.example:8388#Four", "ss://YWVzOnNlY3JldA@e.example:8388#Five",
		"vmess://eyJhZGQiOiJmLmV4YW1wbGUifQ==#Six",
		vless + "type=grpc&serviceName=svc#NoGoodNow",             // good: a server
		vless + "type=grpc#GRPCWithoutName",                       // invalid
		vless + "type=kcp#KCP",                                    // transport
		vless + "type=kcp&seed=secret#KCP2",                       // transport again
		vless + "type=ws&allowInsecure=1#Insecure",                // any certificate
		vless + "type=tcp&encryption=mlkem768x25519#Enc",          // encryption
		"hy2://a@203.0.113.5:443/?obfs=salamander#NoObfsPassword", // not valid
		"hysteria2://auth@203.0.113.6:443/?insecure=1#Good",
	}, "\n")
	servers, _, unsupported, kinds, err := parseEntries(text, "sub")
	if err != nil || len(servers) != 2 || unsupported != 12 {
		t.Fatalf("servers=%d unsupported=%d err=%v", len(servers), unsupported, err)
	}
	want := map[string]int{"trojan": 3, "ss": 2, "vmess": 1, "vless (invalid)": 1, "vless (transport)": 2, "vless (any certificate)": 1,
		"vless (encryption)": 1, "hysteria2": 1}
	if !reflect.DeepEqual(map[string]int(kinds), want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
	checkKinds(t, unsupported, kinds)
}

func TestUnsupportedKindsOfMihomoProfile(t *testing.T) {
	const profileText = `proxies:
  - {name: Good, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true, servername: edge.example.net, grpc-opts: {grpc-service-name: svc}}
  - {name: gRPC no name, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true}
  - {name: KCP, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: kcp}
  - {name: Any cert, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: tcp, tls: true, skip-cert-verify: true}
  - {name: Trojan A, type: trojan, server: a.example, port: 443, password: secret}
  - {name: Trojan B, type: Trojan, server: b.example, port: 443, password: secret}
  - {name: SS, type: ss, server: c.example, port: 8388, cipher: aes-128-gcm, password: secret}
  - {name: Bad WG, type: wireguard, server: d.example, port: 51820}
  - {name: No type, server: e.example, port: 1}
  - just a string
  - {name: Strange, type: "a/b@c.example:1", server: f.example, port: 2}
`
	servers, _, unsupported, kinds, err := parseMihomoProfile(profileText, "sub")
	if err != nil || len(servers) != 1 || unsupported != 10 {
		t.Fatalf("servers=%d unsupported=%d err=%v", len(servers), unsupported, err)
	}
	want := map[string]int{"vless (invalid)": 1, "vless (transport)": 1, "vless (any certificate)": 1, "trojan": 2, "ss": 1, "wireguard": 1, "other": 3}
	if !reflect.DeepEqual(map[string]int(kinds), want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
	checkKinds(t, unsupported, kinds)
}

func TestUnsupportedKindsAreCapped(t *testing.T) {
	var lines []string
	for i := range 30 {
		lines = append(lines, fmt.Sprintf("scheme%d://x@a.example:1", i))
	}
	lines = append(lines, "scheme3://x@a.example:1", "hysteria2://auth@203.0.113.6:443/?insecure=1", strings.Repeat("a", 60)+"://x")
	_, _, unsupported, kinds, err := parseEntries(strings.Join(lines, "\n"), "sub")
	if err != nil || unsupported != 32 {
		t.Fatalf("unsupported=%d err=%v", unsupported, err)
	}
	if len(kinds) != maxKinds || kinds["other"] == 0 || kinds["scheme0"] != 1 || kinds["scheme3"] != 2 {
		t.Errorf("kinds = %v", kinds)
	}
	checkKinds(t, unsupported, kinds)

	// more servers than the list holds: the rest is "other" too
	var many []string
	for i := range maxServers + 7 {
		many = append(many, fmt.Sprintf("hysteria2://auth@203.0.113.%d:%d/?insecure=1", i%250, 1000+i))
	}
	servers, entries, unsupported, kinds, err := parseEntries(strings.Join(append(many, "trojan://x@a.example:1"), "\n"), "sub")
	if err != nil {
		t.Fatal(err)
	}
	_, _, unsupported, kinds = capServers(servers, entries, unsupported, kinds)
	if unsupported != 8 || kinds["trojan"] != 1 || kinds["other"] != 7 {
		t.Errorf("unsupported=%d kinds=%v", unsupported, kinds)
	}
	checkKinds(t, unsupported, kinds)
}

func TestUnsupportedKindsReachTheWindow(t *testing.T) {
	store := openTestStore(t, t.TempDir(), nil)
	text := "hysteria2://auth@203.0.113.6:443/?insecure=1#Good\ntrojan://secret@a.example:443#T\nss://YWVzOnNlY3JldA@d.example:8388#S\nvless://" + kindID + "@e.example:443?type=kcp#K"
	preview, err := store.Preview(context.Background(), text)
	if err != nil || preview.Unsupported != 3 {
		t.Fatalf("preview = %#v, %v", preview, err)
	}
	want := map[string]int{"trojan": 1, "ss": 1, "vless (transport)": 1}
	if !reflect.DeepEqual(preview.UnsupportedKinds, want) {
		t.Errorf("preview kinds = %v", preview.UnsupportedKinds)
	}
	added, err := store.Add(context.Background(), text)
	if err != nil || !reflect.DeepEqual(added.UnsupportedKinds, want) {
		t.Fatalf("add = %#v, %v", added, err)
	}
	listed := store.List()
	if len(listed) != 1 || !reflect.DeepEqual(listed[0].UnsupportedKinds, want) {
		t.Fatalf("list = %#v", listed)
	}
	listed[0].UnsupportedKinds["trojan"] = 99 // a copy: the store's own count does not change
	if store.List()[0].UnsupportedKinds["trojan"] != 1 {
		t.Error("List hands out the store's own map")
	}
	data, _ := json.Marshal(added)
	var wire struct {
		Unsupported      int            `json:"unsupported"`
		UnsupportedKinds map[string]int `json:"unsupported_kinds"`
	}
	if err := json.Unmarshal(data, &wire); err != nil || wire.Unsupported != 3 || !reflect.DeepEqual(wire.UnsupportedKinds, want) {
		t.Errorf("json = %s", data)
	}
	// nothing unsupported: no field at all
	clean, err := store.Preview(context.Background(), "hysteria2://auth@203.0.113.6:443/?insecure=1")
	data, _ = json.Marshal(clean)
	if err != nil || strings.Contains(string(data), "unsupported_kinds") {
		t.Errorf("clean json = %s, %v", data, err)
	}
}

func TestMihomoVLESSGRPCAndHTTPUpgrade(t *testing.T) {
	const profileText = `proxies:
  - {name: gRPC, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true, servername: edge.example.net, client-fingerprint: firefox, grpc-opts: {grpc-service-name: my-svc}}
  - {name: Upgrade, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: ws, tls: true, servername: edge.example.net, ws-opts: {path: /up, v2ray-http-upgrade: true, headers: {Host: front.example.net}}}
  - {name: Still ws, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: ws, tls: true, servername: edge.example.net, ws-opts: {path: /ws, v2ray-http-upgrade: false}}
  - {name: Upgrade net, type: vless, server: edge.example.net, port: 80, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: httpupgrade, http-upgrade-opts: {path: /hu, host: front.example.net}}
  - {name: Upgrade net 2, type: vless, server: edge.example.net, port: 80, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: httpupgrade, httpupgrade-opts: {path: /hu2, headers: {Host: h2.example.net}}}
  - {name: gRPC any cert, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true, skip-cert-verify: true, grpc-opts: {grpc-service-name: s}}
  - {name: gRPC no name, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true, grpc-opts: {}}
  - {name: Upgrade on reality, type: vless, server: 203.0.113.7, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: ws, tls: true, servername: www.example.org, ws-opts: {v2ray-http-upgrade: true}, reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8, short-id: 0a1b}}
  - {name: Encrypted, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, encryption: mlkem768x25519plus.native.0rtt.abc, grpc-opts: {grpc-service-name: s}}
`
	servers, entries, unsupported, kinds, err := parseMihomoProfile(profileText, "sub")
	if err != nil || len(servers) != 5 || unsupported != 4 {
		t.Fatalf("servers=%d unsupported=%d err=%v", len(servers), unsupported, err)
	}
	want := []struct{ transport, path, host, service, security string }{
		{"grpc", "", "", "my-svc", "tls"}, {"httpupgrade", "/up", "front.example.net", "", "tls"}, {"ws", "/ws", "", "", "tls"},
		{"httpupgrade", "/hu", "front.example.net", "", "none"}, {"httpupgrade", "/hu2", "h2.example.net", "", "none"},
	}
	for i, entry := range entries {
		p, err := parseVLESSEntry(entry.Raw)
		if err != nil || p.Transport != want[i].transport || p.Path != want[i].path && want[i].transport != "grpc" || p.HTTPHost != want[i].host ||
			p.ServiceName != want[i].service || p.Security != want[i].security {
			t.Errorf("entry %d = %+v, %v", i, p, err)
		}
	}
	if g, _ := parseVLESSEntry(entries[0].Raw); g.Mode != "gun" || g.Fingerprint != "firefox" {
		t.Errorf("grpc = %+v", g)
	}
	wantKinds := map[string]int{"vless (any certificate)": 1, "vless (invalid)": 1, "vless (security)": 1, "vless (encryption)": 1}
	if !reflect.DeepEqual(map[string]int(kinds), wantKinds) {
		t.Errorf("kinds = %v, want %v", kinds, wantKinds)
	}
	checkKinds(t, unsupported, kinds)
}
