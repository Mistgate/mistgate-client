package subs

import "testing"

func TestMihomoVLESSProxies(t *testing.T) {
	const profile = `proxies:
  - {name: Plain, type: vless, server: edge.example.net, port: 8080, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: tcp, udp: true, client-fingerprint: chrome}
  - {name: Reality, type: vless, server: 203.0.113.7, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: tcp, tls: true, servername: www.example.org, flow: xtls-rprx-vision, client-fingerprint: firefox, reality-opts: {public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8, short-id: 0a1b}}
  - {name: WS, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: ws, tls: true, servername: edge.example.net, ws-opts: {path: /ws, headers: {Host: front.example.net}}}
  - {name: Any cert, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: tcp, tls: true, skip-cert-verify: true}
  - {name: gRPC, type: vless, server: edge.example.net, port: 443, uuid: 8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b, network: grpc, tls: true}
`
	servers, entries, unsupported, err := parseMihomoProfile(profile, "sub")
	if err != nil || len(servers) != 3 || unsupported != 2 {
		t.Fatalf("servers=%d unsupported=%d err=%v", len(servers), unsupported, err)
	}
	want := []struct{ security, transport, flow string }{{"none", "raw", ""}, {"reality", "raw", "xtls-rprx-vision"}, {"tls", "ws", ""}}
	for i, entry := range entries {
		if entry.Server.Protocol != "vless" {
			t.Fatalf("entry %d protocol = %s", i, entry.Server.Protocol)
		}
		p, err := parseVLESSEntry(entry.Raw)
		if err != nil || p.Security != want[i].security || p.Transport != want[i].transport || p.Flow != want[i].flow {
			t.Fatalf("entry %d = %+v, %v", i, p, err)
		}
	}
	if ws, _ := parseVLESSEntry(entries[2].Raw); ws.Path != "/ws" || ws.HTTPHost != "front.example.net" {
		t.Fatalf("ws = %+v", ws)
	}
}
