package profile

import (
	"strings"
	"testing"
)

func TestParseVLESSLink(t *testing.T) {
	const id = "8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b"
	// TLS over xhttp, as a third-party panel gives it: the extras this build does not read are ignored
	tls, err := ParseVLESSLink("vless://" + id + "@edge.example.net:443?type=xhttp&security=tls&sni=cdn.example.net&fp=firefox&alpn=h2&mode=stream-one&path=%2Fup&encryption=none&allowInsecure=0&insecure=0&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#Name")
	if err != nil {
		t.Fatal(err)
	}
	if tls.Host != "edge.example.net" || tls.Port != 443 || tls.UUID != id || tls.Transport != "xhttp" || tls.Security != "tls" || tls.SNI != "cdn.example.net" ||
		tls.Fingerprint != "firefox" || tls.Mode != "stream-one" || tls.Path != "/up" || len(tls.ALPN) != 1 || tls.ALPN[0] != "h2" || tls.XPadding != [2]int32{100, 1000} {
		t.Fatalf("tls link = %+v", tls)
	}
	// REALITY on raw with Vision; "tcp" is the old name of raw, no fingerprint means chrome
	reality, err := ParseVLESSLink("vless://" + id + "@203.0.113.7:8443?type=tcp&security=reality&sni=www.example.org&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b&flow=xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	if reality.Transport != "raw" || reality.Security != "reality" || reality.Flow != VLESSFlowVision || reality.Fingerprint != "chrome" || reality.PublicKey[1] != 1 {
		t.Fatalf("reality link = %+v", reality)
	}
	if ws, err := ParseVLESSLink("vless://" + id + "@edge.example.net:443?type=ws&security=tls&host=front.example.net"); err != nil || ws.Path != "/" || ws.HTTPHost != "front.example.net" {
		t.Fatalf("ws link = %+v, %v", ws, err)
	}
	// plain VLESS, and Vision over TLS
	if plain, err := ParseVLESSLink("vless://" + id + "@edge.example.net:80?type=tcp&security=none"); err != nil || plain.Security != "none" || plain.Transport != "raw" {
		t.Fatalf("plain link = %+v, %v", plain, err)
	}
	if vision, err := ParseVLESSLink("vless://" + id + "@edge.example.net:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=edge.example.net"); err != nil || vision.Flow != VLESSFlowVision {
		t.Fatalf("vision over tls = %+v, %v", vision, err)
	}
	for name, link := range map[string]string{
		"vision without tls":  "vless://" + id + "@edge.example.net:80?type=tcp&security=none&flow=xtls-rprx-vision",
		"grpc without a name": "vless://" + id + "@edge.example.net:443?type=grpc&security=tls",
		"any certificate":     "vless://" + id + "@edge.example.net:443?type=ws&security=tls&allowInsecure=1",
		"vless encryption":    "vless://" + id + "@edge.example.net:443?type=tcp&security=reality&encryption=mlkem768x25519plus.native.0rtt.abc",
		"header disguise":     "vless://" + id + "@edge.example.net:443?type=tcp&security=tls&headerType=http",
		"bad id":              "vless://not-a-uuid@edge.example.net:443?type=tcp&security=tls",
		"no port":             "vless://" + id + "@edge.example.net?type=tcp&security=tls",
		"another scheme":      strings.Replace("vless://"+id+"@edge.example.net:443?security=tls", "vless", "vmess", 1),
		"reality without key": "vless://" + id + "@edge.example.net:443?type=tcp&security=reality&sni=www.example.org",
	} {
		if p, err := ParseVLESSLink(link); err == nil {
			t.Errorf("%s: accepted as %+v", name, p)
		}
	}
}
