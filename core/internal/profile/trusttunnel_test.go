package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

type trustTunnelTLV struct {
	tag   uint64
	value []byte
}

func trustTunnelVarint(value uint64) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value)}
	case value < 1<<14:
		return []byte{byte(value>>8) | 0x40, byte(value)}
	case value < 1<<30:
		return []byte{byte(value>>24) | 0x80, byte(value >> 16), byte(value >> 8), byte(value)}
	default:
		out := make([]byte, 8)
		for i := range out {
			out[7-i] = byte(value >> (8 * i))
		}
		out[0] |= 0xc0
		return out
	}
}

func trustTunnelLink(fields ...trustTunnelTLV) string {
	var payload []byte
	for _, field := range fields {
		payload = append(payload, trustTunnelVarint(field.tag)...)
		payload = append(payload, trustTunnelVarint(uint64(len(field.value)))...)
		payload = append(payload, field.value...)
	}
	return "tt://?" + base64.RawURLEncoding.EncodeToString(payload)
}

func trustTunnelBase() []trustTunnelTLV {
	return []trustTunnelTLV{
		{tag: 0x01, value: []byte("edge.example.test")},
		{tag: 0x02, value: []byte("203.0.113.9:443")},
		{tag: 0x05, value: []byte("user")},
		{tag: 0x06, value: []byte("secret")},
	}
}

func TestParseTrustTunnelDefaultsAndLastValues(t *testing.T) {
	fields := append([]trustTunnelTLV{{tag: 0x00, value: trustTunnelVarint(2)}}, trustTunnelBase()...)
	fields = append(fields,
		trustTunnelTLV{tag: 0x01, value: []byte("new.example.test")},
		trustTunnelTLV{tag: 0x02, value: []byte("edge.example.test:8443")},
		trustTunnelTLV{tag: 0x05, value: []byte("new-user")},
		trustTunnelTLV{tag: 0x06, value: []byte("new-secret")},
		trustTunnelTLV{tag: 0x03, value: []byte("sni.example.test")},
		trustTunnelTLV{tag: 0x04, value: []byte{0}},
		trustTunnelTLV{tag: 0x07, value: []byte{1}},
		trustTunnelTLV{tag: 0x0c, value: []byte("test endpoint")},
		trustTunnelTLV{tag: 0x09, value: trustTunnelVarint(2)},
		trustTunnelTLV{tag: 0x0a, value: []byte{1}},
		trustTunnelTLV{tag: 0x0d, value: []byte{0xff}},
		trustTunnelTLV{tag: 0x20, value: []byte("unknown")},
	)
	p, err := ParseTrustTunnel(trustTunnelLink(fields...))
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "new.example.test" || p.SNI != "sni.example.test" || p.Username != "new-user" || p.Password != "new-secret" {
		t.Fatalf("last value did not win: %#v", p)
	}
	if len(p.Addresses) != 2 || p.Addresses[0] != "203.0.113.9:443" || p.Addresses[1] != "edge.example.test:8443" {
		t.Fatalf("repeated addresses were not kept in order: %#v", p.Addresses)
	}
	if p.HasIPv6 || !p.Insecure || p.Name != "test endpoint" {
		t.Fatalf("optional values were not parsed: %#v", p)
	}
	if defaultProfile, err := ParseTrustTunnel(trustTunnelLink(trustTunnelBase()...)); err != nil || !defaultProfile.HasIPv6 || defaultProfile.Insecure {
		t.Fatalf("defaults: %#v, %v", defaultProfile, err)
	}
}

// Tag 0x09 asks for the transport: 1 is HTTP/2 alone, 2 is HTTP/3 with the fall back to HTTP/2.
func TestParseTrustTunnelTransportTag(t *testing.T) {
	for _, test := range []struct {
		transport uint64
		h3        bool
		ok        bool
	}{{1, false, true}, {2, true, true}, {3, false, false}} {
		p, err := ParseTrustTunnel(trustTunnelLink(append(trustTunnelBase(), trustTunnelTLV{tag: 0x09, value: trustTunnelVarint(test.transport)})...))
		if (err == nil) != test.ok || err == nil && p.H3 != test.h3 {
			t.Errorf("transport %d: H3 = %v, error = %v", test.transport, p != nil && p.H3, err)
		}
	}
	if p, err := ParseTrustTunnel(trustTunnelLink(trustTunnelBase()...)); err != nil || p.H3 {
		t.Fatalf("link without the tag: H3 = %v, %v", p != nil && p.H3, err)
	}
}

func TestParseTrustTunnelTwoByteLengthAndPadding(t *testing.T) {
	fields := append(trustTunnelBase(), trustTunnelTLV{tag: 0x0c, value: []byte(strings.Repeat("n", 80))})
	raw := trustTunnelLink(fields...)
	raw += strings.Repeat("=", (4-len(raw[len("tt://?"):])%4)%4)
	p, err := ParseTrustTunnel(raw)
	if err != nil || p.Name != strings.Repeat("n", 80) {
		t.Fatalf("two-byte length: name length=%d, err=%v", len(p.Name), err)
	}
}

func TestParseTrustTunnelCertificateChainForcesVerification(t *testing.T) {
	first, second := trustTunnelCertificate(t), trustTunnelCertificate(t)
	fields := append(trustTunnelBase(), trustTunnelTLV{tag: 0x07, value: []byte{1}}, trustTunnelTLV{tag: 0x08, value: append(first, second...)})
	p, err := ParseTrustTunnel(trustTunnelLink(fields...))
	if err != nil {
		t.Fatal(err)
	}
	if p.Insecure || len(p.Certs) != 2 || string(p.Certs[0]) != string(first) || string(p.Certs[1]) != string(second) {
		t.Fatalf("certificate chain: insecure=%v certs=%d", p.Insecure, len(p.Certs))
	}
	fields[len(fields)-1].value = []byte("not DER")
	if _, err := ParseTrustTunnel(trustTunnelLink(fields...)); err == nil {
		t.Fatal("accepted invalid DER")
	}
}

func TestParseTrustTunnelTypedUnsupportedKinds(t *testing.T) {
	subscription := trustTunnelLink(trustTunnelTLV{tag: 0x0e, value: []byte("https://example.test/sub")})
	if _, err := ParseTrustTunnel(subscription); err != ErrTrustTunnelSubscription || TrustTunnelKind(err) != "trusttunnel (subscription)" {
		t.Fatalf("subscription error = %v", err)
	}
	for _, tag := range []uint64{0x0b, 0x0f} {
		fields := append(trustTunnelBase(), trustTunnelTLV{tag: tag, value: []byte("00")})
		if _, err := ParseTrustTunnel(trustTunnelLink(fields...)); err != ErrTrustTunnelClientRandom || TrustTunnelKind(err) != "trusttunnel (client random)" {
			t.Fatalf("tag %x error = %v", tag, err)
		}
	}
	fields := append(trustTunnelBase(), trustTunnelTLV{tag: 0x0e, value: []byte("https://example.test/sub")})
	if _, err := ParseTrustTunnel(trustTunnelLink(fields...)); err != nil {
		t.Fatalf("static values with a subscription URL: %v", err)
	}
	fields[len(fields)-1].value = []byte("http://example.test/sub")
	if _, err := ParseTrustTunnel(trustTunnelLink(fields...)); err != nil {
		t.Fatalf("static values with an ignored subscription URL: %v", err)
	}
	partialStatic := trustTunnelLink(trustTunnelTLV{tag: 0x04, value: []byte{0}}, trustTunnelTLV{tag: 0x0e, value: []byte("not a URL")})
	if _, err := ParseTrustTunnel(partialStatic); err == nil || TrustTunnelKind(err) != "trusttunnel" {
		t.Fatalf("partial static settings error = %v", err)
	}
}

func TestParseTrustTunnelRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name   string
		fields []trustTunnelTLV
	}{
		{name: "missing hostname", fields: []trustTunnelTLV{{tag: 0x02, value: []byte("203.0.113.9:443")}, {tag: 0x05, value: []byte("u")}, {tag: 0x06, value: []byte("p")}}},
		{name: "missing address", fields: []trustTunnelTLV{{tag: 0x01, value: []byte("edge.example.test")}, {tag: 0x05, value: []byte("u")}, {tag: 0x06, value: []byte("p")}}},
		{name: "missing username", fields: []trustTunnelTLV{{tag: 0x01, value: []byte("edge.example.test")}, {tag: 0x02, value: []byte("203.0.113.9:443")}, {tag: 0x06, value: []byte("p")}}},
		{name: "missing password", fields: []trustTunnelTLV{{tag: 0x01, value: []byte("edge.example.test")}, {tag: 0x02, value: []byte("203.0.113.9:443")}, {tag: 0x05, value: []byte("u")}}},
		{name: "bad hostname", fields: []trustTunnelTLV{{tag: 0x01, value: []byte("bad host")}, {tag: 0x02, value: []byte("203.0.113.9:443")}, {tag: 0x05, value: []byte("u")}, {tag: 0x06, value: []byte("p")}}},
		{name: "bad sni", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x03, value: []byte("bad name")})},
		{name: "bad address", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x02, value: []byte("edge.example.test:0")})},
		{name: "username colon", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x05, value: []byte("bad:user")})},
		{name: "username control", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x05, value: []byte("bad\nuser")})},
		{name: "password control", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x06, value: []byte("bad\x7fpass")})},
		{name: "bad bool", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x04, value: []byte{2}})},
		{name: "bad upstream", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x09, value: trustTunnelVarint(3)})},
		{name: "bad anti dpi bool", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x0a, value: []byte{2}})},
		{name: "version three", fields: append(trustTunnelBase(), trustTunnelTLV{tag: 0x00, value: trustTunnelVarint(3)})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseTrustTunnel(trustTunnelLink(test.fields...)); err == nil {
				t.Fatal("accepted malformed link")
			}
		})
	}
}

func TestParseTrustTunnelRejectsTruncatedAndOversize(t *testing.T) {
	truncated := []byte{0x01, 0x42, 0x61}
	raw := "tt://?" + base64.RawURLEncoding.EncodeToString(truncated)
	if _, err := ParseTrustTunnel(raw); err == nil {
		t.Fatal("accepted truncated TLV value")
	}
	if _, err := ParseTrustTunnel("tt://?" + strings.Repeat("A", maxTrustTunnelLink)); err == nil {
		t.Fatal("accepted link above 16 KiB")
	}
	if _, err := ParseTrustTunnel("vless://x"); err == nil {
		t.Fatal("accepted another scheme")
	}
}

func TestParseTrustTunnelPath(t *testing.T) {
	valid := map[string]any{
		"server": "relay.example.test", "port": 443, "sni": "node.example.test", "username": "device",
		"password": "secret", "transport": "auto", "tls": "pin", "pin_sha256": strings.Repeat("aB", 32),
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTrustTunnelPath(raw)
	if err != nil {
		t.Fatal("ParseTrustTunnelPath rejected a valid path")
	}
	if parsed.Host != "node.example.test" || parsed.SNI != "node.example.test" || parsed.Addresses[0] != "relay.example.test:443" ||
		parsed.Username != "device" || parsed.Password != "secret" || !parsed.HasIPv6 || parsed.Insecure || !parsed.HasPin || parsed.PinSHA256[0] != 0xab {
		t.Fatal("parsed TrustTunnel path has incorrect fields")
	}
	if !parsed.H3 {
		t.Fatal("transport auto did not ask for HTTP/3")
	}

	valid["server"] = "2001:db8::7"
	valid["transport"] = "h2"
	valid["tls"] = "ca"
	delete(valid, "pin_sha256")
	raw, err = json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseTrustTunnelPath(raw)
	if err != nil || parsed.Addresses[0] != "[2001:db8::7]:443" || parsed.HasPin || parsed.H3 {
		t.Fatal("IPv6 CA path was not parsed correctly")
	}
	delete(valid, "tls")
	raw, err = json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseTrustTunnelPath(raw)
	if err != nil || parsed.HasPin {
		t.Fatal("path without a TLS mode was not parsed with system roots")
	}

	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{name: "transport", edit: func(s map[string]any) { s["transport"] = "h3" }},
		{name: "tls", edit: func(s map[string]any) { s["tls"] = "skip" }},
		{name: "missing sni", edit: func(s map[string]any) { delete(s, "sni") }},
		{name: "bad port", edit: func(s map[string]any) { s["port"] = 70000 }},
		{name: "username control", edit: func(s map[string]any) { s["username"] = "bad\nuser" }},
		{name: "password control", edit: func(s map[string]any) { s["password"] = "bad\x7fpass" }},
		{name: "username colon", edit: func(s map[string]any) { s["username"] = "bad:user" }},
		{name: "missing pin", edit: func(s map[string]any) { s["tls"] = "pin"; delete(s, "pin_sha256") }},
		{name: "bad pin", edit: func(s map[string]any) { s["tls"] = "pin"; s["pin_sha256"] = strings.Repeat("g", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := map[string]any{
				"server": "relay.example.test", "port": 443, "sni": "node.example.test", "username": "device",
				"password": "secret", "transport": "auto", "tls": "ca",
			}
			test.edit(settings)
			raw, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseTrustTunnelPath(raw); err == nil {
				t.Fatal("accepted unsupported TrustTunnel path")
			}
		})
	}
}

func TestAutoSelectionCanChooseTrustTunnelOnlySubscription(t *testing.T) {
	profiles := []Profile{{ID: "tt", Name: "Tunnel", Protocol: "trusttunnel", Sub: "sub", TT: &TrustTunnel{}}}
	for name, pick := range map[string]func() (Profile, bool){
		"pick":     func() (Profile, bool) { return Pick(profiles, "auto", "auto", "sub") },
		"settings": func() (Profile, bool) { return PickForSettings(profiles, "auto", "auto", "sub", "auto", true) },
	} {
		selected, ok := pick()
		if !ok || selected.Protocol != "trusttunnel" {
			t.Errorf("%s picked %#v, %v", name, selected, ok)
		}
	}
	home, ring, ok := Ring(profiles, "auto", "auto", "sub", "auto", false)
	if !ok || home.Protocol != "trusttunnel" || len(ring) != 1 || ring[0].ID != "tt" {
		t.Fatalf("trusttunnel ring = %#v %#v %v", home, ring, ok)
	}
	if next, ok := Next(profiles, "auto", "auto", "sub", "auto", false, "tt"); ok || next != "" {
		t.Fatalf("Next on a single profile = %q, %v", next, ok)
	}
	if others := Others(profiles, "auto", "auto", "sub", "auto", false, "auto"); len(others) != 0 {
		t.Fatalf("single-profile alternatives = %#v", others)
	}
}

func trustTunnelCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseTrustTunnelWithoutQuestionMark(t *testing.T) {
	raw := strings.Replace(trustTunnelLink(trustTunnelBase()...), "tt://?", "tt://", 1)
	got, err := ParseTrustTunnel(raw)
	if err != nil || got.Host != "edge.example.test" || got.Username != "user" || !got.HasIPv6 {
		t.Fatalf("a first-draft link: %#v, %v", got, err)
	}
}
