package subs

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTrustTunnelLinkAmongPastedLinks(t *testing.T) {
	ttLink := subscriptionTrustTunnelLink(
		[2]byte{0x01, 0x11}, []byte("edge.example.test"),
		[2]byte{0x02, 0x0f}, []byte("203.0.113.8:443"),
		[2]byte{0x05, 0x04}, []byte("user"),
		[2]byte{0x06, 0x06}, []byte("secret"),
		[2]byte{0x07, 0x01}, []byte{1},
		[2]byte{0x0c, 0x04}, []byte("Edge"),
	)
	text := "hy2://auth@203.0.113.9:443#Fast " + ttLink + " vless://invalid"
	preview, err := openTestStore(t, t.TempDir(), nil).Preview(context.Background(), text)
	if err != nil || len(preview.Servers) != 2 || preview.Unsupported != 1 {
		t.Fatalf("pasted mixed links = %#v, %v", preview, err)
	}
	if preview.Servers[1].Protocol != "trusttunnel" || preview.Servers[1].Name != "Edge" || !preview.Servers[1].Insecure {
		t.Fatalf("TrustTunnel entry = %#v", preview.Servers[1])
	}
}

func TestTrustTunnelSubscriptionProfileRoundTrip(t *testing.T) {
	link := subscriptionTrustTunnelLink(
		[2]byte{0x01, 0x11}, []byte("edge.example.test"),
		[2]byte{0x02, 0x0f}, []byte("203.0.113.8:443"),
		[2]byte{0x05, 0x04}, []byte("user"),
		[2]byte{0x06, 0x06}, []byte("secret"),
		[2]byte{0x09, 0x01}, []byte{2},
		[2]byte{0x0c, 0x04}, []byte("Edge"),
	)
	dir := t.TempDir()
	store := openTestStore(t, dir, nil)
	added, err := store.Add(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := reopened.Profiles()
	if err != nil || len(profiles) != 1 {
		t.Fatalf("TrustTunnel profiles = %#v, %v", profiles, err)
	}
	p := profiles[0]
	if p.Protocol != "trusttunnel" || p.TT == nil || p.Name != "Edge" || p.TT.Host != "edge.example.test" || p.TT.Username != "user" || p.Sub != added.ID {
		t.Fatalf("TrustTunnel profile did not round-trip: %#v", p)
	}
	if !p.TT.H3 {
		t.Fatal("the HTTP/3 request of the link was lost on the way through the store")
	}
}

func TestTrustTunnelUnsupportedKinds(t *testing.T) {
	subscriptionOnly := subscriptionTrustTunnelLink([2]byte{0x0e, 0x18}, []byte("https://example.test/sub"))
	clientRandom := subscriptionTrustTunnelLink(
		[2]byte{0x01, 0x11}, []byte("edge.example.test"),
		[2]byte{0x02, 0x0f}, []byte("203.0.113.8:443"),
		[2]byte{0x05, 0x04}, []byte("user"),
		[2]byte{0x06, 0x06}, []byte("secret"),
		[2]byte{0x0b, 0x02}, []byte("00"),
	)
	_, _, unsupported, kinds, err := parseEntries(strings.Join([]string{subscriptionOnly, clientRandom, "tt://?A"}, "\n"), "sub")
	if err == nil || unsupported != 3 {
		t.Fatalf("unsupported TrustTunnel links = %d, %v", unsupported, err)
	}
	want := map[string]int{"trusttunnel (subscription)": 1, "trusttunnel (client random)": 1, "trusttunnel": 1}
	if len(kinds) != len(want) {
		t.Fatalf("unsupported kinds = %v", kinds)
	}
	for kind, count := range want {
		if kinds[kind] != count {
			t.Errorf("kind %q = %d, want %d", kind, kinds[kind], count)
		}
	}
}

func subscriptionTrustTunnelLink(parts ...any) string {
	var payload []byte
	for i := 0; i < len(parts); i += 2 {
		tag := parts[i].([2]byte)
		payload = append(payload, tag[:]...)
		payload = append(payload, parts[i+1].([]byte)...)
	}
	return "tt://?" + base64.RawURLEncoding.EncodeToString(payload)
}
