package profile

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net/netip"
)

func TestParseHy2(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	got, err := ParseHy2("hysteria2://user%3Asecret@10.77.0.11:4433/?sni=relay.example&obfs=gecko&obfs-password=obfs%2Bpw&pinSHA256=" + pin)
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth != "user:secret" || got.Host != "10.77.0.11" || got.Port != 4433 || got.ServerName != "relay.example" {
		t.Fatalf("unexpected Hysteria2 identity")
	}
	if got.Obfs != "gecko" || got.ObfsPassword != "obfs+pw" || !got.HasPin || got.Insecure {
		t.Fatalf("unexpected Hysteria2 options")
	}
	if hex.EncodeToString(got.PinSHA256[:]) != pin {
		t.Fatal("certificate pin was not decoded")
	}
}

func TestParseHy2WithoutPinAndInsecure(t *testing.T) {
	plain, err := ParseHy2("hy2://token@example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	if plain.HasPin || plain.Insecure || plain.ServerName != "example.test" {
		t.Fatalf("unexpected default TLS options")
	}
	insecure, err := ParseHy2("hy2://token@example.test:443?insecure=1")
	if err != nil || !insecure.Insecure || insecure.HasPin {
		t.Fatalf("insecure URI = %#v, %v", insecure, err)
	}
}

func TestParseHy2PortHopping(t *testing.T) {
	for _, test := range []struct {
		raw  string
		port uint16
	}{
		{"hy2://token@example.test:443?mport=20000-20100", 443},
		{"hy2://token@example.test:20000-20100", 20000},
		{"hy2://token@example.test:443,20000-20100", 443},
	} {
		got, err := ParseHy2(test.raw)
		if err != nil || got.Port != test.port || got.Ports != "20000-20100" {
			t.Errorf("ParseHy2(%q) = %#v, %v", test.raw, got, err)
		}
	}
	for _, raw := range []string{
		"hy2://token@example.test:443?mport=0-10",
		"hy2://token@example.test:443?mport=200-100",
		"hy2://token@example.test:20000-70000",
	} {
		if _, err := ParseHy2(raw); err == nil {
			t.Errorf("ParseHy2(%q) should reject an invalid port range", raw)
		}
	}
}

func TestParseAWG(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	conf := `[Interface]
Address = 10.66.4.3/32, fd66:66:0:1::3/128
DNS = 1.1.1.1, resolver.example, 2001:4860:4860::8888
MTU = 1280
PrivateKey = ` + key + `
Jc = 5
Jmin = 20
Jmax = 90
S1 = 13
S2 = 14
S3 = 15
S4 = 16
H1 = 1-2
H2 = 3
H3 = 4-5
H4 = 6
I1 = <b 0x4142><t>
HeaderProtectionKey = ` + key + `
ContentPaddingAddition = 20-63
RekeyAfterTime = 124-145
RekeyTimeout = 6-8
RejectAfterTime = 190-207
KeepaliveTimeout = 14-20
MaxHandshakeAttempts = 16-20
RandomTrailers = on
DisableCookies = off
[Peer]
PublicKey = ` + key + `
PresharedKey = ` + key + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:10796
PersistentKeepalive = 25-30
`
	got, err := ParseAWG(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 2 || got.Addresses[0].String() != "10.66.4.3/32" || got.MTU != 1280 {
		t.Fatalf("unexpected interface settings: %#v", got)
	}
	if len(got.DNS) != 2 || got.DNS[0].String() != "1.1.1.1" || got.DNS[1].String() != "2001:4860:4860::8888" {
		t.Fatalf("unexpected DNS servers: %v", got.DNS)
	}
	if got.EndpointHost != "vpn.example" || got.EndpointPort != 10796 || len(got.AllowedIPs) != 2 {
		t.Fatalf("unexpected peer settings")
	}
	for _, line := range []string{
		"jc=5", "jmin=20", "jmax=90", "s1=13", "s2=14", "s3=15", "s4=16",
		"private_key=" + strings.Repeat("00", 32), "h1=1-2", "h2=3", "h3=4-5", "h4=6",
		"i1=<b 0x4142><t>", "header_protection_key=" + strings.Repeat("00", 32),
		"content_padding_addition=20-63", "rekey_after_time=124-145", "rekey_timeout=6-8",
		"reject_after_time=190-207", "keepalive_timeout=14-20", "max_handshake_attempts=16-20",
		"random_trailers=true", "disable_cookies=false", "preshared_key=" + strings.Repeat("00", 32),
		"persistent_keepalive_interval=25-30", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0",
	} {
		if !strings.Contains(got.uapi, line+"\n") {
			t.Errorf("UAPI is missing field %q", line)
		}
	}
	if strings.Contains(got.uapi, "endpoint=") {
		t.Fatal("unresolved endpoint was included in UAPI")
	}
	endpoint := netip.MustParseAddrPort("198.51.100.4:10796")
	if !strings.HasSuffix(got.UAPI(endpoint), "endpoint=198.51.100.4:10796\n") {
		t.Fatal("resolved endpoint was not rendered in UAPI")
	}
}

func TestParseAWGErrorsDoNotLeakSecrets(t *testing.T) {
	secret := "conf-private-key-secret-marker"
	conf := `[Interface]
PrivateKey = ` + secret + `
[Peer]
PublicKey = also-not-a-key
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example:51820
`
	_, err := ParseAWG(conf)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "also-not-a-key") {
		t.Fatalf("unexpected configuration error: %v", err)
	}
}

func TestLoadNamesServerIDOnProfileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	data := `{"servers":[{"id":"de1-hy2","name":"Germany","protocol":"hysteria2","uri":"not a secret uri"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "de1-hy2") || strings.Contains(err.Error(), "not a secret uri") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestPick(t *testing.T) {
	profiles := []Profile{
		{ID: "hy2-first", Protocol: "hysteria2"},
		{ID: "awg-second", Protocol: "awg"},
		{ID: "hy2-third", Protocol: "hysteria2"},
	}
	for _, test := range []struct {
		server, protocol, want string
	}{
		{"auto", "awg", "awg-second"},
		{"", "auto", "hy2-first"},
		{"hy2-third", "hysteria2", "hy2-third"},
	} {
		got, ok := Pick(profiles, test.server, test.protocol, "")
		if !ok || got.ID != test.want {
			t.Errorf("Pick(%q, %q) = %#v, %v; want %q", test.server, test.protocol, got, ok, test.want)
		}
	}
	if _, ok := Pick(profiles, "awg-second", "hysteria2", ""); ok {
		t.Fatal("Pick matched an id with the wrong protocol")
	}
	profiles[0].Sub = "one"
	profiles[1].Sub = "two"
	if got, ok := Pick(profiles, "auto", "auto", "two"); !ok || got.ID != "awg-second" {
		t.Fatalf("Pick with subscription = %#v, %v", got, ok)
	}
}

func TestPickForSettingsGameModePrefersAWG(t *testing.T) {
	profiles := []Profile{
		{ID: "hy2", Protocol: "hysteria2", Sub: "one"},
		{ID: "awg", Protocol: "awg", Sub: "one"},
		{ID: "other-awg", Protocol: "awg", Sub: "two"},
		{ID: "only-hy2", Protocol: "hysteria2", Sub: "three"},
	}
	if got, ok := PickForSettings(profiles, "auto", "auto", "one", "auto", true); !ok || got.ID != "awg" {
		t.Fatalf("game selection = %#v, %v; want awg", got, ok)
	}
	if got, ok := PickForSettings(profiles, "auto", "auto", "one", "hysteria2", true); !ok || got.ID != "hy2" {
		t.Fatalf("configured protocol selection = %#v, %v; want hy2", got, ok)
	}
	if got, ok := PickForSettings(profiles, "awg", "hysteria2", "one", "hysteria2", true); !ok || got.ID != "awg" {
		t.Fatalf("concrete server selection = %#v, %v; want awg", got, ok)
	}
	if got, ok := PickForSettings(profiles, "auto", "auto", "one", "auto", true); !ok || got.ID == "other-awg" {
		t.Fatalf("subscription selection = %#v, %v; selected server from another subscription", got, ok)
	}
	if got, ok := PickForSettings(profiles, "auto", "auto", "three", "auto", true); !ok || got.ID != "only-hy2" {
		t.Fatalf("game fallback = %#v, %v; want the only available server", got, ok)
	}
}

func TestParseUintRange(t *testing.T) {
	for input, expected := range map[string]string{"5": "5", "20-63": "20-63", "0003-0004": "3-4"} {
		got, err := parseUintRange(input, 16)
		if err != nil || got != expected {
			t.Errorf("parseUintRange(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "8-2", "1-2-3", "65536", "x-y"} {
		if _, err := parseUintRange(input, 16); err == nil {
			t.Errorf("parseUintRange(%q) should fail", input)
		}
	}
}
