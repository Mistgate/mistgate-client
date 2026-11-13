package profile

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func tlsGRPC() map[string]any {
	return map[string]any{"server": "cdn.example", "port": 443, "uuid": testID, "transport": "grpc", "service_name": "svc",
		"security": "tls", "sni": "front.example", "alpn": []string{"h2"}}
}

func tlsHTTPUpgrade() map[string]any {
	return map[string]any{"server": "cdn.example", "port": 443, "uuid": testID, "transport": "httpupgrade", "path": "/up", "host": "front.example",
		"security": "tls", "sni": "front.example"}
}

func TestParseVLESSGRPC(t *testing.T) {
	p, err := ParseVLESS(vlessSettings(t, tlsGRPC(), nil))
	if err != nil || p.Transport != "grpc" || p.ServiceName != "svc" || p.Mode != "gun" || p.HTTPHost != "" || p.Security != "tls" || p.Path != "" {
		t.Fatalf("tls+grpc = %#v, %v", p, err)
	}
	p, err = ParseVLESS(vlessSettings(t, tlsGRPC(), map[string]any{"mode": "multi", "host": "auth.example", "service_name": "/a/b/Tun|TunMulti"}))
	if err != nil || p.Mode != "multi" || p.HTTPHost != "auth.example" || p.ServiceName != "/a/b/Tun|TunMulti" {
		t.Fatalf("multi, authority, custom path = %#v, %v", p, err)
	}
	// Xray asks for no TLS on gRPC (h2c), so plain is taken like on the other transports; REALITY carries gRPC
	if p, err = ParseVLESS(vlessSettings(t, tlsGRPC(), map[string]any{"security": "none", "sni": nil, "alpn": nil})); err != nil || p.Security != "none" {
		t.Fatalf("grpc without security = %#v, %v", p, err)
	}
	reality := vlessSettings(t, realityXHTTP(), map[string]any{"transport": "grpc", "service_name": "svc", "path": nil, "mode": nil, "x_padding_bytes": nil})
	if p, err = ParseVLESS(reality); err != nil || p.Security != "reality" || p.Transport != "grpc" {
		t.Fatalf("grpc over reality = %#v, %v", p, err)
	}
	for name, change := range map[string]map[string]any{
		"no service name":        {"service_name": nil},
		"service name a space":   {"service_name": "a b"},
		"service name a query":   {"service_name": "a?b"},
		"service name newline":   {"service_name": "a\nb"},
		"service name non-ascii": {"service_name": "сервис"},
		"service name too long":  {"service_name": strings.Repeat("a", 129)},
		"xhttp mode":             {"mode": "packet-up"},
		"authority with a CRLF":  {"host": "a.example\r\nX: y"},
	} {
		if p, err := ParseVLESS(vlessSettings(t, tlsGRPC(), change)); err == nil {
			t.Errorf("%s: accepted %#v", name, p)
		}
	}
}

func TestParseVLESSHTTPUpgrade(t *testing.T) {
	p, err := ParseVLESS(vlessSettings(t, tlsHTTPUpgrade(), nil))
	if err != nil || p.Transport != "httpupgrade" || p.Path != "/up" || p.HTTPHost != "front.example" || p.Mode != "" || p.XMux != nil {
		t.Fatalf("tls+httpupgrade = %#v, %v", p, err)
	}
	if p, err = ParseVLESS(vlessSettings(t, tlsHTTPUpgrade(), map[string]any{"security": "none", "sni": nil})); err != nil || p.Security != "none" {
		t.Fatalf("plain httpupgrade = %#v, %v", p, err)
	}
	for name, test := range map[string]struct {
		base   map[string]any
		change map[string]any
	}{
		"no path":           {tlsHTTPUpgrade(), map[string]any{"path": nil}},
		"path with a space": {tlsHTTPUpgrade(), map[string]any{"path": "/u p"}},
		"host with a CRLF":  {tlsHTTPUpgrade(), map[string]any{"host": "a.example\r\nX: y"}},
		"vision":            {tlsHTTPUpgrade(), map[string]any{"flow": "xtls-rprx-vision"}},
		"reality":           {realityXHTTP(), map[string]any{"transport": "httpupgrade"}}, // Xray: REALITY carries raw, xhttp and gRPC only
	} {
		if p, err := ParseVLESS(vlessSettings(t, test.base, test.change)); err == nil {
			t.Errorf("%s: accepted %#v", name, p)
		}
	}
}

func TestParseVLESSXMux(t *testing.T) {
	r := func(from, to int32) *[2]int32 { return &[2]int32{from, to} }
	p, err := ParseVLESS(vlessSettings(t, realityXHTTP(), map[string]any{"xmux": map[string]any{
		"maxConcurrency": "16-32", "cMaxReuseTimes": 7, "hMaxRequestTimes": "900-600", "hMaxReusableSecs": "0", "hKeepAlivePeriod": 45}}))
	if err != nil || p.XMux == nil || *p.XMux.MaxConcurrency != [2]int32{16, 32} || *p.XMux.CMaxReuseTimes != [2]int32{7, 7} ||
		*p.XMux.HMaxRequestTimes != [2]int32{600, 900} || *p.XMux.HMaxReusableSecs != [2]int32{} || p.XMux.MaxConnections != nil || p.XMux.HKeepAlivePeriod != 45 {
		t.Fatalf("xmux = %#v, %v", p, err)
	}
	// an explicit 0 on one of the two is no conflict (the common "maxConcurrency 16-32, maxConnections 0")
	if p, err = ParseVLESS(vlessSettings(t, realityXHTTP(), map[string]any{"xmux": map[string]any{"maxConcurrency": "16-32", "maxConnections": 0}})); err != nil ||
		*p.XMux.MaxConnections != *r(0, 0) {
		t.Fatalf("xmux with maxConnections 0 = %#v, %v", p, err)
	}
	if p, err = ParseVLESS(vlessSettings(t, realityXHTTP(), map[string]any{"xmux": map[string]any{}})); err != nil || p.XMux == nil || p.XMux.MaxConnections != nil {
		t.Fatalf("empty xmux = %#v, %v", p, err)
	}
	// xmux means nothing outside xhttp
	if p, err = ParseVLESS(vlessSettings(t, tlsWS(), map[string]any{"xmux": map[string]any{"maxConnections": 2}})); err != nil || p.XMux != nil {
		t.Fatalf("ws with xmux = %#v, %v", p, err)
	}
	for name, xmux := range map[string]any{
		"negative":          map[string]any{"maxConnections": -1},
		"negative range":    map[string]any{"maxConnections": "-3-5"},
		"text":              map[string]any{"maxConnections": "many"},
		"too big":           map[string]any{"maxConnections": "1-99999999999"},
		"an object":         map[string]any{"maxConnections": map[string]any{"a": 1}},
		"both":              map[string]any{"maxConcurrency": 8, "maxConnections": 2},
		"keep-alive minus":  map[string]any{"hKeepAlivePeriod": -5},
		"keep-alive a text": map[string]any{"hKeepAlivePeriod": "often"},
		"not an object":     "fast",
	} {
		if p, err := ParseVLESS(vlessSettings(t, realityXHTTP(), map[string]any{"xmux": xmux})); err == nil {
			t.Errorf("%s: accepted %#v", name, p.XMux)
		}
	}
}

func TestParseVLESSLinkGRPCAndHTTPUpgrade(t *testing.T) {
	const id = "8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b"
	base := "vless://" + id + "@edge.example.net:443?security=tls&sni=cdn.example.net&"
	g, err := ParseVLESSLink(base + "type=grpc&serviceName=my-svc&mode=multi&authority=auth.example.net#n")
	if err != nil || g.Transport != "grpc" || g.ServiceName != "my-svc" || g.Mode != "multi" || g.HTTPHost != "auth.example.net" || g.Security != "tls" {
		t.Fatalf("grpc link = %+v, %v", g, err)
	}
	if g, err = ParseVLESSLink(base + "type=grpc&serviceName=" + url.QueryEscape("/a/b/Tun")); err != nil || g.Mode != "gun" || g.ServiceName != "/a/b/Tun" || g.HTTPHost != "" {
		t.Fatalf("grpc link, defaults = %+v, %v", g, err)
	}
	if g, err = ParseVLESSLink(base + "type=grpc&serviceName=s&host=h.example.net"); err != nil || g.HTTPHost != "h.example.net" {
		t.Fatalf("grpc link, host for authority = %+v, %v", g, err)
	}
	h, err := ParseVLESSLink(base + "type=httpupgrade&path=%2Fup&host=front.example.net")
	if err != nil || h.Transport != "httpupgrade" || h.Path != "/up" || h.HTTPHost != "front.example.net" {
		t.Fatalf("httpupgrade link = %+v, %v", h, err)
	}
	if h, err = ParseVLESSLink(base + "type=httpupgrade"); err != nil || h.Path != "/" {
		t.Fatalf("httpupgrade link, no path = %+v, %v", h, err)
	}
	for name, link := range map[string]string{
		"grpc without a name":    base + "type=grpc",
		"grpc, odd mode":         base + "type=grpc&serviceName=s&mode=auto",
		"httpupgrade on reality": "vless://" + id + "@edge.example.net:443?type=httpupgrade&security=reality&sni=www.example.org&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"grpc, any certificate":  base + "type=grpc&serviceName=s&allowInsecure=1",
		"httpupgrade, vision":    base + "type=httpupgrade&flow=xtls-rprx-vision",
		"kcp":                    base + "type=kcp",
		"quic":                   base + "type=quic",
	} {
		if p, err := ParseVLESSLink(link); err == nil {
			t.Errorf("%s: accepted as %+v", name, p)
		}
	}
}

func TestParseVLESSLinkXMux(t *testing.T) {
	const id = "8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b"
	link := func(extra string) string {
		return "vless://" + id + "@edge.example.net:443?type=xhttp&security=tls&sni=cdn.example.net&path=%2Fup&extra=" + url.QueryEscape(extra)
	}
	p, err := ParseVLESSLink(link(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32","maxConnections":0,"cMaxReuseTimes":"64","hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":30},"downloadSettings":{"address":"x.example"},"scMaxEachPostBytes":1000000,"noGRPCHeader":true}`))
	if err != nil || p.XPadding != [2]int32{100, 1000} || p.XMux == nil || *p.XMux.MaxConcurrency != [2]int32{16, 32} || *p.XMux.MaxConnections != [2]int32{} ||
		*p.XMux.CMaxReuseTimes != [2]int32{64, 64} || *p.XMux.HMaxRequestTimes != [2]int32{600, 900} || *p.XMux.HMaxReusableSecs != [2]int32{1800, 3000} || p.XMux.HKeepAlivePeriod != 30 {
		t.Fatalf("xmux from extra = %+v (%+v), %v", p, p.XMux, err)
	}
	// extra is the server's tuning, never a reason to lose the server: what cannot be read is left out
	for name, extra := range map[string]string{
		"not json":         `{{{`,
		"a list":           `[1,2,3]`,
		"xmux a string":    `{"xmux":"fast"}`,
		"xmux negative":    `{"xmux":{"maxConnections":-4}}`,
		"xmux conflicting": `{"xmux":{"maxConnections":4,"maxConcurrency":4}}`,
		"xmux garbage":     `{"xmux":{"maxConnections":{"x":[]}}}`,
		"unknown only":     `{"somethingNew":1}`,
	} {
		p, err := ParseVLESSLink(link(extra))
		if err != nil || p.XMux != nil || p.Transport != "xhttp" {
			t.Errorf("%s: %+v, %v", name, p, err)
		}
	}
	// the padding next to a bad xmux is still read
	if p, err = ParseVLESSLink(link(`{"xPaddingBytes":"50-60","xmux":"fast"}`)); err != nil || p.XPadding != [2]int32{50, 60} || p.XMux != nil {
		t.Errorf("padding beside a bad xmux = %+v, %v", p, err)
	}
	// extra on another transport is not looked at
	if p, err = ParseVLESSLink("vless://" + id + "@edge.example.net:443?type=ws&security=tls&extra=" + url.QueryEscape(`{"xmux":{"maxConnections":2}}`)); err != nil || p.XMux != nil {
		t.Errorf("ws with extra = %+v, %v", p, err)
	}
}

func TestVLESSReason(t *testing.T) {
	const id = "8f3c1e2a-6b7d-4c9e-a1b2-3c4d5e6f7a8b"
	base := "vless://" + id + "@edge.example.net:443?security=tls&sni=cdn.example.net&"
	for want, link := range map[string]string{
		ReasonTransport:   base + "type=kcp",
		ReasonEncryption:  base + "type=tcp&encryption=mlkem768x25519plus.native.0rtt.abc",
		ReasonCertificate: base + "type=ws&allowInsecure=1",
		ReasonDisguise:    base + "type=tcp&headerType=http",
		ReasonFlow:        "vless://" + id + "@edge.example.net:80?type=tcp&security=none&flow=xtls-rprx-vision",
		ReasonSecurity:    "vless://" + id + "@edge.example.net:80?type=tcp&security=xtls",
		ReasonInvalid:     base + "type=grpc",
	} {
		_, err := ParseVLESSLink(link)
		if got := VLESSReason(err); err == nil || got != want {
			t.Errorf("%s: reason %q, err %v", want, got, err)
		}
	}
	if got := VLESSReason(errors.New("anything else")); got != ReasonInvalid {
		t.Errorf("foreign error: %q", got)
	}
}
