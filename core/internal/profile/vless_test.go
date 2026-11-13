package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testKey = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM" // 32 bytes, base64url without padding
	testID  = "5783A3E7-E373-51CD-8642-C83782B807C5"
)

func vlessSettings(t *testing.T, base map[string]any, change map[string]any) json.RawMessage {
	t.Helper()
	merged := map[string]any{}
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range change {
		if v == nil {
			delete(merged, k)
		} else {
			merged[k] = v
		}
	}
	data, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func realityVision() map[string]any {
	return map[string]any{"server": "node.example", "port": 443, "uuid": testID, "flow": "xtls-rprx-vision", "transport": "raw",
		"security": "reality", "sni": "www.example.com", "public_key": testKey, "short_id": "0123456789abcdef", "spider_x": "/"}
}

func realityXHTTP() map[string]any {
	return map[string]any{"server": "203.0.113.9", "port": 8443, "uuid": testID, "transport": "xhttp", "path": "/xh", "mode": "stream-up",
		"x_padding_bytes": "100-1000", "security": "reality", "sni": "www.example.com", "fingerprint": "firefox",
		"public_key": testKey, "short_id": "ab"}
}

func tlsWS() map[string]any {
	return map[string]any{"server": "cdn.example", "port": 443, "uuid": testID, "transport": "ws", "path": "/ws?ed=2048", "host": "front.example",
		"security": "tls", "sni": "front.example", "alpn": []string{"h2", "http/1.1"}}
}

func TestParseVLESSGood(t *testing.T) {
	p, err := ParseVLESS(vlessSettings(t, realityVision(), nil))
	if err != nil || p.Host != "node.example" || p.Port != 443 || p.UUID != strings.ToLower(testID) || p.Flow != VLESSFlowVision ||
		p.Transport != "raw" || p.Security != "reality" || p.SNI != "www.example.com" || p.Fingerprint != "chrome" ||
		p.ShortID != [8]byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef} || p.PublicKey[0] != 0x13 || p.SpiderX != "/" || p.Mode != "" {
		t.Fatalf("reality+raw+vision = %#v, %v", p, err)
	}
	p, err = ParseVLESS(vlessSettings(t, realityXHTTP(), nil))
	if err != nil || p.Transport != "xhttp" || p.Path != "/xh" || p.Mode != "stream-up" || p.XPadding != [2]int32{100, 1000} ||
		p.Fingerprint != "firefox" || p.ShortID != [8]byte{0xab} || p.HTTPHost != "" || p.Flow != "" {
		t.Fatalf("reality+xhttp = %#v, %v", p, err)
	}
	p, err = ParseVLESS(vlessSettings(t, realityXHTTP(), map[string]any{"mode": nil, "x_padding_bytes": 300, "host": "h.example", "short_id": ""}))
	if err != nil || p.Mode != "auto" || p.XPadding != [2]int32{300, 300} || p.HTTPHost != "h.example" || p.ShortID != [8]byte{} {
		t.Fatalf("defaults = %#v, %v", p, err)
	}
	p, err = ParseVLESS(vlessSettings(t, tlsWS(), nil))
	if err != nil || p.Transport != "ws" || p.Path != "/ws?ed=2048" || p.HTTPHost != "front.example" || p.Security != "tls" || len(p.ALPN) != 2 || p.Mode != "" {
		t.Fatalf("tls+ws = %#v, %v", p, err)
	}
	p, err = ParseVLESS(vlessSettings(t, tlsWS(), map[string]any{"transport": "xhttp", "path": "/x", "sni": nil, "server": "2001:db8::1"}))
	if err != nil || p.Host != "2001:db8::1" || p.SNI != "" || p.Mode != "auto" {
		t.Fatalf("tls+xhttp, address, no sni = %#v, %v", p, err)
	}
	if p, err = ParseVLESS(vlessSettings(t, tlsWS(), map[string]any{"sni": nil})); err != nil || p.SNI != "cdn.example" {
		t.Fatalf("tls without sni takes the server name: %#v, %v", p, err)
	}
	// values meant for another transport are ignored, not an error
	if _, err := ParseVLESS(vlessSettings(t, realityVision(), map[string]any{"path": "/ignored", "mode": "packet-up"})); err != nil {
		t.Fatalf("raw with xhttp fields: %v", err)
	}
}

func TestParseVLESSBad(t *testing.T) {
	for name, test := range map[string]struct {
		base   map[string]any
		change map[string]any
	}{
		"no server":               {realityVision(), map[string]any{"server": nil}},
		"server with a path":      {realityVision(), map[string]any{"server": "node.example/x"}},
		"server with a space":     {realityVision(), map[string]any{"server": "node example"}},
		"server with a zone":      {realityVision(), map[string]any{"server": "fe80::1%eth0"}},
		"bracketed server":        {realityVision(), map[string]any{"server": "[2001:db8::1]"}},
		"port zero":               {realityVision(), map[string]any{"port": 0}},
		"port too big":            {realityVision(), map[string]any{"port": 65536}},
		"port a string":           {realityVision(), map[string]any{"port": "443"}},
		"no port":                 {realityVision(), map[string]any{"port": nil}},
		"short uuid":              {realityVision(), map[string]any{"uuid": "5783a3e7-e373-51cd-8642"}},
		"uuid without dashes":     {realityVision(), map[string]any{"uuid": "5783a3e7e37351cd8642c83782b807c5xxxx"}},
		"uuid not hex":            {realityVision(), map[string]any{"uuid": "5783a3e7-e373-51cd-8642-c83782b807cz"}},
		"unknown flow":            {realityVision(), map[string]any{"flow": "xtls-rprx-direct"}},
		"vision on xhttp":         {realityXHTTP(), map[string]any{"flow": "xtls-rprx-vision"}},
		"grpc without a name":     {realityVision(), map[string]any{"transport": "grpc"}},
		"no transport":            {realityVision(), map[string]any{"transport": nil}},
		"xhttp without a path":    {realityXHTTP(), map[string]any{"path": nil}},
		"path without a slash":    {realityXHTTP(), map[string]any{"path": "xh"}},
		"path with a space":       {realityXHTTP(), map[string]any{"path": "/x h"}},
		"path with a newline":     {realityXHTTP(), map[string]any{"path": "/x\nHost: evil"}},
		"path with a fragment":    {realityXHTTP(), map[string]any{"path": "/x#y"}},
		"path too long":           {realityXHTTP(), map[string]any{"path": "/" + strings.Repeat("a", 300)}},
		"host header with a CRLF": {realityXHTTP(), map[string]any{"host": "a.example\r\nX: y"}},
		"unknown mode":            {realityXHTTP(), map[string]any{"mode": "burst"}},
		"padding zero":            {realityXHTTP(), map[string]any{"x_padding_bytes": 0}},
		"padding reversed":        {realityXHTTP(), map[string]any{"x_padding_bytes": "900-100"}},
		"padding text":            {realityXHTTP(), map[string]any{"x_padding_bytes": "many"}},
		"padding huge":            {realityXHTTP(), map[string]any{"x_padding_bytes": "1-99999999"}},
		"padding an object":       {realityXHTTP(), map[string]any{"x_padding_bytes": map[string]any{"from": 1, "to": 2}}},
		"no security":             {realityVision(), map[string]any{"security": nil}},
		"security none":           {realityVision(), map[string]any{"security": "none"}},
		"reality on ws":           {realityXHTTP(), map[string]any{"transport": "ws"}},
		"reality without sni":     {realityVision(), map[string]any{"sni": nil}},
		"sni with a slash":        {realityVision(), map[string]any{"sni": "a/b"}},
		"no public key":           {realityVision(), map[string]any{"public_key": nil}},
		"short public key":        {realityVision(), map[string]any{"public_key": testKey[:40]}},
		"public key with padding": {realityVision(), map[string]any{"public_key": testKey + "="}},
		"public key not base64":   {realityVision(), map[string]any{"public_key": strings.Repeat("!", 43)}},
		"odd short id":            {realityVision(), map[string]any{"short_id": "abc"}},
		"short id not hex":        {realityVision(), map[string]any{"short_id": "zz"}},
		"long short id":           {realityVision(), map[string]any{"short_id": "0123456789abcdef00"}},
		"spider without a slash":  {realityVision(), map[string]any{"spider_x": "p"}},
		"unknown fingerprint":     {realityVision(), map[string]any{"fingerprint": "netscape"}},
		"unsafe fingerprint":      {realityVision(), map[string]any{"fingerprint": "unsafe"}},
		"tls sni with a space":    {tlsWS(), map[string]any{"sni": "a b"}},
		"tls alpn with a space":   {tlsWS(), map[string]any{"alpn": []string{"h 2"}}},
		"tls alpn empty":          {tlsWS(), map[string]any{"alpn": []string{""}}},
		"tls too many alpn":       {tlsWS(), map[string]any{"alpn": []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}}},
	} {
		if p, err := ParseVLESS(vlessSettings(t, test.base, test.change)); err == nil {
			t.Errorf("%s: accepted %#v", name, p)
		}
	}
	if _, err := ParseVLESS(json.RawMessage(`[1,2]`)); err == nil {
		t.Error("accepted a JSON array")
	}
	if _, err := ParseVLESS(nil); err == nil {
		t.Error("accepted no settings")
	}
}

// An error says what is wrong, never the value that is: a log line made of one would carry a key or a server.
func TestParseVLESSErrorsDoNotLeakValues(t *testing.T) {
	for _, change := range []map[string]any{
		{"public_key": "secret-key-material"}, {"uuid": "secret-user-id"}, {"server": "secret.server.example/x"},
		{"short_id": "secret"}, {"sni": "secret sni"}, {"path": "secret path"},
	} {
		_, err := ParseVLESS(vlessSettings(t, realityXHTTP(), change))
		if err == nil {
			t.Fatalf("%v accepted", change)
		}
		for _, v := range change {
			if strings.Contains(err.Error(), v.(string)) {
				t.Errorf("error %q repeats %q", err, v)
			}
		}
	}
}

func TestPickWithVLESS(t *testing.T) {
	profiles := []Profile{
		{ID: "hy2", Protocol: "hysteria2", Sub: "one"},
		{ID: "vl", Protocol: "vless", Sub: "one"},
		{ID: "awg", Protocol: "awg", Sub: "one"},
		{ID: "vl2", Protocol: "vless", Sub: "one"},
	}
	if got, ok := Pick(profiles, "auto", "vless", "one"); !ok || got.ID != "vl" {
		t.Fatalf("Pick vless = %#v, %v", got, ok)
	}
	if _, ok := Pick(profiles, "vl", "awg", "one"); ok {
		t.Fatal("Pick matched a vless id under another protocol")
	}
	// the configured protocol decides in automatic selection, and the game preference gives way to it
	if got, ok := PickForSettings(profiles, "auto", "auto", "one", "vless", true); !ok || got.ID != "vl" {
		t.Fatalf("configured vless = %#v, %v", got, ok)
	}
	if got, ok := PickForSettings(profiles, "auto", "vless", "one", "hysteria2", false); !ok || got.ID != "vl" {
		t.Fatalf("requested vless = %#v, %v", got, ok)
	}
	if got, ok := PickForSettings(profiles, "awg", "vless", "one", "vless", false); !ok || got.ID != "awg" {
		t.Fatalf("a concrete server keeps its own protocol = %#v, %v", got, ok)
	}
	if next, ok := Next(profiles, "auto", "auto", "one", "vless", false, "vl"); !ok || next != "vl2" {
		t.Fatalf("Next in a vless round = %q, %v", next, ok)
	}
	if others := Others(profiles, "auto", "auto", "one", "vless", false, "vl"); len(others) != 1 || others[0].ID != "vl2" {
		t.Fatalf("Others in a vless round = %#v", others)
	}
}
