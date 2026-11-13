package profile

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ParseVLESSLink reads a "vless://" share link, as other panels and apps give them (the v2rayN form):
//
//	vless://<uuid>@<host>:<port>?type=..&security=..&sni=..&fp=..&pbk=..&sid=..&flow=..&path=..&host=..&mode=..&alpn=..#name
//
// It is turned into the settings of a panel's "vless" path and checked by ParseVLESS, so a link is held to the same
// rules. What this build cannot carry is refused, not guessed around: transports other than raw (tcp), xhttp, ws,
// httpupgrade and grpc, VLESS's own encryption, a header disguise on raw, and a link that asks to accept any certificate.
func ParseVLESSLink(raw string) (*VLESS, error) {
	link, _, _ := strings.Cut(strings.TrimSpace(raw), "#")
	u, err := url.Parse(link)
	if err != nil || !strings.EqualFold(u.Scheme, "vless") || u.User == nil {
		return nil, errors.New("invalid VLESS link")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, errors.New("invalid VLESS port")
	}
	q := u.Query()
	first := func(keys ...string) string {
		for _, key := range keys {
			if value := q.Get(key); value != "" {
				return value
			}
		}
		return ""
	}
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		return nil, refuse(ReasonEncryption, "unsupported VLESS encryption")
	}
	for _, key := range []string{"allowInsecure", "insecure", "allow_insecure"} {
		if value := strings.ToLower(q.Get(key)); value == "1" || value == "true" {
			return nil, refuse(ReasonCertificate, "VLESS link asks to accept any certificate")
		}
	}
	transport := strings.ToLower(first("type", "net"))
	switch transport {
	case "", "tcp", "raw":
		transport = "raw"
		if head := first("headerType"); head != "" && head != "none" {
			return nil, refuse(ReasonDisguise, "unsupported VLESS header disguise")
		}
	case "xhttp", "splithttp":
		transport = "xhttp"
	case "ws", "httpupgrade", "grpc":
	default:
		return nil, refuse(ReasonTransport, "unsupported VLESS transport")
	}
	settings := map[string]any{
		"server": u.Hostname(), "port": port, "uuid": u.User.Username(), "flow": q.Get("flow"),
		"transport": transport, "path": q.Get("path"), "host": q.Get("host"), "mode": q.Get("mode"),
		"service_name": q.Get("serviceName"),
		"security":     strings.ToLower(q.Get("security")), "sni": first("sni", "peer", "serverName"), "fingerprint": strings.ToLower(q.Get("fp")),
		"public_key": q.Get("pbk"), "short_id": q.Get("sid"), "spider_x": q.Get("spx"),
	}
	if transport != "raw" && settings["path"] == "" {
		settings["path"] = "/"
	}
	if transport == "grpc" { // the :authority is the link's "authority"; some exporters put it in "host"
		settings["host"] = first("authority", "host")
	}
	if alpn := q.Get("alpn"); alpn != "" {
		settings["alpn"] = strings.Split(alpn, ",")
	}
	// xhttp's "extra" is Xray's own JSON. Of it the padding is taken (the server may insist on it) and the xmux (how
	// connections are shared; client-side only). A xmux this build cannot read is dropped, not held against the link:
	// the defaults are safe, and the link works without it.
	// ponytail: downloadSettings, the sc* limits, noGRPCHeader and the other fields are not read; add them when a server needs them.
	if extra := q.Get("extra"); extra != "" && transport == "xhttp" {
		var e struct {
			XPaddingBytes json.RawMessage `json:"xPaddingBytes"`
			XMux          json.RawMessage `json:"xmux"`
		}
		if json.Unmarshal([]byte(extra), &e) == nil {
			if len(e.XPaddingBytes) > 0 {
				settings["x_padding_bytes"] = e.XPaddingBytes
			}
			if _, err := parseXMux(e.XMux); err == nil && len(e.XMux) > 0 {
				settings["xmux"] = e.XMux
			}
		}
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, errors.New("invalid VLESS link")
	}
	return ParseVLESS(encoded)
}
