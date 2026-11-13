package profile

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// VLESS is a panel path that Xray carries (docs/client-api.md). Every value is checked in ParseVLESS, the only place
// that knows the panel's field names; internal/xray trusts what it gets here.
type VLESS struct {
	Host      string // bare host name or address; the client resolves it, Xray is given the address
	Port      uint16
	UUID      string
	Flow      string // "" or "xtls-rprx-vision"
	Transport string // "raw", "xhttp" or "ws"
	Path      string // xhttp and ws; starts with "/"
	HTTPHost  string // xhttp and ws; the Host header when it differs from the SNI
	Mode      string // xhttp: "auto", "packet-up", "stream-up" or "stream-one"
	XPadding  [2]int32
	Security  string // "reality", "tls" or "none" (no outer encryption: only what the sites themselves encrypt is hidden)
	SNI       string
	// Fingerprint is the uTLS ClientHello to imitate.
	Fingerprint string
	PublicKey   [32]byte // reality
	ShortID     [8]byte  // reality, zero-padded
	SpiderX     string   // reality
	ALPN        []string // tls
}

// VLESSFlowVision is the only flow; any other value makes the path unsupported.
const VLESSFlowVision = "xtls-rprx-vision"

// fingerprints are the uTLS presets of Xray that make a browser-like hello ("unsafe" and the like are left out).
var fingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true, "360": true, "qq": true,
	"random": true, "randomized": true, "randomizednoalpn": true,
}

// ParseVLESS reads the settings object of a "vless" path.
func ParseVLESS(settings json.RawMessage) (*VLESS, error) {
	var s struct {
		Server        string          `json:"server"`
		Port          int             `json:"port"`
		UUID          string          `json:"uuid"`
		Flow          string          `json:"flow"`
		Transport     string          `json:"transport"`
		Path          string          `json:"path"`
		Host          string          `json:"host"`
		Mode          string          `json:"mode"`
		XPaddingBytes json.RawMessage `json:"x_padding_bytes"`
		Security      string          `json:"security"`
		SNI           string          `json:"sni"`
		Fingerprint   string          `json:"fingerprint"`
		PublicKey     string          `json:"public_key"`
		ShortID       string          `json:"short_id"`
		SpiderX       string          `json:"spider_x"`
		ALPN          []string        `json:"alpn"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil, errors.New("invalid VLESS settings")
	}
	out := &VLESS{Host: s.Server, Flow: s.Flow, Transport: s.Transport, Security: s.Security, SNI: s.SNI, Fingerprint: s.Fingerprint}
	if out.Security == "" {
		out.Security = "none" // said before the flow is checked: Vision needs TLS or REALITY
	}
	if !validHost(s.Server) {
		return nil, errors.New("invalid VLESS server")
	}
	port, err := parsePort(strconv.Itoa(s.Port))
	if err != nil {
		return nil, errors.New("invalid VLESS port")
	}
	out.Port = port
	if out.UUID = canonicalUUID(s.UUID); out.UUID == "" {
		return nil, errors.New("invalid VLESS user id")
	}
	switch out.Transport {
	case "raw": // path, host and the xhttp fields mean nothing here and are ignored
	case "xhttp", "ws":
		if out.Path = s.Path; !validPath(out.Path) {
			return nil, errors.New("invalid VLESS path")
		}
		if s.Host != "" {
			if !validHost(s.Host) {
				return nil, errors.New("invalid VLESS host header")
			}
			out.HTTPHost = s.Host
		}
		if out.Transport == "ws" {
			break
		}
		switch out.Mode = s.Mode; out.Mode {
		case "":
			out.Mode = "auto"
		case "auto", "packet-up", "stream-up", "stream-one":
		default:
			return nil, errors.New("unsupported VLESS xhttp mode")
		}
		if out.XPadding, err = parseXPadding(s.XPaddingBytes); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported VLESS transport")
	}
	switch out.Flow {
	case "":
	case VLESSFlowVision:
		// Vision rides directly on the TLS (or REALITY) of the raw transport; Xray refuses it anywhere else.
		if out.Transport != "raw" || out.Security == "none" {
			return nil, errors.New("VLESS flow needs the raw transport with TLS or REALITY")
		}
	default:
		return nil, errors.New("unsupported VLESS flow")
	}
	if out.Fingerprint == "" {
		out.Fingerprint = "chrome"
	}
	if !fingerprints[out.Fingerprint] {
		return nil, errors.New("unsupported VLESS fingerprint")
	}
	switch out.Security {
	case "reality":
		if out.Transport == "ws" {
			return nil, errors.New("VLESS reality does not carry ws")
		}
		if !validName(s.SNI) {
			return nil, errors.New("invalid VLESS server name")
		}
		key, err := base64.RawURLEncoding.DecodeString(s.PublicKey)
		if err != nil || len(key) != len(out.PublicKey) {
			return nil, errors.New("invalid VLESS reality key")
		}
		copy(out.PublicKey[:], key)
		id, err := hex.DecodeString(s.ShortID)
		if err != nil || len(id) > len(out.ShortID) {
			return nil, errors.New("invalid VLESS reality short id")
		}
		copy(out.ShortID[:], id)
		if out.SpiderX = s.SpiderX; out.SpiderX != "" && !validPath(out.SpiderX) {
			return nil, errors.New("invalid VLESS reality spider path")
		}
	case "tls":
		if s.SNI != "" && !validName(s.SNI) {
			return nil, errors.New("invalid VLESS server name")
		}
		if _, isAddress := netip.ParseAddr(out.Host); out.SNI == "" && isAddress != nil {
			out.SNI = out.Host // the certificate must be good for the name the server is known by
		}
		if len(s.ALPN) > 8 {
			return nil, errors.New("too many VLESS ALPN values")
		}
		for _, protocol := range s.ALPN {
			if !validALPN(protocol) {
				return nil, errors.New("invalid VLESS ALPN value")
			}
		}
		out.ALPN = s.ALPN
	case "none":
		// Plain VLESS, as some providers give it: nothing wraps the connection, so the network on the way sees that it is
		// VLESS, and of the traffic everything a site does not encrypt itself. Taken as it is; the choice is the provider's.
		out.SNI = ""
	default:
		return nil, errors.New("unsupported VLESS security")
	}
	return out, nil
}

// validName is a DNS name's characters, at most 253 of them. It is not a full hostname check; the name only ever goes
// into a TLS server name or a Host header.
func validName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// validHost is a name or a bare IP address (IPv6 without brackets).
func validHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	return validName(value)
}

// validPath is a URL path (a query may follow): "/" first, printable ASCII, no space.
func validPath(value string) bool {
	if len(value) == 0 || len(value) > 256 || value[0] != '/' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= ' ' || value[i] >= 0x7f || value[i] == '#' {
			return false
		}
	}
	return true
}

func validALPN(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// canonicalUUID is the lower-case 8-4-4-4-12 form of a UUID, or "".
func canonicalUUID(value string) string {
	if len(value) != 36 {
		return ""
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return ""
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'):
			return ""
		}
	}
	return strings.ToLower(value)
}

// parseXPadding reads xhttp's padding range: absent (Xray's default, 0-0), a number, or "from-to". The panel's shape
// for it may still move, so this is the one place that reads it.
func parseXPadding(raw json.RawMessage) ([2]int32, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return [2]int32{}, nil
	}
	text := strings.Trim(string(raw), `"`)
	from, to, isRange := strings.Cut(text, "-")
	if !isRange {
		to = from
	}
	lo, err1 := strconv.ParseInt(from, 10, 32)
	hi, err2 := strconv.ParseInt(to, 10, 32)
	if err1 != nil || err2 != nil || lo < 1 || hi < lo || hi > 65535 {
		return [2]int32{}, errors.New("invalid VLESS xhttp padding")
	}
	return [2]int32{int32(lo), int32(hi)}, nil
}
