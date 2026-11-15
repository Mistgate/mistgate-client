package profile

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxTrustTunnelLink         = 16 * 1024
	maxTrustTunnelPathSettings = 16 * 1024 // Bound each panel settings object before decoding its fields.
)

var (
	ErrTrustTunnelSubscription = errors.New("TrustTunnel subscriptions are not supported")
	ErrTrustTunnelClientRandom = errors.New("TrustTunnel client random authentication is not supported")
)

// TrustTunnel is the static endpoint data from a TrustTunnel deep link.
type TrustTunnel struct {
	Host      string
	Addresses []string
	SNI       string
	Username  string
	Password  string
	HasIPv6   bool
	Insecure  bool
	Certs     [][]byte
	Name      string
	PinSHA256 [32]byte
	HasPin    bool
}

// ParseTrustTunnelPath reads the settings object of a panel's TrustTunnel path.
func ParseTrustTunnelPath(settings json.RawMessage) (*TrustTunnel, error) {
	if len(settings) == 0 || len(settings) > maxTrustTunnelPathSettings {
		return nil, errors.New("invalid TrustTunnel settings")
	}
	var input struct {
		Server    string `json:"server"`
		Port      int    `json:"port"`
		SNI       string `json:"sni"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		Transport string `json:"transport"`
		TLS       string `json:"tls"`
		PinSHA256 string `json:"pin_sha256"`
	}
	if json.Unmarshal(settings, &input) != nil || !validHost(input.Server) || !validHost(input.SNI) || input.Port < 1 || input.Port > 65535 {
		return nil, errors.New("invalid TrustTunnel endpoint")
	}
	if input.Transport != "h2" && input.Transport != "auto" {
		return nil, errors.New("unsupported TrustTunnel transport")
	}
	// Bound credentials before they are saved in the raw path and encoded into the authorization header.
	if len(input.Username) == 0 || len(input.Username) > 1024 || strings.ContainsRune(input.Username, ':') || hasTrustTunnelControl(input.Username) {
		return nil, errors.New("invalid TrustTunnel username")
	}
	if len(input.Password) == 0 || len(input.Password) > 1024 || hasTrustTunnelControl(input.Password) {
		return nil, errors.New("invalid TrustTunnel password")
	}
	result := &TrustTunnel{
		Host: input.SNI, SNI: input.SNI, Addresses: []string{net.JoinHostPort(input.Server, strconv.Itoa(input.Port))},
		Username: input.Username, Password: input.Password, HasIPv6: true,
	}
	switch input.TLS {
	case "", "ca":
	case "pin":
		pin, err := hex.DecodeString(input.PinSHA256)
		if err != nil || len(pin) != len(result.PinSHA256) {
			return nil, errors.New("invalid TrustTunnel certificate pin")
		}
		copy(result.PinSHA256[:], pin)
		result.HasPin = true
	default:
		return nil, errors.New("unsupported TrustTunnel TLS mode")
	}
	return result, nil
}

// TrustTunnelKind keeps unsupported link counts independent of link contents.
func TrustTunnelKind(err error) string {
	switch {
	case errors.Is(err, ErrTrustTunnelSubscription):
		return "trusttunnel (subscription)"
	case errors.Is(err, ErrTrustTunnelClientRandom):
		return "trusttunnel (client random)"
	default:
		return "trusttunnel"
	}
}

// ParseTrustTunnel reads the bounded TLV payload of a tt://? deep link.
func ParseTrustTunnel(raw string) (*TrustTunnel, error) {
	if len(raw) > maxTrustTunnelLink {
		return nil, errors.New("invalid TrustTunnel link")
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || !strings.EqualFold(scheme, "tt") {
		return nil, errors.New("invalid TrustTunnel link")
	}
	// The payload follows "tt://?"; links of the first draft, still met in the wild, have no "?".
	data, err := decodeTrustTunnelPayload(strings.TrimPrefix(rest, "?"))
	if err != nil {
		return nil, errors.New("invalid TrustTunnel link")
	}

	fields := make(map[uint64][]byte)
	addresses := make([][]byte, 0, 2)
	hasClientRandom := false
	for len(data) != 0 {
		tag, n, ok := readTrustTunnelVarint(data)
		if !ok {
			return nil, errors.New("invalid TrustTunnel link")
		}
		data = data[n:]
		length, n, ok := readTrustTunnelVarint(data)
		if !ok {
			return nil, errors.New("invalid TrustTunnel link")
		}
		data = data[n:]
		if length > uint64(len(data)) {
			return nil, errors.New("invalid TrustTunnel link")
		}
		value := data[:int(length)]
		data = data[int(length):]
		switch tag {
		case 0x02:
			if len(addresses) >= 64 {
				return nil, errors.New("invalid TrustTunnel link")
			}
			addresses = append(addresses, append([]byte(nil), value...))
		case 0x0b, 0x0f:
			hasClientRandom = true
		default:
			if tag <= 0x0e {
				fields[tag] = append([]byte(nil), value...)
			}
		}
	}
	if hasClientRandom {
		return nil, ErrTrustTunnelClientRandom
	}

	version := uint64(0)
	if value, ok := fields[0x00]; ok {
		parsed, used, ok := readTrustTunnelVarint(value)
		if !ok || used != len(value) {
			return nil, errors.New("invalid TrustTunnel link")
		}
		version = parsed
	}
	if version > 2 {
		return nil, errors.New("unsupported TrustTunnel link version")
	}

	_, hasSubscription := fields[0x0e]
	staticPresent := len(addresses) != 0
	for tag := uint64(0x01); tag <= 0x0a; tag++ {
		if _, present := fields[tag]; present {
			staticPresent = true
		}
	}
	if hasSubscription && !staticPresent {
		return nil, ErrTrustTunnelSubscription
	}

	host, ok := trustTunnelString(fields, 0x01, 253)
	if !ok || !validHost(host) {
		return nil, errors.New("invalid TrustTunnel hostname")
	}
	if len(addresses) == 0 {
		return nil, errors.New("TrustTunnel address is missing")
	}
	profile := &TrustTunnel{Host: host, HasIPv6: true}
	for _, rawAddress := range addresses {
		if !utf8.Valid(rawAddress) || len(rawAddress) > 320 {
			return nil, errors.New("invalid TrustTunnel address")
		}
		address := string(rawAddress)
		hostPart, portPart, err := net.SplitHostPort(address)
		port, portErr := strconv.ParseUint(portPart, 10, 16)
		if err != nil || portErr != nil || port == 0 || !validHost(hostPart) {
			return nil, errors.New("invalid TrustTunnel address")
		}
		profile.Addresses = append(profile.Addresses, address)
	}
	if len(profile.Addresses) == 0 {
		return nil, errors.New("TrustTunnel address is missing")
	}

	if _, present := fields[0x03]; present {
		profile.SNI, ok = trustTunnelString(fields, 0x03, 253)
		if !ok || !validHost(profile.SNI) {
			return nil, errors.New("invalid TrustTunnel server name")
		}
	}
	profile.Username, ok = trustTunnelString(fields, 0x05, 1024)
	if !ok || profile.Username == "" || strings.ContainsRune(profile.Username, ':') || hasTrustTunnelControl(profile.Username) {
		return nil, errors.New("invalid TrustTunnel username")
	}
	profile.Password, ok = trustTunnelString(fields, 0x06, 1024)
	if !ok || profile.Password == "" || hasTrustTunnelControl(profile.Password) {
		return nil, errors.New("invalid TrustTunnel password")
	}
	if value, present := fields[0x04]; present {
		parsed, ok := trustTunnelBool(value)
		if !ok {
			return nil, errors.New("invalid TrustTunnel IPv6 setting")
		}
		profile.HasIPv6 = parsed
	}
	if value, present := fields[0x07]; present {
		parsed, ok := trustTunnelBool(value)
		if !ok {
			return nil, errors.New("invalid TrustTunnel certificate setting")
		}
		profile.Insecure = parsed
	}
	if value, present := fields[0x08]; present && len(value) != 0 {
		certificates, err := x509.ParseCertificates(value)
		if err != nil || len(certificates) == 0 {
			return nil, errors.New("invalid TrustTunnel certificate")
		}
		for _, certificate := range certificates {
			profile.Certs = append(profile.Certs, append([]byte(nil), certificate.Raw...))
		}
		profile.Insecure = false
	}
	if value, present := fields[0x09]; present {
		protocol, used, ok := readTrustTunnelVarint(value)
		if !ok || used != len(value) || protocol != 1 && protocol != 2 {
			return nil, errors.New("unsupported TrustTunnel transport")
		}
		// ponytail: HTTP/3 is step 2; links that request it use HTTP/2 until then.
	}
	if value, present := fields[0x0a]; present {
		if _, ok := trustTunnelBool(value); !ok {
			return nil, errors.New("invalid TrustTunnel anti-DPI setting")
		}
		// ponytail: anti-DPI is ignored in step 1; upgrade = implement the requested TLS changes.
	}
	if value, present := fields[0x0c]; present {
		if !utf8.Valid(value) {
			return nil, errors.New("invalid TrustTunnel name")
		}
		profile.Name = string(value)
	}
	// Tag 0x0d (DNS upstreams) does not affect the system resolver in this step.
	return profile, nil
}

func decodeTrustTunnelPayload(payload string) ([]byte, error) {
	if payload == "" {
		return nil, errors.New("empty payload")
	}
	padding := strings.IndexByte(payload, '=')
	encoded := payload
	if padding >= 0 {
		if len(payload)-padding > 2 || len(payload)%4 != 0 {
			return nil, errors.New("invalid padding")
		}
		encoded = payload[:padding]
		for i := range encoded {
			if !isURLBase64(encoded[i]) {
				return nil, errors.New("invalid payload")
			}
		}
		for i := padding; i < len(payload); i++ {
			if payload[i] != '=' {
				return nil, errors.New("invalid padding")
			}
		}
		return base64.URLEncoding.Strict().DecodeString(payload)
	}
	for i := range payload {
		if !isURLBase64(payload[i]) {
			return nil, errors.New("invalid payload")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(payload)
}

func isURLBase64(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-' || value == '_'
}

func readTrustTunnelVarint(data []byte) (uint64, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, false
	}
	value := uint64(data[0] & 0x3f)
	for _, part := range data[1:size] {
		value = value<<8 | uint64(part)
	}
	return value, size, true
}

func trustTunnelString(fields map[uint64][]byte, tag uint64, limit int) (string, bool) {
	value, present := fields[tag]
	if !present || len(value) == 0 || len(value) > limit || !utf8.Valid(value) {
		return "", false
	}
	return string(value), true
}

func trustTunnelBool(value []byte) (bool, bool) {
	if len(value) != 1 || value[0] > 1 {
		return false, false
	}
	return value[0] == 1, true
}

func hasTrustTunnelControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
