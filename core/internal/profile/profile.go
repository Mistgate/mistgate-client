package profile

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Profile struct {
	ID       string
	Name     string
	Protocol string
	Hy2      *Hy2
	AWG      *AWG
	Verify   string
}

type Hy2 struct {
	Auth         string
	Host         string
	Port         uint16
	ServerName   string
	Obfs         string
	ObfsPassword string
	PinSHA256    [32]byte
	HasPin       bool
	Insecure     bool
}

type AWG struct {
	Addresses    []netip.Prefix
	MTU          int
	DNS          []netip.Addr
	AllowedIPs   []netip.Prefix
	ServerKey    string
	EndpointHost string
	EndpointPort uint16
	uapi         string
}

func ParseHy2(raw string) (*Hy2, error) {
	if hasPortHopping(raw) {
		return nil, errors.New("Hysteria2 port hopping is not supported")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "hysteria2" && u.Scheme != "hy2") || u.User == nil || u.Hostname() == "" {
		return nil, errors.New("invalid Hysteria2 URI")
	}
	query := u.Query()
	if _, ok := query["mport"]; ok {
		return nil, errors.New("Hysteria2 port hopping is not supported")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, errors.New("Hysteria2 URI has an invalid server port")
	}
	auth := u.User.Username()
	if password, ok := u.User.Password(); ok {
		auth += ":" + password
	}
	if auth == "" {
		return nil, errors.New("Hysteria2 URI has no authentication value")
	}

	profile := &Hy2{
		Auth:       auth,
		Host:       u.Hostname(),
		Port:       port,
		ServerName: query.Get("sni"),
		Obfs:       strings.ToLower(query.Get("obfs")),
	}
	if profile.ServerName == "" {
		profile.ServerName = profile.Host
	}
	if profile.Obfs == "" {
		profile.Obfs = "none"
	}
	if profile.Obfs != "none" && profile.Obfs != "salamander" && profile.Obfs != "gecko" {
		return nil, errors.New("unsupported Hysteria2 obfuscation")
	}
	profile.ObfsPassword = query.Get("obfs-password")
	if profile.Obfs != "none" && profile.ObfsPassword == "" {
		return nil, errors.New("Hysteria2 obfuscation password is missing")
	}
	if value, ok := query["pinSHA256"]; ok {
		pinText := strings.ReplaceAll(strings.Join(value, ""), ":", "")
		pin, err := hex.DecodeString(pinText)
		if err != nil || len(pin) != len(profile.PinSHA256) {
			return nil, errors.New("Hysteria2 URI has an invalid SHA-256 certificate pin")
		}
		copy(profile.PinSHA256[:], pin)
		profile.HasPin = true
	}
	if insecure := query.Get("insecure"); insecure != "" && insecure != "0" {
		if insecure != "1" {
			return nil, errors.New("Hysteria2 URI has an invalid insecure option")
		}
		if !profile.HasPin {
			profile.Insecure = true
		}
	}
	return profile, nil
}

func hasPortHopping(raw string) bool {
	withoutFragment := strings.SplitN(raw, "#", 2)[0]
	if _, query, ok := strings.Cut(withoutFragment, "?"); ok {
		for _, item := range strings.Split(query, "&") {
			key, _, _ := strings.Cut(item, "=")
			if key == "mport" {
				return true
			}
		}
	}
	_, rest, ok := strings.Cut(withoutFragment, "://")
	if !ok {
		return false
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	var port string
	if strings.HasPrefix(rest, "[") {
		if end := strings.LastIndexByte(rest, ']'); end >= 0 && end+1 < len(rest) && rest[end+1] == ':' {
			port = rest[end+2:]
		}
	} else if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		port = rest[i+1:]
	}
	return strings.ContainsAny(port, ",- ")
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid port")
	}
	return uint16(n), nil
}

func ParseAWG(conf string) (*AWG, error) {
	sections := map[string]map[string]string{"interface": {}, "peer": {}}
	sectionCount := map[string]int{}
	current := ""
	for _, rawLine := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(rawLine)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if _, ok := sections[current]; !ok {
				return nil, errors.New("unsupported wg-quick section")
			}
			sectionCount[current]++
			continue
		}
		if current == "" {
			return nil, errors.New("wg-quick value appears before a section")
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid wg-quick line")
		}
		sections[current][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if sectionCount["interface"] != 1 || sectionCount["peer"] != 1 {
		return nil, errors.New("wg-quick config needs one interface and one peer")
	}
	iface, peer := sections["interface"], sections["peer"]
	privateKey, err := base64Key(iface["privatekey"])
	if err != nil {
		return nil, errors.New("invalid interface private key")
	}
	serverKey, err := base64Key(peer["publickey"])
	if err != nil {
		return nil, errors.New("invalid peer public key")
	}

	out := &AWG{ServerKey: serverKey, MTU: 1280}
	for _, value := range splitCSV(iface["address"]) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("invalid interface address")
		}
		out.Addresses = append(out.Addresses, prefix)
	}
	var hasIPv4 bool
	for _, address := range out.Addresses {
		hasIPv4 = hasIPv4 || address.Addr().Is4()
	}
	if !hasIPv4 {
		return nil, errors.New("wg-quick config has no IPv4 interface address")
	}
	for _, value := range splitCSV(iface["dns"]) {
		if address, err := netip.ParseAddr(value); err == nil {
			out.DNS = append(out.DNS, address)
		}
	}
	if mtu := iface["mtu"]; mtu != "" {
		out.MTU, err = strconv.Atoi(mtu)
		if err != nil || out.MTU < 576 || out.MTU > 65535 {
			return nil, errors.New("invalid interface MTU")
		}
	}
	for _, value := range splitCSV(peer["allowedips"]) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errors.New("invalid peer allowed IP")
		}
		out.AllowedIPs = append(out.AllowedIPs, prefix)
	}
	if len(out.AllowedIPs) == 0 {
		return nil, errors.New("wg-quick peer has no allowed IPs")
	}
	endpointHost, endpointPort, err := net.SplitHostPort(peer["endpoint"])
	if err != nil || strings.TrimSpace(endpointHost) == "" {
		return nil, errors.New("invalid wg-quick peer endpoint")
	}
	out.EndpointPort, err = parsePort(endpointPort)
	if err != nil {
		return nil, errors.New("invalid wg-quick peer endpoint port")
	}
	out.EndpointHost = endpointHost

	psk := ""
	if peer["presharedkey"] != "" {
		psk, err = base64Key(peer["presharedkey"])
		if err != nil {
			return nil, errors.New("invalid peer preshared key")
		}
	}
	var b strings.Builder
	write := func(key, value string) { fmt.Fprintf(&b, "%s=%s\n", key, value) }
	write("private_key", privateKey)
	write("listen_port", "0")
	for _, field := range []struct{ config, uapi string }{{"jc", "jc"}, {"jmin", "jmin"}, {"jmax", "jmax"}} {
		if value := iface[field.config]; value != "" {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, errors.New("invalid AmneziaWG junk parameter")
			}
			write(field.uapi, strconv.FormatUint(n, 10))
		}
	}
	for i := 1; i <= 4; i++ {
		name := "s" + strconv.Itoa(i)
		if value := iface[name]; value != "" {
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return nil, errors.New("invalid AmneziaWG padding parameter")
			}
			write(name, strconv.FormatUint(n, 10))
		}
	}
	for i := 1; i <= 4; i++ {
		name := "h" + strconv.Itoa(i)
		if value := iface[name]; value != "" {
			canonical, err := parseUintRange(value, 32)
			if err != nil {
				return nil, errors.New("invalid AmneziaWG header parameter")
			}
			write(name, canonical)
		}
	}
	for i := 1; i <= 5; i++ {
		name := "i" + strconv.Itoa(i)
		if value := iface[name]; value != "" {
			write(name, value)
		}
	}
	if key := iface["headerprotectionkey"]; key != "" {
		keyHex, err := base64Key(key)
		if err != nil {
			return nil, errors.New("invalid header protection key")
		}
		write("header_protection_key", keyHex)
	}
	for _, field := range []struct{ config, uapi string }{
		{"contentpaddingaddition", "content_padding_addition"}, {"rekeyaftertime", "rekey_after_time"},
		{"rekeytimeout", "rekey_timeout"}, {"rejectaftertime", "reject_after_time"},
		{"keepalivetimeout", "keepalive_timeout"}, {"maxhandshakeattempts", "max_handshake_attempts"},
	} {
		if value := iface[field.config]; value != "" {
			canonical, err := parseUintRange(value, 16)
			if err != nil {
				return nil, errors.New("invalid AmneziaWG timing range")
			}
			write(field.uapi, canonical)
		}
	}
	for _, field := range []struct{ config, uapi string }{{"randomtrailers", "random_trailers"}, {"disablecookies", "disable_cookies"}} {
		if value := iface[field.config]; value != "" {
			parsed, err := parseBoolOnOff(value)
			if err != nil {
				return nil, errors.New("invalid AmneziaWG boolean parameter")
			}
			write(field.uapi, strconv.FormatBool(parsed))
		}
	}
	write("replace_peers", "true")
	write("public_key", serverKey)
	if psk != "" {
		write("preshared_key", psk)
	}
	if value := peer["persistentkeepalive"]; value != "" {
		canonical, err := parseUintRange(value, 16)
		if err != nil {
			return nil, errors.New("invalid persistent keepalive range")
		}
		write("persistent_keepalive_interval", canonical)
	}
	for _, prefix := range out.AllowedIPs {
		write("allowed_ip", prefix.String())
	}
	out.uapi = b.String()
	return out, nil
}

func (a *AWG) UAPI(endpoint netip.AddrPort) string {
	return a.uapi + "endpoint=" + endpoint.String() + "\n"
}

func base64Key(value string) (string, error) {
	data, err := decodeBase64(value)
	if err != nil || len(data) != 32 {
		return "", errors.New("invalid key")
	}
	return fmt.Sprintf("%x", data), nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(value)
	}
	return data, err
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func parseUintRange(value string, bits int) (string, error) {
	parts := strings.Split(value, "-")
	if len(parts) > 2 || len(parts) == 0 {
		return "", errors.New("invalid range")
	}
	lo, err := strconv.ParseUint(parts[0], 10, bits)
	if err != nil {
		return "", errors.New("invalid range")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, bits)
		if err != nil || lo > hi {
			return "", errors.New("invalid range")
		}
	}
	if lo == hi {
		return strconv.FormatUint(lo, 10), nil
	}
	return strconv.FormatUint(lo, 10) + "-" + strconv.FormatUint(hi, 10), nil
}

func parseBoolOnOff(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return strconv.ParseBool(value)
	}
}

func Load(path string) ([]Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read profiles file")
	}
	var file struct {
		Servers []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
			URI      string `json:"uri"`
			Conf     string `json:"conf"`
			Verify   string `json:"verify"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, errors.New("invalid profiles file")
	}
	profiles := make([]Profile, 0, len(file.Servers))
	for i, server := range file.Servers {
		label := server.ID
		if label == "" {
			return nil, fmt.Errorf("server id missing at index %d", i)
		}
		p := Profile{ID: server.ID, Name: server.Name, Protocol: server.Protocol, Verify: server.Verify}
		var parseErr error
		switch server.Protocol {
		case "hysteria2":
			p.Hy2, parseErr = ParseHy2(server.URI)
		case "awg":
			p.AWG, parseErr = ParseAWG(server.Conf)
		default:
			parseErr = errors.New("unsupported protocol")
		}
		if parseErr == nil && server.Verify != "" {
			if err := validateHostPort(server.Verify); err != nil {
				parseErr = errors.New("invalid verify endpoint")
			}
		}
		if parseErr != nil {
			return nil, fmt.Errorf("server %q: %w", label, parseErr)
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func validateHostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("invalid host:port")
	}
	_, err = parsePort(port)
	return err
}

func Pick(profiles []Profile, server, protocol string) (Profile, bool) {
	anyProtocol := protocol == "" || protocol == "auto"
	if server == "" || server == "auto" {
		for _, p := range profiles {
			if anyProtocol || p.Protocol == protocol {
				return p, true
			}
		}
		return Profile{}, false
	}
	for _, p := range profiles {
		if p.ID == server && (anyProtocol || p.Protocol == protocol) {
			return p, true
		}
	}
	return Profile{}, false
}
