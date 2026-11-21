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
	"slices"
	"strconv"
	"strings"
	"time"
)

type Profile struct {
	ID       string
	Name     string
	Protocol string
	Sub      string
	// The panel's last-resort path marker; other values are discarded when the path is read.
	Purpose string
	Hy2     *Hy2
	AWG     *AWG
	VLESS   *VLESS
	TT      *TrustTunnel
	Verify  string
	// From a panel's client API: how the path reaches the server (direct, relay, warp); empty when not known.
	Via string
	// What the panel's sync said about DNS (plain resolvers only); empty for a subscription that is not managed.
	PanelDNS   []netip.Addr
	PanelSplit []DNSSplit
	// The panel said no IPv6 leaves through this path (ipv6_egress false): the engine takes its word and does not probe.
	NoIPv6 bool
}

const PurposeWhitelist = "whitelist"

// DNSSplit is a panel's resolver list for the regions in Geo (lower-case country codes), for the names under Suffixes
// (domain suffix bodies) and for the names in Sites ("geosite:<name>" collections).
type DNSSplit struct {
	Geo      []string     `json:"geo,omitempty"`
	Suffixes []string     `json:"suffixes,omitempty"`
	Sites    []string     `json:"sites,omitempty"`
	Servers  []netip.Addr `json:"servers"`
}

type Hy2 struct {
	Auth         string
	Host         string
	Port         uint16
	Ports        string
	HopInterval  time.Duration
	ServerName   string
	ALPN         []string
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
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || (strings.ToLower(scheme) != "hysteria2" && strings.ToLower(scheme) != "hy2") {
		return nil, errors.New("invalid Hysteria2 URI")
	}
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	userinfo, hostPort := "", authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo, hostPort = authority[:at+1], authority[at+1:]
	}
	host, portText, ok := splitHostPortText(hostPort)
	if !ok || host == "" || userinfo == "" {
		return nil, errors.New("invalid Hysteria2 URI")
	}
	ports := ""
	basePort := ""
	var err error
	if primary, rangeText, hasRange := strings.Cut(portText, ","); hasRange {
		basePort = primary
		ports = rangeText
	} else if _, err := parsePort(portText); err == nil {
		basePort = portText
	} else {
		ports, basePort, err = parsePortRange(portText)
		if err != nil {
			return nil, errors.New("Hysteria2 URI has an invalid server port")
		}
	}
	port, err := parsePort(basePort)
	if err != nil {
		return nil, errors.New("Hysteria2 URI has an invalid server port")
	}
	parseable := scheme + "://" + userinfo + host + ":" + strconv.Itoa(int(port)) + rest[authorityEnd:]
	u, err := url.Parse(parseable)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return nil, errors.New("invalid Hysteria2 URI")
	}
	query := u.Query()
	if queryPorts, ok := query["mport"]; ok {
		if len(queryPorts) != 1 {
			return nil, errors.New("Hysteria2 URI has an invalid port range")
		}
		ports, _, err = parsePortRange(queryPorts[0])
		if err != nil {
			return nil, errors.New("Hysteria2 URI has an invalid port range")
		}
	} else if ports != "" {
		ports, _, err = parsePortRange(ports)
		if err != nil {
			return nil, errors.New("Hysteria2 URI has an invalid port range")
		}
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
		Ports:      ports,
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

func splitHostPortText(value string) (host, port string, ok bool) {
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndexByte(value, ']')
		if end < 0 || end+1 >= len(value) || value[end+1] != ':' {
			return "", "", false
		}
		return value[:end+1], value[end+2:], true
	}
	colon := strings.LastIndexByte(value, ':')
	if colon <= 0 || strings.Contains(value[:colon], ":") {
		return "", "", false
	}
	return value[:colon], value[colon+1:], true
}

func parsePortRange(value string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 2 {
		return "", "", errors.New("invalid port range")
	}
	from, err := parsePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", "", err
	}
	to, err := parsePort(strings.TrimSpace(parts[1]))
	if err != nil || from > to {
		return "", "", errors.New("invalid port range")
	}
	return strconv.Itoa(int(from)) + "-" + strconv.Itoa(int(to)), strconv.Itoa(int(from)), nil
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

func Pick(profiles []Profile, server, protocol, sub string) (Profile, bool) {
	anyProtocol := protocol == "" || protocol == "auto"
	if server == "" || server == "auto" {
		// the home of "auto" before a connection: what the status shows; the engine measures and chooses at connect
		for _, p := range profiles {
			if p.Purpose != PurposeWhitelist && (sub == "" || p.Sub == sub) && (anyProtocol || p.Protocol == protocol) {
				return p, true
			}
		}
		return Profile{}, false
	}
	for _, p := range profiles {
		if p.ID == server && (sub == "" || p.Sub == sub) && (anyProtocol || p.Protocol == protocol || p.Purpose == PurposeWhitelist) { // the protocol preference is about ordinary servers
			return p, true
		}
	}
	return Profile{}, false
}

// Next is the server after `after` in the subscription that PickForSettings(server, ...) belongs to, wrapping
// around. `after` "" or "auto" stands for the picked server itself. Other whitelist paths are skipped, as are servers
// the protocol rules out; the picked one stays in the round so it can wrap back. It is false when no other server exists.
func Next(profiles []Profile, server, requestedProtocol, sub, configuredProtocol string, game bool, after string) (string, bool) {
	home, ring, ok := Ring(profiles, server, requestedProtocol, sub, configuredProtocol, game)
	if !ok {
		return "", false
	}
	if after == "" || after == "auto" {
		after = home.ID
	}
	for i, p := range ring {
		if p.ID == after {
			if len(ring) == 1 {
				return "", false
			}
			return ring[(i+1)%len(ring)].ID, true
		}
	}
	return home.ID, true // `after` left the subscription
}

// Ring is the round Next walks: the picked server (home) and the ordinary servers of its subscription that the protocol allows.
func Ring(profiles []Profile, server, requestedProtocol, sub, configuredProtocol string, game bool) (home Profile, ring []Profile, ok bool) {
	home, ok = PickForSettings(profiles, server, requestedProtocol, sub, configuredProtocol, game)
	if !ok {
		return Profile{}, nil, false
	}
	protocol := requestedProtocol
	if protocol == "" || protocol == "auto" {
		protocol = configuredProtocol
	}
	for _, p := range profiles {
		if p.Sub == home.Sub && (p.ID == home.ID || p.Purpose != PurposeWhitelist) &&
			(p.ID == home.ID || protocol == "" || protocol == "auto" || p.Protocol == protocol) {
			ring = append(ring, p)
		}
	}
	return home, ring, true
}

// Others is the round without `except` ("" and "auto" stand for the picked server itself).
func Others(profiles []Profile, server, requestedProtocol, sub, configuredProtocol string, game bool, except string) []Profile {
	home, ring, _ := Ring(profiles, server, requestedProtocol, sub, configuredProtocol, game)
	if except == "" || except == "auto" {
		except = home.ID
	}
	var others []Profile
	for _, p := range ring {
		if p.ID != except {
			others = append(others, p)
		}
	}
	return others
}

func PickForSettings(profiles []Profile, server, requestedProtocol, sub, configuredProtocol string, game bool) (Profile, bool) {
	if server != "" && server != "auto" {
		return Pick(profiles, server, "auto", sub)
	}
	protocol := requestedProtocol
	if protocol == "" || protocol == "auto" {
		protocol = configuredProtocol
	}
	if protocol != "" && protocol != "auto" {
		return Pick(profiles, server, protocol, sub)
	}
	if game {
		if selected, ok := Pick(profiles, server, "awg", sub); ok {
			return selected, true
		}
	}
	return Pick(profiles, server, "auto", sub)
}

// Direct is a path that reaches its server itself, not through a relay or a WARP exit.
func (p Profile) Direct() bool { return p.Via == "" || p.Via == "direct" }

// Endpoint is the host and port the path's server is reached at, as the profile gives them.
func (p Profile) Endpoint() (string, uint16, error) {
	switch p.Protocol {
	case "hysteria2":
		if p.Hy2 == nil || p.Hy2.Host == "" || p.Hy2.Port == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return p.Hy2.Host, p.Hy2.Port, nil
	case "awg":
		if p.AWG == nil || p.AWG.EndpointHost == "" || p.AWG.EndpointPort == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return p.AWG.EndpointHost, p.AWG.EndpointPort, nil
	case "vless":
		if p.VLESS == nil || p.VLESS.Host == "" || p.VLESS.Port == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return p.VLESS.Host, p.VLESS.Port, nil
	case "trusttunnel":
		if p.TT == nil || len(p.TT.Addresses) == 0 {
			return "", 0, errors.New("invalid profile")
		}
		host, portText, err := net.SplitHostPort(p.TT.Addresses[0])
		port, portErr := strconv.ParseUint(portText, 10, 16)
		if err != nil || portErr != nil || port == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return host, uint16(port), nil
	default:
		return "", 0, errors.New("invalid profile")
	}
}

const autoWaveSize, autoWaves = 3, 3

// AutoWaves orders the paths Auto may take into the waves it tries one after another: a wave is measured at once, and
// the first wave with an answer decides. Direct paths come first (the first wave is only direct ones, if there are
// any), then the rest of them, then relays and WARP exits. Inside a wave a path of another transport family than the
// one before it, on a host the wave does not have yet, is preferred, so that one block does not take a whole wave.
// `avoid` are the paths that failed lately; when they would leave nothing, they are not avoided.
// ponytail: nine paths at most; the rest are reached by `avoid` on the next attempts.
func AutoWaves(candidates []Profile, avoid []string) [][]Profile {
	var rest, relays []Profile
	for _, p := range candidates {
		if slices.Contains(avoid, p.ID) {
			continue
		}
		if p.Direct() {
			rest = append(rest, p)
		} else {
			relays = append(relays, p)
		}
	}
	if len(rest)+len(relays) == 0 {
		if len(avoid) == 0 {
			return nil
		}
		return AutoWaves(candidates, nil) // nothing but avoided paths: they are all there is
	}
	if len(rest) == 0 {
		rest, relays = relays, nil // no direct path: relays from the first wave
	}
	var waves [][]Profile
	for len(rest) > 0 && len(waves) < autoWaves {
		var wave []Profile
		hosts := map[string]bool{}
		for len(wave) < autoWaveSize && len(rest) > 0 {
			pick := 0
			for i, p := range rest {
				host, _, _ := p.Endpoint()
				if len(wave) == 0 || transportFamily(p) != transportFamily(wave[len(wave)-1]) && !hosts[host] {
					pick = i
					break
				}
			}
			host, _, _ := rest[pick].Endpoint()
			hosts[host] = true
			wave = append(wave, rest[pick])
			rest = slices.Delete(rest, pick, pick+1)
		}
		waves = append(waves, wave)
		if len(waves) == 1 {
			rest = append(rest, relays...) // relays follow what is left of the direct paths
		}
	}
	return waves
}

// transportFamily: UDP (Hysteria2, AmneziaWG) or TCP (VLESS, TrustTunnel); a block of one tends to leave the other.
func transportFamily(p Profile) string {
	if p.Protocol == "vless" || p.Protocol == "trusttunnel" {
		return "tcp"
	}
	return "udp"
}
