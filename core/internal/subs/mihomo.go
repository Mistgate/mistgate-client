package subs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"go.yaml.in/yaml/v3"
)

func parseMihomoProfile(body, subscriptionID string) ([]Server, []storedEntry, int, kindCounts, error) {
	var document map[string]any
	if yaml.Unmarshal([]byte(body), &document) != nil {
		return nil, nil, 0, nil, &Error{Code: "unsupported_format"}
	}
	value, ok := field(document, "proxies")
	if !ok {
		return nil, nil, 0, nil, &Error{Code: "unsupported_format"}
	}
	proxies, ok := value.([]any)
	if !ok {
		return nil, nil, 0, nil, &Error{Code: "unsupported_format"}
	}
	if notice, refused := refusedProfile(proxies); refused {
		return nil, nil, 0, nil, &Error{Code: "refused", Notice: notice}
	}

	servers := make([]Server, 0, len(proxies))
	entries := make([]storedEntry, 0, len(proxies))
	seen := make(map[string]bool)
	unsupported, kinds := 0, kindCounts{}
	for _, value := range proxies {
		proxy, ok := value.(map[string]any)
		if !ok {
			unsupported++
			kinds.add("other", 1)
			continue
		}
		protocol, _, _, err := parseProxyProfile(proxy)
		if err != nil {
			unsupported++
			kinds.add(proxyKind(proxy, err), 1)
			continue
		}
		raw, err := yaml.Marshal(proxy)
		if err != nil {
			unsupported++
			kinds.add(proxyKind(proxy, err), 1)
			continue
		}
		identity := make(map[string]any, len(proxy))
		for key, value := range proxy {
			if key != "name" {
				identity[key] = value
			}
		}
		identityBytes, err := yaml.Marshal(identity)
		if err != nil {
			unsupported++
			kinds.add(proxyKind(proxy, err), 1)
			continue
		}
		server := Server{
			ID:       serverID(subscriptionID, string(identityBytes)),
			Name:     stringValue(proxy["name"]),
			Protocol: protocol,
		}
		if seen[server.ID] {
			continue
		}
		seen[server.ID] = true
		servers = append(servers, server)
		entries = append(entries, storedEntry{Server: server, Raw: string(raw)})
	}
	if len(entries) == 0 {
		return nil, nil, unsupported, kinds, &Error{Code: "no_servers"}
	}
	return servers, entries, unsupported, kinds, nil
}

// proxyKind is the kind of a proxy this build did not take: its type, and for vless the reason as well.
func proxyKind(proxy map[string]any, err error) string {
	kind := strings.ToLower(stringValue(proxy["type"]))
	if kind == "vless" {
		return vlessKind(err)
	}
	return kind
}

func refusedProfile(proxies []any) (string, bool) {
	if len(proxies) == 0 {
		return "", false
	}
	first, ok := proxies[0].(map[string]any)
	if !ok {
		return "", false
	}
	for _, value := range proxies {
		proxy, ok := value.(map[string]any)
		if !ok {
			return "", false
		}
		server := strings.TrimSpace(stringValue(proxy["server"]))
		portValue, hasPort := field(proxy, "port")
		port, portErr := strconv.Atoi(stringValue(portValue))
		badPort := hasPort && portErr == nil && (port == 0 || port == 1)
		if server != "0.0.0.0" && server != "127.0.0.1" && server != "::" && !badPort {
			return "", false
		}
	}
	notice := strings.Join(strings.Fields(strings.ToValidUTF8(stringValue(first["name"]), "�")), " ")
	return shortTextN(notice, maxNotice), true
}

func parseMihomoEntry(raw, expectedProtocol string) (*profile.Hy2, *profile.AWG, error) {
	var proxy map[string]any
	if err := yaml.Unmarshal([]byte(raw), &proxy); err != nil {
		return nil, nil, errors.New("invalid stored profile")
	}
	protocol, hy2, awg, err := parseProxyProfile(proxy)
	if err != nil || protocol != expectedProtocol {
		return nil, nil, errors.New("invalid stored profile")
	}
	return hy2, awg, nil
}

func parseProxyProfile(proxy map[string]any) (string, *profile.Hy2, *profile.AWG, error) {
	typeName := strings.ToLower(stringValue(proxy["type"]))
	switch typeName {
	case "hysteria2":
		parsed, err := parseHy2Proxy(proxy)
		return "hysteria2", parsed, nil, err
	case "wireguard":
		parsed, err := parseWireguardProxy(proxy)
		return "awg", nil, parsed, err
	case "vless":
		_, err := parseVLESSProxy(proxy)
		return "vless", nil, nil, err
	default:
		return "", nil, nil, errors.New("unsupported proxy type")
	}
}

// parseVLESSEntry is a stored Mihomo "vless" proxy (kept as its YAML) as a profile.
func parseVLESSEntry(raw string) (*profile.VLESS, error) {
	var proxy map[string]any
	if yaml.Unmarshal([]byte(raw), &proxy) != nil {
		return nil, errors.New("invalid stored profile")
	}
	return parseVLESSProxy(proxy)
}

// parseVLESSProxy reads a Mihomo "vless" proxy: its fields are turned into the settings of a panel's "vless" path and
// checked by profile.ParseVLESS, as a share link is. Refused: networks other than tcp, ws, httpupgrade, grpc and xhttp,
// VLESS's own encryption, and skip-cert-verify (the app does not accept any certificate).
func parseVLESSProxy(proxy map[string]any) (*profile.VLESS, error) {
	text := func(name string) string { value, _ := field(proxy, name); return stringValue(value) }
	section := func(name string) map[string]any {
		value, _ := field(proxy, name)
		m, _ := value.(map[string]any)
		return m
	}
	flag := func(name string) bool { value, _ := field(proxy, name); on, _ := boolValue(value); return on }
	port, err := strconv.Atoi(text("port"))
	if err != nil {
		return nil, errors.New("invalid VLESS port")
	}
	if enc := text("encryption"); enc != "" && enc != "none" {
		return nil, &profile.VLESSError{Reason: profile.ReasonEncryption, Text: "unsupported VLESS encryption"}
	}
	if flag("skip-cert-verify") {
		return nil, &profile.VLESSError{Reason: profile.ReasonCertificate, Text: "VLESS proxy asks to accept any certificate"}
	}
	settings := map[string]any{
		"server": text("server"), "port": port, "uuid": text("uuid"), "flow": text("flow"),
		"sni": text("servername"), "fingerprint": strings.ToLower(text("client-fingerprint")), "security": "none",
	}
	if settings["sni"] == "" {
		settings["sni"] = text("sni")
	}
	if flag("tls") {
		settings["security"] = "tls"
	}
	if opts := section("reality-opts"); opts != nil {
		settings["security"], settings["public_key"], settings["short_id"] = "reality", stringValue(opts["public-key"]), stringValue(opts["short-id"])
	}
	if value, ok := field(proxy, "alpn"); ok {
		if list, err := stringList(value); err == nil {
			settings["alpn"] = list
		}
	}
	switch strings.ToLower(text("network")) {
	case "", "tcp":
		settings["transport"] = "raw"
	case "ws":
		opts := section("ws-opts")
		headers, _ := opts["headers"].(map[string]any)
		settings["transport"], settings["path"], settings["host"] = "ws", stringValue(opts["path"]), stringValue(headers["Host"])
		// Mihomo has no network for HTTP upgrade: it is ws-opts with this switch.
		if value, ok := field(opts, "v2ray-http-upgrade"); ok {
			if on, _ := boolValue(value); on {
				settings["transport"] = "httpupgrade"
			}
		}
	case "httpupgrade":
		// Not a Mihomo network as far as I know (see "ws"); taken for profiles of other makers, under either name of the options.
		opts := section("http-upgrade-opts")
		if opts == nil {
			opts = section("httpupgrade-opts")
		}
		headers, _ := opts["headers"].(map[string]any)
		host := stringValue(opts["host"])
		if host == "" {
			host = stringValue(headers["Host"])
		}
		settings["transport"], settings["path"], settings["host"] = "httpupgrade", stringValue(opts["path"]), host
	case "grpc":
		settings["transport"], settings["service_name"] = "grpc", stringValue(section("grpc-opts")["grpc-service-name"])
	case "xhttp":
		opts := section("xhttp-opts")
		settings["transport"], settings["path"], settings["host"], settings["mode"] = "xhttp", stringValue(opts["path"]), stringValue(opts["host"]), stringValue(opts["mode"])
	default:
		return nil, &profile.VLESSError{Reason: profile.ReasonTransport, Text: "unsupported VLESS network"}
	}
	if settings["transport"] != "raw" && settings["path"] == "" {
		settings["path"] = "/"
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, errors.New("invalid VLESS proxy")
	}
	return profile.ParseVLESS(encoded)
}

func parseHy2Proxy(proxy map[string]any) (*profile.Hy2, error) {
	host := strings.TrimSpace(stringValue(proxy["server"]))
	password := stringValue(proxy["password"])
	port, err := proxyPort(proxy["port"])
	if host == "" || password == "" || err != nil {
		return nil, errors.New("incomplete Hysteria2 proxy")
	}

	out := &profile.Hy2{
		Host:       host,
		Port:       port,
		Auth:       password,
		ServerName: strings.TrimSpace(stringValue(proxy["sni"])),
		Obfs:       strings.ToLower(strings.TrimSpace(stringValue(proxy["obfs"]))),
	}
	if out.ServerName == "" {
		out.ServerName = host
	}
	if out.Obfs == "" {
		out.Obfs = "none"
	}
	if out.Obfs != "none" && out.Obfs != "salamander" && out.Obfs != "gecko" {
		return nil, errors.New("unsupported Hysteria2 obfuscation")
	}
	out.ObfsPassword = stringValue(proxy["obfs-password"])
	if out.Obfs != "none" && out.ObfsPassword == "" {
		return nil, errors.New("missing Hysteria2 obfuscation password")
	}
	if value, ok := field(proxy, "skip-cert-verify"); ok {
		out.Insecure, err = boolValue(value)
		if err != nil {
			return nil, errors.New("invalid Hysteria2 TLS setting")
		}
	}
	if value, ok := field(proxy, "ports"); ok {
		out.Ports, err = checkedPortRange(stringValue(value))
		if err != nil {
			return nil, errors.New("invalid Hysteria2 port range")
		}
	}
	if value, ok := field(proxy, "hop-interval"); ok {
		out.HopInterval, err = secondsDuration(value)
		if err != nil {
			return nil, errors.New("invalid Hysteria2 hop interval")
		}
	}
	if value, ok := field(proxy, "alpn"); ok {
		out.ALPN, err = stringList(value)
		if err != nil {
			return nil, errors.New("invalid Hysteria2 ALPN")
		}
	}
	for _, key := range []string{"pinsha256", "fingerprint"} {
		value, ok := field(proxy, key)
		if !ok {
			continue
		}
		pinText := strings.ReplaceAll(stringValue(value), ":", "")
		pin, decodeErr := hex.DecodeString(pinText)
		if decodeErr != nil || len(pin) != len(out.PinSHA256) {
			return nil, errors.New("invalid Hysteria2 certificate pin")
		}
		copy(out.PinSHA256[:], pin)
		out.HasPin = true
		break
	}
	if out.HasPin {
		out.Insecure = false
	}
	return out, nil
}

func parseWireguardProxy(proxy map[string]any) (*profile.AWG, error) {
	host := strings.TrimSpace(stringValue(proxy["server"]))
	privateKey := stringValue(proxy["private-key"])
	publicKey := stringValue(proxy["public-key"])
	address := strings.TrimSpace(stringValue(proxy["ip"]))
	port, err := proxyPort(proxy["port"])
	allowedIPs, listErr := stringList(proxy["allowed-ips"])
	if host == "" || privateKey == "" || publicKey == "" || address == "" || err != nil || listErr != nil || len(allowedIPs) == 0 ||
		!singleLine(host) || !singleLine(address) || !allSingleLine(allowedIPs) {
		return nil, errors.New("incomplete WireGuard proxy")
	}
	if ipv6 := strings.TrimSpace(stringValue(proxy["ipv6"])); ipv6 != "" {
		address += ", " + ipv6
	}
	if !singleLine(privateKey) || !singleLine(publicKey) {
		return nil, errors.New("invalid WireGuard key")
	}

	var conf strings.Builder
	write := func(key, value string) { fmt.Fprintf(&conf, "%s = %s\n", key, value) }
	conf.WriteString("[Interface]\n")
	write("Address", address)
	write("PrivateKey", privateKey)
	if value, ok := field(proxy, "dns"); ok {
		dns, err := stringList(value)
		if err != nil || !allSingleLine(dns) {
			return nil, errors.New("invalid WireGuard DNS")
		}
		if len(dns) > 0 {
			write("DNS", strings.Join(dns, ", "))
		}
	}
	if value, ok := field(proxy, "mtu"); ok {
		mtu, valid := scalarString(value)
		if !valid || !singleLine(mtu) {
			return nil, errors.New("invalid WireGuard MTU")
		}
		write("MTU", mtu)
	}
	if optionValue, ok := field(proxy, "amnezia-wg-option"); ok && optionValue != nil {
		option, ok := optionValue.(map[string]any)
		if !ok {
			return nil, errors.New("invalid AmneziaWG options")
		}
		if err := writeAmneziaOptions(&conf, option); err != nil {
			return nil, err
		}
	}
	conf.WriteString("[Peer]\n")
	write("PublicKey", publicKey)
	if key := stringValue(proxy["pre-shared-key"]); key != "" {
		if !singleLine(key) {
			return nil, errors.New("invalid WireGuard preshared key")
		}
		write("PresharedKey", key)
	}
	write("AllowedIPs", strings.Join(allowedIPs, ", "))
	write("Endpoint", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if value, ok := field(proxy, "persistent-keepalive"); ok {
		keepalive, valid := scalarString(value)
		if !valid || !singleLine(keepalive) {
			return nil, errors.New("invalid WireGuard keepalive")
		}
		write("PersistentKeepalive", keepalive)
	}
	return profile.ParseAWG(conf.String())
}

func writeAmneziaOptions(conf *strings.Builder, options map[string]any) error {
	// The option version describes the panel schema; the device UAPI protocol version remains 1.
	known := map[string]string{
		"version": "Version", "jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
		"headerprotectionkey": "HeaderProtectionKey", "contentpaddingaddition": "ContentPaddingAddition",
		"rekeyaftertime": "RekeyAfterTime", "rekeytimeout": "RekeyTimeout", "rejectaftertime": "RejectAfterTime",
		"keepalivetimeout": "KeepaliveTimeout", "maxhandshakeattempts": "MaxHandshakeAttempts",
		"randomtrailers": "RandomTrailers", "disablecookies": "DisableCookies",
	}
	for i := 1; i <= 4; i++ {
		known["s"+strconv.Itoa(i)] = "S" + strconv.Itoa(i)
		known["h"+strconv.Itoa(i)] = "H" + strconv.Itoa(i)
	}
	for i := 1; i <= 5; i++ {
		known["i"+strconv.Itoa(i)] = "I" + strconv.Itoa(i)
	}
	values := make(map[string]string, len(options))
	for key, value := range options {
		normalized := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
		if _, ok := known[normalized]; !ok {
			continue
		}
		text, ok := scalarString(value)
		if !ok || !singleLine(text) {
			return errors.New("invalid AmneziaWG option")
		}
		values[normalized] = text
	}
	order := []string{"version", "jc", "jmin", "jmax"}
	for i := 1; i <= 4; i++ {
		order = append(order, "s"+strconv.Itoa(i))
	}
	for i := 1; i <= 4; i++ {
		order = append(order, "h"+strconv.Itoa(i))
	}
	for i := 1; i <= 5; i++ {
		order = append(order, "i"+strconv.Itoa(i))
	}
	order = append(order, "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers", "disablecookies")
	for _, key := range order {
		if value, ok := values[key]; ok {
			fmt.Fprintf(conf, "%s = %s\n", known[key], value)
		}
	}
	return nil
}

func field(values map[string]any, name string) (any, bool) {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func stringValue(value any) string {
	text, _ := scalarString(value)
	return text
}

func scalarString(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return strings.TrimSpace(value), true
	case int:
		return strconv.Itoa(value), true
	case int64:
		return strconv.FormatInt(value, 10), true
	case uint64:
		return strconv.FormatUint(value, 10), true
	case float64:
		if math.Trunc(value) == value {
			return strconv.FormatFloat(value, 'f', 0, 64), true
		}
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(value), true
	default:
		return "", false
	}
}

func proxyPort(value any) (uint16, error) {
	text, ok := scalarString(value)
	if !ok {
		return 0, errors.New("invalid port")
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("invalid port")
	}
	return uint16(port), nil
}

func checkedPortRange(value string) (string, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 2 {
		return "", errors.New("invalid port range")
	}
	from, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil || from == 0 {
		return "", errors.New("invalid port range")
	}
	to, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil || to < from {
		return "", errors.New("invalid port range")
	}
	return strconv.FormatUint(from, 10) + "-" + strconv.FormatUint(to, 10), nil
}

func boolValue(value any) (bool, error) {
	switch value := value.(type) {
	case bool:
		return value, nil
	case string:
		return strconv.ParseBool(strings.TrimSpace(value))
	default:
		return false, errors.New("invalid boolean")
	}
}

func secondsDuration(value any) (time.Duration, error) {
	text, ok := scalarString(value)
	if !ok {
		return 0, errors.New("invalid seconds")
	}
	seconds, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > float64(math.MaxInt64)/float64(time.Second) {
		return 0, errors.New("invalid seconds")
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

func stringList(value any) ([]string, error) {
	switch values := value.(type) {
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := scalarString(value)
			if !ok || text == "" {
				return nil, errors.New("invalid string list")
			}
			result = append(result, text)
		}
		return result, nil
	case []string:
		return append([]string(nil), values...), nil
	case string:
		if strings.TrimSpace(values) == "" {
			return nil, nil
		}
		parts := strings.Split(values, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
			if parts[i] == "" {
				return nil, errors.New("invalid string list")
			}
		}
		return parts, nil
	default:
		return nil, errors.New("invalid string list")
	}
}

func singleLine(value string) bool { return !strings.ContainsAny(value, "\r\n") }

func allSingleLine(values []string) bool {
	for _, value := range values {
		if !singleLine(value) {
			return false
		}
	}
	return true
}
