package engine

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mistgate/mistgate-client/core/internal/geo"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxSniffBytes  = 4 << 10
	dnsMemoryLimit = 50000
)

func parseTLSClientHello(data []byte) (string, bool) {
	var handshake []byte
	for offset := 0; ; {
		if len(data)-offset < 5 {
			return "", false
		}
		if data[offset] != 22 || data[offset+1] != 3 || data[offset+2] > 4 {
			return "", true
		}
		recordLen := int(data[offset+3])<<8 | int(data[offset+4])
		if recordLen == 0 || recordLen > maxSniffBytes-5 {
			return "", true
		}
		if len(data)-offset < 5+recordLen {
			return "", false
		}
		handshake = append(handshake, data[offset+5:offset+5+recordLen]...)
		offset += 5 + recordLen
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return "", true
		}
		helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if helloLen > maxSniffBytes-4 {
			return "", true
		}
		if len(handshake) < 4+helloLen {
			continue
		}
		return parseClientHello(handshake[4 : 4+helloLen])
	}
}

func parseClientHello(hello []byte) (string, bool) {
	if len(hello) < 34 {
		return "", true
	}
	i := 34
	if i >= len(hello) {
		return "", true
	}
	sessionIDLen := int(hello[i])
	i++
	if i+sessionIDLen+2 > len(hello) {
		return "", true
	}
	i += sessionIDLen
	cipherLen := int(hello[i])<<8 | int(hello[i+1])
	i += 2
	if cipherLen == 0 || cipherLen%2 != 0 || i+cipherLen+1 > len(hello) {
		return "", true
	}
	i += cipherLen
	compressionLen := int(hello[i])
	i++
	if compressionLen == 0 || i+compressionLen > len(hello) {
		return "", true
	}
	i += compressionLen
	if i == len(hello) {
		return "", true
	}
	if i+2 > len(hello) {
		return "", true
	}
	extensionsLen := int(hello[i])<<8 | int(hello[i+1])
	i += 2
	if i+extensionsLen != len(hello) {
		return "", true
	}
	end := i + extensionsLen
	serverName := ""
	seenServerName := false
	for i < end {
		if i+4 > end {
			return "", true
		}
		typ := int(hello[i])<<8 | int(hello[i+1])
		extLen := int(hello[i+2])<<8 | int(hello[i+3])
		i += 4
		if i+extLen > end {
			return "", true
		}
		if typ == 0 {
			if seenServerName {
				return "", true
			}
			seenServerName = true
			serverName = parseServerNameExtension(hello[i : i+extLen])
		}
		i += extLen
	}
	return serverName, true
}

func parseServerNameExtension(extension []byte) string {
	if len(extension) < 2 {
		return ""
	}
	listLen := int(extension[0])<<8 | int(extension[1])
	if listLen != len(extension)-2 {
		return ""
	}
	serverName := ""
	seenHostName := false
	for i := 2; i < len(extension); {
		if i+3 > len(extension) {
			return ""
		}
		nameType := extension[i]
		nameLen := int(extension[i+1])<<8 | int(extension[i+2])
		i += 3
		if nameLen == 0 || i+nameLen > len(extension) {
			return ""
		}
		if nameType == 0 {
			if seenHostName {
				return ""
			}
			seenHostName = true
			serverName = normalizeFlowName(string(extension[i : i+nameLen]))
		}
		i += nameLen
	}
	return serverName
}

func parseHTTPHost(data []byte) (string, bool) {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		if len(data) >= maxSniffBytes || bytes.Contains(data, []byte{'\n'}) {
			return "", true
		}
		return "", false
	}
	requestLine := bytes.Split(data[:lineEnd], []byte{' '})
	if len(requestLine) != 3 || len(requestLine[0]) == 0 || len(requestLine[1]) == 0 ||
		string(requestLine[2]) != "HTTP/1.0" && string(requestLine[2]) != "HTTP/1.1" || !validHTTPToken(requestLine[0]) {
		return "", true
	}
	for _, b := range requestLine[1] {
		if b <= ' ' || b == 127 {
			return "", true
		}
	}
	var host string
	hostSeen := false
	for i := lineEnd + 2; ; {
		relativeEnd := bytes.Index(data[i:], []byte("\r\n"))
		if relativeEnd < 0 {
			if len(data) >= maxSniffBytes || bytes.Contains(data[i:], []byte{'\n'}) {
				return "", true
			}
			return "", false
		}
		end := i + relativeEnd
		if end == i {
			return host, true
		}
		line := data[i:end]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHTTPToken(line[:colon]) {
			return "", true
		}
		for _, b := range line[colon+1:] {
			if b != '\t' && (b < ' ' || b == 127) {
				return "", true
			}
		}
		if strings.EqualFold(string(line[:colon]), "host") {
			if hostSeen {
				return "", true
			}
			hostSeen = true
			value := strings.Trim(string(line[colon+1:]), " \t")
			var ok bool
			host, ok = parseHostAuthority(value)
			if !ok {
				return "", true
			}
			if !bytes.Contains(data, []byte("\r\n\r\n")) {
				return host, true
			}
		}
		i = end + 2
	}
}

func validHTTPToken(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, b := range value {
		if b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}

func parseHostAuthority(value string) (string, bool) {
	if value == "" || strings.ContainsAny(value, " /\\?#@\t\r\n") {
		return "", false
	}
	if strings.HasPrefix(value, "[") {
		return "", false
	}
	if strings.Count(value, ":") == 1 {
		host, port, _ := strings.Cut(value, ":")
		if _, err := strconv.ParseUint(port, 10, 16); err != nil || port == "" {
			return "", false
		}
		value = host
	} else if strings.Contains(value, ":") {
		return "", false
	}
	name := normalizeFlowName(value)
	return name, name != ""
}

func normalizeFlowName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " /:\\?#@\t\r\n") {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, r := range label {
			if r == '-' || r >= '0' && r <= '9' || unicode.IsLetter(r) {
				continue
			}
			return ""
		}
	}
	return name
}

func sniffTCPName(conn net.Conn, port uint16) (string, []byte) {
	if port != 80 && port != 443 {
		return "", nil
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	data := make([]byte, 0, maxSniffBytes)
	for len(data) < maxSniffBytes {
		var name string
		var complete bool
		if port == 443 {
			name, complete = parseTLSClientHello(data)
		} else {
			name, complete = parseHTTPHost(data)
		}
		if name != "" || complete {
			_ = conn.SetReadDeadline(time.Time{})
			return name, data
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", data
		}
		var buffer [maxSniffBytes]byte
		n, err := conn.Read(buffer[:maxSniffBytes-len(data)])
		if n > 0 {
			data = append(data, buffer[:n]...)
		}
		if err != nil {
			var name string
			if port == 443 {
				name, _ = parseTLSClientHello(data)
			} else {
				name, _ = parseHTTPHost(data)
			}
			_ = conn.SetReadDeadline(time.Time{})
			return name, data
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return "", data
}

type dnsEntry struct {
	name    string
	expires time.Time
}

// ponytail: encrypted DNS hides its answers from this cache; upgrade = observe a local DNS proxy, while TCP uses SNI.
type dnsMemory struct {
	mu      sync.Mutex
	entries map[netip.Addr]dnsEntry
}

func directByRules(address netip.Addr, name, mode string, region *geo.Set, rules *geo.SiteRules) bool {
	if !directAddressAllowed(address) {
		return false
	}
	switch mode {
	case "smart":
		if rules.ByName(mode, name) == geo.RuleDirect {
			return true
		}
		return region != nil && region.Contains(address)
	case "selected":
		return rules.ByName(mode, name) != geo.RuleVPN
	default:
		return false
	}
}

// appVerdict is what the rules say about the program that owns a flow. A program's rule beats the site and address
// rules in its own direction only: block, the DNS port, private addresses and a missing direct IPv6 still win over it.
type appVerdict uint8

const (
	appNone   appVerdict = iota // the program is not listed (or its owner is unknown): the site and address rules decide
	appDirect                   // smart: a program of rules.direct.apps
	appVPN                      // selected: a program of rules.vpn.apps
)

// appsListed says whether any program is named for this mode; without one no flow is looked up.
func appsListed(mode string, rules *geo.SiteRules) bool {
	if rules == nil {
		return false
	}
	switch mode {
	case "smart":
		return len(rules.DirectApps) != 0
	case "selected":
		return len(rules.VPNApps) != 0
	}
	return false
}

// appRule reads the program's path (lower case) against the sets of the mode: smart sees only the direct programs and
// selected only the VPN ones, as for sites.
func appRule(mode string, rules *geo.SiteRules, path string) appVerdict {
	if rules == nil || path == "" {
		return appNone
	}
	switch mode {
	case "smart":
		if _, ok := rules.DirectApps[path]; ok {
			return appDirect
		}
	case "selected":
		if _, ok := rules.VPNApps[path]; ok {
			return appVPN
		}
	}
	return appNone
}

func (m *dnsMemory) remember(message []byte) {
	m.rememberAt(message, time.Now())
}

func (m *dnsMemory) rememberAt(message []byte, now time.Time) {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return
	}
	question, err := parser.Question()
	if err != nil {
		return
	}
	questionName := normalizeFlowName(question.Name.String())
	if questionName == "" {
		return
	}
	if err := parser.SkipAllQuestions(); err != nil && !errors.Is(err, dnsmessage.ErrSectionDone) {
		return
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return
	}
	type cname struct {
		name string
		ttl  uint32
	}
	cnames := make(map[string]cname)
	for _, answer := range answers {
		if value, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			owner := normalizeFlowName(answer.Header.Name.String())
			target := normalizeFlowName(value.CNAME.String())
			if owner != "" && target != "" {
				cnames[owner] = cname{name: target, ttl: answer.Header.TTL}
			}
		}
	}
	chainTTL := make(map[string]uint32)
	chainTTL[questionName] = ^uint32(0)
	current := questionName
	for i := 0; i < 16; i++ {
		alias, ok := cnames[current]
		if !ok {
			break
		}
		previousTTL := chainTTL[current]
		if alias.ttl < previousTTL {
			previousTTL = alias.ttl
		}
		if _, duplicate := chainTTL[alias.name]; duplicate {
			break
		}
		chainTTL[alias.name] = previousTTL
		current = alias.name
	}
	for _, answer := range answers {
		value, ok := answer.Body.(*dnsmessage.AResource)
		if !ok {
			continue
		}
		owner := normalizeFlowName(answer.Header.Name.String())
		pathTTL, ok := chainTTL[owner]
		if !ok {
			continue
		}
		ttl := answer.Header.TTL
		if pathTTL < ttl {
			ttl = pathTTL
		}
		if ttl < 60 {
			ttl = 60
		} else if ttl > 3600 {
			ttl = 3600
		}
		m.rememberAddressAt(netip.AddrFrom4(value.A), questionName, time.Duration(ttl)*time.Second, now)
	}
}

func (m *dnsMemory) rememberAddressAt(address netip.Addr, name string, ttl time.Duration, now time.Time) {
	if m == nil || !address.IsValid() || name == "" {
		return
	}
	if ttl < time.Minute {
		ttl = time.Minute
	} else if ttl > time.Hour {
		ttl = time.Hour
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[netip.Addr]dnsEntry)
	}
	if _, exists := m.entries[address]; !exists && len(m.entries) >= dnsMemoryLimit {
		for key, entry := range m.entries {
			if !entry.expires.After(now) {
				delete(m.entries, key)
			}
		}
		if len(m.entries) >= dnsMemoryLimit {
			clear(m.entries)
		}
	}
	m.entries[address] = dnsEntry{name: name, expires: now.Add(ttl)}
}

func (m *dnsMemory) lookup(address netip.Addr) string {
	return m.lookupAt(address, time.Now())
}

func (m *dnsMemory) lookupAt(address netip.Addr, now time.Time) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[address]
	if !ok {
		return ""
	}
	if !entry.expires.After(now) {
		delete(m.entries, address)
		return ""
	}
	return entry.name
}
