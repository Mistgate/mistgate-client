package subs

// The client side of the Mistgate Client API (docs/client-api.md): enrol, sync, leave.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

const (
	capsHeader         = "v=1; hysteria2=2; gecko=1; awg=2.0,3.1"
	apiUserAgent       = "Mistgate/0.0.1 (Windows)"
	minSyncSeconds     = 600
	defaultSyncSeconds = 3600
	maxRetryAfter      = 24 * 3600
)

// Enrol answers that a retry does not fix: the user has to act, or refresh by hand.
var noRetryCodes = map[string]bool{
	"device_exists": true, "device_limit": true, "device_blocked": true,
	"user_inactive": true, "app_disabled": true, "client_api_off": true,
}

// apiState is what a subscription keeps once the panel has enrolled this device (Key set).
type apiState struct {
	Base      string `json:"base,omitempty"`
	Key       string `json:"key,omitempty"`
	ETag      string `json:"etag,omitempty"`
	SyncEvery int64  `json:"sync_every_s,omitempty"`
	NextUnix  int64  `json:"next_unix,omitempty"` // no automatic sync before this
	Halt      bool   `json:"halt,omitempty"`      // no automatic refresh at all
	// The panel's plain resolvers: the tunnel's DNS, and per region the ones its own people use. Not secret.
	DNS      []netip.Addr       `json:"dns,omitempty"`
	DNSSplit []profile.DNSSplit `json:"dns_split,omitempty"`
}

type syncBody struct {
	V         int    `json:"v"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	SyncEvery int64  `json:"sync_every_s"`
	Brand     struct {
		Parts []string `json:"parts"`
	} `json:"brand"`
	Notice struct {
		Text string `json:"text"`
	} `json:"notice"`
	Plan struct {
		ExpiresUnix int64 `json:"expires_unix"`
		QuotaBytes  int64 `json:"quota_bytes"`
		UsedBytes   int64 `json:"used_bytes"`
	} `json:"plan"`
	DNS     *syncDNS `json:"dns"`
	Servers []struct {
		ID      string     `json:"id"`
		Country string     `json:"country"`
		City    string     `json:"city"`
		Load    string     `json:"load"`
		Paths   []syncPath `json:"paths"`
	} `json:"servers"`
}

type syncDNS struct {
	Servers []syncResolver `json:"servers"`
	Split   []struct {
		Geo     []string       `json:"geo"`
		Servers []syncResolver `json:"servers"`
	} `json:"split"`
	SplitDirect bool `json:"split_direct"`
}

type syncResolver struct {
	Transport string   `json:"transport"`
	Address   string   `json:"address"`
	IPs       []string `json:"ips"`
}

// plainResolvers are the addresses of the plain entries (at most two): the address when it is an IP, or an IP with
// port 53, else the entry's ips. ponytail: plain only; DoT and DoH need a resolver client, and a port other than 53
// cannot be given to the direct path.
func plainResolvers(entries []syncResolver) []netip.Addr {
	var out []netip.Addr
	add := func(text string) {
		if address, err := netip.ParseAddr(text); err == nil && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && len(out) < 2 && !slices.Contains(out, address) {
			out = append(out, address)
		}
	}
	for _, entry := range entries {
		if entry.Transport == "plain" {
			for _, text := range entry.addresses() {
				add(text)
			}
		}
	}
	return out
}

// addresses are the IPs a plain entry names: its address when that is an IP (or an IP with port 53), else its ips.
func (r syncResolver) addresses() []string {
	if _, err := netip.ParseAddr(r.Address); err == nil {
		return []string{r.Address}
	}
	host, port, err := net.SplitHostPort(r.Address)
	if err != nil {
		return r.IPs // a host name
	}
	if port != "53" {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}
	}
	return r.IPs
}

// panelDNS keeps what the engine can use: the resolvers for the tunnel and, when the panel splits direct, those of
// each region it names.
func panelDNS(dns *syncDNS) ([]netip.Addr, []profile.DNSSplit) {
	if dns == nil {
		return nil, nil
	}
	var split []profile.DNSSplit
	if dns.SplitDirect {
		for _, entry := range dns.Split {
			var codes []string
			for _, code := range entry.Geo {
				if code = strings.ToLower(code); len(code) == 2 && code[0] >= 'a' && code[0] <= 'z' && code[1] >= 'a' && code[1] <= 'z' {
					codes = append(codes, code)
				}
			}
			if servers := plainResolvers(entry.Servers); len(codes) != 0 && len(servers) != 0 {
				split = append(split, profile.DNSSplit{Geo: codes, Servers: servers})
			}
		}
	}
	return plainResolvers(dns.Servers), split
}

type syncPath struct {
	ID       string          `json:"id"`
	Protocol string          `json:"protocol"`
	Via      string          `json:"via"`
	IPv6     bool            `json:"ipv6"`
	Settings json.RawMessage `json:"settings"`
}

// pathVersion is the AmneziaWG generation in a path's settings ("2.0", "3.1"): two AmneziaWG paths of one node differ
// by it. Empty for other protocols and when the panel does not say.
func pathVersion(path syncPath) string {
	if path.Protocol != "awg" {
		return ""
	}
	var settings struct {
		Version json.RawMessage `json:"version"`
	}
	if json.Unmarshal(path.Settings, &settings) != nil {
		return ""
	}
	version := strings.Trim(string(settings.Version), `"`)
	if len(version) == 0 || len(version) > 8 || version == "null" {
		return ""
	}
	return version
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

// call makes one API request. A redirect is never followed: it would carry the device key elsewhere.
func (s *Store) call(ctx context.Context, method, target, bearer string, body []byte, timeout time.Duration, etag string) (reply, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	request.Header.Set("User-Agent", apiUserAgent)
	request.Header.Set("X-Mistgate-Caps", capsHeader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	client := *s.client
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return reply{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(data) > maxBodyBytes {
		return reply{}, errors.New("unreadable answer")
	}
	return reply{response.StatusCode, response.Header, data}, nil
}

// replyCode is the "error" of a JSON error answer; empty for anything else (a decoy, HTML, a proxy's page).
func replyCode(body []byte) string {
	var answer struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return ""
	}
	return answer.Error
}

func originOf(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// enrol makes (or, with the old key as bearer, moves) this device and returns the panel's base URL.
func (s *Store) enrol(ctx context.Context, link, hwid, key, bearer string) (string, error) {
	body, _ := json.Marshal(struct {
		HWID      string `json:"hwid"`
		Platform  string `json:"platform"`
		Model     string `json:"model"`
		OSVersion string `json:"os_version"`
		DeviceKey string `json:"device_key"`
	}{hwid, "windows", "", "", key})
	target, err := url.JoinPath(link, "client", "enrol")
	if err != nil {
		return "", &Error{Code: "bad_link"}
	}
	r, err := s.call(ctx, http.MethodPost, target, bearer, body, 15*time.Second, "")
	if err != nil {
		return "", &Error{Code: fetchErrorCode(err)}
	}
	if r.status == http.StatusOK {
		var answer struct {
			Base string `json:"base"`
		}
		if json.Unmarshal(r.body, &answer) == nil && strings.HasPrefix(answer.Base, "https://") && originOf(answer.Base) == originOf(link) {
			return answer.Base, nil
		}
		return "", &Error{Code: "fetch_failed"}
	}
	if code := replyCode(r.body); noRetryCodes[code] || code == "device_removed" {
		return "", &Error{Code: code}
	}
	return "", &Error{Code: "fetch_failed"}
}

// manage enrols this device on a panel that announced the Client API and takes the first sync. If anything fails the
// plain result stays (unmanaged, Error says why) and the pending key stays for the next refresh.
func (s *Store) manage(ctx context.Context, plain storedSubscription) storedSubscription {
	link := plain.URL
	hwid, err := s.enrolHwid(originOf(link))
	var key string
	if err == nil {
		key, err = s.pendingKey(link)
	}
	if err != nil {
		plain.Error = "service_error"
		return plain
	}
	base, err := s.enrol(ctx, link, hwid, key, "")
	if err != nil {
		plain.Error = errorCode(err)
		if noRetryCodes[plain.Error] {
			plain.Halt = true
			_ = s.remember(func(d *diskState) { delete(d.Pending, link) })
		}
		return plain
	}
	managed := plain
	managed.Key, managed.Base, managed.Managed = key, base, true
	if managed, err = s.syncNow(ctx, managed); err != nil {
		plain.Error = errorCode(err)
		return plain
	}
	return managed
}

// reenrol moves a managed subscription to a rotated link: the old key authorises, a new key replaces it.
func (s *Store) reenrol(ctx context.Context, link string, st storedSubscription) (storedSubscription, error) {
	hwid, err := s.enrolHwid(originOf(link))
	var key string
	if err == nil {
		key, err = s.pendingKey(link)
	}
	if err != nil {
		return st, &Error{Code: "service_error"}
	}
	base, err := s.enrol(ctx, link, hwid, key, st.Key)
	if err != nil {
		if code := errorCode(err); code == "device_removed" || code == "device_blocked" {
			applyDeviceCode(&st, code)
		}
		return st, err
	}
	st.URL, st.Base, st.Key, st.ETag, st.Halt, st.Error = link, base, key, "", false, ""
	return s.syncNow(ctx, st)
}

// applyDeviceCode records an answer that says what became of this device.
func applyDeviceCode(st *storedSubscription, code string) {
	st.Error, st.Halt = code, true
	switch code {
	case "device_removed":
		st.Key, st.Base, st.ETag, st.Managed, st.Notice = "", "", "", false, ""
		st.Servers, st.Entries, st.Unsupported = []Server{}, nil, 0
	case "device_blocked":
		st.ETag, st.Servers, st.Entries, st.Unsupported = "", []Server{}, nil, 0
	}
	// link_changed keeps the servers: the tunnel works, only the sync is cut off.
}

// syncNow takes the subscription from the panel. The returned subscription is what to keep, error or not.
func (s *Store) syncNow(ctx context.Context, st storedSubscription) (storedSubscription, error) {
	fail := func(code string) (storedSubscription, error) {
		if !st.Halt { // a stopped subscription keeps saying why it stopped
			st.Error = code
		}
		return st, &Error{Code: code}
	}
	target, err := url.JoinPath(st.Base, "sync")
	if err != nil {
		return fail("fetch_failed")
	}
	etag := ""
	if st.Error == "" {
		etag = st.ETag
	}
	// ponytail: X-Mistgate-Direct is not sent, the service does not know yet whether this request leaves outside the
	// tunnel; `asn` comes with it.
	r, err := s.call(ctx, http.MethodGet, target, st.Key, nil, 15*time.Second, etag)
	if err != nil {
		return fail(fetchErrorCode(err))
	}
	now := time.Now()
	switch {
	case r.status == http.StatusNotModified:
		st.Halt, st.Error, st.UpdatedUnix = false, "", now.Unix()
		st.schedule(now, st.SyncEvery)
		return st, nil
	case r.status != http.StatusOK:
		switch code := replyCode(r.body); code {
		case "device_removed", "device_blocked", "link_changed":
			applyDeviceCode(&st, code)
			return st, &Error{Code: code}
		}
		if n, err := strconv.ParseInt(r.header.Get("Retry-After"), 10, 64); err == nil && n > 0 && (r.status == 429 || r.status == 503) {
			st.NextUnix = now.Unix() + min(n, maxRetryAfter)
		}
		return fail("fetch_failed")
	}
	var b syncBody
	if json.Unmarshal(r.body, &b) != nil {
		return fail("fetch_failed")
	}
	if b.V != 1 {
		return fail("unsupported_format")
	}
	st.Halt, st.Error, st.ETag, st.UpdatedUnix = false, "", r.header.Get("ETag"), now.Unix()
	st.schedule(now, b.SyncEvery)
	if name := strings.Join(b.Brand.Parts, ""); name != "" {
		st.Name = name
	}
	st.ExpireUnix, st.TotalBytes, st.UsedBytes = b.Plan.ExpiresUnix, b.Plan.QuotaBytes, b.Plan.UsedBytes
	st.Notice = strings.Join(strings.Fields(b.Notice.Text), " ")
	st.DNS, st.DNSSplit = panelDNS(b.DNS) // absent unless active: the old resolvers go with the old answer
	st.Servers, st.Entries, st.Unsupported = []Server{}, nil, 0
	if b.Status != "active" {
		st.Error = "inactive"
		if st.Notice == "" {
			st.Notice = b.Status
		}
		return st, nil
	}
	if b.Reason == "app_disabled" { // the owner switched the app off for this person: no servers, the device and its
		st.Error = b.Reason // key stay, and the usual sync brings the servers back when it is switched on again
		return st, nil
	}
	seen := make(map[string]bool)
	for number, server := range b.Servers {
		for _, path := range server.Paths {
			raw, err := json.Marshal(path)
			if _, _, perr := pathProfile(string(raw)); err != nil || perr != nil || path.ID == "" {
				st.Unsupported++
				continue
			}
			if seen[path.ID] {
				continue
			}
			seen[path.ID] = true
			name := server.City
			if name == "" {
				name = server.Country
			}
			if name == "" { // a node the operator gave no place
				name = "Server " + strconv.Itoa(number+1)
			}
			if path.Via != "" && path.Via != "direct" {
				name += " · " + path.Via
			}
			if path.IPv6 {
				name += " · IPv6"
			}
			node := server.ID
			if node == "" {
				node = "n" + strconv.Itoa(number+1)
			}
			entry := Server{ID: path.ID, Name: name, Protocol: path.Protocol, Version: pathVersion(path), Node: node, Country: server.Country, City: server.City, Via: path.Via, IPv6: path.IPv6, Load: server.Load}
			st.Servers = append(st.Servers, entry)
			st.Entries = append(st.Entries, storedEntry{Server: entry, Raw: string(raw)})
		}
	}
	return st, nil
}

// schedule sets the next automatic sync: the panel's interval (at least 10 minutes) plus up to 10% of random wait,
// so clients behind one exit address do not come together.
func (st *storedSubscription) schedule(now time.Time, every int64) {
	if every == 0 {
		every = defaultSyncSeconds
	}
	st.SyncEvery = max(every, minSyncSeconds)
	st.NextUnix = now.Unix() + st.SyncEvery + mrand.Int64N(st.SyncEvery/10+1)
}

// leave removes this device from the panel. Whatever it answers, the caller removes the subscription.
// ponytail: a failed leave leaves the device in the panel's list until it goes silent; a retry queue if owners complain.
func (s *Store) leave(base, key string) {
	if target, err := url.JoinPath(base, "leave"); err == nil {
		_, _ = s.call(context.Background(), http.MethodPost, target, key, nil, 5*time.Second, "")
	}
}

// remember saves a change to the state's small maps before the request that depends on it.
func (s *Store) remember(change func(*diskState)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneState(s.state)
	if candidate.Hwids == nil {
		candidate.Hwids = map[string]string{}
	}
	if candidate.Pending == nil {
		candidate.Pending = map[string]string{}
	}
	change(&candidate)
	if err := s.save(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

// enrolHwid is the hwid of an origin (one operator's panel), made at the first contact and kept forever: the plain
// fetch and enrol send the same one, so enrol takes over the device the fetch made. The first origin gets the install
// id, every other an id of its own, so two operators cannot tell that it is one machine.
func (s *Store) enrolHwid(origin string) (string, error) {
	s.mu.RLock()
	id, known := s.state.Hwids[origin]
	if !known {
		id = s.state.InstallID
		for _, used := range s.state.Hwids {
			if used == id {
				id = ""
			}
		}
	}
	s.mu.RUnlock()
	if known {
		return id, nil
	}
	if id == "" {
		var err error
		if id, err = installID(); err != nil {
			return "", err
		}
	}
	return id, s.remember(func(d *diskState) { d.Hwids[origin] = id })
}

// pendingKey is the device key to send for a link: made and saved before the first request, so that a lost answer is
// repaired by repeating the same request.
func (s *Store) pendingKey(link string) (string, error) {
	s.mu.RLock()
	key := s.state.Pending[link]
	s.mu.RUnlock()
	if key != "" {
		return key, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key = base64.RawURLEncoding.EncodeToString(raw)
	return key, s.remember(func(d *diskState) { d.Pending[link] = key })
}

// pathProfile turns a stored path (the panel's JSON) into a profile through the Mihomo proxy parsers, so that one
// place knows the profiles and the UAPI.
func pathProfile(raw string) (*profile.Hy2, *profile.AWG, error) {
	var path syncPath
	if json.Unmarshal([]byte(raw), &path) != nil {
		return nil, nil, errors.New("invalid stored path")
	}
	var proxy map[string]any
	var err error
	switch path.Protocol {
	case "hysteria2":
		proxy, err = hy2Proxy(path.Settings)
	case "awg":
		proxy, err = awgProxy(path.Settings)
	default:
		err = errors.New("unsupported path protocol")
	}
	if err != nil {
		return nil, nil, err
	}
	_, hy2, awg, err := parseProxyProfile(proxy)
	return hy2, awg, err
}

func hy2Proxy(settings json.RawMessage) (map[string]any, error) {
	var s struct {
		Server       string   `json:"server"`
		Port         int      `json:"port"`
		Ports        string   `json:"ports"`
		HopIntervalS int      `json:"hop_interval_s"`
		Auth         string   `json:"auth"`
		TLS          string   `json:"tls"`
		PinSHA256    string   `json:"pin_sha256"`
		SNI          string   `json:"sni"`
		ALPN         []string `json:"alpn"`
		Obfs         struct {
			Type     string `json:"type"`
			Password string `json:"password"`
		} `json:"obfs"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil, errors.New("invalid Hysteria2 settings")
	}
	// There is no insecure mode in the API: skip-cert-verify is never set.
	proxy := map[string]any{"type": "hysteria2", "server": s.Server, "port": s.Port, "password": s.Auth, "sni": s.SNI}
	switch s.TLS {
	case "ca":
	case "pin":
		if s.PinSHA256 == "" {
			return nil, errors.New("missing Hysteria2 certificate pin")
		}
		proxy["pinsha256"] = s.PinSHA256
	default:
		return nil, errors.New("unknown Hysteria2 TLS mode")
	}
	if s.Ports != "" {
		proxy["ports"] = s.Ports
	}
	if s.HopIntervalS > 0 {
		proxy["hop-interval"] = s.HopIntervalS
	}
	if len(s.ALPN) > 0 {
		proxy["alpn"] = s.ALPN
	}
	if s.Obfs.Type != "" {
		proxy["obfs"], proxy["obfs-password"] = s.Obfs.Type, s.Obfs.Password
	}
	return proxy, nil
}

func awgProxy(settings json.RawMessage) (map[string]any, error) {
	var s struct {
		Endpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"endpoint"`
		PublicKey    string         `json:"public_key"`
		PrivateKey   string         `json:"private_key"`
		PresharedKey string         `json:"preshared_key"`
		AddressV4    string         `json:"address_v4"`
		AddressV6    string         `json:"address_v6"`
		AllowedIPs   []string       `json:"allowed_ips"`
		DNS          []string       `json:"dns"`
		MTU          int            `json:"mtu"`
		KeepaliveS   int            `json:"keepalive_s"`
		Params       map[string]any `json:"params"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil, errors.New("invalid AmneziaWG settings")
	}
	// The endpoint host is bare; the Mihomo parser joins it with the port (brackets for IPv6).
	proxy := map[string]any{
		"type": "wireguard", "server": s.Endpoint.Host, "port": s.Endpoint.Port,
		"public-key": s.PublicKey, "private-key": s.PrivateKey, "pre-shared-key": s.PresharedKey,
		"ip": s.AddressV4, "ipv6": s.AddressV6, "allowed-ips": s.AllowedIPs,
	}
	if len(s.DNS) > 0 {
		proxy["dns"] = s.DNS
	}
	if s.MTU > 0 {
		proxy["mtu"] = s.MTU
	}
	if s.KeepaliveS > 0 {
		proxy["persistent-keepalive"] = s.KeepaliveS
	}
	if len(s.Params) > 0 {
		proxy["amnezia-wg-option"] = s.Params
	}
	return proxy, nil
}
