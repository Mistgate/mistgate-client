package subs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/ipcsize"
	"github.com/mistgate/mistgate-client/core/internal/profile"
)

const (
	fileName                   = "subscriptions.bin"
	maxBodyBytes               = 4 << 20
	maxPublicSubscriptionBytes = ipcsize.MaxLineBytes / 4
	defaultIntervalHours       = 12
)

type Subscription struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	UpdatedUnix int64    `json:"updated_unix"`
	ExpireUnix  int64    `json:"expire_unix"`
	UsedBytes   int64    `json:"used_bytes"`
	TotalBytes  int64    `json:"total_bytes"`
	Error       string   `json:"error"`
	Notice      string   `json:"notice"`
	Unsupported int      `json:"unsupported"`
	Managed     bool     `json:"managed"`
	Servers     []Server `json:"servers"`
	// From a panel's client API only. A Telegram link carries its proxy's secret: it goes to the trusted window and
	// is never logged. DevicesLimit 0: the panel did not say.
	Telegram     []Telegram `json:"telegram,omitempty"`
	DevicesUsed  int        `json:"devices_used,omitempty"`
	DevicesLimit int        `json:"devices_limit,omitempty"`
	Debug        *Debug     `json:"debug,omitempty"` // nil: the panel did not say (a link subscription, an old panel)
	// Block reports (report.go). Probe nil: the panel did not say, or the subscription is not managed. Report is the
	// person's switch (off by default; kept when the panel stops taking reports). ReportLast is set in memory by List only.
	Probe      *Probe      `json:"probe,omitempty"`
	Report     bool        `json:"report"`
	ReportLast *ReportLast `json:"report_last,omitempty"`

	// UnsupportedKinds says what Unsupported was made of: kind -> count, the counts adding up to Unsupported. A kind is
	// the scheme of a link or the type of a profile's proxy, lower case ("trojan", "ss"); a vless that failed has its
	// reason in brackets ("vless (transport)"). Nothing of the server is in it (see kindCounts). Absent: nothing was
	// unsupported, the subscription is managed, or it was saved by an older build and has not been refreshed since.
	UnsupportedKinds map[string]int `json:"unsupported_kinds,omitempty"`
}

// Telegram is one MTProto proxy of the subscription, as a link Telegram opens. Twins of one server share Node.
type Telegram struct {
	Node       string `json:"node,omitempty"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
	Via        string `json:"via,omitempty"`
	ViaCountry string `json:"via_country,omitempty"`
	IPv6       bool   `json:"ipv6,omitempty"`
	Link       string `json:"link"`
}

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	// From a panel's client API only: the paths of one node share Node. Via is direct, relay or warp.
	Node    string `json:"node,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Via     string `json:"via,omitempty"`
	IPv6    bool   `json:"ipv6,omitempty"`
	Version string `json:"version,omitempty"` // the AmneziaWG generation of the path ("2.0", "3.1"), when the panel says
	Load    string `json:"load,omitempty"`    // low, medium or high; empty when the panel does not know
	// The owner's names: of the path's profile and of the server. ViaCountry is where a relay path enters.
	Label      string `json:"label,omitempty"`
	NodeLabel  string `json:"node_label,omitempty"`
	ViaCountry string `json:"via_country,omitempty"`
	IPv6Egress *bool  `json:"ipv6_egress,omitempty"` // whether IPv6 leaves through this path; nil: the panel did not say
}

type Error struct {
	Code   string
	Notice string
}

func (e *Error) Error() string { return e.Code }

type storedEntry struct {
	Server Server `json:"server"`
	Raw    string `json:"raw"`
}

type storedSubscription struct {
	Subscription
	apiState
	URL           string        `json:"url,omitempty"`
	Entries       []storedEntry `json:"entries"`
	IntervalHours int64         `json:"interval_hours,omitempty"`
}

type diskState struct {
	InstallID     string               `json:"install_id"`
	Subscriptions []storedSubscription `json:"subscriptions"`
	Hwids         map[string]string    `json:"hwids,omitempty"`   // origin of a link -> hwid, never deleted
	Pending       map[string]string    `json:"pending,omitempty"` // link -> device key sent to enrol and not yet confirmed
}

type Store struct {
	dir     string
	path    string
	mu      sync.RWMutex
	opMu    sync.Mutex
	state   diskState
	changes chan struct{}
	client  *http.Client
	protect func([]byte) ([]byte, error)
	clock   func() time.Time // nil: time.Now (tests)

	reportMu sync.Mutex // after mu, never before it
	reports  map[string]*reportState
}

func Open(dir string) (*Store, error) {
	return openStore(dir, protect, unprotect, secureDirectory)
}

func openStore(dir string, protectData, unprotectData func([]byte) ([]byte, error), secureDir func(string) error) (*Store, error) {
	if err := prepareStoreDirectory(dir, secureDir); err != nil {
		return nil, errors.New("cannot create subscription data directory")
	}
	s := &Store{
		dir:     dir,
		path:    filepath.Join(dir, fileName),
		changes: make(chan struct{}, 1),
		client:  &http.Client{Timeout: 15 * time.Second},
		protect: protectData,
	}
	data, err := os.ReadFile(s.path)
	if err == nil {
		plain, decryptErr := unprotectData(data)
		var state diskState
		if decryptErr == nil && json.Unmarshal(plain, &state) == nil && validInstallID(state.InstallID) {
			if state.Subscriptions == nil {
				state.Subscriptions = []storedSubscription{}
			}
			s.state = state
			s.fillVersions()
			return s, nil
		}
		badPath := filepath.Join(dir, "subscriptions.bad")
		if quarantineErr := os.Rename(s.path, badPath); quarantineErr != nil {
			return nil, errors.New("cannot quarantine unreadable subscription store")
		}
		slog.Default().With("src", "subs").Warn("subscription store could not be decrypted or parsed; starting empty")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot read subscription store")
	}
	id, err := installID()
	if err != nil {
		return nil, errors.New("cannot create install id")
	}
	s.state = diskState{InstallID: id, Subscriptions: []storedSubscription{}}
	if err := s.save(s.state); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Changes() <-chan struct{} { return s.changes }

// fillVersions gives stored client API paths the AmneziaWG generation an older build did not keep: the panel answers
// "not changed" to a sync, so the stored copy is all there is until the list changes.
func (s *Store) fillVersions() {
	for i := range s.state.Subscriptions {
		sub := &s.state.Subscriptions[i]
		// A copy kept by a build that did not read ipv6_egress (the panel sends it on every path) is taken again in
		// full: "not changed" would never bring the fields that build dropped.
		if sub.Managed && sub.ETag != "" && !slices.ContainsFunc(sub.Servers, func(server Server) bool { return server.IPv6Egress != nil }) {
			sub.ETag = ""
		}
		versions := make(map[string]string)
		for j := range sub.Entries {
			entry := &sub.Entries[j]
			if entry.Server.Version != "" || entry.Server.Protocol != "awg" || !strings.HasPrefix(entry.Raw, "{") {
				continue
			}
			var path syncPath
			if json.Unmarshal([]byte(entry.Raw), &path) == nil {
				entry.Server.Version = pathVersion(path)
				versions[entry.Server.ID] = entry.Server.Version
			}
		}
		for j := range sub.Servers {
			if version := versions[sub.Servers[j].ID]; version != "" {
				sub.Servers[j].Version = version
			}
		}
	}
}

func (s *Store) List() []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Subscription, len(s.state.Subscriptions))
	for i, sub := range s.state.Subscriptions {
		result[i] = s.withLast(publicCopy(sub.Subscription))
	}
	return result
}

// Link is the link the user pasted for a url subscription (it carries the token: never log it). Other kinds have none.
func (s *Store) Link(id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.state.Subscriptions {
		if sub.ID != id {
			continue
		}
		if sub.Kind != "url" || sub.URL == "" {
			return "", &Error{Code: "no_link"}
		}
		return sub.URL, nil
	}
	return "", &Error{Code: "unknown_subscription"}
}

func (s *Store) Preview(ctx context.Context, text string) (Subscription, error) {
	stored, err := s.preview(ctx, text, "")
	return stored.Subscription, err
}

func (s *Store) Add(ctx context.Context, text string) (Subscription, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	var id string
	var rotated *storedSubscription // a managed subscription of the same panel whose link the panel has rotated
	if rawURL, ok := subscriptionURL(text); ok {
		s.mu.RLock()
		for _, sub := range s.state.Subscriptions {
			if sub.Kind != "url" {
				continue
			}
			if sub.URL == rawURL {
				id, rotated = sub.ID, nil
				if sub.Key != "" {
					s.mu.RUnlock()
					return s.refresh(ctx, id) // a managed subscription is never fetched plain again
				}
				break
			}
			if sub.Error == "link_changed" && sub.Key != "" && originOf(sub.URL) == originOf(rawURL) {
				copied := cloneStored(sub)
				rotated = &copied
			}
		}
		s.mu.RUnlock()
	}
	if rotated != nil {
		id = rotated.ID
	}
	if id == "" {
		var err error
		id, err = randomHex(8)
		if err != nil {
			return Subscription{}, &Error{Code: "service_error"}
		}
	}
	var stored storedSubscription
	var err error
	if rotated != nil {
		rawURL, _ := subscriptionURL(text)
		stored, err = s.reenrol(ctx, rawURL, *rotated)
	} else if stored, err = s.preview(ctx, text, id); err != nil {
		return publicCopy(stored.Subscription), err
	}
	stored.ID = id

	s.mu.Lock()
	candidate := cloneState(s.state)
	for i := range candidate.Subscriptions {
		if candidate.Subscriptions[i].ID == id {
			candidate.Subscriptions = append(candidate.Subscriptions[:i], candidate.Subscriptions[i+1:]...)
			break
		}
	}
	candidate.Subscriptions = append(candidate.Subscriptions, stored)
	if stored.Key != "" {
		delete(candidate.Pending, stored.URL)
	}
	saveErr := s.save(candidate)
	if saveErr == nil {
		s.state = candidate
	}
	s.mu.Unlock()
	if saveErr != nil {
		return Subscription{}, saveErr
	}
	s.changed()
	return publicCopy(stored.Subscription), err
}

func (s *Store) Remove(id string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	var base, key string
	s.mu.RLock()
	for _, sub := range s.state.Subscriptions {
		if sub.ID == id {
			base, key = sub.Base, sub.Key
		}
	}
	s.mu.RUnlock()
	if key != "" {
		s.leave(base, key)
	}
	s.mu.Lock()
	candidate := cloneState(s.state)
	for i, sub := range candidate.Subscriptions {
		if sub.ID == id {
			candidate.Subscriptions = append(candidate.Subscriptions[:i], candidate.Subscriptions[i+1:]...)
			delete(candidate.Pending, sub.URL)
			if err := s.save(candidate); err != nil {
				s.mu.Unlock()
				return err
			}
			s.state = candidate
			s.mu.Unlock()
			s.forgetReport(id)
			s.changed()
			return nil
		}
	}
	s.mu.Unlock()
	return &Error{Code: "unknown_subscription"}
}

func (s *Store) Refresh(ctx context.Context, id string) (Subscription, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.refresh(ctx, id)
}

func (s *Store) refresh(ctx context.Context, id string) (Subscription, error) {
	s.mu.RLock()
	var current storedSubscription
	found := false
	for _, sub := range s.state.Subscriptions {
		if sub.ID == id {
			current, found = cloneStored(sub), true
			break
		}
	}
	s.mu.RUnlock()
	if !found {
		return Subscription{}, &Error{Code: "unknown_subscription"}
	}
	if current.Kind != "url" {
		return publicCopy(current.Subscription), nil
	}

	var next storedSubscription
	var err error
	if current.Key != "" {
		next, err = s.syncNow(ctx, current)
	} else if next, err = s.loadURL(ctx, current.URL, id); err != nil {
		code := errorCode(err)
		changed := false
		s.mu.Lock()
		candidate := cloneState(s.state)
		for i := range candidate.Subscriptions {
			if candidate.Subscriptions[i].ID == id {
				if candidate.Subscriptions[i].Error != code || next.Notice != "" && candidate.Subscriptions[i].Notice != next.Notice || candidate.Subscriptions[i].Halt != next.Halt {
					candidate.Subscriptions[i].Error = code
					candidate.Subscriptions[i].Halt = next.Halt
					if next.Notice != "" {
						candidate.Subscriptions[i].Notice = next.Notice
					}
					if saveErr := s.save(candidate); saveErr != nil {
						s.mu.Unlock()
						return publicCopy(current.Subscription), saveErr
					}
					s.state = candidate
					changed = true
				}
				current = cloneStored(candidate.Subscriptions[i])
				break
			}
		}
		s.mu.Unlock()
		if changed {
			s.changed()
		}
		return publicCopy(current.Subscription), err
	}
	next.ID = id
	s.mu.Lock()
	candidate := cloneState(s.state)
	for i := range candidate.Subscriptions {
		if candidate.Subscriptions[i].ID == id {
			next.Report = candidate.Subscriptions[i].Report // the person may have used the switch while the sync ran
			candidate.Subscriptions[i] = next
			break
		}
	}
	if next.Key != "" {
		delete(candidate.Pending, next.URL)
	}
	if saveErr := s.save(candidate); saveErr != nil {
		s.mu.Unlock()
		return publicCopy(current.Subscription), saveErr
	}
	s.state = candidate
	s.mu.Unlock()
	s.changed()
	return publicCopy(next.Subscription), err
}

func (s *Store) Profiles() ([]profile.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := make([]profile.Profile, 0)
	for _, sub := range s.state.Subscriptions {
		for _, entry := range sub.Entries {
			p := profile.Profile{ID: entry.Server.ID, Name: entry.Server.Name, Protocol: entry.Server.Protocol, Sub: sub.ID, Via: entry.Server.Via, PanelDNS: sub.DNS, PanelSplit: sub.DNSSplit,
				NoIPv6: entry.Server.IPv6Egress != nil && !*entry.Server.IPv6Egress}
			var err error
			switch {
			case strings.HasPrefix(entry.Raw, "{"):
				p.Hy2, p.AWG, p.VLESS, err = pathProfile(entry.Raw)
			case entry.Server.Protocol == "hysteria2":
				if strings.Contains(entry.Raw, "://") {
					p.Hy2, err = profile.ParseHy2(entry.Raw)
				} else {
					p.Hy2, _, err = parseMihomoEntry(entry.Raw, entry.Server.Protocol)
				}
			case entry.Server.Protocol == "vless":
				if strings.Contains(strings.SplitN(entry.Raw, "\n", 2)[0], "://") {
					p.VLESS, err = profile.ParseVLESSLink(entry.Raw)
				} else { // a Mihomo profile's proxy
					p.VLESS, err = parseVLESSEntry(entry.Raw)
				}
			case entry.Server.Protocol == "awg":
				if strings.HasPrefix(strings.TrimSpace(entry.Raw), "[Interface]") {
					p.AWG, err = profile.ParseAWG(entry.Raw)
				} else {
					_, p.AWG, err = parseMihomoEntry(entry.Raw, entry.Server.Protocol)
				}
			default:
				err = errors.New("unsupported profile protocol")
			}
			if err != nil {
				continue // one entry this build cannot read (kept by another build) must not take the rest away
			}
			profiles = append(profiles, p)
		}
	}
	return profiles, nil
}

func (s *Store) Run(ctx context.Context) {
	refreshDue := func() {
		for _, id := range s.due(time.Now().Unix()) {
			if ctx.Err() != nil {
				return
			}
			_, _ = s.Refresh(ctx, id)
		}
	}
	refreshDue()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshDue()
		}
	}
}

// due lists the URL subscriptions whose automatic refresh is due. Subscriptions stopped by the panel's answer wait for
// a refresh by hand.
func (s *Store) due(now int64) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []string
	for _, sub := range s.state.Subscriptions {
		if sub.Kind != "url" || sub.Halt {
			continue
		}
		hours := sub.IntervalHours
		if hours < 1 {
			hours = defaultIntervalHours
		}
		if sub.Key != "" && now >= sub.NextUnix ||
			sub.Key == "" && (sub.UpdatedUnix == 0 || now >= sub.UpdatedUnix && (now-sub.UpdatedUnix)/int64(time.Hour/time.Second) >= hours) {
			ids = append(ids, sub.ID)
		}
	}
	return ids
}

func (s *Store) preview(ctx context.Context, text, id string) (storedSubscription, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return storedSubscription{}, &Error{Code: "bad_link"}
	}
	if strings.HasPrefix(text, "http://") {
		return storedSubscription{}, &Error{Code: "insecure_link"}
	}
	if rawURL, ok := subscriptionURL(text); ok {
		return s.loadURL(ctx, rawURL, id)
	}
	if strings.Contains(text, "[Interface]") {
		if _, err := profile.ParseAWG(text); err != nil {
			return storedSubscription{}, &Error{Code: "bad_link"}
		}
		server := Server{ID: serverID(id, text), Name: "AmneziaWG", Protocol: "awg"}
		sub := Subscription{ID: id, Kind: "awg", Name: "AmneziaWG", UpdatedUnix: time.Now().Unix(), Servers: []Server{server}}
		return storedSubscription{Subscription: sub, Entries: []storedEntry{{Server: server, Raw: text}}, IntervalHours: defaultIntervalHours}, nil
	}
	servers, entries, unsupported, kinds, parseErr := parseEntries(text, id)
	if parseErr != nil {
		return storedSubscription{}, parseErr
	}
	servers, entries, unsupported, kinds = capServers(servers, entries, unsupported, kinds)
	sub := Subscription{ID: id, Kind: "links", Name: "Servers", UpdatedUnix: time.Now().Unix(), Unsupported: unsupported, UnsupportedKinds: kinds, Servers: servers}
	return storedSubscription{Subscription: sub, Entries: entries, IntervalHours: defaultIntervalHours}, nil
}

// loadURL fetches the plain subscription. On a panel that announces the Client API (and for a saved subscription, not
// a preview) it goes on to enrol; an error comes back only when the plain answer itself is unusable.
func (s *Store) loadURL(ctx context.Context, rawURL, id string) (storedSubscription, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return storedSubscription{}, &Error{Code: "bad_link"}
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return storedSubscription{}, &Error{Code: "bad_link"}
	}
	// the hwid of this panel from the first contact on, so that enrol later takes over the device this fetch makes
	hwid, err := s.enrolHwid(originOf(rawURL))
	if err != nil {
		return storedSubscription{}, &Error{Code: "service_error"}
	}
	request.Header.Set("User-Agent", plainUserAgent())
	request.Header.Set("x-hwid", hwid)
	request.Header.Set("x-device-os", "Windows")
	request.Header.Set("X-Mistgate-Caps", capsHeader)
	client := *s.client
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 5 || request.URL.Scheme != "https" {
			return errors.New("invalid subscription redirect")
		}
		// the device id of this panel is not for another host
		if !strings.EqualFold(request.URL.Host, via[0].URL.Host) {
			request.Header.Del("x-hwid")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return storedSubscription{}, &Error{Code: fetchErrorCode(err)}
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return storedSubscription{}, &Error{Code: "bad_link"}
	case http.StatusOK:
	default:
		return storedSubscription{}, &Error{Code: "fetch_failed"}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		return storedSubscription{}, &Error{Code: "fetch_failed"}
	}
	name := responseName(response.Header.Get("profile-title"), parsed.Host)
	used, total, expire := parseUserInfo(response.Header.Get("subscription-userinfo"))
	sub := Subscription{
		ID: id, Kind: "url", Name: name, Host: shortText(parsed.Host), UpdatedUnix: time.Now().Unix(),
		ExpireUnix: expire, UsedBytes: used, TotalBytes: total, Notice: responseNotice(response.Header.Get("Announce")),
	}
	servers, entries, unsupported, kinds, err := parseURLBody(string(body), id)
	servers, entries, unsupported, kinds = capServers(servers, entries, unsupported, kinds)
	sub.Name, sub.Notice = shortText(sub.Name), shortTextN(sub.Notice, maxNotice)
	var coded *Error
	if err != nil && errors.As(err, &coded) && coded.Notice != "" {
		sub.Notice = shortTextN(coded.Notice, maxNotice)
	}
	if err == nil {
		sub.Unsupported, sub.UnsupportedKinds, sub.Servers = unsupported, kinds, servers
	}
	plain := storedSubscription{Subscription: sub, URL: rawURL, Entries: entries, IntervalHours: parseInterval(response.Header.Get("profile-update-interval"))}
	if id != "" && strings.TrimSpace(response.Header.Get("Mistgate-Client-Api")) == "1" {
		managed := s.manage(ctx, plain)
		if managed.Key != "" || err == nil {
			return managed, nil
		}
		plain.Halt = managed.Halt // the plain answer is a placeholder; enrol said not to try again
	}
	return plain, err
}

func parseURLBody(body, id string) ([]Server, []storedEntry, int, kindCounts, error) {
	body = strings.TrimSpace(body)
	if !strings.Contains(body, "://") {
		if decoded, err := decodeSubscription(body); err == nil {
			decodedBody := strings.TrimSpace(string(decoded))
			if strings.Contains(decodedBody, "://") && !mihomoProxiesKey.MatchString(decodedBody) {
				body = decodedBody
			}
		}
	}
	if strings.Contains(body, "://") && !mihomoProxiesKey.MatchString(body) {
		return parseEntries(body, id)
	}
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return nil, nil, 0, nil, &Error{Code: "unsupported_format"}
	}
	return parseMihomoProfile(body, id)
}

var linkStart = regexp.MustCompile(`\s+([a-zA-Z][a-zA-Z0-9+.-]*://)`)
var mihomoProxiesKey = regexp.MustCompile(`(?m)^proxies\s*:`)

func parseEntries(text, id string) ([]Server, []storedEntry, int, kindCounts, error) {
	servers := make([]Server, 0)
	entries := make([]storedEntry, 0)
	seen := make(map[string]bool)
	unsupported, count, kinds := 0, 0, kindCounts{}
	// a single-line field turns a pasted list into one line: a new link starts wherever whitespace is followed by a scheme
	for _, line := range strings.Split(linkStart.ReplaceAllString(text, "\n$1"), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		scheme, _, ok := strings.Cut(line, "://")
		if !ok {
			continue
		}
		count++
		protocol := strings.ToLower(scheme)
		var err error
		switch protocol {
		case "hysteria2", "hy2":
			protocol = "hysteria2"
			_, err = profile.ParseHy2(line)
		case "vless":
			_, err = profile.ParseVLESSLink(line)
		default:
			err = errors.New("unsupported link")
		}
		if err != nil {
			unsupported++
			if protocol == "vless" {
				kinds.add(vlessKind(err), 1)
			} else {
				kinds.add(protocol, 1)
			}
			continue
		}
		name := linkFragment(line)
		entry := strings.SplitN(line, "#", 2)[0]
		server := Server{ID: serverID(id, entry), Name: name, Protocol: protocol}
		if seen[server.ID] {
			continue
		}
		seen[server.ID] = true
		servers = append(servers, server)
		entries = append(entries, storedEntry{Server: server, Raw: line})
	}
	if count == 0 {
		return nil, nil, unsupported, kinds, &Error{Code: "bad_link"}
	}
	if len(entries) == 0 {
		return nil, nil, unsupported, kinds, &Error{Code: "no_servers"}
	}
	return servers, entries, unsupported, kinds, nil
}

// kindCounts is Subscription.UnsupportedKinds while it is being counted. The kinds go to the window and can be shown
// to the person, so a name is let in only if it looks like a kind (lower case words, at most 40 characters, nothing
// like a host, key or path) and there are at most 12 of them; whatever does not fit is counted as "other".
type kindCounts map[string]int

const maxKinds = 12

var kindName = regexp.MustCompile(`^[a-z0-9][a-z0-9 ()+._-]{0,39}$`)

func (k kindCounts) add(kind string, n int) {
	if !kindName.MatchString(kind) || k[kind] == 0 && kind != "other" && len(k) >= maxKinds-1 {
		kind = "other"
	}
	k[kind] += n
}

// vlessKind is how a vless that failed is counted: "vless" and the reason from profile's fixed set.
func vlessKind(err error) string { return "vless (" + profile.VLESSReason(err) + ")" }

func linkFragment(line string) string {
	_, fragment, ok := strings.Cut(line, "#")
	if !ok {
		return ""
	}
	if decoded, err := url.PathUnescape(fragment); err == nil {
		return decoded
	}
	return fragment
}

func subscriptionURL(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if strings.ContainsAny(text, "\r\n") {
		return "", false
	}
	return text, strings.HasPrefix(text, "https://")
}

func decodeSubscription(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func parseUserInfo(value string) (used, total, expire int64) {
	values := make(map[string]int64)
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil && n >= 0 {
			values[strings.ToLower(strings.TrimSpace(key))] = n
		}
	}
	upload, download := values["upload"], values["download"]
	if upload <= int64(^uint64(0)>>1)-download {
		used = upload + download
	} else {
		used = int64(^uint64(0) >> 1)
	}
	return used, values["total"], values["expire"]
}

func responseName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "base64:") {
		if decoded, err := decodeSubscription(strings.TrimPrefix(value, "base64:")); err == nil {
			value = string(decoded)
		} else {
			value = ""
		}
	}
	if value == "" {
		return fallback
	}
	return strings.ToValidUTF8(value, "�")
}

func responseNotice(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "base64:") {
		decoded, err := decodeSubscription(strings.TrimPrefix(value, "base64:"))
		if err != nil {
			return ""
		}
		value = string(decoded)
	}
	return strings.Join(strings.Fields(strings.ToValidUTF8(value, "�")), " ")
}

func parseInterval(value string) int64 {
	hours, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return defaultIntervalHours
	}
	if hours < 1 {
		return 1
	}
	return hours
}

func fetchErrorCode(err error) string {
	var timeout interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "fetch_failed"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "offline"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "offline"
	}
	return "fetch_failed"
}

func errorCode(err error) string {
	var coded *Error
	if errors.As(err, &coded) && coded.Code != "" {
		return coded.Code
	}
	return "fetch_failed"
}

func serverID(subscriptionID, entry string) string {
	sum := sha256.Sum256([]byte(subscriptionID + "\x00" + entry))
	return hex.EncodeToString(sum[:])
}

func installID() (string, error) { return randomHex(16) }

func randomHex(bytes int) (string, error) {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func validInstallID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func (s *Store) save(state diskState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("cannot encode subscription store")
	}
	data, err = s.protect(data)
	if err != nil {
		return errors.New("cannot protect subscription store")
	}
	temp, err := os.CreateTemp(s.dir, ".subscriptions-*.tmp")
	if err != nil {
		return errors.New("cannot write subscription store")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot write subscription store")
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return errors.New("cannot replace subscription store")
	}
	return nil
}

func (s *Store) changed() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func publicCopy(sub Subscription) Subscription {
	sub.ID = shortTextN(sub.ID, 128)
	sub.Kind = shortText(sub.Kind)
	sub.Name = shortText(sub.Name)
	sub.Host = shortText(sub.Host)
	sub.Error = shortText(sub.Error)
	sub.Notice = shortTextN(sub.Notice, maxNotice)
	if sub.Debug != nil { // a copy of its own; a request past its time is not shown
		d := *sub.Debug
		if d.Request != nil && d.Request.ExpiresUnix <= time.Now().Unix() {
			d.Request = nil
		} else if d.Request != nil {
			request := *d.Request
			request.ID, request.Level, request.Note = shortTextN(request.ID, 64), shortText(request.Level), shortTextN(request.Note, 300)
			d.Request = &request
		}
		sub.Debug = &d
	}
	if sub.Probe != nil {
		p := *sub.Probe
		sub.Probe = &p
	}
	if sub.ReportLast != nil {
		last := *sub.ReportLast
		last.Error = shortText(last.Error)
		sub.ReportLast = &last
	}
	sub.UnsupportedKinds = maps.Clone(sub.UnsupportedKinds)
	if sub.UnsupportedKinds != nil {
		keys := make([]string, 0, len(sub.UnsupportedKinds))
		for kind, count := range sub.UnsupportedKinds {
			if kindName.MatchString(kind) && count > 0 {
				keys = append(keys, kind)
			}
		}
		slices.Sort(keys)
		kinds := make(map[string]int, min(len(keys), maxKinds))
		for _, kind := range keys[:min(len(keys), maxKinds)] {
			kinds[shortTextN(kind, 40)] = min(sub.UnsupportedKinds[kind], maxBodyBytes)
		}
		sub.UnsupportedKinds = kinds
	}
	sub.Servers = append([]Server(nil), sub.Servers...)
	if sub.Servers == nil {
		sub.Servers = []Server{}
	}
	for i := range sub.Servers {
		server := &sub.Servers[i]
		server.ID = shortTextN(server.ID, 128)
		server.Name, server.Protocol = shortText(server.Name), shortText(server.Protocol)
		server.Node, server.Country, server.City = shortText(server.Node), shortText(server.Country), shortText(server.City)
		server.Via, server.Version, server.Load = shortText(server.Via), shortText(server.Version), shortText(server.Load)
		server.Label, server.NodeLabel = shortText(server.Label), shortText(server.NodeLabel)
		server.ViaCountry = countryCode(server.ViaCountry)
	}
	if sub.Telegram != nil {
		telegram := append([]Telegram(nil), sub.Telegram...)
		if len(telegram) > maxTelegram {
			telegram = telegram[:maxTelegram]
		}
		for i := range telegram {
			telegram[i].Node, telegram[i].City, telegram[i].Via = shortText(telegram[i].Node), shortText(telegram[i].City), shortText(telegram[i].Via)
			telegram[i].Country, telegram[i].ViaCountry = countryCode(telegram[i].Country), countryCode(telegram[i].ViaCountry)
			if !telegramLink(telegram[i].Link) {
				telegram[i].Link = ""
			} else {
				telegram[i].Link = shortTextN(telegram[i].Link, 2048)
			}
		}
		sub.Telegram = telegram
	}
	if len(sub.Servers) > 0 {
		servers := sub.Servers
		low, high := 0, len(servers)
		for low < high {
			mid := low + (high-low+1)/2
			sub.Servers = servers[:mid]
			encoded, _ := json.Marshal(sub)
			if len(encoded) <= maxPublicSubscriptionBytes {
				low = mid
			} else {
				high = mid - 1
			}
		}
		sub.Servers = servers[:low]
	}
	return sub
}

func cloneState(state diskState) diskState {
	copyState := diskState{InstallID: state.InstallID, Hwids: maps.Clone(state.Hwids), Pending: maps.Clone(state.Pending), Subscriptions: make([]storedSubscription, len(state.Subscriptions))}
	for i := range state.Subscriptions {
		copyState.Subscriptions[i] = cloneStored(state.Subscriptions[i])
	}
	return copyState
}

func cloneStored(sub storedSubscription) storedSubscription {
	sub.Subscription = publicCopy(sub.Subscription)
	sub.Entries = append([]storedEntry(nil), sub.Entries...)
	return sub
}
