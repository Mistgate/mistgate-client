package geo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxFileBytes = 8 << 20
	minPrefixes  = 100
	maxAge       = 24 * time.Hour
	fetchTimeout = 20 * time.Second
)

type ipRange struct{ first, last uint32 }

type Set struct {
	ranges   []ipRange
	prefixes int
}

func (s *Set) Contains(address netip.Addr) bool {
	if s == nil || !address.Is4() {
		return false
	}
	raw := address.As4()
	value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].last >= value })
	return i < len(s.ranges) && s.ranges[i].first <= value
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ranges)
}

func (s *Set) PrefixCount() int {
	if s == nil {
		return 0
	}
	return s.prefixes
}

func (s *Set) sameRanges(other *Set) bool {
	if s == nil || other == nil || len(s.ranges) != len(other.ranges) {
		return s == other
	}
	for i := range s.ranges {
		if s.ranges[i] != other.ranges[i] {
			return false
		}
	}
	return true
}

func parse(data []byte) (*Set, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	ranges := make([]ipRange, 0)
	valid := 0
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR on line %d", lineNo)
		}
		if !prefix.Addr().Is4() {
			continue
		}
		valid++
		prefix = prefix.Masked()
		raw := prefix.Addr().As4()
		base := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		mask := ^uint32(0)
		if prefix.Bits() == 0 {
			mask = 0
		} else {
			mask <<= 32 - prefix.Bits()
		}
		first := base & mask
		ranges = append(ranges, ipRange{first: first, last: first | ^mask})
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("geo list is too large or unreadable")
	}
	if valid < minPrefixes {
		return nil, errors.New("geo list has too few IPv4 prefixes")
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].first == ranges[j].first {
			return ranges[i].last < ranges[j].last
		}
		return ranges[i].first < ranges[j].first
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if current.first <= last.last || last.last != ^uint32(0) && current.first == last.last+1 {
			if current.last > last.last {
				last.last = current.last
			}
			continue
		}
		merged = append(merged, current)
	}
	return &Set{ranges: merged, prefixes: valid}, nil
}

type Routes struct {
	Mode        string           `json:"mode"`
	Region      string           `json:"region"`
	Effective   string           `json:"effective"`
	Available   bool             `json:"available"`
	Entries     int              `json:"entries"`
	UpdatedUnix int64            `json:"updated_unix"`
	Rules       Rules            `json:"rules"`
	BlockActive bool             `json:"block_active"` // names are blocked in smart and selected; "all" has no forwarder
	Collections []SiteCollection `json:"collections"`
	Suggest     Suggest          `json:"suggest"`
	Version     uint64           `json:"-"`
}

type Options struct {
	HTTPClient              *http.Client
	PrimaryURLTemplate      string
	FallbackURLTemplate     string
	SitePrimaryURLTemplate  string
	SiteFallbackURLTemplate string
}

type Store struct {
	dir             string
	routesPath      string
	client          *http.Client
	primaryURL      string
	fallbackURL     string
	sitePrimaryURL  string
	siteFallbackURL string
	mu              sync.Mutex
	sets            map[string]*Set
	versions        map[string]uint64
	loaded          map[string]bool
	refreshing      map[string]bool
	siteSets        map[string]*SiteSet
	siteLoaded      map[string]bool
	siteRefreshing  map[string]bool
	rules           Rules
	rulesCompileMu  sync.Mutex
	siteRules       atomic.Pointer[SiteRules]
	suggest         *Tracker
	changes         chan struct{}
}

func Open(dataDir string, options ...Options) (*Store, error) {
	dir := filepath.Join(dataDir, "geo")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create geo cache directory")
	}
	store := &Store{
		dir:             dir,
		client:          http.DefaultClient,
		primaryURL:      "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/%s.list",
		fallbackURL:     "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/%s.list",
		sitePrimaryURL:  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/%s.list",
		siteFallbackURL: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/%s.list",
		routesPath:      filepath.Join(dataDir, "routes.json"),
		sets:            make(map[string]*Set),
		versions:        make(map[string]uint64),
		loaded:          make(map[string]bool),
		refreshing:      make(map[string]bool),
		siteSets:        make(map[string]*SiteSet),
		siteLoaded:      make(map[string]bool),
		siteRefreshing:  make(map[string]bool),
		changes:         make(chan struct{}, 1),
	}
	if len(options) != 0 {
		option := options[0]
		if option.HTTPClient != nil {
			store.client = option.HTTPClient
		}
		if option.PrimaryURLTemplate != "" {
			store.primaryURL = option.PrimaryURLTemplate
		}
		if option.FallbackURLTemplate != "" {
			store.fallbackURL = option.FallbackURLTemplate
		}
		if option.SitePrimaryURLTemplate != "" {
			store.sitePrimaryURL = option.SitePrimaryURLTemplate
		}
		if option.SiteFallbackURLTemplate != "" {
			store.siteFallbackURL = option.SiteFallbackURLTemplate
		}
	}
	store.suggest = newTracker(store.fixed)
	store.loadRules()
	store.rebuildSiteRules()
	return store, nil
}

func ValidRegion(cc string) bool {
	return len(cc) == 2 && cc[0] >= 'a' && cc[0] <= 'z' && cc[1] >= 'a' && cc[1] <= 'z'
}

func (s *Store) Region(cc string) (*Set, bool) {
	if s == nil || !ValidRegion(cc) {
		return nil, false
	}
	s.mu.Lock()
	if !s.loaded[cc] {
		s.loaded[cc] = true
		path := filepath.Join(s.dir, cc+".list")
		if info, err := os.Stat(path); err == nil && info.Size() <= maxFileBytes {
			if data, err := os.ReadFile(path); err == nil {
				if set, parseErr := parse(data); parseErr == nil {
					s.sets[cc] = set
				}
			}
		}
	}
	set := s.sets[cc]
	info, statErr := os.Stat(filepath.Join(s.dir, cc+".list"))
	stale := statErr != nil || time.Since(info.ModTime()) >= maxAge
	if stale && !s.refreshing[cc] {
		s.refreshing[cc] = true
		go s.refresh(cc)
	}
	s.mu.Unlock()
	return set, set != nil
}

func (s *Store) Detect(public netip.Addr, candidates []string) string {
	if !public.Is4() {
		return ""
	}
	for _, cc := range candidates {
		if set, ok := s.Region(cc); ok && set.Contains(public) {
			return cc
		}
	}
	return ""
}

func (s *Store) Changes() <-chan struct{} { return s.changes }

func (s *Store) Routes(mode, region, autoRegion string) Routes {
	if mode != "smart" && mode != "selected" {
		mode = "all"
	}
	if region == "" {
		region = "auto"
	}
	effective := "none"
	if mode == "selected" {
		effective = "selected"
	} else if mode == "smart" {
		effective = region
		if region == "auto" {
			effective = autoRegion
		}
		if effective == "" || effective == "auto" || effective == "none" || !ValidRegion(effective) {
			effective = "none"
		}
	}
	routes := Routes{Mode: mode, Region: region, Effective: effective, Rules: emptyRules(), BlockActive: mode != "all", Collections: []SiteCollection{}, Suggest: Suggest{VPN: []SuggestSite{}, Direct: []SuggestSite{}}}
	if s == nil {
		return routes
	}
	if mode != "all" {
		routes.Suggest = s.suggest.List(time.Now())
	}
	routes.Rules = s.GetRules()
	for _, collection := range ruleCollections(routes.Rules) {
		_, _ = s.Sites(collection)
		set, available := s.siteSet(collection)
		item := SiteCollection{ID: collection, Available: available}
		if set != nil {
			item.Entries = set.Len()
		}
		if info, err := os.Stat(s.sitePath(collection)); err == nil {
			item.UpdatedUnix = info.ModTime().Unix()
		}
		routes.Collections = append(routes.Collections, item)
	}
	if ValidRegion(effective) {
		if mode != "smart" {
			return routes
		}
		_, _ = s.Region(effective)
		s.mu.Lock()
		set := s.sets[effective]
		routes.Version = s.versions[effective]
		s.mu.Unlock()
		if set != nil {
			routes.Available = true
			routes.Entries = set.PrefixCount()
		}
		if info, err := os.Stat(filepath.Join(s.dir, effective+".list")); err == nil {
			routes.UpdatedUnix = info.ModTime().Unix()
		}
	}
	return routes
}

func (s *Store) refresh(cc string) {
	defer func() {
		s.mu.Lock()
		s.refreshing[cc] = false
		s.mu.Unlock()
	}()
	data, set, err := s.fetch(cc)
	if err != nil || writeAtomic(filepath.Join(s.dir, cc+".list"), data) != nil {
		return
	}
	s.mu.Lock()
	if !s.sets[cc].sameRanges(set) {
		s.versions[cc]++
	}
	s.sets[cc] = set
	s.loaded[cc] = true
	s.mu.Unlock()
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func (s *Store) fetch(cc string) ([]byte, *Set, error) {
	for _, template := range []string{s.primaryURL, s.fallbackURL} {
		url := fmt.Sprintf(template, cc)
		parsed, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil || parsed.URL.Scheme != "https" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			continue
		}
		request.Header.Set("User-Agent", "Mistgate/0.0.1")
		client := *s.client
		client.Timeout = fetchTimeout
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return errors.New("invalid geo redirect")
			}
			return nil
		}
		response, err := client.Do(request)
		if err != nil {
			cancel()
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			cancel()
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxFileBytes+1))
		_ = response.Body.Close()
		cancel()
		if readErr != nil || len(data) > maxFileBytes {
			continue
		}
		set, err := parse(data)
		if err == nil {
			return data, set, nil
		}
	}
	return nil, nil, errors.New("geo list unavailable")
}

func writeAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".geo-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
