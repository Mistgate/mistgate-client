package geo

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
)

type Selection struct {
	Collections []string `json:"collections"`
	Sites       []string `json:"sites"`
}

type Rules struct {
	Direct Selection `json:"direct"`
	VPN    Selection `json:"vpn"`
}

type SiteCollection struct {
	ID          string `json:"id"`
	Available   bool   `json:"available"`
	Entries     int    `json:"entries"`
	UpdatedUnix int64  `json:"updated_unix"`
}

type SiteRules struct {
	Direct    *SiteSet
	VPN       *SiteSet
	HasDirect bool
	HasVPN    bool
}

var ErrBadRules = errors.New("bad route rules")

func emptySelection() Selection {
	return Selection{Collections: []string{}, Sites: []string{}}
}

func (s *Store) loadRules() {
	s.rules = Rules{Direct: emptySelection(), VPN: emptySelection()}
	data, err := os.ReadFile(s.routesPath)
	if err != nil {
		return
	}
	var rules Rules
	if json.Unmarshal(data, &rules) != nil {
		return
	}
	if rules, err = normalizeRules(rules); err == nil {
		s.rules = rules
	}
}

func (s *Store) GetRules() Rules {
	if s == nil {
		return Rules{Direct: emptySelection(), VPN: emptySelection()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRules(s.rules)
}

func (s *Store) SetRules(rules Rules) (Rules, bool, error) {
	if s == nil {
		return Rules{}, false, errors.New("route rules store unavailable")
	}
	normalized, err := normalizeRules(rules)
	if err != nil {
		return s.GetRules(), false, err
	}
	s.mu.Lock()
	if sameRules(s.rules, normalized) {
		current := cloneRules(s.rules)
		s.mu.Unlock()
		return current, false, nil
	}
	data, err := json.Marshal(normalized)
	if err == nil {
		err = writeAtomic(s.routesPath, data)
	}
	if err != nil {
		current := cloneRules(s.rules)
		s.mu.Unlock()
		return current, false, errors.New("cannot save route rules")
	}
	s.rules = normalized
	s.mu.Unlock()
	s.rebuildSiteRules()
	s.signalChange()
	return cloneRules(normalized), true, nil
}

func (s *Store) ActiveSiteRules() *SiteRules {
	if s == nil {
		return nil
	}
	return s.siteRules.Load()
}

func (s *Store) rebuildSiteRules() {
	s.rulesCompileMu.Lock()
	defer s.rulesCompileMu.Unlock()
	rules := s.GetRules()
	direct := &SiteSet{domains: make(map[string]struct{})}
	vpn := &SiteSet{domains: make(map[string]struct{})}
	add := func(target *SiteSet, selection Selection) {
		for _, domain := range selection.Sites {
			target.add(domain)
		}
		for _, collection := range selection.Collections {
			if set, ok := s.Sites(collection); ok {
				for domain := range set.domains {
					target.add(domain)
				}
			}
		}
	}
	add(direct, rules.Direct)
	add(vpn, rules.VPN)
	s.siteRules.Store(&SiteRules{
		Direct:    direct,
		VPN:       vpn,
		HasDirect: len(rules.Direct.Collections)+len(rules.Direct.Sites) != 0,
		HasVPN:    len(rules.VPN.Collections)+len(rules.VPN.Sites) != 0,
	})
}

func (s *Store) signalChange() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func normalizeRules(rules Rules) (Rules, error) {
	direct, err := normalizeSelection(rules.Direct)
	if err != nil {
		return Rules{}, err
	}
	vpn, err := normalizeSelection(rules.VPN)
	if err != nil {
		return Rules{}, err
	}
	return Rules{Direct: direct, VPN: vpn}, nil
}

func normalizeSelection(selection Selection) (Selection, error) {
	if len(selection.Collections) > 200 || len(selection.Sites) > 500 {
		return Selection{}, ErrBadRules
	}
	collections := make([]string, 0, len(selection.Collections))
	seen := make(map[string]struct{}, len(selection.Collections))
	for _, collection := range selection.Collections {
		if _, _, ok := siteCachePath("", collection); !ok {
			return Selection{}, ErrBadRules
		}
		if _, ok := seen[collection]; !ok {
			seen[collection] = struct{}{}
			collections = append(collections, collection)
		}
	}
	sites := make([]string, 0, len(selection.Sites))
	seen = make(map[string]struct{}, len(selection.Sites))
	for _, site := range selection.Sites {
		domain, ok := normalizeUserSite(site)
		if !ok {
			return Selection{}, ErrBadRules
		}
		if _, ok := seen[domain]; !ok {
			seen[domain] = struct{}{}
			sites = append(sites, domain)
		}
	}
	return Selection{Collections: collections, Sites: sites}, nil
}

func normalizeUserSite(value string) (string, bool) {
	if strings.TrimSpace(value) != value {
		return "", false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" {
			return "", false
		}
		value = parsed.Hostname()
	}
	return normalizeSiteDomain(value)
}

func cloneRules(rules Rules) Rules {
	return Rules{
		Direct: Selection{Collections: append([]string{}, rules.Direct.Collections...), Sites: append([]string{}, rules.Direct.Sites...)},
		VPN:    Selection{Collections: append([]string{}, rules.VPN.Collections...), Sites: append([]string{}, rules.VPN.Sites...)},
	}
}

func sameRules(a, b Rules) bool {
	return sameStrings(a.Direct.Collections, b.Direct.Collections) && sameStrings(a.Direct.Sites, b.Direct.Sites) &&
		sameStrings(a.VPN.Collections, b.VPN.Collections) && sameStrings(a.VPN.Sites, b.VPN.Sites)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ruleCollections(rules Rules) []string {
	seen := make(map[string]struct{}, len(rules.Direct.Collections)+len(rules.VPN.Collections))
	collections := make([]string, 0, len(seen))
	for _, collection := range append(append([]string(nil), rules.Direct.Collections...), rules.VPN.Collections...) {
		if _, ok := seen[collection]; !ok {
			seen[collection] = struct{}{}
			collections = append(collections, collection)
		}
	}
	return collections
}
