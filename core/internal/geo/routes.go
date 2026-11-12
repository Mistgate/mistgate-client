package geo

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxApps    = 200 // programs per selection
	maxAppPath = 512 // bytes of one path
)

type Selection struct {
	Collections []string `json:"collections"`
	Sites       []string `json:"sites"`
	// Apps are full paths of programs (lower case, backslashes), whose connections follow the selection. Not for block.
	Apps []string `json:"apps"`
}

type Rules struct {
	Direct Selection `json:"direct"`
	VPN    Selection `json:"vpn"`
	Block  Selection `json:"block"`
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
	Block     *SiteSet
	HasDirect bool
	HasVPN    bool
	HasBlock  bool
	// Programs by normalised path. Only the direct set counts in smart and only the VPN set in selected.
	DirectApps map[string]struct{}
	VPNApps    map[string]struct{}
}

var ErrBadRules = errors.New("bad route rules")

func emptySelection() Selection {
	return Selection{Collections: []string{}, Sites: []string{}, Apps: []string{}}
}

func emptyRules() Rules {
	return Rules{Direct: emptySelection(), VPN: emptySelection(), Block: emptySelection()}
}

func (s *Store) loadRules() {
	s.rules = emptyRules()
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
		return emptyRules()
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
	// a list the rules no longer name is let go: it can be megabytes
	named := make(map[string]bool)
	for _, collection := range ruleCollections(normalized) {
		named[collection] = true
	}
	for collection := range s.siteSets {
		if !named[collection] {
			delete(s.siteSets, collection)
			delete(s.siteLoaded, collection)
			delete(s.errs, collection)
		}
	}
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
	block := &SiteSet{domains: make(map[string]struct{})}
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
	add(block, rules.Block)
	s.siteRules.Store(&SiteRules{
		Direct:     direct,
		VPN:        vpn,
		Block:      block,
		HasDirect:  len(rules.Direct.Collections)+len(rules.Direct.Sites) != 0,
		HasVPN:     len(rules.VPN.Collections)+len(rules.VPN.Sites) != 0,
		HasBlock:   len(rules.Block.Collections)+len(rules.Block.Sites) != 0,
		DirectApps: appSet(rules.Direct.Apps),
		VPNApps:    appSet(rules.VPN.Apps),
	})
}

func appSet(paths []string) map[string]struct{} {
	set := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		set[path] = struct{}{}
	}
	return set
}

func (s *Store) signalChange() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func normalizeRules(rules Rules) (Rules, error) {
	direct, err := normalizeSelection(rules.Direct, true)
	if err != nil {
		return Rules{}, err
	}
	vpn, err := normalizeSelection(rules.VPN, true)
	if err != nil {
		return Rules{}, err
	}
	block, err := normalizeSelection(rules.Block, false)
	if err != nil {
		return Rules{}, err
	}
	return Rules{Direct: direct, VPN: vpn, Block: block}, nil
}

func normalizeSelection(selection Selection, allowApps bool) (Selection, error) {
	if len(selection.Collections) > 200 || len(selection.Sites) > 500 || len(selection.Apps) > maxApps || len(selection.Apps) != 0 && !allowApps {
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
	apps := make([]string, 0, len(selection.Apps))
	seen = make(map[string]struct{}, len(selection.Apps))
	for _, app := range selection.Apps {
		path, ok := normalizeAppPath(app)
		if !ok {
			return Selection{}, ErrBadRules
		}
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			apps = append(apps, path)
		}
	}
	slices.Sort(apps)
	return Selection{Collections: collections, Sites: sites, Apps: apps}, nil
}

// normalizeAppPath accepts the full path of an exe on a drive letter and returns it in the form flows are compared in
// (lower case, backslashes). The path comes from the window, so everything a file name cannot hold is refused.
func normalizeAppPath(value string) (string, bool) {
	if len(value) > maxAppPath || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) || strings.ContainsAny(value, `<>"|?*`) {
		return "", false
	}
	path := strings.ReplaceAll(strings.ToLower(value), "/", `\`)
	if len(path) < 8 || path[0] < 'a' || path[0] > 'z' || path[1] != ':' || path[2] != '\\' || !strings.HasSuffix(path, ".exe") { // 8 = the shortest, c:\a.exe
		return "", false
	}
	parts := strings.Split(path[3:], `\`)
	for i, part := range parts {
		// no empty or dot parts, no stream (":") and no trailing dot or space, which Windows would drop silently
		if part == "" || part == "." || part == ".." || strings.Contains(part, ":") || strings.HasSuffix(part, " ") || i < len(parts)-1 && strings.HasSuffix(part, ".") {
			return "", false
		}
	}
	if parts[len(parts)-1] == ".exe" {
		return "", false
	}
	return path, true
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
		Direct: cloneSelection(rules.Direct),
		VPN:    cloneSelection(rules.VPN),
		Block:  cloneSelection(rules.Block),
	}
}

func cloneSelection(s Selection) Selection {
	return Selection{Collections: append([]string{}, s.Collections...), Sites: append([]string{}, s.Sites...), Apps: append([]string{}, s.Apps...)}
}

func sameRules(a, b Rules) bool {
	return sameSelection(a.Direct, b.Direct) && sameSelection(a.VPN, b.VPN) && sameSelection(a.Block, b.Block)
}

func sameSelection(a, b Selection) bool {
	return sameStrings(a.Collections, b.Collections) && sameStrings(a.Sites, b.Sites) && sameStrings(a.Apps, b.Apps)
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
	seen := make(map[string]struct{}, len(rules.Direct.Collections)+len(rules.VPN.Collections)+len(rules.Block.Collections))
	collections := make([]string, 0, len(seen))
	for _, collection := range slices.Concat(rules.Direct.Collections, rules.VPN.Collections, rules.Block.Collections) {
		if _, ok := seen[collection]; !ok {
			seen[collection] = struct{}{}
			collections = append(collections, collection)
		}
	}
	return collections
}
