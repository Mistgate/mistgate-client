package geo

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Route is the path the forwarder gave a flow.
type Route uint8

const (
	ViaDirect Route = iota
	ViaVPN
)

const (
	suggestFailures  = 3                // confirmed failures before a site is offered
	suggestWindow    = 24 * time.Hour   // older failures are forgotten
	suggestRecentOK  = 60 * time.Second // a failure counts at once if the route worked this recently
	suggestSettle    = 15 * time.Second // ... or if it works within this long after
	suggestTracked   = 200
	suggestPerRoute  = 10
	suggestPending   = 64
	suggestFailKeep  = 16
	suggestDismissed = 500
)

type SuggestSite struct {
	Site  string `json:"site"`
	Count int    `json:"count"`
}

// Suggest lists the sites worth moving: VPN = fail direct, Direct = fail through the VPN.
type Suggest struct {
	VPN    []SuggestSite `json:"vpn"`
	Direct []SuggestSite `json:"direct"`
}

type suggestKey struct {
	route Route
	site  string
}

type pendingFail struct {
	site string
	at   time.Time
}

// Tracker remembers the sites that failed on the route they were given. Names are the user's browsing: they stay
// in this struct (never logged, never written to disk) and leave only through List.
type Tracker struct {
	mu        sync.Mutex
	fixed     func(site string, toVPN bool) bool
	lastOK    [2]time.Time
	pending   [2][]pendingFail // failures waiting for a success on their route
	fails     map[suggestKey][]time.Time
	dismissed map[suggestKey]struct{}
}

// newTracker: fixed says that the user's rules already settle the site, so it is not offered.
func newTracker(fixed func(site string, toVPN bool) bool) *Tracker {
	return &Tracker{fixed: fixed, fails: make(map[suggestKey][]time.Time), dismissed: make(map[suggestKey]struct{})}
}

// registrable is the site's key; name must be lower case. IP literals and single labels have none.
func registrable(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 || strings.Trim(name[dot+1:], "0123456789") == "" {
		return ""
	}
	site, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return site
}

// Fail reports a flow that did not work on its route. It counts only while the route works for other sites.
func (t *Tracker) Fail(route Route, name string, now time.Time) {
	site := registrable(name)
	if site == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok := t.lastOK[route]; !ok.IsZero() && now.Sub(ok) <= suggestRecentOK {
		t.confirm(route, site, now)
		return
	}
	p := t.pending[route]
	for len(p) > 0 && now.Sub(p[0].at) > suggestSettle {
		p = p[1:]
	}
	if len(p) == suggestPending {
		p = p[1:]
	}
	t.pending[route] = append(p, pendingFail{site, now})
}

// OK reports a flow that got an answer. On the common path (nothing tracked) it only stamps the time.
func (t *Tracker) OK(route Route, name string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastOK[route] = now
	if len(t.fails) == 0 && len(t.pending[route]) == 0 {
		return
	}
	// Keys are registrable domains, so deleting every suffix of the name finds the key without a suffix-list lookup.
	for rest := name; ; {
		delete(t.fails, suggestKey{route, rest})
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	for _, f := range t.pending[route] {
		if !under(name, f.site) && now.Sub(f.at) <= suggestSettle {
			t.confirm(route, f.site, f.at)
		}
	}
	t.pending[route] = t.pending[route][:0]
}

// under: name is site or a name below it.
func under(name, site string) bool {
	cut := len(name) - len(site)
	return cut == 0 && name == site || cut > 0 && name[cut-1] == '.' && name[cut:] == site
}

func (t *Tracker) confirm(route Route, site string, at time.Time) {
	key := suggestKey{route, site}
	if _, off := t.dismissed[key]; off {
		return
	}
	f, exists := t.fails[key]
	if !exists && len(t.fails) >= suggestTracked {
		t.dropOldest()
	}
	if len(f) == suggestFailKeep {
		f = f[1:]
	}
	t.fails[key] = append(f, at)
}

func (t *Tracker) dropOldest() {
	var oldest suggestKey
	var oldestAt time.Time
	for key, f := range t.fails {
		if last := slices.MaxFunc(f, time.Time.Compare); oldestAt.IsZero() || last.Before(oldestAt) {
			oldest, oldestAt = key, last
		}
	}
	delete(t.fails, oldest)
}

// Dismiss forgets the site and keeps it out of the list until the service stops. toVPN names the list it was in.
func (t *Tracker) Dismiss(toVPN bool, site string) {
	route := ViaDirect
	if !toVPN {
		route = ViaVPN
	}
	key := suggestKey{route, registrable(site)}
	if key.site == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, key)
	if len(t.dismissed) < suggestDismissed {
		t.dismissed[key] = struct{}{}
	}
}

// List returns the sites that failed enough, most failures first, at most suggestPerRoute per list.
func (t *Tracker) List(now time.Time) Suggest {
	out := Suggest{VPN: []SuggestSite{}, Direct: []SuggestSite{}}
	var candidates []suggestKey
	counts := map[suggestKey]int{}
	t.mu.Lock()
	for key, f := range t.fails {
		f = slices.DeleteFunc(f, func(at time.Time) bool { return now.Sub(at) >= suggestWindow })
		if len(f) == 0 {
			delete(t.fails, key)
			continue
		}
		t.fails[key] = f
		if _, off := t.dismissed[key]; !off && len(f) >= suggestFailures {
			candidates = append(candidates, key)
			counts[key] = len(f)
		}
	}
	t.mu.Unlock()
	// The rules are asked outside the lock: this one sits on the path of every flow.
	for _, key := range candidates {
		toVPN := key.route == ViaDirect
		if t.fixed != nil && t.fixed(key.site, toVPN) {
			continue
		}
		if toVPN {
			out.VPN = append(out.VPN, SuggestSite{key.site, counts[key]})
		} else {
			out.Direct = append(out.Direct, SuggestSite{key.site, counts[key]})
		}
	}
	for _, list := range []*[]SuggestSite{&out.VPN, &out.Direct} {
		slices.SortFunc(*list, func(a, b SuggestSite) int { return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Site, b.Site)) })
		*list = (*list)[:min(len(*list), suggestPerRoute)]
	}
	return out
}

// Failures is where the forwarder reports flows that did not open.
func (s *Store) Failures() *Tracker {
	if s == nil {
		return nil
	}
	return s.suggest
}

// Dismiss forgets a suggested site; false if the site is not a valid name.
func (s *Store) Dismiss(toVPN bool, site string) bool {
	site, ok := normalizeSiteDomain(site)
	if !ok || s == nil {
		return false
	}
	s.suggest.Dismiss(toVPN, site)
	return true
}

// fixed: the user already decided the site, either by listing it (or a name under it, or above it) in a sites list,
// or by a list on the side it would move to. Collections on the other side may be overridden.
func (s *Store) fixed(site string, toVPN bool) bool {
	rules := s.GetRules()
	for _, selection := range [...]Selection{rules.Direct, rules.VPN} {
		for _, listed := range selection.Sites {
			if listed == site || strings.HasSuffix(site, "."+listed) || strings.HasSuffix(listed, "."+site) {
				return true
			}
		}
	}
	active := s.ActiveSiteRules()
	if active == nil {
		return false
	}
	if toVPN {
		return active.VPN.Match(site)
	}
	return active.Direct.Match(site)
}
