package geo

import (
	"net/netip"
	"slices"
	"strings"
)

// What the site rules alone say about a name.
type RuleVerdict uint8

const (
	NoRule RuleVerdict = iota
	RuleDirect
	RuleVPN
	RuleBlock
)

// ByName is the name half of every routing decision (flows and DNS questions use it alike). Block wins; then smart reads
// only the direct sites and selected only the VPN sites. Other modes have no forwarder, so no rule applies.
// ponytail: blocking in "all" needs the forwarder path for DNS only (Hysteria2 already has the bridge there; AmneziaWG
// is native); upgrade = run the bridge for DNS in "all" and let this return RuleBlock for that mode.
func (r *SiteRules) ByName(mode, name string) RuleVerdict {
	if r == nil || mode != "smart" && mode != "selected" {
		return NoRule
	}
	// Len first: an empty set cannot match, and Match would normalise the name for nothing.
	if r.Block.Len() != 0 && r.Block.Match(name) {
		return RuleBlock
	}
	if mode == "smart" && r.Direct.Len() != 0 && r.Direct.Match(name) {
		return RuleDirect
	}
	if mode == "selected" && r.VPN.Len() != 0 && r.VPN.Match(name) {
		return RuleVPN
	}
	return NoRule
}

// The routes of DecideName and Check.Route, and the reasons of DecideName.
const (
	NameDirect = "direct"
	NameVPN    = "vpn"
	NameBlock  = "block"

	byMode    = "mode"
	byRules   = "rules" // Check splits it into site and collection
	byRegion  = "region"
	byDefault = "default"
)

// DecideName is what the forwarder decides for a host name alone, without an address. In smart mode "vpn by default"
// only means that no name rule applies: the address of the flow still decides there.
func DecideName(name, mode, region string, rules *SiteRules) (route, by string) {
	if mode != "smart" && mode != "selected" {
		return NameVPN, byMode
	}
	switch rules.ByName(mode, name) {
	case RuleBlock:
		return NameBlock, byRules
	case RuleDirect:
		return NameDirect, byRules
	case RuleVPN:
		return NameVPN, byRules
	}
	if mode == "selected" {
		return NameDirect, byDefault
	}
	if RegionTLD(region, name) {
		return NameDirect, byRegion
	}
	return NameVPN, byDefault
}

type regionInfo struct {
	resolvers []netip.Addr
	tlds      []string // punycode and UTF-8 forms
}

var ruResolvers = []netip.Addr{netip.MustParseAddr("77.88.8.8"), netip.MustParseAddr("77.88.8.1")}

var regionTable = map[string]regionInfo{
	"ru": {ruResolvers, []string{"ru", "su", "xn--p1ai", "xn--80adxhks", "xn--d1acj3b", "рф", "москва", "дети"}},
	// ponytail: no well-known public resolver inside the country; the panel's split entry replaces this
	"by": {ruResolvers, []string{"by", "xn--90ais", "бел"}},
	"cn": {[]netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("119.29.29.29")}, []string{"cn", "xn--fiqs8s", "中国"}},
	"ir": {nil, []string{"ir"}},
}

// RegionTLD reports whether a lower-case name is under one of the region's own top-level domains.
func RegionTLD(region, name string) bool {
	info, ok := regionTable[region]
	if !ok {
		return false
	}
	tld := name
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		tld = name[dot+1:]
	}
	return slices.Contains(info.tlds, tld)
}

// RegionResolvers are the public resolvers inside a region; none when the table has none.
func RegionResolvers(region string) []netip.Addr { return regionTable[region].resolvers }

// Check is the answer of routes.check.
type Check struct {
	Route string `json:"route"` // direct, vpn or block
	By    string `json:"by"`    // mode, site, collection, region or default
	Rule  string `json:"rule"`  // the site entry or collection id that matched; empty otherwise
	DNS   string `json:"dns"`   // where the question about the name goes: direct or vpn (a blocked one is answered here)
}

// CheckName decides for a name now by the same code as the flows; resolver says that a direct resolver is known.
func (s *Store) CheckName(mode, region, name string, resolver bool) Check {
	route, by := DecideName(name, mode, region, s.ActiveSiteRules())
	check := Check{Route: route, By: by, DNS: NameVPN}
	if by == byRules {
		check.By, check.Rule = s.matching(route, name)
	}
	if route == NameDirect && resolver {
		check.DNS = NameDirect
	}
	return check
}

// matching names the entry of the side's selection that matched: a site entry first, else a collection.
func (s *Store) matching(route, name string) (by, rule string) {
	rules := s.GetRules()
	selection := rules.Direct
	switch route {
	case NameBlock:
		selection = rules.Block
	case NameVPN:
		selection = rules.VPN
	}
	for _, site := range selection.Sites {
		if name == site || strings.HasSuffix(name, "."+site) {
			return "site", site
		}
	}
	for _, collection := range selection.Collections {
		if set, ok := s.siteSet(collection); ok && set.Match(name) {
			return "collection", collection
		}
	}
	return "site", "" // the lists changed between the decision and this look
}
