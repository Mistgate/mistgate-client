package geo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// nameStore is a store with one collection per side cached on disk (so nothing is fetched).
func nameStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geo", "site-adlist.list"), []byte("+.tracker.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetRules(Rules{
		Direct: Selection{Sites: []string{"direct.example", "both.example"}},
		VPN:    Selection{Sites: []string{"vpn.example"}},
		Block:  Selection{Sites: []string{"ads.example", "both.example"}, Collections: []string{"geosite:adlist"}},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDecideNameTable(t *testing.T) {
	rules := nameStore(t).ActiveSiteRules()
	tests := []struct {
		mode, region, name string
		route, by          string
	}{
		{"all", "ru", "ads.example", NameVPN, "mode"}, // block does nothing without a forwarder
		{"all", "ru", "yandex.ru", NameVPN, "mode"},
		{"smart", "ru", "ads.example", NameBlock, "rules"},
		{"smart", "ru", "x.ads.example", NameBlock, "rules"},
		{"smart", "", "ads.example", NameBlock, "rules"},
		{"smart", "ru", "tracker.example", NameBlock, "rules"}, // from a collection
		{"smart", "ru", "both.example", NameBlock, "rules"},    // block wins over direct
		{"smart", "ru", "direct.example", NameDirect, "rules"},
		{"smart", "ru", "a.direct.example", NameDirect, "rules"},
		{"smart", "ru", "yandex.ru", NameDirect, "region"},
		{"smart", "ru", "a.b.su", NameDirect, "region"},
		{"smart", "ru", "xn--80ak6aa92e.xn--p1ai", NameDirect, "region"},
		{"smart", "ru", "пример.рф", NameDirect, "region"},
		{"smart", "ru", "example.com", NameVPN, "default"},
		{"smart", "ru", "notru", NameVPN, "default"},
		{"smart", "ru", "ru.example.com", NameVPN, "default"}, // only the last label counts
		{"smart", "ru", "vpn.example", NameVPN, "default"},    // smart reads no VPN rules
		{"smart", "", "yandex.ru", NameVPN, "default"},        // no region
		{"smart", "kz", "mail.ru", NameVPN, "default"},        // a region the table does not know
		{"smart", "by", "tut.by", NameDirect, "region"},
		{"smart", "by", "yandex.ru", NameVPN, "default"},
		{"smart", "cn", "baidu.cn", NameDirect, "region"},
		{"smart", "cn", "x.xn--fiqs8s", NameDirect, "region"},
		{"smart", "cn", "yandex.ru", NameVPN, "default"},
		{"smart", "ir", "x.ir", NameDirect, "region"},
		{"selected", "", "example.com", NameDirect, "default"},
		{"selected", "", "vpn.example", NameVPN, "rules"},
		{"selected", "", "sub.vpn.example", NameVPN, "rules"},
		{"selected", "", "ads.example", NameBlock, "rules"},
		{"selected", "", "direct.example", NameDirect, "default"}, // selected reads no direct rules
		{"selected", "ru", "yandex.ru", NameDirect, "default"},
	}
	for _, test := range tests {
		route, by := DecideName(test.name, test.mode, test.region, rules)
		if route != test.route || by != test.by {
			t.Errorf("DecideName(%q, %s, %q) = %s, %s; want %s, %s", test.name, test.mode, test.region, route, by, test.route, test.by)
		}
	}
	if route, by := DecideName("anything.example", "smart", "ru", nil); route != NameVPN || by != "default" {
		t.Errorf("no rules at all: %s, %s", route, by)
	}
	if route, by := DecideName("anything.ru", "smart", "ru", nil); route != NameDirect || by != "region" {
		t.Errorf("region without rules: %s, %s", route, by)
	}
}

func TestByNameDoesNotAllocateForRegionAndEmptySets(t *testing.T) {
	rules := nameStore(t).ActiveSiteRules()
	if allocs := testing.AllocsPerRun(100, func() { _, _ = DecideName("www.example.com", "smart", "ru", rules) }); allocs != 0 {
		t.Fatalf("DecideName allocates %v times for a lower-case name", allocs)
	}
}

func TestCheckNameSaysWhyAndWhere(t *testing.T) {
	store := nameStore(t)
	tests := []struct {
		mode, region, name string
		resolver           bool
		want               Check
	}{
		{"all", "ru", "ads.example", true, Check{"vpn", "mode", "", "vpn"}},
		{"smart", "ru", "sub.ads.example", true, Check{"block", "site", "ads.example", "vpn"}},
		{"smart", "ru", "a.tracker.example", true, Check{"block", "collection", "geosite:adlist", "vpn"}},
		{"smart", "ru", "both.example", false, Check{"block", "site", "both.example", "vpn"}},
		{"smart", "ru", "direct.example", true, Check{"direct", "site", "direct.example", "direct"}},
		{"smart", "ru", "direct.example", false, Check{"direct", "site", "direct.example", "vpn"}},
		{"smart", "ru", "yandex.ru", true, Check{"direct", "region", "", "direct"}},
		{"smart", "ru", "yandex.ru", false, Check{"direct", "region", "", "vpn"}},
		{"smart", "ru", "example.com", true, Check{"vpn", "default", "", "vpn"}},
		{"selected", "", "vpn.example", true, Check{"vpn", "site", "vpn.example", "vpn"}},
		{"selected", "ru", "example.com", true, Check{"direct", "default", "", "direct"}},
		{"selected", "", "example.com", false, Check{"direct", "default", "", "vpn"}},
	}
	for _, test := range tests {
		if got := store.CheckName(test.mode, test.region, test.name, test.resolver); got != test.want {
			t.Errorf("CheckName(%s, %q, %q, %t) = %+v; want %+v", test.mode, test.region, test.name, test.resolver, got, test.want)
		}
	}
	// a collection on the direct side is named too
	dir := t.TempDir()
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geo", "site-local.list"), []byte("+.local.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.SetRules(Rules{Direct: Selection{Collections: []string{"geosite:local"}}}); err != nil {
		t.Fatal(err)
	}
	if got := other.CheckName("smart", "", "a.local.example", false); got != (Check{"direct", "collection", "geosite:local", "vpn"}) {
		t.Errorf("direct collection: %+v", got)
	}
}

func TestBlockRulesAreStoredValidatedAndReported(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geo", "site-adlist.list"), []byte("tracker.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules, changed, err := store.SetRules(Rules{
		Direct: emptySelection(), VPN: emptySelection(),
		Block: Selection{Sites: []string{"https://Ads.Example/x", "ads.example"}, Collections: []string{"geosite:adlist"}},
	})
	if err != nil || !changed || len(rules.Block.Sites) != 1 || rules.Block.Sites[0] != "ads.example" || len(rules.Block.Collections) != 1 {
		t.Fatalf("SetRules = %+v, %t, %v", rules, changed, err)
	}
	for _, bad := range []Selection{{Sites: []string{"a b"}}, {Collections: []string{"geosite:Bad"}}, {Sites: make([]string, 501)}, {Collections: make([]string, 201)}} {
		if _, _, err := store.SetRules(Rules{Block: bad}); err != ErrBadRules {
			t.Errorf("block %+v: err = %v; want ErrBadRules", bad, err)
		}
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.GetRules().Block; len(got.Sites) != 1 || got.Sites[0] != "ads.example" || len(got.Collections) != 1 {
		t.Fatalf("reopened block = %+v", got)
	}
	if !reopened.ActiveSiteRules().HasBlock || reopened.ActiveSiteRules().ByName("smart", "x.tracker.example") != RuleBlock {
		t.Fatal("reopened store does not block")
	}

	smart, all := reopened.Routes("smart", "", ""), reopened.Routes("all", "", "")
	if !smart.BlockActive || all.BlockActive || !reopened.Routes("selected", "", "").BlockActive {
		t.Fatalf("block_active: smart %t, all %t", smart.BlockActive, all.BlockActive)
	}
	if len(smart.Rules.Block.Sites) != 1 || len(smart.Collections) != 1 || smart.Collections[0].ID != "geosite:adlist" || !smart.Collections[0].Available {
		t.Fatalf("routes: block %+v, collections %+v", smart.Rules.Block, smart.Collections)
	}
}

func TestRoutesFileWithoutBlockStillLoads(t *testing.T) {
	dir := t.TempDir()
	old := `{"direct":{"collections":[],"sites":["a.example"]},"vpn":{"collections":[],"sites":[]}}`
	if err := os.WriteFile(filepath.Join(dir, "routes.json"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules := store.GetRules()
	if len(rules.Direct.Sites) != 1 || rules.Block.Sites == nil || rules.Block.Collections == nil || len(rules.Block.Sites) != 0 {
		t.Fatalf("rules = %+v", rules)
	}
}

// normalizeSiteDomain no longer splits the name; it must agree with the version that did.
func TestNormalizeSiteDomainKeepsItsAnswers(t *testing.T) {
	reference := func(value string) (string, bool) {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if value == "" || len(value) > 253 || strings.ContainsAny(value, " /:\\?#@") {
			return "", false
		}
		for _, label := range strings.Split(value, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", false
			}
			for _, r := range label {
				if r == '-' || r >= '0' && r <= '9' || unicode.IsLetter(r) {
					continue
				}
				return "", false
			}
		}
		return value, true
	}
	for _, value := range []string{
		"example.com", "Example.COM", "example.com.", "example.com..", ".", "..", ".a", "a.", "a..b", "a.b.", "-a.com", "a-.com", "a-b.com",
		"a_b.com", "пример.рф", "ПРИМЕР.РФ", "exa mple.com", "a/b", "a:80", "a@b", "", "xn--p1ai", "1.2.3.4", strings.Repeat("a", 63) + ".com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 127) + "a",
	} {
		wantName, wantOK := reference(value)
		gotName, gotOK := normalizeSiteDomain(value)
		if gotName != wantName || gotOK != wantOK {
			t.Errorf("normalizeSiteDomain(%q) = %q, %t; want %q, %t", value, gotName, gotOK, wantName, wantOK)
		}
	}
}
