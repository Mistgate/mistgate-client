package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/geo"
)

func TestDNSMemoryKeepsAliasesForSafeRouting(t *testing.T) {
	store, err := geo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetRules(geo.Rules{
		Direct: geo.Selection{Sites: []string{"plain.example"}},
		VPN:    geo.Selection{Sites: []string{"protected.example"}},
	}); err != nil {
		t.Fatal(err)
	}
	rules := store.ActiveSiteRules()
	address := netip.MustParseAddr("203.0.113.7")
	now := time.Now()
	var memory dnsMemory
	for i := range 6 {
		memory.rememberAddressAt(address, "name"+string(rune('a'+i))+".example", time.Minute, now.Add(time.Duration(i)*time.Second))
	}
	names := memory.lookupNamesAt(address, now.Add(6*time.Second))
	if len(names) != rememberedNamesPerAddress {
		t.Fatalf("remembered names = %d; want %d", len(names), rememberedNamesPerAddress)
	}
	if names[0] != "namec.example" || names[len(names)-1] != "namef.example" {
		t.Fatal("DNS memory did not retain the most recent names")
	}

	memory.rememberAddressAt(address, "protected.example", time.Minute, now.Add(7*time.Second))
	memory.rememberAddressAt(address, "attacker.example", time.Minute, now.Add(8*time.Second))
	selectedNames := memory.lookupNamesAt(address, now.Add(8*time.Second))
	if directByRulesNames(address, "", selectedNames, "selected", nil, rules) {
		t.Fatal("a remembered VPN-listed name was routed directly")
	}
	if directByRulesNames(address, "", []string{"plain.example", "unknown.example"}, "smart", nil, rules) {
		t.Fatal("smart mode routed directly when not every remembered name was direct")
	}
	if !directByRulesNames(address, "", []string{"plain.example"}, "smart", nil, rules) {
		t.Fatal("smart mode did not route directly when every remembered name was direct")
	}
}
