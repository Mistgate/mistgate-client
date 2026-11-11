package subs

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

func addrs(texts ...string) []netip.Addr {
	var out []netip.Addr
	for _, text := range texts {
		out = append(out, netip.MustParseAddr(text))
	}
	return out
}

func TestPlainResolvers(t *testing.T) {
	plain := func(address string, ips ...string) syncResolver {
		return syncResolver{Transport: "plain", Address: address, IPs: ips}
	}
	tests := []struct {
		name    string
		entries []syncResolver
		want    []netip.Addr
	}{
		{"an IP", []syncResolver{plain("1.1.1.1")}, addrs("1.1.1.1")},
		{"an IPv6", []syncResolver{plain("2606:4700:4700::1111")}, addrs("2606:4700:4700::1111")},
		{"ip with port 53", []syncResolver{plain("9.9.9.9:53")}, addrs("9.9.9.9")},
		{"IPv6 with port 53", []syncResolver{plain("[2620:fe::fe]:53")}, addrs("2620:fe::fe")},
		{"another port is skipped, not stripped", []syncResolver{plain("9.9.9.9:5353", "9.9.9.9"), plain("8.8.8.8")}, addrs("8.8.8.8")},
		{"a host name takes its ips", []syncResolver{plain("dns.example", "203.0.113.1", "203.0.113.2", "bad")}, addrs("203.0.113.1", "203.0.113.2")},
		{"a host name with port 53", []syncResolver{plain("dns.example:53", "203.0.113.5")}, addrs("203.0.113.5")},
		{"DoH and DoT are skipped", []syncResolver{
			{Transport: "doh", Address: "https://dns.example/dns-query", IPs: []string{"203.0.113.9"}},
			{Transport: "dot", Address: "dns.example:853", IPs: []string{"203.0.113.9"}},
			{Transport: "dot", Address: "1.1.1.1"},
			plain("8.8.4.4"),
		}, addrs("8.8.4.4")},
		{"an entry with no transport is not plain", []syncResolver{{Address: "1.1.1.1"}}, nil},
		{"at most two, no repeats", []syncResolver{plain("1.1.1.1"), plain("1.1.1.1"), plain("1.0.0.1"), plain("8.8.8.8")}, addrs("1.1.1.1", "1.0.0.1")},
		{"unusable addresses", []syncResolver{plain("0.0.0.0"), plain("127.0.0.1"), plain("::1"), plain("224.0.0.1"), plain("not an ip"), plain("")}, nil},
		{"none", nil, nil},
	}
	for _, test := range tests {
		if got := plainResolvers(test.entries); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: got %v; want %v", test.name, got, test.want)
		}
	}
}

func TestPanelDNSFromTheSyncObject(t *testing.T) {
	var dns syncDNS
	body := `{"transport":"plain","servers":[
		{"transport":"plain","address":"1.1.1.1","ips":["1.1.1.1"]},
		{"transport":"doh","address":"https://dns.example/dns-query","ips":["203.0.113.1"]},
		{"transport":"plain","address":"1.0.0.1"}],
	 "split":[
		{"suffixes":["ru"],"geo":["CN"],"servers":[{"transport":"plain","address":"223.5.5.5"},{"transport":"dot","address":"dot.example"}]},
		{"suffixes":["ir"],"geo":["ir","tr"],"servers":[{"transport":"plain","address":"10.202.10.10:53"}]},
		{"suffixes":["xx"],"geo":[],"servers":[{"transport":"plain","address":"4.4.4.4"}]},
		{"suffixes":["yy"],"geo":["ru"],"servers":[{"transport":"doh","address":"https://x.example/"}]},
		{"suffixes":["zz"],"geo":["russia","r1"],"servers":[{"transport":"plain","address":"5.5.5.5"}]}],
	 "split_direct":true,"block_ads":false,"ipv4_only":false}`
	if err := json.Unmarshal([]byte(body), &dns); err != nil {
		t.Fatal(err)
	}
	servers, split := panelDNS(&dns)
	wantSplit := []profile.DNSSplit{
		{Geo: []string{"cn"}, Servers: addrs("223.5.5.5")},
		{Geo: []string{"ir", "tr"}, Servers: addrs("10.202.10.10")},
	}
	if !reflect.DeepEqual(servers, addrs("1.1.1.1", "1.0.0.1")) || !reflect.DeepEqual(split, wantSplit) {
		t.Fatalf("servers %v, split %+v", servers, split)
	}

	// without split_direct the split is not kept (the panel sends it empty then, but do not rely on it)
	dns.SplitDirect = false
	if _, split := panelDNS(&dns); split != nil {
		t.Fatalf("split kept without split_direct: %+v", split)
	}
	if servers, split := panelDNS(nil); servers != nil || split != nil {
		t.Fatal("absent dns gave resolvers")
	}
}

func TestSyncStoresPanelDNSAndSurvivesRestartAndClears(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	withDNS := func(dns any) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(panel.syncBody), &doc); err != nil {
			t.Fatal(err)
		}
		if dns == nil {
			delete(doc, "dns")
		} else {
			doc["dns"] = dns
		}
		out, _ := json.Marshal(doc)
		return string(out)
	}
	plain := func(address string) map[string]any { return map[string]any{"transport": "plain", "address": address} }
	panel.set(func() {
		panel.syncBody = withDNS(map[string]any{
			"transport": "plain", "servers": []any{plain("9.9.9.9"), map[string]any{"transport": "doh", "address": "https://d.example/q"}},
			"split":        []any{map[string]any{"suffixes": []string{"ru"}, "geo": []string{"cn"}, "servers": []any{plain("223.5.5.5")}}},
			"split_direct": true,
		})
	})
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	profiles, err := store.Profiles()
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles = %d, %v", len(profiles), err)
	}
	p := profiles[0]
	if !reflect.DeepEqual(p.PanelDNS, addrs("9.9.9.9")) || len(p.PanelSplit) != 1 || p.PanelSplit[0].Geo[0] != "cn" || p.PanelSplit[0].Servers[0] != netip.MustParseAddr("223.5.5.5") {
		t.Fatalf("profile DNS = %v, %+v", p.PanelDNS, p.PanelSplit)
	}

	// kept with the subscription across a restart
	saved, err := json.Marshal(store.state.Subscriptions[0])
	if err != nil {
		t.Fatal(err)
	}
	var back storedSubscription
	if err := json.Unmarshal(saved, &back); err != nil || !reflect.DeepEqual(back.DNS, p.PanelDNS) || !reflect.DeepEqual(back.DNSSplit, p.PanelSplit) {
		t.Fatalf("stored again: %v, %v, %+v", err, back.DNS, back.DNSSplit)
	}

	// not part of what the window sees
	listed, _ := json.Marshal(store.List())
	for _, leak := range []string{"9.9.9.9", "223.5.5.5", "dns"} {
		if strings.Contains(string(listed), leak) {
			t.Errorf("List JSON mentions %q", leak)
		}
	}

	// the next answer without dns clears it
	panel.set(func() { panel.syncBody = withDNS(nil) })
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	if profiles, _ = store.Profiles(); len(profiles[0].PanelDNS) != 0 || len(profiles[0].PanelSplit) != 0 {
		t.Fatalf("old DNS survived: %v, %+v", profiles[0].PanelDNS, profiles[0].PanelSplit)
	}

	// and so does an inactive status
	panel.set(func() { panel.syncBody = withDNS(map[string]any{"servers": []any{plain("9.9.9.9")}}) })
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	if profiles, _ = store.Profiles(); !reflect.DeepEqual(profiles[0].PanelDNS, addrs("9.9.9.9")) {
		t.Fatalf("DNS = %v", profiles[0].PanelDNS)
	}
	panel.set(func() { panel.syncBody = syncDoc("expired") })
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	if got := store.state.Subscriptions[0]; len(got.DNS) != 0 || len(got.DNSSplit) != 0 {
		t.Fatalf("an inactive subscription kept resolvers: %v %+v", got.DNS, got.DNSSplit)
	}
}
