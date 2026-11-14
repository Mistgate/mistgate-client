//go:build windows

package engine

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/geo"
)

// fakeOwners is the stand-in for the socket tables: it names the program behind a source port and counts the questions.
type fakeOwners struct {
	mu     sync.Mutex
	byPort map[uint16]string
	cached bool // whether Cached knows the answer without a table read
	quick  int
	slow   int
}

func (f *fakeOwners) Cached(_ bool, src netip.AddrPort) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quick++
	return f.byPort[src.Port()], f.cached
}

func (f *fakeOwners) Owner(_ bool, src netip.AddrPort) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slow++
	return f.byPort[src.Port()]
}

const (
	chat  = `c:\apps\chat.exe`
	game  = `c:\apps\game.exe`
	other = `c:\apps\other.exe`
)

// appBridge is a bridge with the rules in a real store, so that rules and verdicts are read the way the service reads them.
func appBridge(t *testing.T, mode *string, rules geo.Rules, owners *fakeOwners) (*gvisorBridge, *countOutbound, *countOutbound) {
	t.Helper()
	store, err := geo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	vpn, direct := &countOutbound{}, &countOutbound{}
	probe := netip.MustParseAddr("203.0.113.99")
	bridge := &gvisorBridge{
		vpn:    vpn,
		direct: direct,
		// the plain decision: "selected" sends everything direct but the VPN sites, "smart" only the region
		shouldDirect: func(address netip.Addr, name string, remembered []string) bool {
			return directByRulesNames(address, name, remembered, *mode, nil, store.ActiveSiteRules())
		},
		apps: &appRouter{
			owners: owners,
			listed: func() bool { return appsListed(*mode, store.ActiveSiteRules()) },
			rule:   func(path string) appVerdict { return appRule(*mode, store.ActiveSiteRules(), path) },
			plain:  func(address netip.Addr) bool { return address == probe },
			blocks: func() bool { return store.ActiveSiteRules().HasBlock },
		},
	}
	return bridge, vpn, direct
}

type flowCase struct {
	name   string
	udp    bool
	target string
	port   uint16 // the source port: who owns it is in the fake
	// the exit: "d" direct, "v" VPN
	want string
	// whether the owner had to be looked up
	looked bool
}

func runFlows(t *testing.T, bridge *gvisorBridge, direct *countOutbound, owners *fakeOwners, cases []flowCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := [3]int{owners.quick, owners.slow, int(direct.tcp.Load() + direct.udp.Load())}
			target := netip.MustParseAddrPort(c.target)
			src := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), c.port)
			app := bridge.appWait(c.udp, src, target)
			var err error
			if c.udp {
				_, err = bridge.listenUDP(context.Background(), target, app)
			} else {
				_, _, err = bridge.dialTCPName(context.Background(), target, "", app)
			}
			if err != nil {
				t.Fatal(err)
			}
			wentDirect := int(direct.tcp.Load()+direct.udp.Load()) > before[2]
			if wentDirect != (c.want == "d") {
				t.Fatalf("direct = %t; want %q", wentDirect, c.want)
			}
			if looked := owners.quick+owners.slow > before[0]+before[1]; looked != c.looked {
				t.Fatalf("owner looked up = %t; want %t", looked, c.looked)
			}
		})
	}
}

func TestProgramRulesDecideFlows(t *testing.T) {
	realIPv6 := directIPv6
	defer func() { directIPv6 = realIPv6 }()
	directIPv6 = func() bool { return true }

	owners := &fakeOwners{byPort: map[uint16]string{1000: chat, 1001: other, 1002: game}, cached: true}

	t.Run("smart", func(t *testing.T) {
		mode := "smart"
		bridge, _, direct := appBridge(t, &mode, geo.Rules{
			Direct: geo.Selection{Apps: []string{chat}},
			VPN:    geo.Selection{Apps: []string{game}}, // smart reads only the direct programs
			Block:  geo.Selection{Sites: []string{"ads.example"}},
		}, owners)
		runFlows(t, bridge, direct, owners, []flowCase{
			{"listed TCP goes direct", false, "198.51.100.7:443", 1000, "d", true},
			{"listed UDP (QUIC) goes direct", true, "198.51.100.7:443", 1000, "d", true},
			{"another program takes the plain rule: VPN", false, "198.51.100.7:443", 1001, "v", true},
			{"a VPN program means nothing in smart", false, "198.51.100.7:443", 1002, "v", true},
			{"unknown owner takes the plain rule", false, "198.51.100.7:443", 4242, "v", true},
			{"the DNS port stays on the VPN and is not looked up", true, "198.51.100.7:53", 1000, "v", false},
			{"TCP port 53 too", false, "198.51.100.7:53", 1000, "v", false},
			{"a private address stays on the VPN, not looked up", false, "192.168.1.5:443", 1000, "v", false},
			{"loopback stays on the VPN", false, "127.0.0.1:443", 1000, "v", false},
			{"the tunnel check's address stays on the VPN, not looked up", false, "203.0.113.99:443", 1000, "v", false},
			{"IPv6 with a direct path", false, "[2001:4860:4860::8888]:443", 1000, "d", true},
		})
		directIPv6 = func() bool { return false }
		runFlows(t, bridge, direct, owners, []flowCase{
			{"IPv6 without a direct path falls to the VPN", false, "[2001:4860:4860::8888]:443", 1000, "v", true},
			{"IPv6 UDP the same", true, "[2001:4860:4860::8888]:443", 1000, "v", true},
			{"IPv4 is still direct", false, "198.51.100.7:443", 1000, "d", true},
		})
		directIPv6 = func() bool { return true }

		// block works on the name, before the exit is chosen: a listed program's 443 and 80 flows are still read for
		// it, other ports are not, and nothing is read without block rules
		for _, c := range []struct {
			app         appVerdict
			port        uint16
			needs, seen bool
		}{
			{appDirect, 443, true, false}, {appDirect, 80, true, false}, {appDirect, 8443, false, false},
		} {
			if needs, watching := bridge.readsName(c.app, c.port); needs != c.needs || watching != c.seen {
				t.Errorf("readsName(%d, %d) = %t, %t; want %t, %t", c.app, c.port, needs, watching, c.needs, c.seen)
			}
		}
	})

	t.Run("selected", func(t *testing.T) {
		mode := "selected"
		bridge, _, direct := appBridge(t, &mode, geo.Rules{
			VPN:    geo.Selection{Apps: []string{game}},
			Direct: geo.Selection{Apps: []string{chat}}, // selected reads only the VPN programs
		}, owners)
		runFlows(t, bridge, direct, owners, []flowCase{
			{"a VPN program goes through the VPN", false, "198.51.100.7:443", 1002, "v", true},
			{"and its UDP", true, "198.51.100.7:443", 1002, "v", true},
			{"another program goes direct", false, "198.51.100.7:443", 1001, "d", true},
			{"a direct program means nothing in selected", false, "198.51.100.7:443", 1000, "d", true},
			{"the DNS port stays on the VPN", true, "198.51.100.7:53", 1002, "v", false},
			{"a private address stays on the VPN", false, "10.1.1.1:443", 1002, "v", false},
		})
		if _, _, err := bridge.dialTCPName(context.Background(), netip.MustParseAddrPort("198.51.100.7:443"), "", appVPN); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no program named: nothing is looked up", func(t *testing.T) {
		mode := "smart"
		quiet := &fakeOwners{byPort: map[uint16]string{1000: chat}, cached: true}
		bridge, _, direct := appBridge(t, &mode, geo.Rules{Direct: geo.Selection{Sites: []string{"a.example"}}}, quiet)
		runFlows(t, bridge, direct, quiet, []flowCase{{"plain", false, "198.51.100.7:443", 1000, "v", false}})
		mode = "all"
		bridge, _, direct = appBridge(t, &mode, geo.Rules{Direct: geo.Selection{Apps: []string{chat}}}, quiet)
		runFlows(t, bridge, direct, quiet, []flowCase{{"all mode", false, "198.51.100.7:443", 1000, "v", false}})
	})

	t.Run("a bridge without the router", func(t *testing.T) {
		bridge := &gvisorBridge{vpn: &countOutbound{}, direct: &countOutbound{}}
		if v, ready := bridge.appQuick(false, netip.MustParseAddrPort("10.9.0.2:1"), netip.MustParseAddrPort("198.51.100.7:443")); v != appNone || !ready {
			t.Fatalf("appQuick = %d, %t", v, ready)
		}
	})
}

func TestUnknownOwnerNeedsTheSlowPath(t *testing.T) {
	mode := "smart"
	owners := &fakeOwners{byPort: map[uint16]string{1000: chat}}
	bridge, _, _ := appBridge(t, &mode, geo.Rules{Direct: geo.Selection{Apps: []string{chat}}}, owners)
	src, target := netip.MustParseAddrPort("10.9.0.2:1000"), netip.MustParseAddrPort("198.51.100.7:443")
	if v, ready := bridge.appQuick(true, src, target); ready || v != appNone {
		t.Fatalf("appQuick with nothing cached = %d, %t; want not ready", v, ready)
	}
	if v := bridge.appResolve(true, src); v != appDirect {
		t.Fatalf("appResolve = %d; want direct", v)
	}
}

func TestReadsNameWithoutPrograms(t *testing.T) {
	tracker, err := geo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sites := false
	bridge := &gvisorBridge{hasSiteRules: func() bool { return sites }}
	if needs, watching := bridge.readsName(appNone, 443); needs || watching {
		t.Fatal("no tracker and no site rules: nothing to read")
	}
	sites = true
	if needs, _ := bridge.readsName(appNone, 8443); !needs {
		t.Fatal("site rules need the name")
	}
	bridge.track = tracker.Failures()
	sites = false
	if needs, watching := bridge.readsName(appNone, 443); !needs || !watching {
		t.Fatal("a watched TLS flow is read first")
	}
	// a flow decided by its program is not watched, even with a tracker, and is read only to be blocked
	bridge.apps = &appRouter{blocks: func() bool { return false }}
	if needs, watching := bridge.readsName(appDirect, 443); needs || watching {
		t.Fatalf("program flow: needs %t, watching %t", needs, watching)
	}
	bridge.apps = &appRouter{blocks: func() bool { return true }}
	if needs, watching := bridge.readsName(appVPN, 443); !needs || watching {
		t.Fatalf("program flow with block rules: needs %t, watching %t", needs, watching)
	}
}
