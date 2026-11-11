package geo

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func sec(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }

func vpnSites(t *Tracker, now time.Time) []SuggestSite    { return t.List(now).VPN }
func directSites(t *Tracker, now time.Time) []SuggestSite { return t.List(now).Direct }

func TestRegistrable(t *testing.T) {
	for name, want := range map[string]string{
		"www.example.com": "example.com", "a.b.example.co.uk": "example.co.uk", "example.com": "example.com",
		"localhost": "", "1.2.3.4": "", "co.uk": "", "": "", "foo.github.io": "foo.github.io",
	} {
		if got := registrable(name); got != want {
			t.Errorf("registrable(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestThreeFailuresWithAWorkingRouteAreSuggested(t *testing.T) {
	tr := newTracker(nil)
	tr.OK(ViaDirect, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaDirect, "www.example.com", sec(i*5))
	}
	got := vpnSites(tr, sec(20))
	if len(got) != 1 || got[0] != (SuggestSite{"example.com", 3}) || len(directSites(tr, sec(20))) != 0 {
		t.Fatalf("suggest = %#v", tr.List(sec(20)))
	}
	if list := tr.List(sec(20)); list.VPN == nil || list.Direct == nil {
		t.Fatal("lists must not be nil")
	}
}

func TestNoSuccessOnTheRouteMeansNothing(t *testing.T) {
	tr := newTracker(nil)
	for i := 0; i < 5; i++ {
		tr.Fail(ViaDirect, "example.com", sec(i))
	}
	if got := vpnSites(tr, sec(30)); len(got) != 0 {
		t.Fatalf("the internet is down, yet suggest = %#v", got)
	}
	// a success from the other route does not help
	tr.OK(ViaVPN, "other.org", sec(6))
	if got := vpnSites(tr, sec(30)); len(got) != 0 {
		t.Fatalf("other route's success confirmed failures: %#v", got)
	}
}

func TestPendingFailuresConfirmedBySuccessWithin15s(t *testing.T) {
	tr := newTracker(nil)
	for i := 0; i < 3; i++ {
		tr.Fail(ViaVPN, "example.com", sec(i))
	}
	tr.OK(ViaVPN, "other.org", sec(10)) // 10 s after the first, 8 s after the last
	if got := directSites(tr, sec(11)); len(got) != 1 || got[0].Count != 3 {
		t.Fatalf("suggest = %#v", tr.List(sec(11)))
	}

	late := newTracker(nil)
	for i := 0; i < 3; i++ {
		late.Fail(ViaVPN, "example.com", sec(i))
	}
	late.OK(ViaVPN, "other.org", sec(30)) // too late for all of them
	if got := directSites(late, sec(31)); len(got) != 0 {
		t.Fatalf("stale failures counted: %#v", got)
	}
}

func TestSuccessClearsAndRoutesAreIndependent(t *testing.T) {
	tr := newTracker(nil)
	tr.OK(ViaDirect, "other.org", sec(0))
	tr.OK(ViaVPN, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaDirect, "example.com", sec(i))
	}
	tr.Fail(ViaVPN, "example.com", sec(4))
	if len(vpnSites(tr, sec(5))) != 1 || len(directSites(tr, sec(5))) != 0 {
		t.Fatalf("suggest = %#v", tr.List(sec(5)))
	}
	tr.OK(ViaVPN, "example.com", sec(6)) // the other route's success changes nothing
	if len(vpnSites(tr, sec(7))) != 1 {
		t.Fatal("a success on the VPN cleared the direct failures")
	}
	tr.OK(ViaDirect, "cdn.example.com", sec(8)) // same site, same route
	if got := vpnSites(tr, sec(9)); len(got) != 0 {
		t.Fatalf("a later success did not clear: %#v", got)
	}
	// and failures after the clearing start from zero
	tr.Fail(ViaDirect, "example.com", sec(10))
	if len(vpnSites(tr, sec(11))) != 0 {
		t.Fatal("one failure after a success is enough")
	}
}

func TestDismissal(t *testing.T) {
	tr := newTracker(nil)
	tr.OK(ViaDirect, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaDirect, "example.com", sec(i))
	}
	tr.Dismiss(true, "example.com")
	if len(vpnSites(tr, sec(5))) != 0 {
		t.Fatal("dismissed site still suggested")
	}
	for i := 6; i <= 10; i++ {
		tr.Fail(ViaDirect, "example.com", sec(i))
	}
	if len(vpnSites(tr, sec(11))) != 0 {
		t.Fatal("dismissed site came back")
	}
	// the other list is a different question
	tr.OK(ViaVPN, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaVPN, "example.com", sec(i))
	}
	if len(directSites(tr, sec(5))) != 1 {
		t.Fatal("dismissing vpn hid the direct list")
	}
}

func TestBounds(t *testing.T) {
	tr := newTracker(nil)
	tr.OK(ViaDirect, "other.org", sec(0))
	for i := 0; i < suggestTracked+50; i++ {
		tr.OK(ViaDirect, "other.org", sec(1+i))
		for j := 0; j < 3; j++ {
			tr.Fail(ViaDirect, fmt.Sprintf("s%03d.example", i), sec(1+i))
		}
	}
	if len(tr.fails) != suggestTracked {
		t.Fatalf("tracked %d sites, want %d", len(tr.fails), suggestTracked)
	}
	if _, kept := tr.fails[suggestKey{ViaDirect, "s000.example"}]; kept {
		t.Fatal("the oldest site was not dropped")
	}
	list := vpnSites(tr, sec(400))
	if len(list) != suggestPerRoute {
		t.Fatalf("returned %d sites, want %d", len(list), suggestPerRoute)
	}
	// pending is bounded as well
	p := newTracker(nil)
	for i := 0; i < 3*suggestPending; i++ {
		p.Fail(ViaVPN, fmt.Sprintf("s%03d.example", i), sec(0))
	}
	if len(p.pending[ViaVPN]) != suggestPending {
		t.Fatalf("pending %d, want %d", len(p.pending[ViaVPN]), suggestPending)
	}
}

func TestListedSitesAreSkipped(t *testing.T) {
	skip := map[string]bool{"fixed.com": true}
	tr := newTracker(func(site string, toVPN bool) bool { return skip[site] })
	tr.OK(ViaDirect, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaDirect, "fixed.com", sec(i))
		tr.Fail(ViaDirect, "free.com", sec(i))
	}
	if got := vpnSites(tr, sec(5)); len(got) != 1 || got[0].Site != "free.com" {
		t.Fatalf("suggest = %#v", got)
	}
}

func TestStoreRulesDecideWhatIsListed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetRules(Rules{Direct: Selection{Sites: []string{"listed.com"}}, VPN: Selection{Sites: []string{"www.deep.org"}}}); err != nil {
		t.Fatal(err)
	}
	tr := store.Failures()
	now := time.Now()
	tr.OK(ViaDirect, "other.org", now)
	for _, site := range []string{"listed.com", "deep.org", "open.com"} {
		for i := 0; i < 3; i++ {
			tr.Fail(ViaDirect, "www."+site, now)
		}
	}
	routes := store.Routes("selected", "", "")
	if len(routes.Suggest.VPN) != 1 || routes.Suggest.VPN[0].Site != "open.com" {
		t.Fatalf("suggest = %#v", routes.Suggest)
	}
	if all := store.Routes("all", "", ""); len(all.Suggest.VPN) != 0 || all.Suggest.VPN == nil {
		t.Fatalf("all mode suggest = %#v", all.Suggest)
	}
	if store.Dismiss(true, "not a name") || !store.Dismiss(true, "Open.com") {
		t.Fatal("Dismiss validation")
	}
	if routes = store.Routes("selected", "", ""); len(routes.Suggest.VPN) != 0 {
		t.Fatalf("dismissed, suggest = %#v", routes.Suggest)
	}
}

func TestFailuresExpireAfter24h(t *testing.T) {
	tr := newTracker(nil)
	tr.OK(ViaDirect, "other.org", sec(0))
	for i := 1; i <= 3; i++ {
		tr.Fail(ViaDirect, "example.com", sec(i))
	}
	if len(vpnSites(tr, sec(3600))) != 1 {
		t.Fatal("fresh failures not suggested")
	}
	if got := vpnSites(tr, sec(25*3600)); len(got) != 0 {
		t.Fatalf("old failures suggested: %#v", got)
	}
	if len(tr.fails) != 0 {
		t.Fatal("old entry kept")
	}
}

func TestSuccessPathDoesNotAllocate(t *testing.T) {
	tr := newTracker(nil)
	now := sec(0)
	if n := testing.AllocsPerRun(100, func() { tr.OK(ViaVPN, "www.example.com", now) }); n != 0 {
		t.Errorf("OK on an empty tracker allocates %v", n)
	}
	tr.OK(ViaVPN, "other.org", now)
	tr.Fail(ViaVPN, "tracked.com", now)
	if n := testing.AllocsPerRun(100, func() { tr.OK(ViaDirect, "www.example.com", now) }); n != 0 {
		t.Errorf("OK with sites tracked allocates %v", n)
	}
}
