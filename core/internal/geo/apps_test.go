package geo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeAppPath(t *testing.T) {
	good := map[string]string{
		`C:\Program Files\App\App.EXE`: `c:\program files\app\app.exe`,
		`c:/tools/x.exe`:               `c:\tools\x.exe`,
		`D:\Игры\Клиент.exe`:           `d:\игры\клиент.exe`,
		`c:\a.exe`:                     `c:\a.exe`,
		`c:\dir.with.dots\a b.exe`:     `c:\dir.with.dots\a b.exe`,
	}
	for in, want := range good {
		if got, ok := normalizeAppPath(in); !ok || got != want {
			t.Errorf("normalizeAppPath(%q) = %q, %t; want %q", in, got, ok, want)
		}
	}
	long := `c:\` + strings.Repeat("a", maxAppPath) + `.exe`
	bad := []string{
		"", `app.exe`, `\app.exe`, `c:app.exe`, `c:\`, `c:\.exe`, `c:\dir\`, `c:\app.dll`, `c:\app.exe.txt`, `c:\app.exe `, ` c:\app.exe`,
		`\\server\share\app.exe`, `\\?\c:\app.exe`, `1:\app.exe`, `cc:\app.exe`, `c:\a\..\app.exe`, `c:\.\app.exe`, `c:\\app.exe`,
		`c:\a\\b.exe`, "c:\\app\x00.exe", "c:\\app\n.exe", "c:\\ap\x7fp.exe", "c:\\ap\u0085p.exe", `c:\a|b.exe`, `c:\a*.exe`, `c:\a?.exe`,
		`c:\a<b>.exe`, `c:\a"b.exe`, `c:\dir.\a.exe`, `c:\app.exe:stream.exe`, "c:\\\xff\\a.exe", long,
	}
	for _, in := range bad {
		if got, ok := normalizeAppPath(in); ok {
			t.Errorf("normalizeAppPath(%q) = %q; want refusal", in, got)
		}
	}
}

func TestAppsInRules(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules, changed, err := store.SetRules(Rules{
		Direct: Selection{Apps: []string{`C:\B\b.exe`, `c:\a\a.exe`, `c:/b/B.exe`}},
		VPN:    Selection{Apps: []string{`c:\v\v.exe`}},
	})
	if err != nil || !changed {
		t.Fatalf("SetRules = %+v, %t, %v", rules, changed, err)
	}
	if got := rules.Direct.Apps; len(got) != 2 || got[0] != `c:\a\a.exe` || got[1] != `c:\b\b.exe` {
		t.Fatalf("direct apps = %q; want sorted without duplicates", got)
	}
	if rules.Block.Apps == nil || rules.Direct.Collections == nil || rules.VPN.Sites == nil {
		t.Fatalf("empty lists must be [] and not null: %+v", rules)
	}
	active := store.ActiveSiteRules()
	if _, ok := active.DirectApps[`c:\a\a.exe`]; !ok || len(active.DirectApps) != 2 || len(active.VPNApps) != 1 {
		t.Fatalf("active programs: direct %v, vpn %v", active.DirectApps, active.VPNApps)
	}
	if _, again, err := store.SetRules(Rules{Direct: Selection{Apps: []string{`c:\a\a.exe`, `C:\B\b.EXE`}}, VPN: Selection{Apps: []string{`c:\v\v.exe`}}}); err != nil || again {
		t.Fatalf("the same programs in another form changed the rules: %t, %v", again, err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.GetRules(); !sameRules(got, rules) {
		t.Fatalf("reopened rules = %+v; want %+v", got, rules)
	}

	// block has no programs; a bad path or too many programs is refused, and nothing changes
	tooMany := make([]string, maxApps+1)
	for i := range tooMany {
		tooMany[i] = `c:\p` + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + `.exe`
	}
	for _, bad := range []Rules{
		{Block: Selection{Apps: []string{`c:\a\a.exe`}}},
		{Direct: Selection{Apps: []string{`a.exe`}}},
		{VPN: Selection{Apps: []string{`c:\a\a.dll`}}},
		{Direct: Selection{Apps: tooMany}},
	} {
		if _, _, err := store.SetRules(bad); err != ErrBadRules {
			t.Errorf("SetRules(%+v) err = %v; want ErrBadRules", bad, err)
		}
	}
	if got := store.GetRules(); !sameRules(got, rules) {
		t.Fatalf("a refused change altered the rules: %+v", got)
	}
	exact := tooMany[:maxApps]
	if _, _, err := store.SetRules(Rules{Direct: Selection{Apps: exact}}); err != nil {
		t.Fatalf("%d programs refused: %v", maxApps, err)
	}
}

func TestRoutesFileWithoutAppsStillLoads(t *testing.T) {
	dir := t.TempDir()
	old := `{"direct":{"collections":[],"sites":["a.example"]},"vpn":{"collections":[],"sites":["b.example"]},"block":{"collections":[],"sites":[]}}`
	if err := os.WriteFile(filepath.Join(dir, "routes.json"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules := store.GetRules()
	if len(rules.Direct.Sites) != 1 || len(rules.VPN.Sites) != 1 || rules.Direct.Apps == nil || len(rules.Direct.Apps) != 0 || rules.VPN.Apps == nil {
		t.Fatalf("rules from an old file = %+v", rules)
	}
	if active := store.ActiveSiteRules(); len(active.DirectApps) != 0 || len(active.VPNApps) != 0 {
		t.Fatalf("programs appeared from nowhere: %v %v", active.DirectApps, active.VPNApps)
	}
	// a file with a bad program is ignored as a whole, like any bad file
	bad := `{"direct":{"collections":[],"sites":[],"apps":["notapath"]},"vpn":{},"block":{}}`
	if err := os.WriteFile(filepath.Join(dir, "routes.json"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.GetRules(); len(got.Direct.Apps) != 0 || len(got.Direct.Sites) != 0 {
		t.Fatalf("rules from a bad file = %+v", got)
	}
}
