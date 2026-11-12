package engine

import (
	"fmt"
	"testing"
)

func TestMergeApps(t *testing.T) {
	running := []AppInfo{
		{Path: `c:\b\zeta.exe`, Name: "Zeta", Running: true},
		{Path: `c:\a\alpha.exe`, Name: "alpha", Running: true},
		{Path: `c:\a\alpha.exe`, Name: "alpha again", Running: true}, // the same path twice
		{Path: `c:\c\mid.exe`, Name: "Mid", Running: true},
	}
	named := []string{`c:\c\mid.exe`, `c:\d\gone.exe`, `c:\e\also.exe`}
	rows := mergeApps(running, named, func(p string) string { return baseName(p) })
	var got []string
	for _, r := range rows {
		got = append(got, fmt.Sprintf("%s|%s|%t", r.Path, r.Name, r.Running))
	}
	want := []string{
		`c:\a\alpha.exe|alpha|true`, `c:\c\mid.exe|Mid|true`, `c:\b\zeta.exe|Zeta|true`, // running first, by name
		`c:\e\also.exe|also|false`, `c:\d\gone.exe|gone|false`, // then the chosen ones that are not running
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rows = %q\nwant   %q", got, want)
	}

	if rows := mergeApps(nil, nil, nil); len(rows) != 0 || rows == nil {
		t.Fatalf("nothing running and nothing chosen = %#v; want an empty list", rows)
	}
}

func TestMergeAppsCapKeepsTheChosen(t *testing.T) {
	var running []AppInfo
	for i := 0; i < 400; i++ {
		running = append(running, AppInfo{Path: fmt.Sprintf(`c:\r\app%03d.exe`, i), Name: fmt.Sprintf("app%03d", i), Running: true})
	}
	// a chosen program that is running but would sort past the cap, and one that is not running
	chosen := []string{`c:\r\app399.exe`, `c:\x\missing.exe`}
	rows := mergeApps(running, chosen, func(p string) string { return baseName(p) })
	if len(rows) != maxAppRows {
		t.Fatalf("%d rows; want %d", len(rows), maxAppRows)
	}
	have := map[string]bool{}
	for _, r := range rows {
		have[r.Path] = true
	}
	for _, p := range chosen {
		if !have[p] {
			t.Errorf("chosen program %s fell out of the capped list", p)
		}
	}
	if rows[0].Path != `c:\r\app000.exe` || !rows[0].Running {
		t.Fatalf("first row = %+v", rows[0])
	}
}

func TestBaseName(t *testing.T) {
	for in, want := range map[string]string{`c:\a\b\Tool.exe`: "Tool", `c:\x.exe`: "x", `c:\dir.v2\app.exe`: "app"} {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q; want %q", in, got, want)
		}
	}
}
