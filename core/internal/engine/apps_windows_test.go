//go:build windows

package engine

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestListAppsOnThisMachine(t *testing.T) {
	exe, _ := os.Executable()
	chosen := `c:\definitely\not\installed\nothing.exe`
	began := time.Now()
	rows := ListApps([]string{chosen})
	t.Logf("first scan: %d rows in %v", len(rows), time.Since(began))
	windir := strings.ToLower(os.Getenv("SystemRoot")) + `\`
	seen := map[string]bool{}
	sawChosen, endOfRunning := false, false
	for _, r := range rows {
		if seen[r.Path] {
			t.Errorf("%s listed twice", r.Path)
		}
		seen[r.Path] = true
		if r.Path != strings.ToLower(r.Path) || r.Name == "" {
			t.Errorf("bad row %+v", r)
		}
		if r.Running && (strings.HasPrefix(r.Path, windir) || strings.EqualFold(r.Path, exe)) {
			t.Errorf("a program that must be left out is listed: %s", r.Path)
		}
		if !r.Running {
			endOfRunning = true
		} else if endOfRunning {
			t.Errorf("running program %s after one that is not", r.Path)
		}
		if r.Path == chosen {
			sawChosen = true
			if r.Running || r.Name != "nothing" {
				t.Errorf("chosen program row = %+v", r)
			}
		}
	}
	if !sawChosen || len(rows) > maxAppRows {
		t.Fatalf("chosen program listed %t, %d rows", sawChosen, len(rows))
	}

	// a second call within 2 s is served from the scan
	began = time.Now()
	again := ListApps([]string{chosen})
	t.Logf("cached list: %d rows in %v", len(again), time.Since(began))
	if len(again) != len(rows) {
		t.Fatalf("the cached list has %d rows; first had %d", len(again), len(rows))
	}
}

func TestFileDescription(t *testing.T) {
	// explorer.exe carries a description in every Windows; a missing file gives none
	if got := fileDescription(os.Getenv("SystemRoot") + `\explorer.exe`); got == "" {
		t.Error("no description for explorer.exe")
	}
	if got := fileDescription(`c:\definitely\not\installed\nothing.exe`); got != "" {
		t.Errorf("description of a missing file = %q", got)
	}
	if got := appName(`c:\definitely\not\installed\nothing.exe`); got != "nothing" {
		t.Errorf("appName of a missing file = %q; want its file name", got)
	}
}
