package engine

import (
	"cmp"
	"path"
	"slices"
	"strings"
)

// AppInfo is one row of the window's list of programs (apps.list).
type AppInfo struct {
	Path    string `json:"path"` // lower case, backslashes: the form the rules store
	Name    string `json:"name"`
	Running bool   `json:"running"`
}

const maxAppRows = 300

// mergeApps joins the running programs with the ones the rules name, so a chosen program that is not running stays in the
// list. Running ones come first, then by name. Past the cap the unnamed running programs go first: a program the user
// chose must not fall out of the list. nameOf gives the name of a program that is not running.
func mergeApps(running []AppInfo, named []string, nameOf func(string) string) []AppInfo {
	rows := make([]AppInfo, 0, len(running)+len(named))
	seen := make(map[string]struct{}, len(running)+len(named))
	for _, app := range running {
		if _, dup := seen[app.Path]; !dup {
			seen[app.Path] = struct{}{}
			rows = append(rows, app)
		}
	}
	chosen := make(map[string]struct{}, len(named))
	for _, p := range named {
		chosen[p] = struct{}{}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			rows = append(rows, AppInfo{Path: p, Name: nameOf(p)})
		}
	}
	slices.SortFunc(rows, func(a, b AppInfo) int {
		if a.Running != b.Running {
			if a.Running {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
	if drop := len(rows) - maxAppRows; drop > 0 {
		kept := rows[:0]
		for i := len(rows) - 1; i >= 0; i-- { // the tail of the sort goes first
			if _, ok := chosen[rows[i].Path]; !ok && drop > 0 {
				rows[i].Path = ""
				drop--
			}
		}
		for _, row := range rows {
			if row.Path != "" {
				kept = append(kept, row)
			}
		}
		rows = kept[:min(len(kept), maxAppRows)]
	}
	return rows
}

// baseName is the file name of a Windows path without its extension.
func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return strings.TrimSuffix(path.Base(p), path.Ext(p))
}
