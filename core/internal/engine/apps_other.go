//go:build !windows

package engine

// ListApps: only Windows has programs to list; the ones the rules name are still shown.
func ListApps(named []string) []AppInfo {
	return mergeApps(nil, named, baseName)
}
