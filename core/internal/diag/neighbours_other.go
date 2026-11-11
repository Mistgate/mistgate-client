//go:build !windows

package diag

// ponytail: non-Windows has nothing to look at; upgrade = /proc and the platform's interface list.
func scanLocal() (processes, drivers, adapters []string) { return nil, nil, nil }
