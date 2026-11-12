//go:build !windows

package proxy

// FirewallRule: only Windows has the rule.
func FirewallRule(bool) error { return nil }
