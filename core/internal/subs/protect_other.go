//go:build !windows

package subs

func secureDirectory(string) error { return nil }

// ClaimDirectory is a Windows matter.
func ClaimDirectory(string) error { return nil }

func protect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }

func unprotect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }
