//go:build !windows

package subs

import "os"

func secureDirectory(string) error { return nil }

func prepareStoreDirectory(path string, secureDir func(string) error) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return secureDir(path)
}

// ClaimDirectory is a Windows matter.
func ClaimDirectory(string) error { return nil }

func protect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }

func unprotect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }
