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

// ClaimDirectory is a Windows matter: the directory is used as it is.
func ClaimDirectory(path string) (string, error) { return path, nil }

// ClaimDirectoryForAdministrators is a Windows matter.
func ClaimDirectoryForAdministrators(path string) (string, error) { return path, nil }

func protect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }

func unprotect(data []byte) ([]byte, error) { return append([]byte(nil), data...), nil }
