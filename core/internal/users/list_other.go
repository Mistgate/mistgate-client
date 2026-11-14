//go:build !windows

package users

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const fileName = "users"

func Read(directory string) ([]string, error) {
	path := filepath.Join(directory, fileName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("users path is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sids []string
	for _, line := range strings.Split(string(data), "\n") {
		if sid, ok := ValidateSID(strings.TrimSpace(line)); ok {
			sids = append(sids, sid)
		}
	}
	return normalizeList(sids), nil
}

func Write(directory string, sids []string) error {
	return writeOther(directory, sids)
}

func WriteForAdministrators(directory string, sids []string) error {
	return writeOther(directory, sids)
}

func writeOther(directory string, sids []string) error {
	path := filepath.Join(directory, fileName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("users path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var content strings.Builder
	for _, sid := range normalizeList(sids) {
		content.WriteString(sid)
		content.WriteByte('\n')
	}
	temp, err := os.CreateTemp(directory, ".users-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.WriteString(content.String()); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
