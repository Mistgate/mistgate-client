//go:build windows

package users

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileName       = "users"
	maxFileSize    = 1 << 20
	maxSIDLineSize = 256
)

// Read loads the account SID list. A missing file is the legacy empty-list state.
func Read(directory string) ([]string, error) {
	path := filepath.Join(directory, fileName)
	file, err := openUsersFile(path, windows.GENERIC_READ)
	if isMissing(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, errors.New("users file too large")
	}

	var sids []string
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > maxSIDLineSize {
			continue
		}
		if sid, ok := ValidateSID(strings.TrimSpace(line)); ok {
			sids = append(sids, sid)
		}
	}
	return normalizeList(sids), nil
}

// Write replaces the account SID list atomically. The caller claims the data directory first.
func Write(directory string, sids []string) error {
	return write(directory, sids, false)
}

// WriteForAdministrators gives the list file an owner the LocalSystem service accepts on its next start.
func WriteForAdministrators(directory string, sids []string) error {
	return write(directory, sids, true)
}

func write(directory string, sids []string, administratorsOwn bool) error {
	path := filepath.Join(directory, fileName)
	if err := rejectReparsePoint(path); err != nil && !isMissing(err) {
		return err
	}

	var content strings.Builder
	for _, sid := range normalizeList(sids) {
		content.WriteString(sid)
		content.WriteByte('\n')
	}

	var tempPath string
	var file *os.File
	for range 10 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		tempPath = filepath.Join(directory, fmt.Sprintf(".users-%x.tmp", nonce))
		handle, err := createTempFile(tempPath)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return err
		}
		file = os.NewFile(uintptr(handle), tempPath)
		break
	}
	if file == nil {
		return errors.New("cannot create users file")
	}
	defer os.Remove(tempPath)

	if _, err := io.WriteString(file, content.String()); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if administratorsOwn {
		if err := setAdministratorsOwner(windows.Handle(file.Fd())); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Close(); err != nil {
		return err
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func openUsersFile(path string, access uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("users path is not a regular file")
	}
	return os.NewFile(uintptr(handle), path), nil
}

func rejectReparsePoint(path string) error {
	file, err := openUsersFile(path, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	return file.Close()
}

func createTempFile(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.GENERIC_WRITE|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func isMissing(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func setAdministratorsOwner(handle windows.Handle) error {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return setOwnerWithRestorePrivilege(handle, owner)
}

func setOwnerWithRestorePrivilege(handle windows.Handle, owner *windows.SID) error {
	token := windows.GetCurrentProcessToken()
	privilegeName, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		return err
	}
	var restorePrivilege windows.LUID
	if err := windows.LookupPrivilegeValue(nil, privilegeName, &restorePrivilege); err != nil {
		return err
	}
	enabled := windows.Tokenprivileges{PrivilegeCount: 1}
	enabled.Privileges[0] = windows.LUIDAndAttributes{Luid: restorePrivilege, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var previous windows.Tokenprivileges
	var returned uint32
	if err := windows.AdjustTokenPrivileges(token, false, &enabled, uint32(unsafe.Sizeof(previous)), &previous, &returned); err != nil {
		return err
	}
	if previous.PrivilegeCount > 0 {
		defer windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
}
