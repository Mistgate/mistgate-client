//go:build windows

package subs

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const directorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

var errDataDirectory = errors.New("cannot safely use subscription data directory")

// foreignMark names what was moved out of the way: a planted directory, or a planted object inside the real one.
const foreignMark = ".foreign-"

type directoryIdentity struct {
	user     *windows.SID
	isSystem bool
}

func currentDirectoryIdentity() (directoryIdentity, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return directoryIdentity{}, errDataDirectory
	}
	return directoryIdentity{user: user.User.Sid, isSystem: user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)}, nil
}

func directoryDescriptor(identity directoryIdentity) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := directorySDDL
	if !identity.isSystem && !identity.user.IsWellKnown(windows.WinLocalSystemSid) && !identity.user.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		sddl += "(A;OICI;FA;;;" + identity.user.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, errDataDirectory
	}
	return sd, nil
}

func secureDirectory(path string) error {
	identity, err := currentDirectoryIdentity()
	if err != nil {
		return errDataDirectory
	}
	return prepareDirectory(path, identity, false)
}

func prepareStoreDirectory(path string, secureDir func(string) error) error {
	return secureDir(path)
}

// ClaimDirectory closes the directory before the service writes crash.log or opens its stores. A directory planted in
// ProgramData is moved aside before the service creates a new one. Existing nested objects are checked without
// following reparse points, so a user cannot redirect a service write through a junction or symlink.
func ClaimDirectory(path string) error {
	identity, err := currentDirectoryIdentity()
	if err != nil {
		return errDataDirectory
	}
	return prepareDirectory(path, identity, identity.isSystem)
}

// ClaimDirectoryForAdministrators prepares the same protected tree for the allow command before service install.
func ClaimDirectoryForAdministrators(path string) error {
	if err := ClaimDirectory(path); err != nil {
		return err
	}
	return setDirectoryOwnerAdministrators(path)
}

func setDirectoryOwnerAdministrators(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errDataDirectory
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errDataDirectory
	}
	defer windows.CloseHandle(handle)
	info, err := directoryInfo(handle)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errDataDirectory
	}
	owner, err := directoryOwner(handle)
	if err != nil {
		return errDataDirectory
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || setObjectOwner(handle, admins) != nil {
		return errDataDirectory
	}
	return nil
}

func setObjectOwner(handle windows.Handle, owner *windows.SID) error {
	token := windows.GetCurrentProcessToken()
	privilegeName, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		return errDataDirectory
	}
	var restorePrivilege windows.LUID
	if err := windows.LookupPrivilegeValue(nil, privilegeName, &restorePrivilege); err != nil {
		return errDataDirectory
	}
	enabled := windows.Tokenprivileges{PrivilegeCount: 1}
	enabled.Privileges[0] = windows.LUIDAndAttributes{Luid: restorePrivilege, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var previous windows.Tokenprivileges
	var returned uint32
	if err := windows.AdjustTokenPrivileges(token, false, &enabled, uint32(unsafe.Sizeof(previous)), &previous, &returned); err != nil {
		return errDataDirectory
	}
	if previous.PrivilegeCount > 0 {
		defer windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return errDataDirectory
	}
	return nil
}

func prepareDirectory(path string, identity directoryIdentity, quarantineForeignRoot bool) error {
	if path == "" {
		return errDataDirectory
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errDataDirectory
	}
	sd, err := directoryDescriptor(identity)
	if err != nil {
		return errDataDirectory
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return errDataDirectory
	}

	handle, err := openDirectoryObject(path)
	if isMissingPath(err) {
		if err = createClosedDirectory(path, sd); err == nil {
			handle, err = openDirectoryObject(path)
		} else if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			handle, err = openDirectoryObject(path)
		}
	}
	if err != nil {
		return errDataDirectory
	}
	defer func() {
		if handle != windows.InvalidHandle {
			_ = windows.CloseHandle(handle)
		}
	}()

	info, err := directoryInfo(handle)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errDataDirectory
	}
	owner, err := directoryOwner(handle)
	if err != nil {
		return errDataDirectory
	}
	if !allowedDirectoryOwner(owner, identity) {
		if !quarantineForeignRoot {
			return errDataDirectory
		}
		if err := windows.CloseHandle(handle); err != nil {
			return errDataDirectory
		}
		handle = windows.InvalidHandle
		moved := path + foreignMark + strconv.FormatInt(time.Now().UnixNano(), 10)
		if err := os.Rename(path, moved); err != nil {
			return errDataDirectory
		}
		if err := createClosedDirectory(path, sd); err != nil {
			return errDataDirectory
		}
		handle, err = openDirectoryObject(path)
		if err != nil {
			return errDataDirectory
		}
		info, err = directoryInfo(handle)
		if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errDataDirectory
		}
	}
	if err := setDirectoryACL(handle, dacl); err != nil {
		return errDataDirectory
	}
	return secureChildren(path, identity, dacl)
}

func allowedDirectoryOwner(owner *windows.SID, identity directoryIdentity) bool {
	if owner == nil {
		return false
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return !identity.isSystem && owner.Equals(identity.user)
}

func createClosedDirectory(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errDataDirectory
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	return windows.CreateDirectory(name, &attributes)
}

func openDirectoryObject(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, errDataDirectory
	}
	return windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func isMissingPath(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func directoryInfo(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, errDataDirectory
	}
	return info, nil
}

func directoryOwner(handle windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return nil, errDataDirectory
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, errDataDirectory
	}
	return owner, nil
}

func setDirectoryACL(handle windows.Handle, dacl *windows.ACL) error {
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func secureChildren(path string, identity directoryIdentity, dacl *windows.ACL) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return errDataDirectory
	}
	for _, entry := range entries {
		// set aside on an earlier start: never read, never judged again
		if strings.Contains(entry.Name(), foreignMark) {
			continue
		}
		childPath := filepath.Join(path, entry.Name())
		handle, err := openDirectoryObject(childPath)
		if err != nil {
			return errDataDirectory
		}
		info, infoErr := directoryInfo(handle)
		owner, ownerErr := directoryOwner(handle)
		if infoErr != nil || ownerErr != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !allowedDirectoryOwner(owner, identity) {
			// Somebody else's object, or a link to elsewhere. Refusing to start over it would let any program keep
			// the service down for good with one file; the directory above is closed by now, so the object is moved
			// out of the service's way under a name nothing reads (a rename does not follow a link), and the start
			// goes on. Only if that fails is the directory unusable.
			_ = windows.CloseHandle(handle)
			if os.Rename(childPath, childPath+foreignMark+strconv.FormatInt(time.Now().UnixNano(), 10)) != nil {
				return errDataDirectory
			}
			continue
		}
		if err := setDirectoryACL(handle, dacl); err != nil {
			_ = windows.CloseHandle(handle)
			return errDataDirectory
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			if err := secureChildren(childPath, identity, dacl); err != nil {
				_ = windows.CloseHandle(handle)
				return err
			}
		}
		if err := windows.CloseHandle(handle); err != nil {
			return errDataDirectory
		}
	}
	return nil
}

func protect(data []byte) ([]byte, error) {
	input := dataBlob(data)
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return blobBytes(output), nil
}

func unprotect(data []byte) ([]byte, error) {
	input := dataBlob(data)
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return blobBytes(output), nil
}

func dataBlob(data []byte) windows.DataBlob {
	if len(data) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func blobBytes(blob windows.DataBlob) []byte {
	if blob.Data == nil || blob.Size == 0 {
		return []byte{}
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
}
