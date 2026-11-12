//go:build windows

package subs

import (
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM, Administrators and the owner. For the installed service the owner is SYSTEM, so nothing is widened; a
// development run from a plain console keeps access to the directory it has just created.
const directorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

func secureDirectory(path string) error {
	sd, err := windows.SecurityDescriptorFromString(directorySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// ClaimDirectory makes sure the data directory is not somebody else's before the service writes into it. ProgramData
// lets any user create a folder there: one made ahead of the first start would stay its maker's, with full control
// over where the service (as SYSTEM) writes. Such a directory is moved aside and a new one is made later. Only the
// installed service does this; a console run keeps what it finds. A directory that cannot be judged is left alone.
func ClaimDirectory(path string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil // not there yet, or unreadable
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return os.Rename(path, path+".foreign-"+strconv.FormatInt(time.Now().Unix(), 10))
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
