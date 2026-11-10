//go:build windows

package subs

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const directorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

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
