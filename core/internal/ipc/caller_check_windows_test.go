//go:build windows

package ipc

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestCallerImageInspectionStaysOnLocalFixedPaths(t *testing.T) {
	service := `C:\Mistgate\mistgate-clientd.exe`
	var inspected []string
	drive := func(root string) uint32 {
		if root == `C:\` {
			return windows.DRIVE_FIXED
		}
		return windows.DRIVE_REMOTE
	}
	inspect := func(path string) signatureFacts {
		inspected = append(inspected, path)
		return signatureFacts{Signed: true, Valid: true}
	}

	if _, allowed := inspectCallerSignatureWith(`C:\Windows\Mistgate.exe`, service, false, drive, inspect); allowed {
		t.Fatal("unsigned service inspected a caller outside its directory")
	}
	if len(inspected) != 0 {
		t.Fatalf("inspected %d paths outside the service directory", len(inspected))
	}
	if _, allowed := inspectCallerSignatureWith(`C:\Mistgate\Mistgate.exe`, service, false, drive, inspect); !allowed {
		t.Fatal("local caller inside the service directory was refused")
	}
	if _, allowed := inspectCallerSignatureWith(`C:\Windows\Mistgate.exe`, service, true, drive, inspect); !allowed {
		t.Fatal("signed service could not inspect a local fixed-drive caller")
	}

	for _, path := range []string{
		`\\server\share\Mistgate.exe`,
		`\\?\C:\Mistgate.exe`,
		`\\.\C:\Mistgate.exe`,
		`\Device\HarddiskVolume1\Mistgate.exe`,
		`\??\C:\Mistgate.exe`,
		`R:\Mistgate.exe`,
	} {
		if _, allowed := inspectCallerSignatureWith(path, service, true, drive, inspect); allowed {
			t.Fatal("a network or device caller path was inspected")
		}
	}
}
