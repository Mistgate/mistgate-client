//go:build windows

package subs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestClaimDirectoryCreatesClosedTree(t *testing.T) {
	rememberInMemory(t) // no reads of the machine's registry either
	asked := filepath.Join(t.TempDir(), "Mistgate")
	dir, err := ClaimDirectory(asked)
	if err != nil || dir != asked {
		t.Fatal("could not create a protected data directory")
	}
	child := filepath.Join(dir, "nested")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if again, err := ClaimDirectory(asked); err != nil || again != asked {
		t.Fatal("could not protect an existing data directory")
	}
	for _, path := range []string{dir, child} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal("could not inspect protected data directory")
		}
		acl := sd.String()
		if !strings.Contains(acl, ";;;SY)") || !strings.Contains(acl, ";;;BA)") || strings.Contains(acl, ";;;OW)") {
			t.Fatalf("data directory ACL is not restricted")
		}
	}
}

func TestServiceRejectsUntrustedNestedOwner(t *testing.T) {
	owner, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	if allowedDirectoryOwner(owner, directoryIdentity{user: owner, isSystem: true}) {
		t.Fatal("a non-service owner was accepted for the LocalSystem data tree")
	}
}

// rememberInMemory replaces the registry, where the claimed fallback is remembered, with a map.
func rememberInMemory(t *testing.T) map[string]string {
	t.Helper()
	remembered := map[string]string{}
	oldRead, oldWrite := readTaken, writeTaken
	readTaken = func(asked string) string { return remembered[asked] }
	writeTaken = func(asked, taken string) error { remembered[asked] = taken; return nil }
	t.Cleanup(func() { readTaken, writeTaken = oldRead, oldWrite })
	return remembered
}

// plantedAndHeld puts a plain file at path and keeps it open without delete sharing, as a program without rights can:
// it cannot be renamed or deleted until the test ends. A file is foreign whoever runs the test, which a directory made
// by the test's own account is not.
func plantedAndHeld(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("planted"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
}

func closedTo(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("could not inspect the directory")
	}
	acl := sd.String()
	if !strings.Contains(acl, ";;;SY)") || !strings.Contains(acl, ";;;BA)") || strings.Contains(acl, ";;;WD)") || strings.Contains(acl, ";;;BU)") {
		t.Fatal("the directory is not closed")
	}
}

func TestClaimDirectoryTakesASiblingWhenTheNameCannotBeMovedAside(t *testing.T) {
	remembered := rememberInMemory(t)
	identity, err := currentDirectoryIdentity()
	if err != nil {
		t.Fatal(err)
	}
	asked := filepath.Join(t.TempDir(), "Mistgate")
	plantedAndHeld(t, asked)

	// quarantine as the service does it (the test's account is not SYSTEM, so the switch is set by hand)
	first, err := claimDirectory(asked, identity, true)
	if err != nil {
		t.Fatal("the held name kept the service from getting a directory")
	}
	if first == asked || !sameParentSibling(asked, first) {
		t.Fatal("the claimed directory is not a sibling of the asked name")
	}
	closedTo(t, first)
	if err := os.WriteFile(filepath.Join(first, "settings.json"), []byte("{}"), 0600); err != nil {
		t.Fatal("the claimed directory cannot be written")
	}
	if remembered[asked] != first {
		t.Fatal("the claimed directory was not remembered")
	}

	second, err := claimDirectory(asked, identity, true)
	if err != nil || second != first {
		t.Fatal("a second claim did not find the same directory")
	}
	// the planted object is left alone, and the fallback stays in use even if the name were free
	if data, err := os.ReadFile(asked); err != nil || string(data) != "planted" {
		t.Fatal("the planted object was touched")
	}
}

func TestClaimDirectoryMovesAsideWhatItCan(t *testing.T) {
	remembered := rememberInMemory(t)
	identity, err := currentDirectoryIdentity()
	if err != nil {
		t.Fatal(err)
	}
	asked := filepath.Join(t.TempDir(), "Mistgate")
	if err := os.WriteFile(asked, []byte("planted"), 0600); err != nil {
		t.Fatal(err)
	}
	claimed, err := claimDirectory(asked, identity, true)
	if err != nil || claimed != asked || len(remembered) != 0 {
		t.Fatal("a name that can be moved aside did not stay the data directory")
	}
	if info, err := os.Stat(asked); err != nil || !info.IsDir() {
		t.Fatal("the name is not a directory")
	}
	closedTo(t, asked)
}

func TestClaimDirectoryIgnoresARememberedDirectoryElsewhere(t *testing.T) {
	remembered := rememberInMemory(t)
	identity, err := currentDirectoryIdentity()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	asked := filepath.Join(base, "Mistgate")
	for _, elsewhere := range []string{
		filepath.Join(t.TempDir(), "Mistgate.abc"), // another parent
		filepath.Join(base, "Other.abc"),           // another name
		filepath.Join(base, "Mistgate.abc", "sub"), // deeper
		filepath.Join(base, "Mistgate"),            // the name itself is not a sibling
	} {
		if sameParentSibling(asked, elsewhere) {
			t.Fatalf("%q was taken for a sibling", filepath.Base(elsewhere))
		}
	}
	remembered[asked] = filepath.Join(t.TempDir(), "Mistgate.abc")
	claimed, err := claimDirectory(asked, identity, false)
	if err != nil || claimed != asked {
		t.Fatal("a remembered path beside another parent was followed")
	}
}
