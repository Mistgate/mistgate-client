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
	dir := filepath.Join(t.TempDir(), "Mistgate")
	if err := ClaimDirectory(dir); err != nil {
		t.Fatal("could not create a protected data directory")
	}
	child := filepath.Join(dir, "nested")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ClaimDirectory(dir); err != nil {
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
