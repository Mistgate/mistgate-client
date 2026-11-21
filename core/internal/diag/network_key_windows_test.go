//go:build windows

package diag

import (
	"regexp"
	"slices"
	"testing"
)

// It only reads the routing table and the adapter list; on a machine with no network the key is empty.
func TestNetworkKeyOfThisMachine(t *testing.T) {
	salt := []byte("test salt")
	key, kind := NetworkKey(salt)
	if key == "" && kind == "" {
		t.Skip("no network")
	}
	if !slices.Contains([]string{"wifi", "ethernet", "mobile", "other"}, kind) {
		t.Fatalf("kind = %q", kind)
	}
	if key != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		t.Fatalf("key %q is not a hex SHA-256", key)
	}
	if again, _ := NetworkKey(salt); again != key {
		t.Fatal("the key changed between two calls")
	}
	if other, _ := NetworkKey([]byte("another salt")); key != "" && other == key {
		t.Fatal("the salt does not change the key")
	}
}
