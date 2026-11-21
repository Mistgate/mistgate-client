package diag

import (
	"net/netip"
	"regexp"
	"testing"
)

func TestNetworkKey(t *testing.T) {
	salt, other := []byte("salt-one"), []byte("salt-two")
	gateway := netip.MustParseAddr("192.0.2.1")
	key := networkKey(salt, "wifi", gateway)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		t.Fatalf("key %q is not a hex SHA-256", key)
	}
	if key != networkKey(salt, "wifi", gateway) {
		t.Fatal("the key is not stable")
	}
	for name, got := range map[string]string{
		"salt":    networkKey(other, "wifi", gateway),
		"kind":    networkKey(salt, "ethernet", gateway),
		"gateway": networkKey(salt, "wifi", netip.MustParseAddr("192.0.2.2")),
	} {
		if got == key {
			t.Errorf("another %s gave the same key", name)
		}
	}
}
