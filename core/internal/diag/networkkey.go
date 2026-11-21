package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

// networkKey is the hash that stands for one network in the memory of Auto: the install's salt, then the interface kind
// and the gateway, with a separator the kind cannot contain.
func networkKey(salt []byte, kind string, gateway netip.Addr) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(kind + "|" + gateway.String()))
	return hex.EncodeToString(h.Sum(nil))
}
