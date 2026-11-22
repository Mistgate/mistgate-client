package profile

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAWGClientKeyID(t *testing.T) {
	conf := func(private, peer string) string {
		return "[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = " + private + "\n[Peer]\nPublicKey = " + peer +
			"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n"
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	a, errA := ParseAWG(conf(key(1), key(7)))
	twin, errB := ParseAWG(conf(key(1), key(8))) // the same client key, another server
	other, errC := ParseAWG(conf(key(2), key(7)))
	if errA != nil || errB != nil || errC != nil {
		t.Fatal(errA, errB, errC)
	}
	if a.ClientKeyID() == "" || a.ClientKeyID() != twin.ClientKeyID() || a.ClientKeyID() == other.ClientKeyID() {
		t.Fatal("the fingerprint must tell the client key and nothing else")
	}
	if strings.Contains(a.ClientKeyID(), strings.Repeat("01", 32)) {
		t.Fatal("the fingerprint is not the key")
	}
}
