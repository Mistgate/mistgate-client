package diag

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

func TestLiveAWGGuardGoesByKey(t *testing.T) {
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	parse := func(private byte) *profile.AWG {
		awg, err := profile.ParseAWG("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = " + key(private) + "\n[Peer]\nPublicKey = " +
			key(9) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n")
		if err != nil {
			t.Fatal(err)
		}
		return awg
	}
	live, twin, other := parse(1), parse(1), parse(2)
	old := LiveAWG
	defer func() { LiveAWG = old }()
	LiveAWG = func() (string, string, time.Duration) { return "live", live.ClientKeyID(), 40 * time.Millisecond }
	for _, c := range []struct {
		name string
		p    profile.Profile
		skip bool
	}{
		{"the profile in use", profile.Profile{ID: "live", AWG: live}, true},
		{"a twin of its key", profile.Profile{ID: "twin", AWG: twin}, true},
		{"another key", profile.Profile{ID: "other", AWG: other}, false},
		{"no AmneziaWG config", profile.Profile{ID: "hy2"}, false},
	} {
		if rtt, skipped := liveAWG(c.p); skipped != c.skip || skipped && rtt != 40*time.Millisecond {
			t.Errorf("%s: skipped=%v rtt=%v", c.name, skipped, rtt)
		}
	}
	LiveAWG = func() (string, string, time.Duration) { return "", "", 0 } // no tunnel: nothing is guarded
	if _, skipped := liveAWG(profile.Profile{ID: "live", AWG: live}); skipped {
		t.Error("with no tunnel up nothing is skipped")
	}
}
