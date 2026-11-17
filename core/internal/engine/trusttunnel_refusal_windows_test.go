//go:build windows

package engine

import (
	"errors"
	"fmt"
	"testing"

	ttclient "github.com/mistgate/mistgate-client/core/internal/trusttunnel"
)

// A destination the server could not reach must not end the tunnel: only a refusal of the account does.
func TestTTRefusalIsAboutTheAccount(t *testing.T) {
	for code, refusal := range map[int]bool{404: true, 403: true, 407: true, 502: false, 503: false, 504: false, 500: false} {
		if got := isTTRefusal(fmt.Errorf("dial: %w", ttclient.StatusError{Code: code})); got != refusal {
			t.Errorf("status %d: refusal = %v, want %v", code, got, refusal)
		}
	}
	if !isTTRefusal(ttclient.ErrAuth) || isTTRefusal(ttclient.ErrStream) || isTTRefusal(errors.New("other")) {
		t.Error("only the authentication error is a refusal among the plain ones")
	}
	if got := verifyReason(ttclient.StatusError{Code: 502}); got != "the server answered 502" {
		t.Errorf("reason = %q", got)
	}
}
