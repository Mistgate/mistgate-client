//go:build windows

package diag

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

// The check says "bad key" only when the server turns the account away (4xx); a server that fails does not answer.
func TestAttemptTTSortsTheCheckAnswer(t *testing.T) {
	physical := loopbackInterface(t)
	for status, want := range map[int]error{
		http.StatusOK:                  nil,
		http.StatusNotFound:            errAuthRejected,
		http.StatusProxyAuthRequired:   errAuthRejected,
		http.StatusBadGateway:          errNoAnswer,
		http.StatusServiceUnavailable:  errNoAnswer,
		http.StatusInternalServerError: errNoAnswer,
	} {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		server.EnableHTTP2 = true
		server.StartTLS()
		endpoint := netip.MustParseAddrPort(server.Listener.Addr().String())
		p := &profile.TrustTunnel{Host: "example.test", Addresses: []string{endpoint.String()}, Username: "user", Password: "password", Insecure: true}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := attemptTT(ctx, p, endpoint, physical)
		cancel()
		server.Close()
		if !errors.Is(err, want) {
			t.Errorf("check answered %d: error = %v, want %v", status, err, want)
		}
	}
}
