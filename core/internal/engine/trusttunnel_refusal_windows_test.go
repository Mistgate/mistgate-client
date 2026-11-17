//go:build windows

package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	ttclient "github.com/mistgate/mistgate-client/core/internal/trusttunnel"
)

func TestVerifyReasonNamesTheStatus(t *testing.T) {
	if got := verifyReason(ttclient.StatusError{Code: 502}); got != "the server answered 502" {
		t.Errorf("reason = %q", got)
	}
}

// ttEchoHandler is the endpoint side of ttStub: an echo for every CONNECT, or the status in refuse while one is set.
func ttEchoHandler(refuse *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := int(refuse.Load()); code != 0 {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()
		if r.Host == "_check" {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	})
}

// ttStub is a TrustTunnel endpoint on loopback that echoes every CONNECT, or answers refuse (a status) while it is set.
func ttStub(t *testing.T, refuse *atomic.Int32) netip.AddrPort {
	t.Helper()
	server := httptest.NewUnstartedServer(ttEchoHandler(refuse))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return netip.MustParseAddrPort(server.Listener.Addr().String())
}

// ttOutboundOn is an outbound as startTT builds it, minus the adapter's routes: the stub is on loopback.
func ttOutboundOn(t *testing.T, endpoint netip.AddrPort) *ttOutbound {
	t.Helper()
	return ttOutboundWith(t, ttclient.Config{
		Host: "example.test", Addresses: []string{endpoint.String()}, Username: "user", Password: "password", Insecure: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	})
}

// ttOutboundWith is ttOutboundOn for a config of the test's own.
func ttOutboundWith(t *testing.T, config ttclient.Config) *ttOutbound {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := ttclient.Connect(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := client.Endpoint()
	pool, err := ttclient.NewPool(ctx, client, config, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := &ttOutbound{ctx: ctx, config: config, endpoint: endpoint, pool: pool, fatalCh: make(chan struct{})}
	t.Cleanup(func() { _ = out.Close() })
	go out.reconnect()
	return out
}

func ttEchoOnce(out *ttOutbound) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := out.DialAuthority(ctx, "example.test:443")
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != "ping" {
		return fmt.Errorf("echo = %q", got)
	}
	return nil
}

// A refusal after the tunnel was up is not final: the server also shows its site to an account at its connection limit.
// The tunnel redials with its backoff and works again once the server lets the account in.
func TestTTRefusalOfAnUpTunnelIsRetried(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusProxyAuthRequired} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var refuse atomic.Int32
			out := ttOutboundOn(t, ttStub(t, &refuse))
			if err := ttEchoOnce(out); err != nil {
				t.Fatalf("tunnel before the refusal: %v", err)
			}
			refuse.Store(int32(code))
			if err := ttEchoOnce(out); !ttclient.IsRefusal(err) {
				t.Fatalf("dial while refused = %v, want the refusal", err)
			}
			if out.isFatal() {
				t.Fatal("one refusal ended the tunnel")
			}
			time.Sleep(1500 * time.Millisecond) // a redial or two against the refusal
			if out.isFatal() {
				t.Fatal("redials against the refusal ended the tunnel before the patience ran out")
			}
			refuse.Store(0)
			deadline := time.Now().Add(15 * time.Second)
			var err error
			for time.Now().Before(deadline) {
				if err = ttEchoOnce(out); err == nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Fatalf("tunnel did not come back after the server let the account in: %v", err)
		})
	}
}

// Refusals that go on without one success for ttRefusalPatience are final.
func TestTTRefusalsForTooLongAreFinal(t *testing.T) {
	old := ttRefusalPatience
	ttRefusalPatience = 500 * time.Millisecond
	t.Cleanup(func() { ttRefusalPatience = old })
	var refuse atomic.Int32
	out := ttOutboundOn(t, ttStub(t, &refuse))
	refuse.Store(http.StatusNotFound)
	if err := ttEchoOnce(out); !ttclient.IsRefusal(err) {
		t.Fatalf("dial while refused = %v, want the refusal", err)
	}
	select {
	case <-out.fatalCh:
	case <-time.After(15 * time.Second):
		t.Fatal("refusals for longer than the patience did not end the tunnel")
	}
	if _, err := out.current(); !ttclient.IsRefusal(err) {
		t.Fatalf("outbound after the patience = %v, want the refusal", err)
	}
}

// The service's own dials (the tunnel check, the proxy) are not held behind the applications' streams.
func TestTTServiceDialsSkipTheStreamCap(t *testing.T) {
	var refuse atomic.Int32
	out := ttOutboundOn(t, ttStub(t, &refuse))
	var open []net.Conn
	t.Cleanup(func() {
		for _, conn := range open {
			_ = conn.Close()
		}
	})
	for range 64 { // the cap
		conn, err := out.DialAuthority(context.Background(), "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, conn)
	}
	short, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := out.DialAuthority(short, "example.test:443"); err == nil {
		t.Fatal("a dial past the cap went through")
	}
	// the local proxy carries applications' traffic: its dials count like any other and wait for a place
	shortProxy, stopProxy := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopProxy()
	if _, err := ttDialer(out)(shortProxy, "example.test", 443); err == nil {
		t.Fatal("a proxy dial past the cap went through")
	}
	bridge := &gvisorBridge{vpn: out}
	if err := bridge.reaches(context.Background(), netip.MustParseAddrPort("203.0.113.9:443")); err != nil {
		t.Fatalf("tunnel check with every place taken: %v", err)
	}
}
