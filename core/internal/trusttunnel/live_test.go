package trusttunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/trusttunnel"
)

// The live checks run against a real endpoint and are skipped without MG_TT_SYNC:
//
//	MG_TT_SYNC  file with a panel's sync answer; its first TrustTunnel path is used
//	MG_TT_ADDR  dial this address instead of the path's server (a stand that listens on loopback)
//	MG_TT_HTTP  host:port of a plain HTTP server reachable from the endpoint
//	MG_TT_ECHO  ip:port of a UDP echo reachable from the endpoint
//	MG_TT_IDLE  any value: also the two checks that sit idle for over a minute
func liveConfig(t *testing.T) trusttunnel.Config {
	t.Helper()
	file := os.Getenv("MG_TT_SYNC")
	if file == "" {
		t.Skip("MG_TT_SYNC is not set")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("the sync file cannot be read")
	}
	var answer struct {
		Servers []struct {
			Paths []struct {
				Protocol string          `json:"protocol"`
				Settings json.RawMessage `json:"settings"`
			} `json:"paths"`
		} `json:"servers"`
	}
	if json.Unmarshal(raw, &answer) != nil {
		t.Fatal("the sync file is not JSON")
	}
	for _, server := range answer.Servers {
		for _, path := range server.Paths {
			if path.Protocol != "trusttunnel" {
				continue
			}
			p, err := profile.ParseTrustTunnelPath(path.Settings)
			if err != nil {
				t.Fatalf("the panel's path is refused: %v", err)
			}
			config := trusttunnel.Config{
				Host: p.Host, Addresses: p.Addresses, SNI: p.SNI, Username: p.Username, Password: p.Password,
				PinSHA256: p.PinSHA256, HasPin: p.HasPin, Certs: p.Certs, Insecure: p.Insecure,
			}
			if address := os.Getenv("MG_TT_ADDR"); address != "" {
				_, port, _ := net.SplitHostPort(p.Addresses[0])
				config.Addresses = []string{net.JoinHostPort(address, port)}
			}
			return config
		}
	}
	t.Fatal("no TrustTunnel path in the sync file")
	return trusttunnel.Config{}
}

func liveDial(t *testing.T, config trusttunnel.Config) *trusttunnel.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := trusttunnel.Dial(ctx, config)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := client.Check(ctx); err != nil {
		_ = client.Close()
		t.Fatalf("check: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func liveGet(ctx context.Context, dial func(context.Context, string) (net.Conn, error), target string) (int, []byte, error) {
	conn, err := dial(ctx, target)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
		return 0, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	return response.StatusCode, body, err
}

func TestLiveRefusals(t *testing.T) {
	config := liveConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if config.HasPin {
		wrong := config
		wrong.PinSHA256[0] ^= 0xff
		if client, err := trusttunnel.Dial(ctx, wrong); !errors.Is(err, trusttunnel.ErrCertificate) {
			if client != nil {
				_ = client.Close()
			}
			t.Errorf("a wrong pin gave %v, want the certificate refusal", err)
		}
	}

	wrong := config
	wrong.Password += "x"
	client, err := trusttunnel.Dial(ctx, wrong)
	if err != nil {
		t.Fatalf("the TLS session itself should open with a wrong password: %v", err)
	}
	defer client.Close()
	err = client.Check(ctx)
	var status trusttunnel.StatusError
	t.Logf("wrong password: check = %v (auth refusal: %v, status: %v)", err, errors.Is(err, trusttunnel.ErrAuth), errors.As(err, &status))
	if err == nil {
		t.Error("a wrong password passed the check")
	}
}

func TestLiveTCP(t *testing.T) {
	config := liveConfig(t)
	target := os.Getenv("MG_TT_HTTP")
	if target == "" {
		t.Skip("MG_TT_HTTP is not set")
	}
	client := liveDial(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code, body, err := liveGet(ctx, client.DialTCP, target)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET through the tunnel: status %d, %v", code, err)
	}
	t.Logf("GET through the tunnel: 200, %d bytes: %q", len(body), bytes.TrimSpace(body))
}

func TestLiveUDP(t *testing.T) {
	config := liveConfig(t)
	target, err := netip.ParseAddrPort(os.Getenv("MG_TT_ECHO"))
	if err != nil {
		t.Skip("MG_TT_ECHO is not set")
	}
	client := liveDial(t, config)
	flow, err := client.ListenUDP(context.Background())
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer flow.Close()
	for _, size := range []int{1, 1200, 1400, 9000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if err := flow.WriteTo(payload, target); err != nil {
			t.Fatalf("send %d bytes: %v", size, err)
		}
		type packet struct {
			payload []byte
			from    netip.AddrPort
			err     error
		}
		got := make(chan packet, 1)
		go func() {
			payload, from, err := flow.ReadFrom()
			got <- packet{payload, from, err}
		}()
		select {
		case p := <-got:
			if p.err != nil || !bytes.Equal(p.payload, payload) || p.from != target {
				t.Errorf("echo of %d bytes: %d bytes from %v, %v", size, len(p.payload), p.from, p.err)
			}
		case <-time.After(5 * time.Second):
			// a datagram above the path's MTU may be dropped by the far side; only the small ones must return
			if size <= 1200 {
				t.Fatalf("no echo of %d bytes", size)
			}
			t.Logf("no echo of %d bytes", size)
			return
		}
	}
}

func TestLivePool(t *testing.T) {
	config := liveConfig(t)
	target := os.Getenv("MG_TT_HTTP")
	if target == "" {
		t.Skip("MG_TT_HTTP is not set")
	}
	primary := liveDial(t, config)
	_, limit := primary.Load()
	pool, err := trusttunnel.NewPool(context.Background(), primary, config, 0)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Held streams, more than the cap: the first 64 open, the rest wait until those close.
	const held = 80
	var opened sync.WaitGroup
	conns := make(chan net.Conn, held)
	for range held {
		opened.Add(1)
		go func() {
			defer opened.Done()
			if conn, err := pool.DialTCP(ctx, target); err == nil {
				conns <- conn
			} else {
				t.Errorf("held stream: %v", err)
			}
		}()
	}
	time.Sleep(3 * time.Second)
	t.Logf("server's stream limit per connection %d; with %d dials waiting: %d open, %d connections", limit, held, len(conns), pool.ConnectionCount())
	if len(conns) != 64 {
		t.Errorf("open streams at the cap = %d, want 64", len(conns))
	}
	go func() {
		opened.Wait()
		close(conns)
	}()
	for conn := range conns {
		_ = conn.Close()
	}

	var group sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	kinds := make(map[string]int)
	started := time.Now()
	for range 200 {
		group.Add(1)
		go func() {
			defer group.Done()
			code, _, err := liveGet(ctx, pool.DialTCP, target)
			if err != nil || code != http.StatusOK {
				mu.Lock()
				failed++
				kinds[fmt.Sprintf("status %d, %v", code, err)]++
				mu.Unlock()
			}
		}()
	}
	group.Wait()
	t.Logf("200 requests in %v, %d failed, %d connections", time.Since(started).Round(time.Millisecond), failed, pool.ConnectionCount())
	if failed != 0 {
		t.Errorf("%d of 200 requests failed: %v", failed, kinds)
	}
}

func TestLiveIdle(t *testing.T) {
	config := liveConfig(t)
	if os.Getenv("MG_TT_IDLE") == "" {
		t.Skip("MG_TT_IDLE is not set")
	}
	t.Run("kept", func(t *testing.T) {
		t.Parallel()
		client := liveDial(t, config)
		for range 2 {
			select {
			case <-client.Done():
				t.Fatalf("the session died between checks: %v", client.Err())
			case <-time.After(45 * time.Second):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			err := client.Check(ctx)
			cancel()
			if err != nil {
				t.Fatalf("check after 45 s of silence: %v", err)
			}
		}
	})
	t.Run("left", func(t *testing.T) {
		t.Parallel()
		client := liveDial(t, config)
		started := time.Now()
		select {
		case <-client.Done():
			t.Logf("a session with no streams was closed after %s: %v", strconv.Itoa(int(time.Since(started).Seconds()))+" s", client.Err())
		case <-time.After(100 * time.Second):
			t.Log("a session with no streams was still open after 100 s")
		}
	})
}
