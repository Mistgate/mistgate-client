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
	"os/exec"
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
//	MG_TT_H3    any value: the path's transport "auto" is honoured, so Connect tries HTTP/3; every test then needs h3
//	MG_TT_IPTABLES  any value: also TestLiveHTTP3Fallback, which drops UDP to the endpoint's port with iptables (only in
//	            the stand's own network namespace, as root)
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
			if os.Getenv("MG_TT_H3") != "" {
				config.H3 = p.H3
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
	trusttunnel.ForgetHTTP3() // what an earlier test chose does not decide this one
	client, err := trusttunnel.Connect(ctx, config)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Logf("protocol: %s", client.Protocol())
	if config.H3 && client.Protocol() != "h3" {
		t.Fatalf("HTTP/3 was asked for and the session is %s", client.Protocol())
	}
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
	t.Logf("protocol of Dial: %s", client.Protocol())
	err = client.Check(ctx)
	var status trusttunnel.StatusError
	t.Logf("wrong password: check = %v (auth refusal: %v, status: %v)", err, errors.Is(err, trusttunnel.ErrAuth), errors.As(err, &status))
	if err == nil {
		t.Error("a wrong password passed the check")
	}

	// Connect says the same with H3 on: HTTP/3 turns nobody away, HTTP/2 has the word.
	trusttunnel.ForgetHTTP3()
	if connected, err := trusttunnel.Connect(ctx, wrong); !trusttunnel.IsRefusal(err) {
		if connected != nil {
			_ = connected.Close()
		}
		t.Errorf("Connect with a wrong password gave %v, want a refusal", err)
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
	// Both sessions are made before the subtests run side by side: liveDial clears what Connect remembers.
	keptClient, leftClient := liveDial(t, config), liveDial(t, config)
	t.Run("kept", func(t *testing.T) {
		t.Parallel()
		client := keptClient
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
		client := leftClient
		started := time.Now()
		select {
		case <-client.Done():
			t.Logf("a session with no streams was closed after %s: %v", strconv.Itoa(int(time.Since(started).Seconds()))+" s", client.Err())
		case <-time.After(100 * time.Second):
			t.Log("a session with no streams was still open after 100 s")
		}
	})
}

// With MG_TT_H3 the endpoint must be reachable over HTTP/3, and Connect must remember it for h3Retry.
func TestLiveTransport(t *testing.T) {
	config := liveConfig(t)
	if !config.H3 {
		t.Skip("MG_TT_H3 is not set, or the path's transport is h2")
	}
	client := liveDial(t, config) // fails unless the session is h3
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	second, err := trusttunnel.Connect(ctx, config)
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	defer second.Close()
	t.Logf("protocol of a connection right after one that got h3: %s", second.Protocol())
	if second.Protocol() != "h2" {
		t.Errorf("a host that just got HTTP/3 was dialled over %s, want h2", second.Protocol())
	}
	_ = client.Close()
}

// The rules are on INPUT, both ways: packets leave and vanish, as in a network that cuts UDP. On OUTPUT the send itself
// would fail and the session would end at once, which no real network does.
func iptablesDrop(t *testing.T, flag, port string) {
	t.Helper()
	for _, side := range []string{"--dport", "--sport"} {
		out, err := exec.Command("iptables", flag, "INPUT", "-p", "udp", side, port, "-j", "DROP").CombinedOutput()
		if err != nil {
			t.Fatalf("iptables %s: %v: %s", flag, err, bytes.TrimSpace(out))
		}
	}
}

// UDP cut to the endpoint's port: a fresh connection is HTTP/2 and no slower than HTTP/2 alone; a live HTTP/3 session
// ends with ErrSession within 45 s and the next connection is HTTP/2; with the rule gone HTTP/3 comes back.
func TestLiveHTTP3Fallback(t *testing.T) {
	config := liveConfig(t)
	if os.Getenv("MG_TT_IPTABLES") == "" {
		t.Skip("MG_TT_IPTABLES is not set")
	}
	if !config.H3 {
		t.Skip("MG_TT_H3 is not set, or the path's transport is h2")
	}
	_, port, err := net.SplitHostPort(config.Addresses[0])
	if err != nil {
		t.Fatal("the endpoint address is not host:port")
	}
	connect := func(config trusttunnel.Config) (*trusttunnel.Client, time.Duration) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		started := time.Now()
		client, err := trusttunnel.Connect(ctx, config)
		took := time.Since(started)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client, took
	}
	dropped := false
	setDrop := func(on bool) {
		if on != dropped {
			iptablesDrop(t, map[bool]string{true: "-I", false: "-D"}[on], port)
			dropped = on
		}
	}
	t.Cleanup(func() { setDrop(false) })

	h2Only := config
	h2Only.H3 = false
	var h2Slowest time.Duration
	for range 3 {
		_, took := connect(h2Only)
		h2Slowest = max(h2Slowest, took)
	}

	setDrop(true)
	trusttunnel.ForgetHTTP3()
	client, took := connect(config)
	t.Logf("UDP cut from the start: protocol %s in %v (HTTP/2 alone, slowest of 3: %v)", client.Protocol(), took, h2Slowest)
	if client.Protocol() != "h2" || took > h2Slowest+200*time.Millisecond {
		t.Errorf("with UDP cut: protocol %s in %v, want h2 within %v", client.Protocol(), took, h2Slowest+200*time.Millisecond)
	}
	_ = client.Close()

	setDrop(false)
	trusttunnel.ForgetHTTP3()
	live, _ := connect(config)
	if live.Protocol() != "h3" {
		t.Fatalf("with UDP open again: protocol %s, want h3", live.Protocol())
	}
	setDrop(true)
	cut := time.Now()
	select {
	case <-live.Done():
		t.Logf("a live HTTP/3 session ended %v after UDP was cut: %v", time.Since(cut).Round(time.Second), live.Err())
		if live.Err() != trusttunnel.ErrSession {
			t.Errorf("the session ended with %v, want ErrSession", live.Err())
		}
	case <-time.After(45 * time.Second):
		t.Fatal("a live HTTP/3 session was still up 45 s after UDP was cut")
	}
	next, _ := connect(config)
	if next.Protocol() != "h2" {
		t.Errorf("the connection after the loss is %s, want h2", next.Protocol())
	}
	_ = next.Close()

	setDrop(false)
	trusttunnel.ForgetHTTP3()
	again, _ := connect(config)
	if again.Protocol() != "h3" {
		t.Errorf("with the rule gone and the memory cleared: protocol %s, want h3", again.Protocol())
	}
}
