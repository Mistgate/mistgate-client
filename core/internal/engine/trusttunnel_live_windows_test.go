//go:build windows

package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

// The engine's TrustTunnel outbound, as the service starts it (sockets bound to the physical interface, the reconnect
// loop), against a real endpoint. No adapter, no routes and no firewall are touched. Skipped without MG_TT_SYNC:
//
//	MG_TT_SYNC   file with a panel's sync answer; its first TrustTunnel path is used
//	MG_TT_ADDR   dial this address instead of the path's server
//	MG_TT_HTTP   host:port of a plain HTTP server reachable from the endpoint
//	MG_TT_CUT    a command that cuts UDP between this machine and the endpoint; MG_TT_UNCUT undoes it
//	MG_TT_CUT_FIRST  any value: UDP is cut before the first connection instead of under a live session
func TestLiveTTOutbound(t *testing.T) {
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
	var p *profile.TrustTunnel
	for _, server := range answer.Servers {
		for _, path := range server.Paths {
			if path.Protocol == "trusttunnel" && p == nil {
				if p, err = profile.ParseTrustTunnelPath(path.Settings); err != nil {
					t.Fatalf("the panel's path is refused: %v", err)
				}
			}
		}
	}
	if p == nil {
		t.Fatal("no TrustTunnel path in the sync file")
	}
	host, port, _ := net.SplitHostPort(p.Addresses[0])
	if address := os.Getenv("MG_TT_ADDR"); address != "" {
		host = address
	}
	number, _ := strconv.Atoi(port)
	address, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal("the endpoint is not a numeric address: set MG_TT_ADDR")
	}
	endpoint := netip.AddrPortFrom(address, uint16(number))

	cut := func(env string) {
		command := os.Getenv(env)
		if command == "" {
			return
		}
		if out, err := exec.Command("cmd", "/c", command).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", env, err, out)
		}
	}
	t.Cleanup(func() { cut("MG_TT_UNCUT") })
	if os.Getenv("MG_TT_CUT_FIRST") != "" {
		cut("MG_TT_CUT")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	out, err := startTT(ctx, p, []netip.AddrPort{endpoint})
	if err != nil {
		t.Fatalf("startTT: %v", err)
	}
	defer out.Close()
	protocol := func() string {
		pool, err := out.current()
		if err != nil {
			return "none"
		}
		return pool.Primary().Protocol()
	}
	t.Logf("connected in %v over %s (HTTP/3 asked: %v)", time.Since(started).Round(time.Millisecond), protocol(), p.H3)

	target := os.Getenv("MG_TT_HTTP")
	get := func(timeout time.Duration) error {
		if target == "" {
			return nil
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := out.DialAuthority(ctx, target)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
			return err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", response.StatusCode)
		}
		return nil
	}
	if err := get(10 * time.Second); err != nil {
		t.Fatalf("GET through the tunnel: %v", err)
	}
	for range 20 {
		if err := get(10 * time.Second); err != nil {
			t.Fatalf("GET through the tunnel: %v", err)
		}
	}
	t.Logf("21 requests through the tunnel over %s", protocol())

	if os.Getenv("MG_TT_CUT") == "" || os.Getenv("MG_TT_CUT_FIRST") != "" {
		return
	}
	was := protocol()
	cut("MG_TT_CUT")
	at := time.Now()
	for time.Since(at) < 3*time.Minute {
		time.Sleep(time.Second)
		if err := get(3 * time.Second); err == nil {
			t.Logf("UDP cut under a live %s session: the tunnel carried a request again after %v, over %s; fatal: %v",
				was, time.Since(at).Round(time.Second), protocol(), out.isFatal())
			return
		}
	}
	t.Fatalf("UDP cut under a live %s session: no request went through for 3 minutes (now %s, fatal: %v)", was, protocol(), out.isFatal())
}
