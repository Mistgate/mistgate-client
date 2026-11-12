//go:build windows

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/xray"
	"github.com/mistgate/mistgate-client/core/internal/xray/xraytest"
)

// The path under test is a real one: REALITY to an Xray server of the same library on loopback.
func vlessPaths(t *testing.T) map[string]*profile.VLESS {
	return map[string]*profile.VLESS{
		"reality+raw+vision": func() *profile.VLESS {
			p := xraytest.RealityProfile("raw", profile.VLESSFlowVision, "")
			return xraytest.Server(t, p, "")
		}(),
		"reality+xhttp": func() *profile.VLESS {
			p := xraytest.RealityProfile("xhttp", "", "auto")
			return xraytest.Server(t, p, "")
		}(),
	}
}

func TestVLESSOutboundTCPAndUDP(t *testing.T) {
	for name, p := range vlessPaths(t) {
		t.Run(name, func(t *testing.T) {
			x, err := xray.Start(p, netip.MustParseAddr(p.Host), "")
			if err != nil {
				t.Fatal(err)
			}
			defer x.Close()
			var out outbound = vlessOutbound{x: x}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			echo := netip.MustParseAddrPort(xraytest.TCPEcho(t))
			conn, err := out.DialTCP(ctx, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte("mistgate"), 8192)
			go conn.Write(payload)
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("TCP echo: %v", err)
			}

			// one flow, two destinations: the engine's flows have one, but the interface allows more
			udpA, okA := xraytest.UDPEcho(t, "127.0.0.1:0")
			udpB, okB := xraytest.UDPEcho(t, "127.0.0.1:0")
			if !okA || !okB {
				t.Skip("no UDP socket")
			}
			flow, err := out.ListenUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{udpA, udpB, udpA} {
				addr := netip.MustParseAddrPort(target)
				if err := flow.WriteTo([]byte("hello "+target), addr); err != nil {
					t.Fatal(err)
				}
				payload, from, err := flow.ReadFrom()
				if err != nil {
					t.Fatal(err)
				}
				if from != addr || string(payload) != "echo:hello "+target {
					t.Fatalf("UDP reply from %v: %q", from, payload)
				}
			}
			if err := flow.Close(); err != nil {
				t.Fatal(err)
			}
			if err := flow.WriteTo([]byte("late"), netip.MustParseAddrPort(udpA)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after Close = %v", err)
			}
			if _, _, err := flow.ReadFrom(); err == nil {
				t.Fatal("read after Close succeeded")
			}
		})
	}
}

func TestVLESSFlowEndsWithItsContext(t *testing.T) {
	p := vlessPaths(t)["reality+raw+vision"]
	x, err := xray.Start(p, netip.MustParseAddr(p.Host), "")
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	ctx, cancel := context.WithCancel(context.Background())
	flow, err := vlessOutbound{x: x}.ListenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := flow.ReadFrom(); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadFrom returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom did not end with the context")
	}
	_ = flow.Close()
}

func TestStartVLESSMapsFailures(t *testing.T) {
	p := vlessPaths(t)["reality+raw+vision"]
	server := netip.MustParseAddr(p.Host)
	// the real targets are public addresses; the test's server reaches loopback only
	old := xray.CheckTargets
	xray.CheckTargets = []string{xraytest.MaskSite(t)}
	defer func() { xray.CheckTargets = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	x, err := startVLESS(ctx, p, server)
	if err != nil {
		t.Fatalf("good path: %v", err)
	}
	_ = x.Close()
	wrong := *p
	wrong.UUID = "00000000-0000-4000-8000-000000000001"
	if _, err := startVLESS(ctx, &wrong, server); !errors.Is(err, xray.ErrRejected) {
		t.Fatalf("unknown user = %v", err)
	}
	dead := *p
	dead.Port = xraytest.Port(t)
	if _, err := startVLESS(ctx, &dead, server); !errors.Is(err, xray.ErrNoAnswer) {
		t.Fatalf("closed port = %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := startVLESS(cancelled, p, server); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled start = %v", err)
	}
}
