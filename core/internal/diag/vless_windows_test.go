//go:build windows

package diag

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/xray"
	"github.com/mistgate/mistgate-client/core/internal/xray/xraytest"
)

func loopbackInterface(t *testing.T) interfaceInfo {
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			return interfaceInfo{Index: uint32(i.Index), Kind: "other"}
		}
	}
	t.Skip("no loopback interface")
	return interfaceInfo{}
}

// The server's socket is bound to an interface, as outside the tunnel; here that interface is loopback.
func TestAttemptVLESS(t *testing.T) {
	old := xray.CheckTargets
	xray.CheckTargets = []string{xraytest.MaskSite(t)} // the real ones are public addresses
	defer func() { xray.CheckTargets = old }()
	physical := loopbackInterface(t)
	p := xraytest.Server(t, xraytest.RealityProfile("raw", profile.VLESSFlowVision, ""), "")
	endpoint := netip.AddrPortFrom(netip.MustParseAddr(p.Host), p.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rtt, err := attemptVLESS(ctx, p, endpoint, physical)
	if err != nil || rtt <= 0 {
		t.Fatalf("working server: %v, %v", rtt, err)
	}
	wrong := *p
	wrong.UUID = "00000000-0000-4000-8000-000000000001"
	if _, err := attemptVLESS(ctx, &wrong, endpoint, physical); !errors.Is(err, errAuthRejected) {
		t.Errorf("unknown user: %v", err)
	}
	dead := netip.AddrPortFrom(endpoint.Addr(), xraytest.Port(t))
	if _, err := attemptVLESS(ctx, p, dead, physical); !errors.Is(err, errNoAnswer) {
		t.Errorf("closed port: %v", err)
	}
	broken := *p
	broken.Transport = "carrier-pigeon"
	if _, err := attemptVLESS(ctx, &broken, endpoint, physical); !errors.Is(err, errBadConfig) {
		t.Errorf("unsupported transport: %v", err)
	}
	if _, err := attemptProfile(ctx, profile.Profile{ID: "x", Protocol: "vless", VLESS: p}, endpoint, physical, Config{}); err != nil {
		t.Errorf("through attemptProfile: %v", err)
	}
}
