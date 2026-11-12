// Package xraytest runs the server side of a VLESS path in-process, on 127.0.0.1, for tests: a vless inbound, a freedom
// outbound that reaches loopback, and for REALITY a local TLS 1.3 server as the site it imitates. Nothing leaves the
// machine. It is only ever imported by tests, so none of it is linked into the service.
package xraytest

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/xray"
	realitylib "github.com/xtls/reality"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/transport/internet/reality"
)

// UUID is the one user every server here knows.
const UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"

// Port is a free TCP port on loopback.
func Port(t testing.TB) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// MaskSite is a TLS 1.3 server with a throw-away certificate for "mask.test": what REALITY's dest points at.
func MaskSite(t testing.TB) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mask.test"}, DNSNames: []string{"mask.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// REALITY's start-up probe cannot finish this handshake (it does not trust the certificate) and
			// reads until the site hangs up; hanging up soon keeps that short.
			time.AfterFunc(300*time.Millisecond, func() { c.Close() })
			go func() { _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	return l.Addr().String()
}

// Server runs the server for a client profile p (host, port, user and REALITY key are filled in) and returns the profile
// to dial it with. A non-empty override sends every target to that one address, whatever name the client asked for.
func Server(t testing.TB, p profile.VLESS, override string) *profile.VLESS {
	t.Helper()
	p.Host, p.Port, p.UUID = "127.0.0.1", Port(t), UUID
	var dest string
	stream, err := xray.StreamConfig(&p)
	if err != nil {
		t.Fatal(err)
	}
	switch p.Security {
	case "reality":
		private, err := ecdhPrivate()
		if err != nil {
			t.Fatal(err)
		}
		public, _ := PublicKey(private)
		copy(p.PublicKey[:], public)
		dest = MaskSite(t)
		stream.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&reality.Config{
			Dest: dest, Type: "tcp", ServerNames: []string{p.SNI}, PrivateKey: private, ShortIds: [][]byte{p.ShortID[:]},
		})}
	}
	flow := p.Flow
	user := &vless.Account{Id: UUID, Flow: flow}
	// freedom refuses loopback by default; the targets here are all on loopback
	freedomConfig := &freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}
	if override != "" { // every target goes to one address, whatever name the client asked for
		addr := netip.MustParseAddrPort(override)
		freedomConfig.DestinationOverride = &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.IPAddress(addr.Addr().AsSlice())), Port: uint32(addr.Port())}}
	}
	config := &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList:       &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(p.Port))}},
				Listen:         xnet.NewIPOrDomain(xnet.LocalHostIP),
				StreamSettings: stream,
			}),
			ProxySettings: serial.ToTypedMessage(&vlessin.Config{Users: []*protocol.User{{Account: serial.ToTypedMessage(user)}}, Decryption: "none"}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(freedomConfig)}},
	}
	x, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	if p.Security == "reality" { // a client that comes before REALITY's start-up probe is done waits 5 s for it
		deadline := time.Now().Add(5 * time.Second)
		for alpn := 0; alpn < 3; alpn++ {
			key := dest + " " + p.SNI + " " + strconv.Itoa(alpn)
			for time.Now().Before(deadline) {
				if v, ok := realitylib.GlobalPostHandshakeRecordsLens.Load(key); ok {
					if _, done := v.([]int); done {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	return &p
}

// TCPEcho echoes every stream; it returns its address.
func TCPEcho(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// UDPEcho answers every datagram with "echo:" and the datagram; false when address cannot be bound.
func UDPEcho(t testing.TB, address string) (string, bool) {
	t.Helper()
	c, err := net.ListenPacket("udp4", address)
	if err != nil {
		return "", false
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().String(), true
}

// RealityProfile is a client profile for a REALITY server; Server fills in the rest.
func RealityProfile(transport, flow, mode string) profile.VLESS {
	p := profile.VLESS{Transport: transport, Flow: flow, Security: "reality", SNI: "mask.test", Fingerprint: "chrome",
		ShortID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if transport == "xhttp" {
		p.Path, p.Mode = "/xh", mode
	}
	return p
}

func ecdhPrivate() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// PublicKey is the REALITY public key of a private one.
func PublicKey(private []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// OtherKey is a public key the server does not hold the private half of.
func OtherKey() [32]byte {
	private, _ := ecdhPrivate()
	public, _ := PublicKey(private)
	var out [32]byte
	copy(out[:], public)
	return out
}
