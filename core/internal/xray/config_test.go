package xray

import (
	"net/netip"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

func sample(security, transport string) *profile.VLESS {
	p := &profile.VLESS{Host: "node.example", Port: 8443, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5", Transport: transport,
		Security: security, SNI: "front.example", Fingerprint: "firefox"}
	switch transport {
	case "xhttp":
		p.Path, p.Mode, p.HTTPHost, p.XPadding = "/xh", "stream-up", "cdn.example", [2]int32{10, 20}
	case "ws":
		p.Path, p.HTTPHost = "/ws", "cdn.example"
	}
	if security == "reality" {
		p.PublicKey[0], p.ShortID[0], p.SpiderX = 7, 9, "/crawl?p=100-200&c=3&t=4-5"
	} else {
		p.ALPN = []string{"h2"}
	}
	return p
}

func TestBuildHasOnlyAnOutbound(t *testing.T) {
	config, err := build(sample("reality", "raw"), netip.MustParseAddr("203.0.113.5"), "Wi-Fi")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Inbound) != 0 || len(config.Outbound) != 1 {
		t.Fatalf("%d inbounds, %d outbounds", len(config.Inbound), len(config.Outbound))
	}
	for _, app := range config.App { // no log, router, DNS, stats or command service is part of it
		switch app.Type {
		case "xray.app.dispatcher.Config", "xray.app.proxyman.InboundConfig", "xray.app.proxyman.OutboundConfig":
		default:
			t.Errorf("unexpected app %q", app.Type)
		}
	}
	proxySettings, _ := config.Outbound[0].ProxySettings.GetInstance()
	server := proxySettings.(*vlessout.Config).Vnext
	// the address, never the name: Xray must have nothing to look up
	if server.Address.GetAddress() == nil || server.Address.GetDomain() != "" || netip.AddrFrom4([4]byte(server.Address.GetIp())).String() != "203.0.113.5" || server.Port != 8443 {
		t.Fatalf("server = %v", server)
	}
	sender, _ := config.Outbound[0].SenderSettings.GetInstance()
	if sender.(*proxyman.SenderConfig).StreamSettings.SocketSettings.Interface != "Wi-Fi" {
		t.Error("interface binding not set")
	}
}

func TestBuildFlowAndAccount(t *testing.T) {
	for flow, want := range map[string]string{"": "", profile.VLESSFlowVision: "xtls-rprx-vision-udp443"} {
		p := sample("reality", "raw")
		p.Flow = flow
		config, err := build(p, netip.MustParseAddr("203.0.113.5"), "")
		if err != nil {
			t.Fatal(err)
		}
		proxySettings, _ := config.Outbound[0].ProxySettings.GetInstance()
		account, _ := proxySettings.(*vlessout.Config).Vnext.User.Account.GetInstance()
		if got := account.(*vless.Account); got.Flow != want || got.Id != p.UUID || got.Encryption != "none" {
			t.Errorf("flow %q: account = %v", flow, got)
		}
		sender, _ := config.Outbound[0].SenderSettings.GetInstance()
		if sender.(*proxyman.SenderConfig).StreamSettings.SocketSettings != nil {
			t.Error("a socket option is set without an interface")
		}
	}
}

func streamOf(t *testing.T, p *profile.VLESS) *internet.StreamConfig {
	t.Helper()
	stream, err := StreamConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestStreamConfig(t *testing.T) {
	stream := streamOf(t, sample("reality", "xhttp"))
	if stream.ProtocolName != "splithttp" || stream.SecurityType != "xray.transport.internet.reality.Config" {
		t.Fatalf("xhttp+reality = %q, %q", stream.ProtocolName, stream.SecurityType)
	}
	transport, _ := stream.TransportSettings[0].Settings.GetInstance()
	x := transport.(*splithttp.Config)
	if x.Path != "/xh" || x.Host != "cdn.example" || x.Mode != "stream-up" || x.XPaddingBytes.From != 10 || x.XPaddingBytes.To != 20 ||
		x.XPaddingKey != "x_padding" || x.Xmux.MaxConnections.From != 3 {
		t.Errorf("xhttp config = %v", x)
	}
	security, _ := stream.SecuritySettings[0].GetInstance()
	r := security.(*reality.Config)
	if r.Fingerprint != "firefox" || r.ServerName != "front.example" || r.PublicKey[0] != 7 || len(r.ShortId) != 8 || r.ShortId[0] != 9 || r.Show {
		t.Errorf("reality config = %v", r)
	}
	// "p", "c", "t" of the spider path become ranges, the rest of the query stays out of the path
	if r.SpiderX != "/crawl" || len(r.SpiderY) != 10 || r.SpiderY[0] != 100 || r.SpiderY[1] != 200 || r.SpiderY[2] != 3 || r.SpiderY[3] != 3 || r.SpiderY[4] != 4 || r.SpiderY[5] != 5 {
		t.Errorf("spider = %q %v", r.SpiderX, r.SpiderY)
	}

	stream = streamOf(t, sample("tls", "ws"))
	if stream.ProtocolName != "websocket" || stream.SecurityType != "xray.transport.internet.tls.Config" {
		t.Fatalf("ws+tls = %q, %q", stream.ProtocolName, stream.SecurityType)
	}
	transport, _ = stream.TransportSettings[0].Settings.GetInstance()
	if w := transport.(*websocket.Config); w.Path != "/ws" || w.Host != "cdn.example" {
		t.Errorf("ws config = %v", w)
	}
	security, _ = stream.SecuritySettings[0].GetInstance()
	// Xray's ordinary certificate check: no pin, no name override, no switch that turns it off exists in the config
	if c := security.(*tls.Config); c.ServerName != "front.example" || len(c.NextProtocol) != 1 || c.Fingerprint != "firefox" ||
		len(c.PinnedPeerCertSha256) != 0 || len(c.VerifyPeerCertByName) != 0 || c.DisableSystemRoot {
		t.Errorf("tls config = %v", c)
	}

	if stream = streamOf(t, sample("reality", "raw")); stream.ProtocolName != "tcp" {
		t.Errorf("raw = %q", stream.ProtocolName)
	}
}

func TestStartRefusesWhatItDoesNotKnow(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.5")
	for name, change := range map[string]func(*profile.VLESS){
		"transport": func(p *profile.VLESS) { p.Transport = "grpc" },
		"security":  func(p *profile.VLESS) { p.Security = "none" },
		"spider":    func(p *profile.VLESS) { p.SpiderX = "/x?p=9-1" },
	} {
		p := sample("reality", "raw")
		change(p)
		if x, err := Start(p, addr, ""); err == nil {
			_ = x.Close()
			t.Errorf("%s: started", name)
		}
	}
	if _, err := Start(nil, addr, ""); err == nil {
		t.Error("started without a profile")
	}
	if _, err := Start(sample("reality", "raw"), netip.Addr{}, ""); err == nil {
		t.Error("started without a server address")
	}
}
