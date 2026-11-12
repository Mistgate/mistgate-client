// Package xray runs one VLESS path on an embedded Xray-core instance: no inbounds, one outbound, and connections taken
// out of it with core.Dial. Only the parts a VLESS client needs are linked in (no routing, DNS, stats or commands).
package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound" // the core insists on an inbound manager
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// Xray's log is process-wide. Nothing registers a handler here (app/log is not part of the config), and this one lets
// no severity through, so no message is even built: it would name servers and targets.
type silent struct{}

func (silent) Handle(xlog.Message)     {}
func (silent) Severity() xlog.Severity { return xlog.Severity_Unknown }

func init() { xlog.RegisterHandler(silent{}) }

var startMu sync.Mutex

// Instance is a started Xray with one VLESS outbound.
type Instance struct {
	x      *core.Instance
	ctx    context.Context // sessions live as long as the instance, not as long as the call that opened them
	cancel context.CancelFunc
}

// Start builds and starts Xray for p. It dials only server (the address p.Host resolved to, so Xray never resolves a
// name). A non-empty iface binds its sockets to that network interface; the engine leaves it empty because the
// route to the server already goes around the tunnel.
func Start(p *profile.VLESS, server netip.Addr, iface string) (*Instance, error) {
	config, err := build(p, server, iface)
	if err != nil {
		return nil, err
	}
	startMu.Lock() // New sets a few package-level variables of Xray (its system dialer's DNS client and outbound manager)
	x, err := core.New(config)
	if err != nil {
		startMu.Unlock()
		return nil, errors.New("create Xray instance")
	}
	err = x.Start()
	startMu.Unlock()
	if err != nil {
		_ = x.Close()
		return nil, errors.New("start Xray instance")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Instance{x: x, ctx: ctx, cancel: cancel}, nil
}

// Close ends the instance and every connection taken out of it.
func (i *Instance) Close() error {
	i.cancel()
	return i.x.Close()
}

// DialTCP opens a stream to host:port through the server. The server resolves a name. VLESS gives no answer before
// the target does, so a refused or unreachable target shows as an error on the first read, not here.
func (i *Instance) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return i.dial(ctx, i.ctx, tcpDest(host, port))
}

// DialUDP opens one UDP flow to target through the server; each write is one datagram, each read one datagram.
func (i *Instance) DialUDP(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	return i.dial(ctx, i.ctx, xnet.UDPDestination(xnet.IPAddress(target.Addr().AsSlice()), xnet.Port(target.Port())))
}

func tcpDest(host string, port uint16) xnet.Destination {
	return xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
}

// dial: ctx only stops a dial that has not started; the connection lives in session, which is the instance's, so a
// caller's dial timeout does not cut the connection it made.
func (i *Instance) dial(ctx, session context.Context, dest xnet.Destination) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	return core.Dial(session, i.x, dest)
}

func build(p *profile.VLESS, server netip.Addr, iface string) (*core.Config, error) {
	if p == nil || !server.IsValid() {
		return nil, errors.New("no VLESS profile")
	}
	stream, err := StreamConfig(p)
	if err != nil {
		return nil, err
	}
	if iface != "" {
		stream.SocketSettings = &internet.SocketConfig{Interface: iface}
	}
	flow := p.Flow
	if flow == profile.VLESSFlowVision {
		// "-udp443" is Xray's switch for letting QUIC through Vision (it is cut off before the wire); without it
		// every UDP/443 flow is refused and HTTP/3 only works by falling back to TCP.
		flow += "-udp443"
	}
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "vless",
			ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(xnet.IPAddress(server.AsSlice())),
				Port:    uint32(p.Port),
				User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
					Id: p.UUID, Flow: flow, Encryption: "none",
				})},
			}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: stream}),
		}},
	}, nil
}

// StreamConfig is what Xray's own JSON loader would build for the panel's transport and security, with the same
// defaults (a server reads the ones it needs from the same places). The tests build their servers from it too.
func StreamConfig(p *profile.VLESS) (*internet.StreamConfig, error) {
	stream := &internet.StreamConfig{}
	switch p.Transport {
	case "raw":
		stream.ProtocolName = "tcp"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})}}
	case "ws":
		stream.ProtocolName = "websocket"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "websocket", Settings: serial.ToTypedMessage(&websocket.Config{Path: p.Path, Host: p.HTTPHost})}}
	case "xhttp":
		config := &splithttp.Config{
			Host: p.HTTPHost, Path: p.Path, Mode: p.Mode,
			XPaddingKey: "x_padding", XPaddingHeader: "X-Padding", XPaddingPlacement: "queryInHeader", XPaddingMethod: "repeat-x",
			UplinkHTTPMethod: "POST", SessionIDPlacement: "path", SeqPlacement: "path",
			UplinkDataPlacement: splithttp.PlacementAuto, UplinkDataKey: "X-Data",
			Xmux: &splithttp.XmuxConfig{
				MaxConnections:   &splithttp.RangeConfig{From: 3, To: 3},
				HMaxRequestTimes: &splithttp.RangeConfig{From: 600, To: 900},
				HMaxReusableSecs: &splithttp.RangeConfig{From: 1800, To: 3000},
			},
		}
		if p.XPadding != [2]int32{} {
			config.XPaddingBytes = &splithttp.RangeConfig{From: p.XPadding[0], To: p.XPadding[1]}
		}
		stream.ProtocolName = "splithttp"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(config)}}
	default:
		return nil, errors.New("unsupported VLESS transport")
	}
	switch p.Security {
	case "reality":
		config := &reality.Config{
			Fingerprint: p.Fingerprint, ServerName: p.SNI, PublicKey: p.PublicKey[:], ShortId: p.ShortID[:],
			SpiderX: "/", SpiderY: make([]int64, 10),
		}
		if p.SpiderX != "" {
			if err := spider(config, p.SpiderX); err != nil {
				return nil, err
			}
		}
		stream.SecurityType = serial.GetMessageType(&reality.Config{})
		stream.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(config)}
	case "tls":
		stream.SecurityType = serial.GetMessageType(&tls.Config{})
		stream.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&tls.Config{
			ServerName: p.SNI, NextProtocol: p.ALPN, Fingerprint: p.Fingerprint,
		})}
	default:
		return nil, errors.New("unsupported VLESS security")
	}
	return stream, nil
}

// spider takes REALITY's crawler path and its p, c, t, i, r ranges out of the query, as Xray's loader does. The crawler
// runs on the connection to the server only when the server's answer is not REALITY's.
func spider(config *reality.Config, text string) error {
	u, err := url.Parse(text)
	if err != nil {
		return errors.New("invalid REALITY spider path")
	}
	q := u.Query()
	for index, name := range []string{"p", "c", "t", "i", "r"} {
		if value := q.Get(name); value != "" {
			from, to, isRange := strings.Cut(value, "-")
			if !isRange {
				to = from
			}
			lo, err1 := strconv.ParseInt(from, 10, 64)
			hi, err2 := strconv.ParseInt(to, 10, 64)
			if err1 != nil || err2 != nil || lo < 0 || hi < lo {
				return errors.New("invalid REALITY spider range")
			}
			config.SpiderY[2*index], config.SpiderY[2*index+1] = lo, hi
		}
		q.Del(name)
	}
	u.RawQuery = q.Encode()
	config.SpiderX = u.String()
	return nil
}
