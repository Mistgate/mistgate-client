//go:build windows

package diag

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/apernet/hysteria/core/v2/client"
	coreerrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type interfaceInfo struct {
	Index uint32
	Kind  string
	DNS   []netip.Addr
}

func physicalNetwork() (interfaceInfo, error) {
	index, err := netcfg.PhysicalInterfaceIndex4()
	if err != nil || index == 0 {
		return interfaceInfo{}, errors.New("offline")
	}
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return interfaceInfo{}, errors.New("offline")
	}
	for _, adapter := range addresses {
		if adapter.IfIndex != index {
			continue
		}
		kind := "other"
		switch adapter.IfType {
		case 71:
			kind = "wifi"
		case 6:
			kind = "ethernet"
		case 243, 244:
			kind = "mobile"
		}
		dns, _ := adapter.LUID.DNS()
		ipv4 := dns[:0]
		for _, server := range dns {
			if server.Is4() {
				ipv4 = append(ipv4, server)
			}
		}
		return interfaceInfo{Index: index, Kind: kind, DNS: ipv4}, nil
	}
	return interfaceInfo{}, errors.New("offline")
}

func interfaceFor(destination netip.Addr, fallback interfaceInfo) interfaceInfo {
	if index, err := netcfg.PhysicalInterfaceIndexFor(destination); err == nil && index != 0 {
		fallback.Index = index
	}
	return fallback
}

func listenPacketBound(ctx context.Context, physical interfaceInfo) (net.PacketConn, error) {
	var config net.ListenConfig
	config.Control = netcfg.SocketControl(physical.Index)
	return config.ListenPacket(ctx, "udp4", ":0")
}

func boundDialer(physical interfaceInfo) *net.Dialer {
	return &net.Dialer{Control: netcfg.SocketControl(physical.Index)}
}

func dialBound(ctx context.Context, network, address string, physical interfaceInfo) (net.Conn, error) {
	return boundDialer(physical).DialContext(ctx, network, address)
}

func resolveHost(ctx context.Context, host string, physical interfaceInfo, _ Config) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, errors.New("IPv6 endpoint is unsupported")
	}
	if len(physical.DNS) == 0 {
		return netip.Addr{}, errors.New("no physical DNS resolver")
	}
	query, id, err := makeDNSQuery(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, server := range physical.DNS {
		response, err := dnsExchange(ctx, server, query, physical)
		if err != nil {
			continue
		}
		answer, err := parseDNSAnswer(response, id)
		if err == nil && answer.Answered && len(answer.Addresses) > 0 {
			return answer.Addresses[0], nil
		}
	}
	return netip.Addr{}, errors.New("host lookup failed")
}

func dnsExchange(ctx context.Context, server netip.Addr, query []byte, physical interfaceInfo) ([]byte, error) {
	if !server.Is4() {
		return nil, errors.New("physical resolver is not IPv4")
	}
	conn, err := listenPacketBound(ctx, physical)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	if _, err := conn.WriteTo(query, &net.UDPAddr{IP: net.IP(server.AsSlice()), Port: 53}); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	response := make([]byte, 4096)
	count, _, err := conn.ReadFrom(response)
	if err != nil {
		return nil, err
	}
	return response[:count], nil
}

func dohRequest(ctx context.Context, endpoint string, physical interfaceInfo) ([]byte, error) {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := resolveHost(ctx, host, physical, Config{})
		if err != nil {
			return nil, err
		}
		return dialBound(ctx, network, net.JoinHostPort(ip.String(), port), physical)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/dns-message")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/dns-message" {
		return nil, errors.New("DoH request failed")
	}
	message, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil || len(message) == 0 || len(message) >= 4096 {
		return nil, errors.New("invalid DoH response")
	}
	return message, nil
}

func attemptProfile(ctx context.Context, p profile.Profile, endpoint netip.AddrPort, physical interfaceInfo, config Config) (time.Duration, error) {
	switch p.Protocol {
	case "hysteria2":
		return attemptHy2(ctx, p.Hy2, endpoint, physical)
	case "awg":
		return attemptAWG(ctx, p.AWG, endpoint, physical, config.AWGTimeout)
	default:
		return 0, errors.New("unsupported protocol")
	}
}

type hy2BoundFactory struct {
	ctx      context.Context
	physical interfaceInfo
	kind     string
	password []byte
	mu       sync.Mutex
	conn     net.PacketConn
	stop     func() bool
	err      error
	sent     time.Time // the first packet out
	answered time.Time // the first packet in
}

func (f *hy2BoundFactory) New(net.Addr) (net.PacketConn, error) {
	conn, err := listenPacketBound(f.ctx, f.physical)
	if err != nil {
		f.mu.Lock()
		f.err = err
		f.mu.Unlock()
		return nil, err
	}
	f.mu.Lock()
	f.conn = conn
	f.stop = context.AfterFunc(f.ctx, func() { _ = conn.Close() })
	f.mu.Unlock()
	conn = &timedConn{PacketConn: conn, factory: f}
	if f.kind == "none" {
		return conn, nil
	}
	var wrapped net.PacketConn
	if f.kind == "gecko" {
		wrapped, err = obfs.WrapPacketConnGecko(conn, obfs.GeckoOptions{Password: f.password})
	} else {
		wrapped, err = obfs.WrapPacketConnSalamander(conn, f.password)
	}
	if err != nil {
		f.mu.Lock()
		f.err = err
		f.mu.Unlock()
		f.close()
		return nil, err
	}
	return wrapped, nil
}

// timedConn notes when the first packet left and when the first one came back: one round trip to the server, without
// the rest of the handshake (the second flight, the certificate check, the authentication request).
type timedConn struct {
	net.PacketConn
	factory *hy2BoundFactory
}

func (c *timedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.factory.mu.Lock()
	if c.factory.sent.IsZero() {
		c.factory.sent = time.Now()
	}
	c.factory.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *timedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.factory.mu.Lock()
		if c.factory.answered.IsZero() {
			c.factory.answered = time.Now()
		}
		c.factory.mu.Unlock()
	}
	return n, addr, err
}

// roundTrip is the time from the first packet out to the first packet in; zero when there was no answer.
func (f *hy2BoundFactory) roundTrip() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sent.IsZero() || f.answered.IsZero() {
		return 0
	}
	return f.answered.Sub(f.sent)
}

func (f *hy2BoundFactory) failure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *hy2BoundFactory) close() {
	f.mu.Lock()
	conn, stop := f.conn, f.stop
	f.conn, f.stop = nil, nil
	f.mu.Unlock()
	if stop != nil {
		stop()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func attemptHy2(ctx context.Context, p *profile.Hy2, endpoint netip.AddrPort, physical interfaceInfo) (time.Duration, error) {
	if p == nil || ctx.Err() != nil {
		return 0, errNoAnswer
	}
	started := time.Now()
	factory := &hy2BoundFactory{ctx: ctx, physical: physical, kind: p.Obfs, password: []byte(p.ObfsPassword)}
	tlsConfig := client.TLSConfig{ServerName: p.ServerName, InsecureSkipVerify: p.Insecure}
	if p.HasPin {
		pin := p.PinSHA256
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server certificate missing")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], pin[:]) != 1 {
				return errors.New("server certificate pin mismatch")
			}
			return nil
		}
	}
	config := &client.Config{
		ConnFactory: factory,
		ServerAddr:  &net.UDPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port()), Zone: endpoint.Addr().Zone()},
		Auth:        p.Auth, TLSConfig: tlsConfig,
	}
	done := make(chan struct {
		err error
	}, 1)
	go func() {
		hclient, _, err := client.NewClient(config)
		if hclient != nil {
			_ = hclient.Close()
		}
		factory.close()
		done <- struct{ err error }{err}
	}()
	select {
	case outcome := <-done:
		if outcome.err == nil {
			// the whole handshake proves the server works; the number is one round trip, like a ping
			if rtt := factory.roundTrip(); rtt > 0 {
				return rtt, nil
			}
			return time.Since(started), nil
		}
		if err := factory.failure(); err != nil {
			return 0, err
		}
		var authErr coreerrs.AuthError
		if errors.As(outcome.err, &authErr) {
			return 0, errAuthRejected
		}
		var configErr coreerrs.ConfigError
		if errors.As(outcome.err, &configErr) {
			return 0, outcome.err
		}
		return 0, errNoAnswer
	case <-ctx.Done():
		factory.close()
		return 0, errNoAnswer
	}
}

func attemptAWG(ctx context.Context, p *profile.AWG, endpoint netip.AddrPort, physical interfaceInfo, timeout time.Duration) (time.Duration, error) {
	if p == nil || ctx.Err() != nil {
		return 0, errNoAnswer
	}
	addresses := make([]netip.Addr, 0, len(p.Addresses))
	for _, address := range p.Addresses {
		if address.IsValid() {
			addresses = append(addresses, address.Addr())
		}
	}
	if len(addresses) == 0 {
		return 0, errors.New("AmneziaWG profile has no tunnel address")
	}
	tunDevice, _, err := netstack.CreateNetTUN(addresses, nil, p.MTU)
	if err != nil {
		return 0, err
	}
	gated := newGatedTun(tunDevice)
	bind := conn.NewDefaultBind()
	awgDevice := device.NewDevice(gated, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := awgDevice.IpcSet(p.UAPI(endpoint)); err != nil {
		gated.release()
		awgDevice.Close()
		return 0, errBadConfig
	}
	gated.release()
	if err := awgDevice.Up(); err != nil {
		awgDevice.Close()
		return 0, err
	}
	defer awgDevice.Close()
	interfaceBind, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return 0, errors.New("AmneziaWG bind cannot select an interface")
	}
	if err := interfaceBind.BindSocketToInterface4(physical.Index, false); err != nil {
		return 0, err
	}
	keyBytes, err := hex.DecodeString(p.ServerKey)
	if err != nil || len(keyBytes) != 32 {
		return 0, errors.New("AmneziaWG peer key is invalid")
	}
	var serverKey [32]byte
	copy(serverKey[:], keyBytes)
	started := time.Now()
	if peer := awgDevice.LookupPeer(device.NoisePublicKey(serverKey)); peer != nil {
		_ = peer.SendHandshakeInitiation(false)
	}
	if err := waitHandshake(ctx, awgDevice, p.ServerKey, timeout); err != nil {
		if ctx.Err() != nil {
			return 0, errNoAnswer
		}
		return 0, errNoAnswer
	}
	return time.Since(started), nil
}

func waitHandshake(ctx context.Context, awgDevice *device.Device, serverKey string, timeout time.Duration) error {
	ticker := time.NewTicker(5 * time.Millisecond) // the answer is one round trip away: a coarse tick would show in the number
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		text, err := awgDevice.IpcGet()
		if err == nil && handshakeSeen(text, serverKey) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handshakeSeen(text, serverKey string) bool {
	scanner := bufio.NewScanner(strings.NewReader(text))
	var active bool
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			active = strings.EqualFold(value, serverKey)
		} else if active && key == "last_handshake_time_sec" {
			seconds, err := strconv.ParseInt(value, 10, 64)
			return err == nil && seconds > 0
		}
	}
	return false
}

type gatedTun struct {
	tun.Device
	once  sync.Once
	close sync.Once
	ready chan struct{}
	done  chan struct{}
}

func newGatedTun(device tun.Device) *gatedTun {
	return &gatedTun{Device: device, ready: make(chan struct{}), done: make(chan struct{})}
}

func (g *gatedTun) release() { close(g.ready) }

func (g *gatedTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		select {
		case <-g.ready:
			return 0, nil
		case <-g.done:
			return 0, os.ErrClosed
		}
	}
	return g.Device.Read(bufs, sizes, offset)
}

func (g *gatedTun) Close() error {
	g.close.Do(func() { close(g.done) })
	return g.Device.Close()
}

func tlsProbe(ctx context.Context, host string, physical interfaceInfo, config Config) bool {
	name, port, err := parseEndpoint(host, 443)
	if err != nil || name == "" {
		return false
	}
	ip, err := resolveHost(ctx, name, physical, config)
	if err != nil {
		return false
	}
	conn, err := dialBound(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), physical)
	if err != nil {
		return false
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
	return tlsConn.HandshakeContext(ctx) == nil
}
