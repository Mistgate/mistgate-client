//go:build windows

package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/apernet/hysteria/core/v2/client"
	coreerrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/mistgate/mistgate-client/core/internal/firewall"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var killSwitchWarning sync.Once

type Real struct {
	load   func() ([]profile.Profile, error)
	verify string

	lifecycle sync.Mutex
	mu        sync.Mutex
	current   *realRun
	resolved  map[string]netip.Addr
	changed   chan struct{}
	routeCB   *winipcfg.RouteChangeCallback
}

type realRun struct {
	cancel  context.CancelFunc
	tunnel  *realTunnel
	hold    bool
	verify  string
	probeIP netip.Addr
	rtt     time.Duration

	lastRX      uint64
	lastTX      uint64
	lastStatsAt time.Time
}

type realTunnel struct {
	mu      sync.Mutex
	closed  bool
	adapter *netcfg.Adapter
	client  client.Client
	bridge  *gvisorBridge
	awg     *device.Device
}

func NewReal(load func() ([]profile.Profile, error), verifyOverride ...string) *Real {
	verify := ""
	if len(verifyOverride) != 0 {
		verify = verifyOverride[0]
	}
	r := &Real{load: load, verify: verify, resolved: make(map[string]netip.Addr), changed: make(chan struct{}, 1)}
	callback, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route == nil || route.DestinationPrefix.Prefix().Bits() != 0 {
			return
		}
		r.mu.Lock()
		isTunnel := false
		if r.current != nil {
			if adapter := r.current.tunnel.adapterSnapshot(); adapter != nil {
				isTunnel = adapter.LUID() == uint64(route.InterfaceLUID)
			}
		}
		r.mu.Unlock()
		if !isTunnel {
			select {
			case r.changed <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		slog.Warn("route change monitor unavailable")
	} else {
		r.routeCB = callback
	}
	return r
}

func (r *Real) Changed() <-chan struct{} { return r.changed }

func (r *Real) Start(ctx context.Context, target Target, report func(Step)) (info Info, retErr error) {
	runCtx, run, startErr := r.startRun(ctx, target.Hold)
	defer func() {
		if retErr != nil {
			r.finish(run)
		}
	}()
	if startErr != nil {
		return Info{}, startErr
	}
	if err := runCtx.Err(); err != nil {
		return Info{}, err
	}

	if r.load == nil {
		return Info{}, failure("no_subscription", "load profiles")
	}
	profiles, err := r.load()
	if err != nil {
		return Info{}, failure("no_subscription", "load profiles")
	}
	if err := runCtx.Err(); err != nil {
		return Info{}, err
	}
	selected, ok := profile.Pick(profiles, target.Server, target.Protocol, target.Sub)
	if !ok {
		return Info{}, failure("no_subscription", "select profile")
	}
	if r.verify != "" {
		selected.Verify = r.verify
	}
	host, port, err := profileEndpoint(selected)
	if err != nil {
		return Info{}, failure("no_subscription", "read profile endpoint")
	}

	step(report, StepResolve)
	serverIP, err := r.resolveServer(runCtx, run, host, target.Hold)
	if err != nil {
		if runCtx.Err() != nil {
			return Info{}, runCtx.Err()
		}
		if !hasDefaultRoute() {
			return Info{}, failure("offline", "resolve server: no default route")
		}
		return Info{}, failure("server_not_found", "resolve server")
	}
	if err := runCtx.Err(); err != nil {
		return Info{}, err
	}
	endpoint := netip.AddrPortFrom(serverIP, port)

	step(report, StepHandshake)
	if selected.Protocol == "hysteria2" {
		hclient, err := startHy2(runCtx, selected.Hy2, endpoint)
		if err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			var authErr coreerrs.AuthError
			if errors.As(err, &authErr) {
				return Info{}, failure("auth_rejected", "Hysteria2 handshake: authentication rejected")
			}
			return Info{}, failure("no_server_answers", "Hysteria2 handshake")
		}
		if !run.tunnel.setClient(hclient) {
			return Info{}, context.Canceled
		}
	} else {
		adapter, err := netcfg.Create(selected.AWG.MTU)
		if err != nil {
			return Info{}, failure("no_server_answers", "AmneziaWG handshake: create adapter")
		}
		if !run.tunnel.setAdapter(adapter) {
			return Info{}, context.Canceled
		}
		err = startAWGHandshake(runCtx, adapter.Device(), selected.AWG, endpoint, run.tunnel)
		if err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			return Info{}, failure("no_server_answers", "AmneziaWG handshake")
		}
	}

	step(report, StepTunnel)
	if err := runCtx.Err(); err != nil {
		return Info{}, err
	}
	adapter := run.tunnel.adapterSnapshot()
	if selected.Protocol == "hysteria2" {
		adapter, err = netcfg.Create(1500)
		if err != nil {
			return Info{}, failure("tunnel_failed", "Hysteria2 tunnel: create adapter")
		}
		if !run.tunnel.setAdapter(adapter) {
			return Info{}, context.Canceled
		}
		dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
		if err := r.setFirewall(run, true, adapter.LUID(), dns); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			return Info{}, failure("tunnel_failed", "enable kill switch")
		}
		if err := adapter.Configure(netcfg.Config{
			MTU:       1500,
			Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			// ponytail: fixed resolvers until settings and the subscription carry them.
			DNS:    dns,
			Bypass: serverIP,
		}); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			if errors.Is(err, netcfg.ErrNoRoute) {
				return Info{}, failure("offline", "Hysteria2 tunnel: no bypass route")
			}
			return Info{}, failure("tunnel_failed", "Hysteria2 tunnel configuration")
		}
		if err := runCtx.Err(); err != nil {
			return Info{}, err
		}
		if err := run.tunnel.createBridge(runCtx, adapter.Device(), 1500); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			return Info{}, failure("tunnel_failed", "Hysteria2 tunnel bridge")
		}
	} else {
		if adapter == nil {
			return Info{}, context.Canceled
		}
		dns := selected.AWG.DNS
		if len(dns) == 0 {
			// ponytail: fixed resolvers until settings and the subscription carry them.
			dns = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
		}
		if err := r.setFirewall(run, true, adapter.LUID(), dns); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			return Info{}, failure("tunnel_failed", "enable kill switch")
		}
		if err := adapter.Configure(netcfg.Config{
			MTU:       selected.AWG.MTU,
			Addresses: selected.AWG.Addresses,
			DNS:       dns,
			Bypass:    serverIP,
		}); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			if errors.Is(err, netcfg.ErrNoRoute) {
				return Info{}, failure("offline", "AmneziaWG tunnel: no bypass route")
			}
			return Info{}, failure("tunnel_failed", "AmneziaWG tunnel configuration")
		}
	}

	step(report, StepVerify)
	verify := selected.Verify
	localIP, ok := firstIPv4(selected, adapter)
	if !ok {
		return Info{}, failure("verify_failed", "verify tunnel: no IPv4 address")
	}
	rtt, err := probeTunnel(runCtx, localIP, verify, 5*time.Second)
	if err != nil {
		if runCtx.Err() != nil {
			return Info{}, runCtx.Err()
		}
		return Info{}, failure("verify_failed", "verify tunnel connection")
	}
	if err := runCtx.Err(); err != nil {
		return Info{}, err
	}

	serverName := selected.Name
	if serverName == "" {
		serverName = selected.ID
	}
	info = Info{Server: serverName, Protocol: selected.Protocol}
	r.mu.Lock()
	if r.current != run || runCtx.Err() != nil {
		r.mu.Unlock()
		return Info{}, context.Canceled
	}
	run.rtt = rtt
	run.verify = verify
	run.probeIP = localIP
	r.mu.Unlock()
	return info, nil
}

func (r *Real) startRun(ctx context.Context, hold bool) (context.Context, *realRun, error) {
	r.lifecycle.Lock()
	runCtx, cancel := context.WithCancel(ctx)
	run := &realRun{cancel: cancel, tunnel: &realTunnel{}, hold: hold, lastStatsAt: time.Now()}
	r.mu.Lock()
	old := r.current
	r.current = run
	r.mu.Unlock()
	var err error
	if hold {
		err = r.setFirewall(run, true, 0, nil)
	}
	if old != nil {
		old.cancel()
		old.tunnel.Close()
	}
	if !hold {
		_ = r.setFirewall(run, false, 0, nil)
	}
	r.lifecycle.Unlock()
	return runCtx, run, err
}

func (r *Real) finish(run *realRun) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.mu.Lock()
	current := r.current == run
	r.mu.Unlock()
	if current {
		if !run.hold {
			_ = r.setFirewall(run, false, 0, nil)
		}
		r.mu.Lock()
		if r.current == run {
			r.current = nil
		}
		r.mu.Unlock()
	}
	run.cancel()
	run.tunnel.Close()
}

func (r *Real) Stop() {
	r.lifecycle.Lock()
	r.mu.Lock()
	run := r.current
	r.current = nil
	r.mu.Unlock()
	if run != nil {
		run.cancel()
		run.tunnel.Close()
	}
	_ = r.setFirewall(nil, false, 0, nil)
	r.lifecycle.Unlock()
}

func (r *Real) setFirewall(run *realRun, enable bool, luid uint64, dns []netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run != nil && r.current != run {
		return context.Canceled
	}
	if !enable {
		firewall.DisableFirewall()
		return nil
	}
	if err := firewall.EnableFirewall(luid, false, dns); err != nil {
		if errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
			killSwitchWarning.Do(func() { slog.Warn("kill switch is off: not running as the Windows service") })
			return nil
		}
		return err
	}
	return nil
}

func (r *Real) Stats() Traffic {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return Traffic{}
	}
	run := r.current
	adapter := run.tunnel.adapterSnapshot()
	if adapter == nil {
		return Traffic{RTTMS: run.rtt.Milliseconds()}
	}
	rx, tx := adapter.Counters()
	now := time.Now()
	elapsed := now.Sub(run.lastStatsAt)
	var rxBPS, txBPS int64
	if elapsed > 0 {
		rxBPS = int64(float64(rx-run.lastRX) * float64(8*time.Second) / float64(elapsed))
		txBPS = int64(float64(tx-run.lastTX) * float64(8*time.Second) / float64(elapsed))
	}
	run.lastRX, run.lastTX, run.lastStatsAt = rx, tx, now
	return Traffic{RXBPS: rxBPS, TXBPS: txBPS, RTTMS: run.rtt.Milliseconds()}
}

func (r *Real) Probe(ctx context.Context) error {
	r.mu.Lock()
	run := r.current
	if run == nil || !run.probeIP.IsValid() || run.tunnel.adapterSnapshot() == nil {
		r.mu.Unlock()
		return errors.New("no active tunnel")
	}
	probeIP, verify := run.probeIP, run.verify
	r.mu.Unlock()
	rtt, err := probeTunnel(ctx, probeIP, verify, 3*time.Second)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != run {
		return context.Canceled
	}
	run.rtt = rtt
	return nil
}

func (r *Real) resolveServer(ctx context.Context, run *realRun, host string, hold bool) (netip.Addr, error) {
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap(), nil
	}
	if hold {
		// ponytail: a moved server needs manual disconnect/connect while held; upgrade = bootstrap through an authenticated tunnel-side resolver.
		r.mu.Lock()
		address, ok := r.resolved[key]
		r.mu.Unlock()
		if ok {
			return address, nil
		}
	}
	address, err := resolveServer(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != run {
		return netip.Addr{}, context.Canceled
	}
	r.resolved[key] = address
	return address, nil
}

func probeTunnel(ctx context.Context, localIP netip.Addr, verify string, timeout time.Duration) (time.Duration, error) {
	targets := []string{verify}
	if verify == "" {
		targets = []string{"1.1.1.1:443", "8.8.8.8:443"}
	}
	var lastErr error
	for _, target := range targets {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(localIP.AsSlice())}}).DialContext(dialCtx, "tcp", target)
		rtt := time.Since(started)
		cancel()
		if err == nil {
			_ = conn.Close()
			return rtt, nil
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no tunnel verification target")
	}
	return 0, lastErr
}

func (t *realTunnel) setAdapter(adapter *netcfg.Adapter) bool {
	t.mu.Lock()
	if !t.closed {
		t.adapter = adapter
		t.mu.Unlock()
		return true
	}
	t.mu.Unlock()
	_ = adapter.Close()
	return false
}

func (t *realTunnel) setClient(hclient client.Client) bool {
	t.mu.Lock()
	if !t.closed {
		t.client = hclient
		t.mu.Unlock()
		return true
	}
	t.mu.Unlock()
	_ = hclient.Close()
	return false
}

func (t *realTunnel) createBridge(ctx context.Context, tunDevice tun.Device, mtu int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return context.Canceled
	}
	bridge, err := newGvisorBridge(ctx, tunDevice, mtu, t.client)
	if err != nil {
		return err
	}
	t.bridge = bridge
	return nil
}

func (t *realTunnel) setAWG(awg *device.Device) bool {
	t.mu.Lock()
	if !t.closed {
		t.awg = awg
		t.mu.Unlock()
		return true
	}
	t.mu.Unlock()
	awg.Close()
	return false
}

func (t *realTunnel) adapterSnapshot() *netcfg.Adapter {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.adapter
}

func (t *realTunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	bridge, awg, hclient, adapter := t.bridge, t.awg, t.client, t.adapter
	t.bridge, t.awg, t.client, t.adapter = nil, nil, nil, nil
	t.mu.Unlock()
	if bridge != nil {
		bridge.Close()
	}
	if awg != nil {
		awg.Close()
	}
	if hclient != nil {
		_ = hclient.Close()
	}
	if adapter != nil {
		_ = adapter.Close()
	}
}

func profileEndpoint(p profile.Profile) (string, uint16, error) {
	switch p.Protocol {
	case "hysteria2":
		if p.Hy2 == nil || p.Hy2.Host == "" || p.Hy2.Port == 0 {
			return "", 0, errors.New("missing Hysteria2 endpoint")
		}
		return p.Hy2.Host, p.Hy2.Port, nil
	case "awg":
		if p.AWG == nil || p.AWG.EndpointHost == "" || p.AWG.EndpointPort == 0 {
			return "", 0, errors.New("missing AmneziaWG endpoint")
		}
		return p.AWG.EndpointHost, p.AWG.EndpointPort, nil
	default:
		return "", 0, errors.New("unsupported profile protocol")
	}
}

func resolveServer(ctx context.Context, host string) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap(), nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, errors.New("server lookup failed")
	}
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() {
			return address, nil
		}
	}
	return addresses[0].Unmap(), nil
}

func hasDefaultRoute() bool {
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			continue
		}
		for _, row := range rows {
			prefix := row.DestinationPrefix.Prefix()
			if prefix.IsValid() && prefix.Bits() == 0 {
				return true
			}
		}
	}
	return false
}

func firstIPv4(p profile.Profile, adapter *netcfg.Adapter) (netip.Addr, bool) {
	if p.Protocol == "awg" && p.AWG != nil {
		for _, address := range p.AWG.Addresses {
			if address.Addr().Is4() {
				return address.Addr(), true
			}
		}
		return netip.Addr{}, false
	}
	return netip.MustParseAddr("198.18.0.1"), adapter != nil
}

func step(report func(Step), current Step) {
	if report != nil {
		report(current)
	}
}

func failure(code, message string) error {
	return &Failure{Code: code, Err: errors.New(message)}
}

type hy2ObfsFactory struct {
	kind     string
	password []byte
}

func (f hy2ObfsFactory) New(net.Addr) (net.PacketConn, error) {
	packetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, errors.New("open Hysteria2 UDP socket")
	}
	var wrapped net.PacketConn
	if f.kind == "gecko" {
		wrapped, err = obfs.WrapPacketConnGecko(packetConn, obfs.GeckoOptions{Password: f.password})
	} else {
		wrapped, err = obfs.WrapPacketConnSalamander(packetConn, f.password)
	}
	if err != nil {
		_ = packetConn.Close()
		return nil, errors.New("configure Hysteria2 obfuscation")
	}
	return wrapped, nil
}

func startHy2(ctx context.Context, p *profile.Hy2, endpoint netip.AddrPort) (client.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Insecure {
		slog.Warn("Hysteria2 TLS verification is disabled")
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type result struct {
		client client.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		addr := &net.UDPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port()), Zone: endpoint.Addr().Zone()}
		tlsConfig := client.TLSConfig{ServerName: p.ServerName}
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
		} else {
			tlsConfig.InsecureSkipVerify = p.Insecure
		}
		config := &client.Config{ServerAddr: addr, Auth: p.Auth, TLSConfig: tlsConfig}
		if p.Obfs != "none" {
			config.ConnFactory = hy2ObfsFactory{kind: p.Obfs, password: []byte(p.ObfsPassword)}
		}
		hclient, err := client.NewReconnectableClient(func() (*client.Config, error) { return config, nil }, nil, false)
		done <- result{client: hclient, err: err}
	}()
	select {
	case outcome := <-done:
		return outcome.client, outcome.err
	case <-connectCtx.Done():
		go func() {
			outcome := <-done
			if outcome.client != nil {
				_ = outcome.client.Close()
			}
		}()
		return nil, connectCtx.Err()
	}
}

func startAWGHandshake(ctx context.Context, tunDevice tun.Device, p *profile.AWG, endpoint netip.AddrPort, tunnel *realTunnel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gated := newGatedTun(tunDevice)
	awgDevice := device.NewDevice(gated, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if !tunnel.setAWG(awgDevice) {
		return context.Canceled
	}
	if err := awgDevice.IpcSet(p.UAPI(endpoint)); err != nil {
		gated.release()
		awgDevice.Close()
		return errors.New("configure AmneziaWG device")
	}
	gated.release()
	if err := awgDevice.Up(); err != nil {
		awgDevice.Close()
		return errors.New("start AmneziaWG device")
	}
	keyBytes, err := hex.DecodeString(p.ServerKey)
	if err != nil || len(keyBytes) != 32 {
		awgDevice.Close()
		return errors.New("decode AmneziaWG peer key")
	}
	var serverKey [32]byte
	copy(serverKey[:], keyBytes)
	peer := awgDevice.LookupPeer(device.NoisePublicKey(serverKey))
	if peer == nil {
		awgDevice.Close()
		return errors.New("find AmneziaWG peer")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		awgDevice.Close()
		return errors.New("send AmneziaWG handshake")
	}
	if err := waitAWGHandshake(ctx, awgDevice, p.ServerKey, 10*time.Second); err != nil {
		awgDevice.Close()
		return err
	}
	return nil
}

type gatedTun struct {
	tun.Device
	first     sync.Once
	readyOnce sync.Once
	closeOnce sync.Once
	ready     chan struct{}
	done      chan struct{}
	closeErr  error
}

func newGatedTun(device tun.Device) *gatedTun {
	return &gatedTun{Device: device, ready: make(chan struct{}), done: make(chan struct{})}
}

func (g *gatedTun) release() { g.readyOnce.Do(func() { close(g.ready) }) }

func (g *gatedTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	first := false
	g.first.Do(func() { first = true })
	if first {
		select {
		case <-g.ready:
			return 0, nil
		case <-g.done:
			return 0, net.ErrClosed
		}
	}
	return g.Device.Read(bufs, sizes, offset)
}

func (g *gatedTun) Close() error {
	g.closeOnce.Do(func() {
		close(g.done)
		g.closeErr = g.Device.Close()
	})
	return g.closeErr
}

func waitAWGHandshake(ctx context.Context, awgDevice *device.Device, serverKey string, timeout time.Duration) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		text, err := awgDevice.IpcGet()
		if err == nil && awgHandshakeSeen(text, serverKey) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return errors.New("wait for AmneziaWG handshake timed out")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func awgHandshakeSeen(text, serverKey string) bool {
	scanner := bufio.NewScanner(strings.NewReader(text))
	var activePeer bool
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			activePeer = strings.EqualFold(value, serverKey)
		} else if activePeer && key == "last_handshake_time_sec" {
			seconds, err := strconv.ParseInt(value, 10, 64)
			return err == nil && seconds > 0
		}
	}
	return false
}
