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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/apernet/hysteria/core/v2/client"
	coreerrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/firewall"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/netcfg"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/stun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var killSwitchWarning sync.Once

type Real struct {
	load        func() ([]profile.Profile, error)
	getSettings func() settings.Settings
	geo         *geo.Store
	verify      string

	lifecycle            sync.Mutex
	mu                   sync.Mutex
	gatewayMu            sync.Mutex
	current              *realRun
	resolved             map[string]netip.Addr
	autoRegion           string
	autoRefreshing       bool
	autoRefreshAgain     bool
	autoRefreshCallbacks []func()
	changed              chan struct{}
	interfaceChanges     chan struct{}
	routeCB              *winipcfg.RouteChangeCallback
	interfaceCB          *winipcfg.InterfaceChangeCallback
	gatewayInterfaces    map[winipcfg.LUID]struct{}
	panelSplit           atomic.Pointer[[]profile.DNSSplit] // the panel's regional resolvers of the profile last started

	// AllowDest, when set before the first connect, vets the addresses a name resolves to inside DialVPN.
	AllowDest func(netip.Addr) bool
}

type realRun struct {
	ctx     context.Context // ends with the run: connections made by DialVPN end with it
	dial    vpnDialer       // set when the tunnel is verified, nil before
	cancel  context.CancelFunc
	tunnel  *realTunnel
	hold    bool
	verify  string
	probeIP netip.Addr
	rtt     time.Duration
	awgID   string // the AmneziaWG profile in use (empty for Hysteria2): nothing else may handshake with its key
	luid    uint64
	dns     []netip.Addr

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

func NewReal(load func() ([]profile.Profile, error), getSettings func() settings.Settings, geoStore *geo.Store, verifyOverride ...string) *Real {
	verify := ""
	if len(verifyOverride) != 0 {
		verify = verifyOverride[0]
	}
	r := &Real{
		load:              load,
		getSettings:       getSettings,
		geo:               geoStore,
		verify:            verify,
		resolved:          make(map[string]netip.Addr),
		changed:           make(chan struct{}, 1),
		interfaceChanges:  make(chan struct{}, 1),
		gatewayInterfaces: make(map[winipcfg.LUID]struct{}),
	}
	diag.LiveAWG = func() (string, time.Duration) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if run := r.current; run != nil && run.probeIP.IsValid() {
			return run.awgID, run.rtt
		}
		return "", 0
	}
	if gateways, err := ipv4GatewayInterfaces(); err == nil {
		r.gatewayInterfaces = gateways
	}
	callback, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route == nil || route.DestinationPrefix.Prefix().Bits() != 0 {
			return
		}
		if !r.isTunnelInterface(route.InterfaceLUID) {
			r.signalChange()
		}
	})
	if err != nil {
		slog.Warn("route change monitor unavailable")
	} else {
		r.routeCB = callback
	}
	interfaceCallback, err := winipcfg.RegisterInterfaceChangeCallback(func(_ winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if iface == nil || iface.Family != windows.AF_INET {
			return
		}
		r.gatewayMu.Lock()
		defer r.gatewayMu.Unlock()
		gateways, err := ipv4GatewayInterfaces()
		if err != nil {
			return
		}
		r.mu.Lock()
		changedGateway := false
		tunnelLUID := uint64(0)
		if r.current != nil {
			if adapter := r.current.tunnel.adapterSnapshot(); adapter != nil {
				tunnelLUID = adapter.LUID()
			}
		}
		for luid := range r.gatewayInterfaces {
			if luid != winipcfg.LUID(tunnelLUID) {
				if _, exists := gateways[luid]; !exists {
					changedGateway = true
				}
			}
		}
		for luid := range gateways {
			if luid != winipcfg.LUID(tunnelLUID) {
				if _, exists := r.gatewayInterfaces[luid]; !exists {
					changedGateway = true
				}
			}
		}
		_, hadGateway := r.gatewayInterfaces[iface.InterfaceLUID]
		_, hasGateway := gateways[iface.InterfaceLUID]
		r.gatewayInterfaces = gateways
		isTunnel := tunnelLUID != 0 && tunnelLUID == uint64(iface.InterfaceLUID)
		r.mu.Unlock()
		if changedGateway || !isTunnel && (hadGateway || hasGateway) {
			select {
			case r.interfaceChanges <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		slog.Warn("interface change monitor unavailable")
	} else {
		r.interfaceCB = interfaceCallback
		go r.debounceInterfaceChanges(time.Second)
	}
	return r
}

func (r *Real) Changed() <-chan struct{} { return r.changed }

func (r *Real) isTunnelInterface(luid winipcfg.LUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return false
	}
	adapter := r.current.tunnel.adapterSnapshot()
	return adapter != nil && adapter.LUID() == uint64(luid)
}

func (r *Real) signalChange() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

func (r *Real) debounceInterfaceChanges(quiet time.Duration) {
	var timer *time.Timer
	var timerC <-chan time.Time
	var last time.Time
	for {
		select {
		case <-r.interfaceChanges:
			last = time.Now()
			if timer == nil {
				timer = time.NewTimer(quiet)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(quiet)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			if delay := debounceDelay(last, time.Now(), quiet); delay > 0 {
				timer.Reset(delay)
				timerC = timer.C
				continue
			}
			last = time.Time{}
			r.signalChange()
		}
	}
}

func ipv4GatewayInterfaces() (map[winipcfg.LUID]struct{}, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	gateways := make(map[winipcfg.LUID]struct{})
	for _, route := range routes {
		if route.DestinationPrefix.Prefix().Bits() == 0 && !route.NextHop.Addr().IsUnspecified() {
			gateways[route.InterfaceLUID] = struct{}{}
		}
	}
	return gateways, nil
}

func (r *Real) EffectiveRoute(configured settings.Settings) string {
	switch configured.RouteMode {
	case "selected":
		return "selected"
	case "all":
		return "all"
	}
	region := r.routeRegion(configured)
	if !geo.ValidRegion(region) || r.geo == nil {
		return "smart"
	}
	if _, available := r.geo.Region(region); !available {
		return "smart"
	}
	return "smart:" + region
}

func (r *Real) RoutePath(configured settings.Settings, target Target, activeProtocol string) string {
	protocol := activeProtocol
	if protocol == "" || protocol == "auto" {
		if r.load != nil {
			if profiles, err := r.load(); err == nil {
				if selected, ok := profile.PickForSettings(profiles, target.Server, target.Protocol, target.Sub, configured.Protocol, configured.Game); ok {
					protocol = selected.Protocol
				}
			}
		}
	}
	if protocol == "" || protocol == "auto" {
		protocol = target.Protocol
	}
	if protocol == "" || protocol == "auto" {
		protocol = configured.Protocol
	}
	if protocol == "awg" && configured.RouteMode == "all" {
		return "native"
	}
	return "forwarder"
}

func (r *Real) routeRegion(configured settings.Settings) string {
	region := configured.RouteRegion
	if region == "" {
		region = "auto"
	}
	if region == "auto" {
		r.mu.Lock()
		region = r.autoRegion
		r.mu.Unlock()
	}
	if region == "auto" || region == "none" || !geo.ValidRegion(region) {
		return ""
	}
	return region
}

func (r *Real) routeDirect(address netip.Addr, name string) bool {
	configured := r.settings()
	var region *geo.Set
	var rules *geo.SiteRules
	if r.geo != nil {
		rules = r.geo.ActiveSiteRules()
		if configured.RouteMode == "smart" {
			if cc := r.routeRegion(configured); cc != "" {
				region, _ = r.geo.Region(cc)
			}
		}
	}
	return directByRules(address, name, configured.RouteMode, region, rules)
}

// nameRoute is the bridge's view of a host name: blocked, or the regional resolver its DNS question goes to (zero: the
// VPN as before). It runs for every DNS question of the machine, so it only reads.
func (r *Real) nameRoute(name string) (block bool, resolver netip.AddrPort) {
	configured := r.settings()
	if configured.RouteMode != "smart" && configured.RouteMode != "selected" {
		return false, netip.AddrPort{}
	}
	var rules *geo.SiteRules
	if r.geo != nil {
		rules = r.geo.ActiveSiteRules()
	}
	region := r.routeRegion(configured)
	switch route, _ := geo.DecideName(name, configured.RouteMode, region, rules); route {
	case geo.NameBlock:
		return true, netip.AddrPort{}
	case geo.NameDirect:
		return false, r.regionResolver(region)
	}
	return false, netip.AddrPort{}
}

func (r *Real) regionResolver(region string) netip.AddrPort {
	var split []profile.DNSSplit
	if p := r.panelSplit.Load(); p != nil {
		split = *p
	}
	return regionResolver(region, split)
}

// CheckSite is routes.check: where the forwarder would send a site now, by the code the flows use.
func (r *Real) CheckSite(configured settings.Settings, name string) geo.Check {
	region := r.routeRegion(configured)
	return r.geo.CheckName(configured.RouteMode, region, name, r.regionResolver(region).IsValid())
}

func (r *Real) Routes(configured settings.Settings) geo.Routes {
	r.mu.Lock()
	autoRegion := r.autoRegion
	r.mu.Unlock()
	return r.geo.Routes(configured.RouteMode, configured.RouteRegion, autoRegion)
}

func (r *Real) setAutoRegion(region string) {
	r.mu.Lock()
	r.autoRegion = region
	r.mu.Unlock()
}

func (r *Real) RefreshAutoRegion(onChange func()) {
	configured := r.settings()
	r.mu.Lock()
	if onChange != nil {
		r.autoRefreshCallbacks = append(r.autoRefreshCallbacks, onChange)
	}
	if r.autoRefreshing {
		r.autoRefreshAgain = true
		r.mu.Unlock()
		return
	}
	if configured.RouteMode != "smart" || !autoRoute(configured.RouteRegion) || r.autoRegion != "" && r.autoRegion != "none" {
		callbacks := r.autoRefreshCallbacks
		r.autoRefreshCallbacks = nil
		r.mu.Unlock()
		for _, callback := range callbacks {
			callback()
		}
		return
	}
	r.autoRefreshing = true
	r.mu.Unlock()
	go r.refreshAutoRegion()
}

func (r *Real) refreshAutoRegion() {
	for {
		configured := r.settings()
		if configured.RouteMode == "smart" && autoRoute(configured.RouteRegion) {
			region := "none"
			if public, err := publicAddress(context.Background()); err == nil && r.geo != nil {
				if detected := r.geo.Detect(public, []string{"ru", "by", "kz", "cn", "ir", "tr"}); detected != "" {
					region = detected
				}
			}
			r.mu.Lock()
			r.autoRegion = region
			r.mu.Unlock()
		}
		r.mu.Lock()
		if r.autoRefreshAgain {
			r.autoRefreshAgain = false
			r.mu.Unlock()
			continue
		}
		r.autoRefreshing = false
		callbacks := r.autoRefreshCallbacks
		r.autoRefreshCallbacks = nil
		r.mu.Unlock()
		for _, callback := range callbacks {
			callback()
		}
		return
	}
}

func autoRoute(region string) bool { return region == "" || region == "auto" }

func publicAddress(ctx context.Context) (netip.Addr, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		server, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err == nil && server.Is4() {
			index, err := netcfg.PhysicalInterfaceIndexFor(server)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Control: netcfg.SocketControl(index)}).DialContext(ctx, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	addresses, err := resolver.LookupNetIP(lookupCtx, "ip4", "stun.l.google.com")
	if err != nil {
		return netip.Addr{}, errors.New("cannot resolve STUN server")
	}
	var server netip.Addr
	for _, address := range addresses {
		if address.Is4() {
			server = address
			break
		}
	}
	if !server.IsValid() {
		return netip.Addr{}, errors.New("STUN server has no IPv4 address")
	}
	index, err := netcfg.PhysicalInterfaceIndexFor(server)
	if err != nil {
		return netip.Addr{}, errors.New("no physical route to STUN server")
	}
	var listen net.ListenConfig
	listen.Control = netcfg.SocketControl(index)
	conn, err := listen.ListenPacket(lookupCtx, "udp4", ":0")
	if err != nil {
		return netip.Addr{}, errors.New("cannot open physical STUN socket")
	}
	defer conn.Close()
	public, err := stun.Query(lookupCtx, conn, netip.AddrPortFrom(server, 19302), 2*time.Second)
	if err != nil {
		return netip.Addr{}, errors.New("STUN did not return an address")
	}
	return public, nil
}

func (r *Real) Start(ctx context.Context, target Target, report func(Step)) (info Info, retErr error) {
	runCtx, run, startErr := r.startRun(ctx, target.Hold)
	defer func() {
		if retErr != nil {
			r.finish(run)
		}
	}()
	if startErr != nil {
		if runCtx.Err() != nil {
			return Info{}, runCtx.Err()
		}
		return Info{}, failure("tunnel_failed", "enable firewall rules")
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
	configured := r.settings()
	selected, ok := profile.PickForSettings(profiles, target.Server, target.Protocol, target.Sub, configured.Protocol, configured.Game)
	if !ok {
		return Info{}, failure("no_subscription", "select profile")
	}
	// Auto is the server that answers quickest now, not the first of the list. No answer from any: the first, as before.
	if target.Server == "" || target.Server == "auto" {
		_, ring, _ := profile.Ring(profiles, target.Server, target.Protocol, target.Sub, configured.Protocol, configured.Game)
		candidates := ring[:0:0]
		for _, p := range ring {
			if !configured.Game || p.Protocol == selected.Protocol { // Game mode has chosen the protocol
				candidates = append(candidates, p)
			}
		}
		// a plain path when the list has one: a relay or a WARP exit answers as soon as its entry does, and is not
		// what Auto should choose by a millisecond
		plain := candidates[:0:0]
		for _, p := range candidates {
			if p.Via == "" || p.Via == "direct" {
				plain = append(plain, p)
			}
		}
		if len(plain) > 0 {
			candidates = plain
		}
		if best := quickestOf(runCtx, candidates); best >= 0 {
			selected = candidates[best]
		}
		if err := runCtx.Err(); err != nil {
			return Info{}, err
		}
	}
	if r.verify != "" {
		selected.Verify = r.verify
	}
	split := selected.PanelSplit
	r.panelSplit.Store(&split)
	host, port, err := profileEndpoint(selected)
	if err != nil {
		return Info{}, failure("no_subscription", "read profile endpoint")
	}

	// AmneziaWG: the round trip is measured now, before the tunnel takes the key (see diag.LiveAWG)
	var before time.Duration
	if selected.Protocol == "awg" {
		before, _ = diag.Handshake(runCtx, selected, fastestTimeout)
		if err := runCtx.Err(); err != nil {
			return Info{}, err
		}
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
	r.setAutoRegion("")
	route := "all"
	useForwarder := configured.RouteMode == "smart" || configured.RouteMode == "selected"
	if configured.RouteMode == "selected" {
		route = "selected"
	} else if configured.RouteMode == "smart" {
		route = "smart"
		region := configured.RouteRegion
		if region == "" {
			region = "auto"
		}
		if region == "auto" {
			r.setAutoRegion("none")
			if public, err := publicAddress(runCtx); err == nil && r.geo != nil {
				if detected := r.geo.Detect(public, []string{"ru", "by", "kz", "cn", "ir", "tr"}); detected != "" {
					r.setAutoRegion(detected)
				}
			}
			r.mu.Lock()
			region = r.autoRegion
			r.mu.Unlock()
		}
		if region != "none" && geo.ValidRegion(region) && r.geo != nil {
			if _, available := r.geo.Region(region); available {
				route = "smart:" + region
			}
		}
	}
	// The tunnel check must go through the tunnel whatever the rules say: in "selected" its address is not selected,
	// would go direct, and the check would say nothing about the tunnel (or fail where that address is blocked).
	var probeAddrs []netip.Addr
	for _, target := range probeTargets(selected.Verify) {
		if parsed, err := netip.ParseAddrPort(target); err == nil {
			probeAddrs = append(probeAddrs, parsed.Addr())
		}
	}
	shouldDirect := func(address netip.Addr, name string) bool {
		return !slices.Contains(probeAddrs, address) && r.routeDirect(address, name)
	}
	hasSiteRules := func() bool {
		if r.geo == nil {
			return false
		}
		rules := r.geo.ActiveSiteRules()
		if rules == nil {
			return false
		}
		switch r.settings().RouteMode {
		case "smart":
			return rules.HasDirect || rules.HasBlock
		case "selected":
			return rules.HasVPN || rules.HasBlock
		default:
			return false
		}
	}
	var track *geo.Tracker // "all" has no forwarder decision to second-guess
	if useForwarder {
		track = r.geo.Failures()
	}

	var awgNet *netstack.Net
	var awgStack bool // AmneziaWG runs its own stack behind the forwarder, not on the adapter itself
	var hy2Client client.Client
	var awgDNS []netip.Addr
	// The settings read here are the ones this attempt uses; a change makes the manager start a new attempt.
	customDNS, customMTU := configured.DNSAddrs(), configured.MTU
	var awgMTU int
	if selected.Protocol == "awg" {
		awgMTU = selected.AWG.MTU
		awgDNS = tunnelDNS(customDNS, selected.AWG.DNS, selected.PanelDNS, defaultTunnelDNS)
		if customMTU != 0 && customMTU < awgMTU {
			awgMTU = customMTU // a size above the server's own only breaks packets
		}
	}

	step(report, StepHandshake)
	if selected.Protocol == "hysteria2" {
		hy2Client, err = startHy2(runCtx, selected.Hy2, endpoint)
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
		if !run.tunnel.setClient(hy2Client) {
			return Info{}, context.Canceled
		}
	} else {
		adapter, err := netcfg.Create(awgMTU)
		if err != nil {
			return Info{}, failure("no_server_answers", "AmneziaWG handshake: create adapter")
		}
		if !run.tunnel.setAdapter(adapter) {
			return Info{}, context.Canceled
		}
		awgTun := adapter.Device()
		// A profile with an IPv6 address goes through the forwarder in "Everything" too: only the forwarder finds out
		// that the server routes no IPv6 and turns it away at once (see noVPN6). On the plain adapter Windows would
		// send IPv6 into a path that carries nothing, and an app without an IPv4 fallback would hang.
		// ponytail: costs the second stack's throughput; a probe on the plain adapter that drops its IPv6 route if this shows.
		awgStack = useForwarder || slices.ContainsFunc(selected.AWG.Addresses, func(a netip.Prefix) bool { return a.Addr().Is6() })
		if awgStack {
			// ponytail: two stacks in a row cost throughput; a packet-level split would be faster.
			addresses := make([]netip.Addr, 0, len(selected.AWG.Addresses))
			for _, address := range selected.AWG.Addresses {
				addresses = append(addresses, address.Addr())
			}
			var err error
			awgTun, awgNet, err = netstack.CreateNetTUN(addresses, awgDNS, awgMTU)
			if err != nil {
				return Info{}, failure("tunnel_failed", "AmneziaWG tunnel: create userspace stack")
			}
		}
		err = startAWGHandshake(runCtx, awgTun, selected.AWG, endpoint, run.tunnel)
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
		mtu := 1500
		if customMTU != 0 {
			mtu = customMTU
		}
		adapter, err = netcfg.Create(mtu)
		if err != nil {
			return Info{}, failure("tunnel_failed", "Hysteria2 tunnel: create adapter")
		}
		if !run.tunnel.setAdapter(adapter) {
			return Info{}, context.Canceled
		}
		dns := tunnelDNS(customDNS, selected.PanelDNS, defaultTunnelDNS)
		configured = r.settings()
		if err := r.setFirewall(run, configured.KillSwitch == "off", adapter.LUID(), dns, configured.LAN); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			if !consoleFirewallUnavailable(err) || configured.KillSwitch == "always" {
				return Info{}, failure("tunnel_failed", "enable firewall rules")
			}
		}
		if err := adapter.Configure(netcfg.Config{
			MTU:       mtu,
			Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			DNS:       dns,
			Bypass:    serverIP,
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
		if err := run.tunnel.createBridge(runCtx, adapter.Device(), mtu, hy2Outbound{client: hy2Client}, directOutbound{}, shouldDirect, hasSiteRules, track, r.nameRoute); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			return Info{}, failure("tunnel_failed", "Hysteria2 tunnel bridge")
		}
	} else {
		if adapter == nil {
			return Info{}, context.Canceled
		}
		dns := awgDNS
		configured = r.settings()
		if err := r.setFirewall(run, configured.KillSwitch == "off", adapter.LUID(), dns, configured.LAN); err != nil {
			if runCtx.Err() != nil {
				return Info{}, runCtx.Err()
			}
			if !consoleFirewallUnavailable(err) || configured.KillSwitch == "always" {
				return Info{}, failure("tunnel_failed", "enable firewall rules")
			}
		}
		if err := adapter.Configure(netcfg.Config{
			MTU:       awgMTU,
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
		if awgStack {
			if awgNet == nil {
				return Info{}, failure("tunnel_failed", "AmneziaWG userspace stack is unavailable")
			}
			if err := run.tunnel.createBridge(runCtx, adapter.Device(), awgMTU, awgOutbound{net: awgNet}, directOutbound{}, shouldDirect, hasSiteRules, track, r.nameRoute); err != nil {
				if runCtx.Err() != nil {
					return Info{}, runCtx.Err()
				}
				return Info{}, failure("tunnel_failed", "AmneziaWG tunnel bridge")
			}
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
	info = Info{Server: serverName, ServerID: selected.ID, Protocol: selected.Protocol, Route: route}
	var proxyDial vpnDialer
	switch {
	case selected.Protocol == "hysteria2":
		proxyDial = hy2Dialer(hy2Outbound{client: hy2Client})
	case awgStack:
		proxyDial = awgStackDialer(awgNet, r.AllowDest)
	default:
		proxyDial = awgPlainDialer(localIP, adapter, awgDNS, r.AllowDest)
	}
	r.mu.Lock()
	if r.current != run || runCtx.Err() != nil {
		r.mu.Unlock()
		return Info{}, context.Canceled
	}
	run.dial = proxyDial
	_ = rtt // the tunnel check's time is not the server's: see keepLatency
	if selected.Protocol == "awg" {
		run.awgID, run.rtt = selected.ID, before
	}
	run.verify = verify
	run.probeIP = localIP
	r.mu.Unlock()
	go r.keepLatency(runCtx, run, selected)
	return info, nil
}

const latencyEvery = 30 * time.Second

// keepLatency keeps the number the window shows beside the speed: one round trip to the server in use, measured
// the way the server list measures it (a handshake outside the tunnel), now and every 30 seconds. The tunnel's own
// probes cannot give it: with the forwarder they are answered inside this process.
func (r *Real) keepLatency(ctx context.Context, run *realRun, p profile.Profile) {
	if p.Protocol == "awg" {
		return // its key is the tunnel's: the number measured before connecting stays
	}
	ticker := time.NewTicker(latencyEvery)
	defer ticker.Stop()
	for {
		if rtt, err := diag.Handshake(ctx, p, fastestTimeout); err == nil {
			r.mu.Lock()
			if r.current == run {
				run.rtt = rtt
			}
			r.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Real) Next(target Target, after string) (string, bool) {
	if r.load == nil {
		return "", false
	}
	profiles, err := r.load()
	if err != nil {
		return "", false
	}
	configured := r.settings()
	return profile.Next(profiles, target.Server, target.Protocol, target.Sub, configured.Protocol, configured.Game, after)
}

// fastestTimeout bounds each server's handshake in Fastest.
const fastestTimeout = 3 * time.Second

// quickestOf makes one handshake to each profile's server at the same time and returns the index of the one that
// answered soonest, or -1 when none did.
func quickestOf(ctx context.Context, profiles []profile.Profile) int {
	round := make([]time.Duration, len(profiles)) // 0: no answer
	var wait sync.WaitGroup
	for i, p := range profiles {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if rtt, err := diag.Handshake(ctx, p, fastestTimeout); err == nil {
				round[i] = rtt
			}
		}()
	}
	wait.Wait()
	best := -1
	for i, rtt := range round {
		if rtt > 0 && (best < 0 || rtt < round[best]) {
			best = i
		}
	}
	return best
}

func (r *Real) Fastest(ctx context.Context, target Target, except string) (string, bool) {
	if r.load == nil {
		return "", false
	}
	profiles, err := r.load()
	if err != nil {
		return "", false
	}
	configured := r.settings()
	others := profile.Others(profiles, target.Server, target.Protocol, target.Sub, configured.Protocol, configured.Game, except)
	best := quickestOf(ctx, others)
	if best < 0 {
		return "", false
	}
	return others[best].ID, true
}

func (r *Real) startRun(ctx context.Context, hold bool) (context.Context, *realRun, error) {
	r.lifecycle.Lock()
	runCtx, cancel := context.WithCancel(ctx)
	run := &realRun{ctx: runCtx, cancel: cancel, tunnel: &realTunnel{}, hold: hold, lastStatsAt: time.Now()}
	r.mu.Lock()
	old := r.current
	r.current = run
	r.mu.Unlock()
	var err error
	if hold {
		settings := r.settings()
		err = r.setFirewall(run, false, 0, nil, settings.LAN)
		if consoleFirewallUnavailable(err) && settings.KillSwitch != "always" {
			err = nil
		}
	}
	if old != nil {
		old.cancel()
		old.tunnel.Close()
	}
	if !hold {
		firewall.DisableFirewall()
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
			firewall.DisableFirewall()
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
	firewall.DisableFirewall()
	r.lifecycle.Unlock()
}

// ponytail: always is open before service startup and after a crash; upgrade = persistent (non-dynamic) rules installed by the service.
func (r *Real) Hold() bool {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	_, cancel := context.WithCancel(context.Background())
	run := &realRun{cancel: cancel, tunnel: &realTunnel{}, hold: true, lastStatsAt: time.Now()}
	r.mu.Lock()
	old := r.current
	r.current = run
	r.mu.Unlock()
	configured := r.settings()
	err := r.setFirewall(run, false, 0, nil, configured.LAN)
	if old != nil {
		old.cancel()
		old.tunnel.Close()
	}
	if err != nil {
		consoleFirewallUnavailable(err)
		r.mu.Lock()
		if r.current == run {
			r.current = nil
		}
		r.mu.Unlock()
		cancel()
		run.tunnel.Close()
		firewall.DisableFirewall()
		return false
	}
	return true
}

func (r *Real) Reapply() {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	configured := r.settings()
	r.mu.Lock()
	run := r.current
	if run == nil {
		r.mu.Unlock()
		return
	}
	adapter := run.tunnel.adapterSnapshot()
	luid := run.luid
	if adapter != nil {
		luid = adapter.LUID()
	}
	dns := append([]netip.Addr(nil), run.dns...)
	doNotRestrict := adapter != nil && configured.KillSwitch == "off"
	if adapter == nil && run.hold {
		doNotRestrict = false
	}
	if adapter == nil && !run.hold {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	if err := r.setFirewall(run, doNotRestrict, luid, dns, configured.LAN); err != nil && !consoleFirewallUnavailable(err) {
		slog.Error("could not reapply firewall rules", "error", err)
	}
}

func (r *Real) setFirewall(run *realRun, doNotRestrict bool, luid uint64, dns []netip.Addr, allowLAN bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run != nil && r.current != run {
		return context.Canceled
	}
	if run != nil {
		run.luid = luid
		run.dns = append([]netip.Addr(nil), dns...)
	}
	return firewall.EnableFirewall(luid, doNotRestrict, allowLAN, dns)
}

func (r *Real) settings() settings.Settings {
	if r.getSettings != nil {
		return r.getSettings()
	}
	return settings.Defaults()
}

func consoleFirewallUnavailable(err error) bool {
	if errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
		killSwitchWarning.Do(func() { slog.Warn("kill switch is off: not running as the Windows service") })
		return true
	}
	return false
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

func (r *Real) Received() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil || r.current.tunnel == nil {
		return 0
	}
	if rx, forwarded := r.current.tunnel.forwardedRx(); forwarded {
		return rx
	}
	adapter := r.current.tunnel.adapterSnapshot()
	if adapter == nil {
		return 0
	}
	rx, _ := adapter.Counters()
	return rx
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
	_ = rtt // not the server's time (the forwarder answers the probe itself): keepLatency measures that
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

func probeTargets(verify string) []string {
	if verify == "" {
		return []string{"1.1.1.1:443", "8.8.8.8:443"}
	}
	return []string{verify}
}

func probeTunnel(ctx context.Context, localIP netip.Addr, verify string, timeout time.Duration) (time.Duration, error) {
	var lastErr error
	for _, target := range probeTargets(verify) {
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

func (t *realTunnel) createBridge(ctx context.Context, tunDevice tun.Device, mtu int, vpn, direct outbound, shouldDirect func(netip.Addr, string) bool, hasSiteRules func() bool, track *geo.Tracker, names func(string) (bool, netip.AddrPort)) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return context.Canceled
	}
	bridge, err := newGvisorBridge(ctx, tunDevice, mtu, vpn, direct, shouldDirect, hasSiteRules, track, names)
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

// forwardedRx: with the forwarder, the bytes that came from the VPN side (the adapter also carries direct answers).
func (t *realTunnel) forwardedRx() (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bridge == nil {
		return 0, false
	}
	return t.bridge.vpnRx.Load(), true
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
	return wrapHy2Obfs(packetConn, f.kind, f.password)
}

func wrapHy2Obfs(packetConn net.PacketConn, kind string, password []byte) (net.PacketConn, error) {
	var wrapped net.PacketConn
	var err error
	if kind == "none" {
		return packetConn, nil
	}
	if kind == "gecko" {
		wrapped, err = obfs.WrapPacketConnGecko(packetConn, obfs.GeckoOptions{Password: password})
	} else {
		wrapped, err = obfs.WrapPacketConnSalamander(packetConn, password)
	}
	if err != nil {
		_ = packetConn.Close()
		return nil, errors.New("configure Hysteria2 obfuscation")
	}
	return wrapped, nil
}

type hy2HopFactory struct {
	kind           string
	password       []byte
	interval       time.Duration
	interfaceIndex uint32
	ipv6           bool
}

func (f hy2HopFactory) New(addr net.Addr) (net.PacketConn, error) {
	hopAddr, ok := addr.(*udphop.UDPHopAddr)
	if !ok {
		return nil, errors.New("invalid Hysteria2 port hopping address")
	}
	listenUDP := func() (net.PacketConn, error) {
		var config net.ListenConfig
		config.Control = netcfg.SocketControl(f.interfaceIndex)
		network := "udp4"
		if f.ipv6 {
			network = "udp6"
		}
		return config.ListenPacket(context.Background(), network, ":0")
	}
	interval := udphop.HopIntervalConfig{}
	if f.interval > 0 {
		interval.Min, interval.Max = f.interval, f.interval
	}
	packetConn, err := udphop.NewUDPHopPacketConn(hopAddr, interval, listenUDP)
	if err != nil {
		return nil, errors.New("open Hysteria2 hopping socket")
	}
	return wrapHy2Obfs(packetConn, f.kind, f.password)
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
		var serverAddr net.Addr = &net.UDPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port()), Zone: endpoint.Addr().Zone()}
		var connFactory client.ConnFactory
		if p.Ports != "" {
			hopAddr, err := udphop.ResolveUDPHopAddr(net.JoinHostPort(endpoint.Addr().String(), p.Ports))
			if err != nil {
				done <- result{err: errors.New("configure Hysteria2 port hopping")}
				return
			}
			interfaceIndex, err := netcfg.PhysicalInterfaceIndexFor(endpoint.Addr())
			if err != nil {
				done <- result{err: errors.New("select Hysteria2 physical interface")}
				return
			}
			serverAddr = hopAddr
			connFactory = hy2HopFactory{
				kind: p.Obfs, password: []byte(p.ObfsPassword), interval: p.HopInterval,
				interfaceIndex: interfaceIndex, ipv6: endpoint.Addr().Is6(),
			}
		} else if p.Obfs != "none" {
			connFactory = hy2ObfsFactory{kind: p.Obfs, password: []byte(p.ObfsPassword)}
		}
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
		config := &client.Config{ServerAddr: serverAddr, Auth: p.Auth, TLSConfig: tlsConfig, ConnFactory: connFactory}
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
		_ = tunDevice.Close()
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
