//go:build windows

package netcfg

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/mistgate/mistgate-client/core/internal/firewall"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var ErrNoRoute = errors.New("no route for server bypass")

var adapterGUID = windows.GUID{
	Data1: 0x4d697374,
	Data2: 0x6761,
	Data3: 0x7465,
	Data4: [8]byte{0x9a, 0x71, 0x42, 0x6f, 0x8c, 0x19, 0x53, 0x2d},
}

type Config struct {
	MTU       int
	Addresses []netip.Prefix
	DNS       []netip.Addr
	Bypass    netip.Addr
}

type Adapter struct {
	mu           sync.Mutex
	device       *countingDevice
	luid         winipcfg.LUID
	closed       bool
	firewall     bool
	configured   bool
	bypassPrefix netip.Prefix
	bypassNext   netip.Addr
	bypassLUID   winipcfg.LUID
	hasBypass    bool
}

func Create(mtu int) (*Adapter, error) {
	device, err := tun.CreateTUNWithRequestedGUID("Mistgate", &adapterGUID, mtu)
	if err != nil {
		return nil, errors.New("cannot create Wintun adapter")
	}
	native, ok := device.(*tun.NativeTun)
	if !ok {
		_ = device.Close()
		return nil, errors.New("Wintun adapter has no interface identifier")
	}
	return &Adapter{
		device: newCountingDevice(device),
		luid:   winipcfg.LUID(native.LUID()),
	}, nil
}

func (a *Adapter) Device() tun.Device { return a.device }

func (a *Adapter) Configure(cfg Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return errors.New("Wintun adapter is closed")
	}
	if a.configured {
		return errors.New("Wintun adapter is already configured")
	}
	if cfg.MTU < 576 || !cfg.Bypass.IsValid() {
		return errors.New("invalid Wintun configuration")
	}
	hasIPv4 := false
	for _, prefix := range cfg.Addresses {
		if !prefix.IsValid() {
			return errors.New("invalid Wintun address")
		}
		hasIPv4 = hasIPv4 || prefix.Addr().Is4()
	}
	if !hasIPv4 {
		return errors.New("Wintun configuration has no IPv4 address")
	}
	// The kill switch. While this adapter lives, the network is open only to the tunnel, the local network, loopback, DHCP and NDP and to
	// this service's own sockets, and DNS only to cfg.DNS. It is a dynamic firewall session: it ends with Close or with
	// the process, so a crash never leaves the machine without a network.
	// ponytail: a crash therefore opens the network; holding it (state "blocked") comes with the health watcher.
	if err := firewall.EnableFirewall(uint64(a.luid), false, cfg.DNS); err == nil {
		a.firewall = true
	} else if errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
		// the rules name the service SID; a console run (development) has none
		slog.Warn("kill switch is off: not running as the Windows service")
	} else {
		return fmt.Errorf("enable kill switch: %w", err)
	}
	if err := setInterface(a.luid, windows.AF_INET, cfg.MTU); err != nil {
		return fmt.Errorf("configure Wintun IPv4 interface: %w", err)
	}
	if err := setInterface(a.luid, windows.AF_INET6, cfg.MTU); err != nil {
		return fmt.Errorf("configure Wintun IPv6 interface: %w", err)
	}
	if err := a.luid.SetIPAddresses(cfg.Addresses); err != nil {
		return fmt.Errorf("assign Wintun addresses: %w", err)
	}
	if err := a.addBypass(cfg.Bypass); err != nil {
		return err
	}
	for _, route := range []struct {
		prefix  netip.Prefix
		nextHop netip.Addr
	}{
		{netip.MustParsePrefix("0.0.0.0/1"), netip.IPv4Unspecified()},
		{netip.MustParsePrefix("128.0.0.0/1"), netip.IPv4Unspecified()},
		{netip.MustParsePrefix("::/1"), netip.IPv6Unspecified()},
		{netip.MustParsePrefix("8000::/1"), netip.IPv6Unspecified()},
	} {
		if err := a.luid.AddRoute(route.prefix, route.nextHop, 0); err != nil && !alreadyExists(err) {
			return fmt.Errorf("add Wintun route: %w", err)
		}
	}
	dns4, dns6 := splitDNS(cfg.DNS)
	if err := a.luid.SetDNS(windows.AF_INET, dns4, nil); err != nil {
		return fmt.Errorf("configure Wintun IPv4 DNS: %w", err)
	}
	if len(dns6) > 0 {
		if err := a.luid.SetDNS(windows.AF_INET6, dns6, nil); err != nil {
			return fmt.Errorf("configure Wintun IPv6 DNS: %w", err)
		}
	}
	a.configured = true
	return nil
}

func setInterface(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	row.DadTransmits = 0
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.NLMTU = uint32(mtu)
	row.UseAutomaticMetric = false
	row.Metric = 0
	return row.Set()
}

func (a *Adapter) addBypass(destination netip.Addr) error {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if destination.Is6() {
		family = winipcfg.AddressFamily(windows.AF_INET6)
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("%w: inspect server bypass route table", ErrNoRoute)
	}
	candidates := make([]routeCandidate, 0, len(rows))
	for _, row := range rows {
		if row.InterfaceLUID == a.luid {
			continue
		}
		prefix := row.DestinationPrefix.Prefix().Masked()
		if !prefix.IsValid() || !prefix.Contains(destination) {
			continue
		}
		ipInterface, err := row.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		candidates = append(candidates, routeCandidate{
			prefix:          prefix,
			nextHop:         row.NextHop.Addr(),
			metric:          row.Metric,
			interfaceMetric: ipInterface.Metric,
			luid:            row.InterfaceLUID,
		})
	}
	choice, ok := chooseRoute(destination, candidates)
	if !ok {
		return ErrNoRoute
	}
	route := netip.PrefixFrom(destination, destination.BitLen())
	if err := choice.luid.AddRoute(route, choice.nextHop, 0); err != nil && !alreadyExists(err) {
		return fmt.Errorf("add server bypass route: %w", err)
	}
	a.bypassPrefix = route
	a.bypassNext = choice.nextHop
	a.bypassLUID = choice.luid
	a.hasBypass = true
	// ponytail: the route is captured at connect time; a network change needs a reconnect; upgrade = bind outer sockets to the default-route interface with a route monitor (as wireguard-windows does).
	return nil
}

type routeCandidate struct {
	prefix          netip.Prefix
	nextHop         netip.Addr
	metric          uint32
	interfaceMetric uint32
	luid            winipcfg.LUID
}

func chooseRoute(destination netip.Addr, candidates []routeCandidate) (routeCandidate, bool) {
	var best routeCandidate
	found := false
	for _, candidate := range candidates {
		if !candidate.prefix.IsValid() || candidate.prefix.Addr().Is4() != destination.Is4() || !candidate.prefix.Contains(destination) {
			continue
		}
		if !found || candidate.prefix.Bits() > best.prefix.Bits() ||
			(candidate.prefix.Bits() == best.prefix.Bits() && routeCost(candidate) < routeCost(best)) {
			best = candidate
			found = true
		}
	}
	return best, found
}

func routeCost(route routeCandidate) uint64 {
	return uint64(route.metric) + uint64(route.interfaceMetric)
}

func alreadyExists(err error) bool {
	return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

func splitDNS(dns []netip.Addr) (v4, v6 []netip.Addr) {
	for _, address := range dns {
		if address.Is4() {
			v4 = append(v4, address)
		} else if address.Is6() {
			v6 = append(v6, address)
		}
	}
	return v4, v6
}

func (a *Adapter) Counters() (rx, tx uint64) {
	return a.device.rx.Load(), a.device.tx.Load()
}

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	var routeErr error
	if a.hasBypass {
		routeErr = a.bypassLUID.DeleteRoute(a.bypassPrefix, a.bypassNext)
		if errors.Is(routeErr, windows.ERROR_NOT_FOUND) {
			routeErr = nil
		}
	}
	deviceErr := a.device.Close()
	if a.firewall {
		firewall.DisableFirewall() // after the adapter: nothing leaves beside the tunnel while it is going down
	}
	if routeErr != nil {
		return fmt.Errorf("remove server bypass route: %w", routeErr)
	}
	if deviceErr != nil {
		return fmt.Errorf("close Wintun adapter: %w", deviceErr)
	}
	return nil
}

type countingDevice struct {
	tun.Device
	rx        atomic.Uint64
	tx        atomic.Uint64
	closeOnce sync.Once
	closeErr  error
}

func newCountingDevice(device tun.Device) *countingDevice {
	return &countingDevice{Device: device}
}

func (d *countingDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n && i < len(sizes); i++ {
		if sizes[i] > 0 {
			d.tx.Add(uint64(sizes[i]))
		}
	}
	return n, err
}

func (d *countingDevice) Write(bufs [][]byte, offset int) (int, error) {
	n, err := d.Device.Write(bufs, offset)
	for i := 0; i < n && i < len(bufs); i++ {
		size := len(bufs[i]) - offset
		if size > 0 {
			d.rx.Add(uint64(size))
		}
	}
	return n, err
}

func (d *countingDevice) Close() error {
	d.closeOnce.Do(func() { d.closeErr = d.Device.Close() })
	return d.closeErr
}
