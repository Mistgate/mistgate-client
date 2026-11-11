//go:build windows

package netcfg

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
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

var dnsBehaviorWarning sync.Once

type Config struct {
	MTU       int
	Addresses []netip.Prefix
	DNS       []netip.Addr
	Bypass    netip.Addr
}

type Adapter struct {
	mu           sync.Mutex
	device       *sessionDevice
	luid         winipcfg.LUID
	closed       bool
	configured   bool
	bypassPrefix netip.Prefix
	bypassNext   netip.Addr
	bypassLUID   winipcfg.LUID
	hasBypass    bool
}

var persistentDevice struct {
	sync.Mutex
	pump   *devicePump
	active *Adapter
	luid   winipcfg.LUID
}

func Create(mtu int) (*Adapter, error) {
	persistentDevice.Lock()
	defer persistentDevice.Unlock()
	if persistentDevice.active != nil {
		if err := persistentDevice.active.Close(); err != nil {
			return nil, fmt.Errorf("close previous Wintun session: %w", err)
		}
	}
	if persistentDevice.pump == nil {
		device, err := tun.CreateTUNWithRequestedGUID("Mistgate", &adapterGUID, mtu)
		if err != nil {
			return nil, errors.New("cannot create Wintun adapter")
		}
		native, ok := device.(*tun.NativeTun)
		if !ok {
			_ = device.Close()
			return nil, errors.New("Wintun adapter has no interface identifier")
		}
		persistentDevice.pump = newDevicePump(device)
		persistentDevice.luid = winipcfg.LUID(native.LUID())
	}
	adapter := &Adapter{
		device: persistentDevice.pump.newSession(mtu),
		luid:   persistentDevice.luid,
	}
	persistentDevice.active = adapter
	return adapter, nil
}

func (a *Adapter) Device() tun.Device { return a.device }

func (a *Adapter) LUID() uint64 { return uint64(a.luid) }

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
	if err := a.luid.SetDNS(windows.AF_INET, dns4, []string{"."}); err != nil {
		return fmt.Errorf("configure Wintun IPv4 DNS: %w", err)
	}
	if len(dns6) > 0 {
		if err := a.luid.SetDNS(windows.AF_INET6, dns6, []string{"."}); err != nil {
			return fmt.Errorf("configure Wintun IPv6 DNS: %w", err)
		}
	}
	if err := quietDNS(a.luid); err != nil {
		dnsBehaviorWarning.Do(func() {
			slog.Warn("could not disable DNS registration behaviors on Wintun", "error", err)
		})
	}
	a.configured = true
	return nil
}

func quietDNS(luid winipcfg.LUID) error {
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	return winipcfg.SetInterfaceDnsSettings(*guid, &winipcfg.DnsInterfaceSettings{
		Version: winipcfg.DnsInterfaceSettingsVersion1,
		Flags: winipcfg.DnsInterfaceSettingsFlagRegistrationEnabled |
			winipcfg.DnsInterfaceSettingsFlagRegisterAdapterName |
			winipcfg.DnsInterfaceSettingsFlagEnableLLMNR |
			winipcfg.DnsInterfaceSettingsFlagQueryAdapterName,
		RegistrationEnabled: 0,
		RegisterAdapterName: 0,
		EnableLLMNR:         0,
		QueryAdapterName:    0,
	})
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

// PhysicalInterfaceIndex4 is the interface the internet is reached through when the tunnel is left out.
func PhysicalInterfaceIndex4() (uint32, error) {
	return PhysicalInterfaceIndexFor(netip.MustParseAddr("1.1.1.1"))
}

// PhysicalInterfaceIndexFor is the interface a destination is reached through when the tunnel is left out.
func PhysicalInterfaceIndexFor(destination netip.Addr) (uint32, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if destination.Is6() {
		family = winipcfg.AddressFamily(windows.AF_INET6)
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, ErrNoRoute
	}
	tunnel, _ := winipcfg.LUIDFromGUID(&adapterGUID)
	candidates := make([]routeCandidate, 0, len(rows))
	for _, row := range rows {
		if tunnel != 0 && row.InterfaceLUID == tunnel {
			continue
		}
		prefix := row.DestinationPrefix.Prefix().Masked()
		if !prefix.IsValid() || !prefix.Contains(destination) {
			continue
		}
		iface, err := row.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		candidates = append(candidates, routeCandidate{
			prefix: prefix, metric: row.Metric, interfaceMetric: iface.Metric, luid: row.InterfaceLUID,
		})
	}
	choice, ok := chooseRoute(destination, candidates)
	if !ok {
		return 0, ErrNoRoute
	}
	iface, err := choice.luid.IPInterface(family)
	if err != nil || iface.InterfaceIndex == 0 {
		return 0, ErrNoRoute
	}
	return iface.InterfaceIndex, nil
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
	var closeErr error
	if err := a.device.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close Wintun session: %w", err))
	}
	if a.hasBypass {
		err := a.bypassLUID.DeleteRoute(a.bypassPrefix, a.bypassNext)
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			err = nil
		}
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("remove server bypass route: %w", err))
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		for _, flush := range []struct {
			name string
			fn   func(winipcfg.AddressFamily) error
		}{
			{"routes", a.luid.FlushRoutes},
			{"addresses", a.luid.FlushIPAddresses},
			{"DNS", a.luid.FlushDNS},
		} {
			if err := flush.fn(family); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("flush Wintun %s: %w", flush.name, err))
			}
		}
	}
	return closeErr
}

type devicePump struct {
	native  tun.Device
	mu      sync.Mutex
	current *sessionDevice
	buffer  []byte
	buffers [][]byte
	sizes   []int
	size    int
}

func newDevicePump(native tun.Device) *devicePump {
	p := &devicePump{
		native:  native,
		buffer:  make([]byte, 65536),
		buffers: make([][]byte, 1),
		sizes:   make([]int, 1),
	}
	p.buffers[0] = p.buffer
	go p.run()
	return p
}

func (p *devicePump) run() {
	for {
		p.sizes[0] = 0
		n, err := p.native.Read(p.buffers, p.sizes, 0)
		if err != nil {
			return
		}
		if n == 0 || p.sizes[0] <= 0 || p.sizes[0] > len(p.buffer) {
			continue
		}
		p.size = p.sizes[0]
		p.mu.Lock()
		session := p.current
		p.mu.Unlock()
		if session == nil {
			continue
		}
		select {
		case session.packet <- struct{}{}:
		case <-session.done:
			continue
		}
		select {
		case <-session.ack:
		case <-session.done:
			select {
			case <-session.packet:
			default:
				<-session.ack
			}
		}
	}
}

func (p *devicePump) newSession(mtu int) *sessionDevice {
	session := &sessionDevice{
		pump:   p,
		mtu:    mtu,
		done:   make(chan struct{}),
		packet: make(chan struct{}, 1),
		ack:    make(chan struct{}, 1),
		events: make(chan tun.Event, 1),
	}
	session.events <- tun.EventUp
	p.mu.Lock()
	p.current = session
	p.mu.Unlock()
	return session
}

type sessionDevice struct {
	pump      *devicePump
	mtu       int
	done      chan struct{}
	packet    chan struct{}
	ack       chan struct{}
	events    chan tun.Event
	closeOnce sync.Once
	rx        atomic.Uint64
	tx        atomic.Uint64
}

func (d *sessionDevice) File() *os.File { return d.pump.native.File() }

func (d *sessionDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, errors.New("invalid Wintun read buffers")
	}
	select {
	case <-d.done:
		return 0, errors.New("Wintun session is closed")
	case <-d.packet:
	}
	defer func() {
		select {
		case d.ack <- struct{}{}:
		default:
		}
	}()
	select {
	case <-d.done:
		return 0, errors.New("Wintun session is closed")
	default:
	}
	if offset > len(bufs[0]) || len(bufs[0])-offset < d.pump.size {
		return 0, errors.New("Wintun read buffer is too small")
	}
	size := copy(bufs[0][offset:], d.pump.buffer[:d.pump.size])
	sizes[0] = size
	d.tx.Add(uint64(size))
	return 1, nil
}

func (d *sessionDevice) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.done:
		return 0, errors.New("Wintun session is closed")
	default:
	}
	n, err := d.pump.native.Write(bufs, offset)
	for i := 0; i < n && i < len(bufs); i++ {
		size := len(bufs[i]) - offset
		if size > 0 {
			d.rx.Add(uint64(size))
		}
	}
	return n, err
}

func (d *sessionDevice) MTU() (int, error) { return d.mtu, nil }

func (d *sessionDevice) Name() (string, error) { return d.pump.native.Name() }

func (d *sessionDevice) Events() <-chan tun.Event { return d.events }

func (d *sessionDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		d.pump.mu.Lock()
		if d.pump.current == d {
			d.pump.current = nil
		}
		d.pump.mu.Unlock()
		close(d.events)
	})
	return nil
}

func (d *sessionDevice) BatchSize() int { return 1 }
