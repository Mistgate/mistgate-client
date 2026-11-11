package diag

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason"`
	RTTMS    int64  `json:"rtt_ms"`
}

type Result struct {
	AtUnix  int64  `json:"at_unix"`
	Sub     string `json:"sub"`
	Network struct {
		Kind string `json:"kind"`
	} `json:"network"`
	Servers []Server `json:"servers"`
	// Route: blocking by address on the way out. Hop is the first silent hop when blocked, the path length when ok.
	Route struct {
		Verdict string `json:"verdict"`
		Hop     int    `json:"hop"`
		Total   int    `json:"total"`
	} `json:"route"`
	UDP struct {
		Verdict string `json:"verdict"`
	} `json:"udp"`
	NAT struct {
		Verdict string `json:"verdict"`
	} `json:"nat"`
	DNS struct {
		Verdict  string `json:"verdict"`
		Checked  int    `json:"checked"`
		Replaced int    `json:"replaced"`
	} `json:"dns"`
	Foreign struct {
		Verdict string `json:"verdict"`
		Total   int    `json:"total"`
		Open    int    `json:"open"`
	} `json:"foreign"`
	// Freeze: a download from a foreign host that stalls after the first kilobytes.
	Freeze struct {
		Verdict string         `json:"verdict"`
		Targets []FreezeTarget `json:"targets"`
	} `json:"freeze"`
	// Neighbours: other VPNs, DPI-bypass tools and packet-interception drivers on this machine.
	Neighbours []Neighbour `json:"neighbours"`
}

type State struct {
	State  string  `json:"state"`
	Step   int     `json:"step"`
	Pct    int     `json:"pct"`
	Error  string  `json:"error"`
	Result *Result `json:"result"`
}

type Config struct {
	Profiles func() ([]profile.Profile, error)
	// Tunnel reports whether the VPN is up: then names can be resolved through it, which the network cannot touch.
	Tunnel         func() bool
	Logger         *slog.Logger
	STUNServers    []string
	DNSNames       []string
	DoHResolvers   []string
	ForeignHosts   []string
	ProfileTimeout time.Duration
	Hy2Timeout     time.Duration
	AWGTimeout     time.Duration
	TCPTimeout     time.Duration
	STUNTimeout    time.Duration
	DNSTimeout     time.Duration
	DoHTimeout     time.Duration
	ForeignTimeout time.Duration
}

type Runner struct {
	config   Config
	publish  func(State)
	mu       sync.Mutex
	state    State
	cancel   context.CancelFunc
	pending  []State
	dispatch bool
}

var (
	errNoAnswer     = errors.New("no answer")
	errAuthRejected = errors.New("authentication rejected")
	errBadConfig    = errors.New("bad configuration")
)

func NewRunner(config Config, publish func(State)) *Runner {
	if config.STUNServers == nil {
		config.STUNServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}
	}
	if config.DNSNames == nil {
		config.DNSNames = []string{"www.facebook.com", "www.instagram.com", "x.com", "www.linkedin.com", "discord.com", "www.youtube.com", "rutracker.org", "www.bbc.com"}
	}
	if config.DoHResolvers == nil {
		config.DoHResolvers = []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"}
	}
	if config.ForeignHosts == nil {
		config.ForeignHosts = []string{"github.com", "www.wikipedia.org", "www.cloudflare.com", "www.amazon.com", "www.microsoft.com", "www.apple.com", "stackoverflow.com", "www.mozilla.org", "www.debian.org", "www.python.org"}
	}
	setDuration(&config.ProfileTimeout, 6*time.Second)
	setDuration(&config.Hy2Timeout, 6*time.Second)
	setDuration(&config.AWGTimeout, 5*time.Second)
	setDuration(&config.TCPTimeout, 2*time.Second)
	setDuration(&config.STUNTimeout, 1500*time.Millisecond)
	setDuration(&config.DNSTimeout, 2*time.Second)
	setDuration(&config.DoHTimeout, 4*time.Second)
	setDuration(&config.ForeignTimeout, 4*time.Second)
	return &Runner{config: config, publish: publish, state: State{State: "idle"}}
}

func setDuration(value *time.Duration, fallback time.Duration) {
	if *value <= 0 {
		*value = fallback
	}
}

func (r *Runner) Start(sub string) State {
	r.mu.Lock()
	if r.cancel != nil {
		state := cloneState(r.state)
		r.mu.Unlock()
		return state
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.state.State, r.state.Step, r.state.Pct, r.state.Error = "running", 0, 0, ""
	flush := r.queueLocked()
	state := cloneState(r.state)
	r.mu.Unlock()
	if flush {
		r.flush()
	}
	go r.run(ctx, sub)
	return state
}

func (r *Runner) Cancel() State {
	r.mu.Lock()
	cancel := r.cancel
	changed := cancel != nil && r.state.State == "running"
	if changed {
		r.state.State, r.state.Error = "failed", "cancelled"
	}
	state := cloneState(r.state)
	flush := changed && r.queueLocked()
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if changed {
		if flush {
			r.flush()
		}
	}
	return state
}

func (r *Runner) Get() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneState(r.state)
}

func (r *Runner) run(ctx context.Context, sub string) {
	result, err := r.check(ctx, sub)
	r.mu.Lock()
	if r.state.State == "failed" && r.state.Error == "cancelled" {
		r.cancel = nil
		r.mu.Unlock()
		return
	}
	switch {
	case ctx.Err() != nil:
		r.state.State, r.state.Error = "failed", "cancelled"
	case err != nil:
		r.state.State, r.state.Error = "failed", errorCode(err)
	default:
		r.state.State, r.state.Step, r.state.Pct, r.state.Error = "done", 4, 100, ""
		r.state.Result = result
	}
	r.cancel = nil
	flush := r.queueLocked()
	r.mu.Unlock()
	if flush {
		r.flush()
	}
}

func (r *Runner) check(ctx context.Context, sub string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.config.Profiles == nil {
		return nil, errors.New("no_subscription")
	}
	profiles, err := r.config.Profiles()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.New("no_subscription")
	}
	if sub == "" && len(profiles) > 0 {
		sub = profiles[0].Sub
	}
	selected := make([]profile.Profile, 0)
	for _, p := range profiles {
		if p.Sub == sub {
			selected = append(selected, p)
		}
	}
	if sub == "" || len(selected) == 0 {
		return nil, errors.New("no_subscription")
	}
	physical, err := physicalNetwork()
	if err != nil || physical.Index == 0 {
		return nil, errors.New("offline")
	}
	result := &Result{Sub: sub, Servers: make([]Server, len(selected))}
	result.Network.Kind = physical.Kind
	result.Neighbours = neighbours(scanLocal())
	r.log("neighbours", fmt.Sprintf("found=%d", len(result.Neighbours)))
	anyServerOK, anyHostAlive := checkProfiles(ctx, selected, physical, r.config, result.Servers)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.log("servers", serverCounts(result.Servers))
	r.advance(1, 20)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result.Route.Verdict = "unknown"
	if r.config.Tunnel != nil && r.config.Tunnel() {
		// ponytail: with the VPN up an echo would leave through the tunnel; upgrade = host routes for the references
		r.log("route", "skipped: the VPN is up")
	} else {
		result.Route.Verdict, result.Route.Hop, result.Route.Total = checkRoute(ctx, icmpEcho)
		r.log("route", fmt.Sprintf("verdict=%s hop=%d total=%d", result.Route.Verdict, result.Route.Hop, result.Route.Total))
	}
	r.advance(2, 40)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stunPorts := checkSTUN(ctx, physical, r.config)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result.NAT.Verdict = natVerdict(stunPorts)
	r.log("udp", fmt.Sprintf("stun_answers=%d server_ok=%t host_alive=%t", len(stunPorts), anyServerOK, anyHostAlive))
	r.advance(3, 60)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local, doh := checkDNS(ctx, physical, r.config)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result.DNS.Checked, result.DNS.Replaced = dnsReplacementCounts(local, doh)
	result.DNS.Verdict = dnsVerdict(local, doh, result.DNS.Checked, result.DNS.Replaced)
	r.log("dns", fmt.Sprintf("verdict=%s checked=%d replaced=%d", result.DNS.Verdict, result.DNS.Checked, result.DNS.Replaced))
	r.advance(4, 80)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// the download runs beside the foreign check (it is the slower one), so the steps stay the same
	var facts string
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		result.Freeze.Verdict, result.Freeze.Targets, facts = checkFreeze(ctx, freezeClient(physical))
	}()
	result.Foreign.Total, result.Foreign.Open = checkForeign(ctx, physical, r.config)
	wait.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.log("freeze", fmt.Sprintf("verdict=%s bytes/idle (control, targets):%s", result.Freeze.Verdict, facts))
	result.Foreign.Verdict = foreignVerdict(result.Foreign.Total, result.Foreign.Open)
	result.UDP.Verdict = udpVerdict(len(stunPorts) > 0, anyServerOK, result.Foreign.Open > 0, anyHostAlive)
	if result.Foreign.Open == 0 {
		result.UDP.Verdict = "unknown"
		result.DNS.Verdict = "unknown"
	}
	r.log("foreign", fmt.Sprintf("verdict=%s total=%d open=%d", result.Foreign.Verdict, result.Foreign.Total, result.Foreign.Open))
	result.AtUnix = time.Now().Unix()
	return result, nil
}

func (r *Runner) advance(step, pct int) {
	r.mu.Lock()
	if r.state.State != "running" || step <= r.state.Step {
		r.mu.Unlock()
		return
	}
	r.state.Step, r.state.Pct = step, pct
	flush := r.queueLocked()
	r.mu.Unlock()
	if flush {
		r.flush()
	}
}

func (r *Runner) log(step, detail string) {
	if r.config.Logger != nil {
		r.config.Logger.Info("diagnostic step " + step + " done: " + detail)
	}
}

func (r *Runner) queueLocked() bool {
	if r.publish == nil {
		return false
	}
	r.pending = append(r.pending, cloneState(r.state))
	if r.dispatch {
		return false
	}
	r.dispatch = true
	return true
}

func (r *Runner) flush() {
	for {
		r.mu.Lock()
		if len(r.pending) == 0 {
			r.dispatch = false
			r.mu.Unlock()
			return
		}
		state := r.pending[0]
		r.pending = r.pending[1:]
		r.mu.Unlock()
		r.publish(state)
	}
}

func cloneState(state State) State {
	if state.Result != nil {
		result := *state.Result
		result.Servers = append([]Server(nil), state.Result.Servers...)
		state.Result = &result
	}
	return state
}

func errorCode(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	var coded interface{ ErrorCode() string }
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return err.Error()
}

func checkProfiles(ctx context.Context, profiles []profile.Profile, physical interfaceInfo, config Config, results []Server) (anyOK, anyAlive bool) {
	limit := make(chan struct{}, 4)
	var wait sync.WaitGroup
	aliveResults := make([]bool, len(profiles))
	for i, p := range profiles {
		wait.Add(1)
		go func(i int, p profile.Profile) {
			defer wait.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()
			server, hostIsAlive := checkProfile(ctx, p, physical, config)
			results[i] = server
			aliveResults[i] = hostIsAlive
		}(i, p)
	}
	wait.Wait()
	for i, server := range results {
		anyOK = anyOK || server.Verdict == "ok"
		anyAlive = anyAlive || aliveResults[i]
	}
	return anyOK, anyAlive
}

func checkProfile(ctx context.Context, p profile.Profile, physical interfaceInfo, config Config) (Server, bool) {
	server := serverForProfile(p)
	host, port, err := profileEndpoint(p)
	if err != nil {
		return server, false
	}
	resolveCtx, cancel := context.WithTimeout(ctx, config.DNSTimeout)
	ip, err := resolveHost(resolveCtx, host, physical, config)
	cancel()
	if err != nil {
		server.Verdict, server.Reason = "down", "not_found"
		return server, false
	}
	// the server's own route decides the interface: it may sit on a local or a second network
	physical = interfaceFor(ip, physical)
	endpoint := netip.AddrPortFrom(ip, port)
	timeout := config.Hy2Timeout
	if p.Protocol == "awg" {
		timeout = config.AWGTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, minDuration(config.ProfileTimeout, timeout))
	rtt, err := attemptProfile(attemptCtx, p, endpoint, physical, config)
	cancel()
	if err == nil {
		server.Verdict, server.Reason = "ok", ""
		server.RTTMS = rtt.Milliseconds()
		return server, false
	}
	switch {
	case errors.Is(err, errAuthRejected):
		server.Verdict, server.Reason = "config", "auth_rejected"
		return server, false
	case errors.Is(err, errBadConfig):
		server.Verdict, server.Reason = "config", "bad_config"
		return server, false
	case !errors.Is(err, errNoAnswer):
		return server, false
	}
	ports := uniquePorts(port, 443, 80)
	alive := hostAlive(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialBound(ctx, network, address, physical)
	}, ip.String(), ports, config.TCPTimeout)
	// ponytail: a dead service on a live host can look blocked; upgrade = combine with panel node health.
	if alive {
		server.Verdict, server.Reason = "blocked", "udp_no_answer"
		return server, true
	}
	server.Verdict, server.Reason = "down", "no_answer"
	return server, false
}

func serverForProfile(p profile.Profile) Server {
	return Server{ID: p.ID, Name: p.Name, Protocol: p.Protocol, Verdict: "app", Reason: "engine_error"}
}

func profileEndpoint(p profile.Profile) (string, uint16, error) {
	switch p.Protocol {
	case "hysteria2":
		if p.Hy2 == nil || p.Hy2.Host == "" || p.Hy2.Port == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return p.Hy2.Host, p.Hy2.Port, nil
	case "awg":
		if p.AWG == nil || p.AWG.EndpointHost == "" || p.AWG.EndpointPort == 0 {
			return "", 0, errors.New("invalid profile")
		}
		return p.AWG.EndpointHost, p.AWG.EndpointPort, nil
	default:
		return "", 0, errors.New("invalid profile")
	}
}

func uniquePorts(port uint16, extra ...uint16) []uint16 {
	ports := make([]uint16, 0, len(extra)+1)
	seen := map[uint16]bool{}
	for _, p := range append(extra, port) {
		if p != 0 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func hostAlive(ctx context.Context, dial dialContextFunc, host string, ports []uint16, timeout time.Duration) bool {
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct{ alive bool }
	results := make(chan outcome, len(ports))
	for _, port := range ports {
		go func(port uint16) {
			dialCtx, stop := context.WithTimeout(checkCtx, timeout)
			defer stop()
			conn, err := dial(dialCtx, "tcp4", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if conn != nil {
				_ = conn.Close()
			}
			results <- outcome{alive: err == nil || connectionRefused(err)}
		}(port)
	}
	for range ports {
		select {
		case outcome := <-results:
			if outcome.alive {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

func connectionRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10061)) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused") || strings.Contains(strings.ToLower(err.Error()), "actively refused")
}

func serverCounts(servers []Server) string {
	counts := map[string]int{}
	for _, server := range servers {
		counts[server.Verdict]++
	}
	return fmt.Sprintf("ok=%d blocked=%d down=%d config=%d app=%d", counts["ok"], counts["blocked"], counts["down"], counts["config"], counts["app"])
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func udpVerdict(stunAnswered, serverOK, tcpOpen, hostAlive bool) string {
	if stunAnswered || serverOK {
		return "ok"
	}
	if tcpOpen || hostAlive {
		return "blocked"
	}
	return "unknown"
}

func foreignVerdict(total, open int) string {
	if open == 0 {
		return "unknown"
	}
	if total-open >= 2 {
		return "cut"
	}
	return "ok"
}

func natVerdict(ports []uint16) string {
	if len(ports) < 2 {
		return "unknown"
	}
	if ports[0] == ports[1] {
		return "open"
	}
	return "limited"
}

func parseEndpoint(value string, defaultPort uint16) (string, uint16, error) {
	if host, port, err := net.SplitHostPort(value); err == nil {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", 0, errors.New("invalid endpoint")
		}
		return host, uint16(n), nil
	}
	if strings.Count(value, ":") > 1 && strings.HasPrefix(value, "[") {
		return "", 0, errors.New("invalid endpoint")
	}
	if value == "" || defaultPort == 0 {
		return "", 0, errors.New("invalid endpoint")
	}
	return value, defaultPort, nil
}

func numericAddress(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return ip, err == nil && ip.Is4()
}
