// Package proxy is the local SOCKS5 and HTTP proxy: programs on this PC, and with a second switch the devices of the
// home network, reach the internet through the VPN tunnel that is up. Nothing it opens goes out any other way.
//
// What is never written to the log: the password, the logins tried, the clients' addresses, the destinations.
package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/settings"
)

const (
	User      = "mistgate"
	SocksPort = 1080
	HTTPPort  = 8080
)

// Config is what the proxy is given; New fills in nothing that is missing except the optional hooks.
type Config struct {
	Dir      string                                                                // where proxy.json lives
	Settings func() settings.Settings                                              // the current settings
	Dial     func(ctx context.Context, host string, port uint16) (net.Conn, error) // a connection through the tunnel
	Host     func() string                                                         // this machine's home-network address, for display
	Firewall func(allow bool) error                                                // the Windows Firewall rule for the home network
	Logger   *slog.Logger

	SocksPort, HTTPPort int // 0 is 1080 and 8080; only a test asks for others
}

// State is the proxy.get object.
type State struct {
	On        bool   `json:"on"`
	LAN       bool   `json:"lan"`
	Host      string `json:"host"`
	SocksPort int    `json:"socks_port"`
	HTTPPort  int    `json:"http_port"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Error     string `json:"error"`
	ErrorPort int    `json:"error_port"`
	Clients   int    `json:"clients"`
}

type Proxy struct {
	cfg Config
	log *slog.Logger

	// The limits and clocks; tests change them before the first Reload.
	isLocal                func(netip.Addr) bool
	socksPort, httpPort    int
	maxConns, maxPerAddr   int
	maxPerLocal            int
	handshake, dialTimeout time.Duration
	idle, halfCloseIdle    time.Duration
	failDelay              time.Duration
	fails                  failureTable

	ctl sync.Mutex // one Reload, NewPassword or Close at a time; the firewall rule is changed under it
	mu  sync.Mutex // the state below, never held while closing or dialling

	applied  bool // Reload has run once
	closed   bool
	on, lan  bool
	errCode  string
	errPort  int
	password string
	run      *run
	sessions map[*session]struct{}
	perAddr  map[netip.Addr]int
	fwKnown  bool
	fwOn     bool
}

// run is one start of the listeners.
type run struct {
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	srv       *http.Server
	transport *http.Transport
}

func New(cfg Config) *Proxy {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	p := &Proxy{
		cfg: cfg, log: logger,
		isLocal:   func(address netip.Addr) bool { return address.Unmap().IsLoopback() },
		socksPort: SocksPort, httpPort: HTTPPort,
		// ponytail: 64 per address as asked, but the local machine's browsers hold many tunnels open: 256 for loopback
		maxConns: 512, maxPerAddr: 64, maxPerLocal: 256,
		handshake: 10 * time.Second, dialTimeout: 15 * time.Second,
		idle: 5 * time.Minute, halfCloseIdle: 15 * time.Second,
		failDelay: time.Second,
		sessions:  make(map[*session]struct{}),
		perAddr:   make(map[netip.Addr]int),
		password:  readPassword(cfg.Dir),
	}
	if cfg.SocksPort != 0 {
		p.socksPort = cfg.SocksPort
	}
	if cfg.HTTPPort != 0 {
		p.httpPort = cfg.HTTPPort
	}
	p.fails.m = make(map[netip.Addr]failure)
	return p
}

// Reload makes the listeners match the settings: it is the one place that starts and stops them, and it is safe to
// call as often as wanted. A failed start (a busy port) is tried again by the next call.
func (p *Proxy) Reload() {
	p.ctl.Lock()
	defer p.ctl.Unlock()
	configured := p.cfg.Settings()
	on, lan := configured.Proxy, configured.Proxy && configured.ProxyLAN
	p.mu.Lock()
	if p.closed || p.applied && on == p.on && lan == p.lan && p.errCode == "" {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	p.teardown()
	p.mu.Lock()
	p.applied, p.on, p.lan, p.errCode, p.errPort = true, on, lan, "", 0
	needPassword := on && p.password == ""
	p.mu.Unlock()
	if needPassword {
		p.createPassword()
	}
	if on {
		if port := p.listen(lan); port != 0 {
			p.mu.Lock()
			p.errCode, p.errPort = "port_busy", port
			p.mu.Unlock()
			p.log.Warn("local proxy: port is busy", "port", port)
		} else {
			p.log.Info("local proxy on", "lan", lan)
		}
	} else {
		p.log.Info("local proxy off")
	}
	p.syncFirewall(lan)
}

// createPassword makes the first password. A disk that will not take it still gives a working proxy until the
// service restarts.
func (p *Proxy) createPassword() {
	password, err := newPassword()
	if err != nil {
		return // no randomness: the proxy stays without a password, and nobody can log in from outside
	}
	if err := writePassword(p.cfg.Dir, password); err != nil {
		p.log.Warn("local proxy: the password could not be saved")
	}
	p.mu.Lock()
	p.password = password
	p.mu.Unlock()
}

// NewPassword replaces the password and drops the connections that came from elsewhere than this machine.
func (p *Proxy) NewPassword() (State, error) {
	p.ctl.Lock()
	password, err := newPassword()
	if err == nil {
		err = writePassword(p.cfg.Dir, password)
	}
	if err == nil {
		p.mu.Lock()
		p.password = password
		p.mu.Unlock()
	}
	p.ctl.Unlock()
	if err != nil {
		return p.State(), errors.New("the new password could not be saved")
	}
	p.killSessions(true)
	return p.State(), nil
}

// Close stops everything and takes the firewall rule away.
func (p *Proxy) Close() {
	p.ctl.Lock()
	defer p.ctl.Unlock()
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.teardown()
	if p.cfg.Firewall != nil {
		_ = p.cfg.Firewall(false)
	}
}

func (p *Proxy) State() State {
	configured := p.cfg.Settings()
	p.mu.Lock()
	state := State{
		On: configured.Proxy, LAN: configured.Proxy && configured.ProxyLAN,
		SocksPort: p.socksPort, HTTPPort: p.httpPort, User: User, Password: p.password,
		Error: p.errCode, ErrorPort: p.errPort, Clients: len(p.sessions),
	}
	p.mu.Unlock()
	if p.cfg.Host != nil {
		state.Host = p.cfg.Host()
	}
	return state
}

// listen binds both ports (the loopback only, or every IPv4 address when the home network is allowed). It returns the
// port that could not be had, 0 when all is well.
func (p *Proxy) listen(lan bool) int {
	host := "127.0.0.1"
	if lan {
		host = "0.0.0.0" // clients are vetted one by one in admit
	}
	socks, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(p.socksPort)))
	if err != nil {
		return max(p.socksPort, 1)
	}
	web, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(p.httpPort)))
	if err != nil {
		_ = socks.Close()
		return max(p.httpPort, 1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{ctx: ctx, cancel: cancel, listeners: []net.Listener{socks, web}}
	r.srv, r.transport = p.newHTTPServer(ctx)
	p.mu.Lock()
	p.run = r
	p.mu.Unlock()
	go p.acceptSocks(&admitListener{Listener: socks, p: p, ctx: ctx})
	go func() { _ = r.srv.Serve(&admitListener{Listener: web, p: p, ctx: ctx}) }()
	return 0
}

// teardown closes the listeners and every connection of the run.
func (p *Proxy) teardown() {
	p.mu.Lock()
	r := p.run
	p.run = nil
	p.mu.Unlock()
	if r == nil {
		return
	}
	r.cancel() // before the sessions are listed: admit refuses a new one once this is done
	for _, ln := range r.listeners {
		_ = ln.Close()
	}
	_ = r.srv.Close()
	r.transport.CloseIdleConnections()
	p.killSessions(false)
}

func (p *Proxy) killSessions(onlyRemote bool) {
	p.mu.Lock()
	list := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		if !onlyRemote || !s.local {
			list = append(list, s)
		}
	}
	p.mu.Unlock()
	for _, s := range list {
		s.kill()
	}
}

// syncFirewall keeps the rule for the home network only while the proxy is listening there.
func (p *Proxy) syncFirewall(lan bool) {
	if p.cfg.Firewall == nil {
		return
	}
	p.mu.Lock()
	want := lan && p.errCode == ""
	known, current := p.fwKnown, p.fwOn
	p.mu.Unlock()
	if known && current == want {
		return
	}
	if err := p.cfg.Firewall(want); err != nil {
		p.log.Warn("local proxy: the firewall rule could not be changed", "error", err)
		return
	}
	p.mu.Lock()
	p.fwKnown, p.fwOn = true, want
	p.mu.Unlock()
}

func (p *Proxy) credsOK(user, password string) bool {
	p.mu.Lock()
	expected := p.password
	p.mu.Unlock()
	if expected == "" {
		return false
	}
	// both are compared, always
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(User))
	passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(expected))
	return userOK&passwordOK == 1
}

// authFailed answers a wrong login: it is counted against the address (a client in the home network gets a few tries
// a minute, this machine is not locked out of its own proxy) and it is made to wait.
func (p *Proxy) authFailed(s *session) {
	if !s.local {
		p.fails.add(s.remote, time.Now())
	}
	timer := time.NewTimer(p.failDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.ctx.Done():
	}
}

// dial vets the destination, then asks the tunnel; there is no other way out.
func (p *Proxy) dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	host, err := cleanTarget(host, port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()
	return p.cfg.Dial(ctx, host, port)
}

var quietLog = log.New(io.Discard, "", 0)

// session is an accepted connection, counted and vetted. Close forgets it; kill also closes what it was relaying to.
type session struct {
	net.Conn
	p      *Proxy
	ctx    context.Context // the run's
	remote netip.Addr
	local  bool
	once   sync.Once
	mu     sync.Mutex
	up     net.Conn
	dead   bool
}

func (s *session) Close() error {
	s.once.Do(func() { s.p.forget(s) })
	return s.Conn.Close()
}

// CloseWrite is the half-close of the client's side of a tunnel.
func (s *session) CloseWrite() error {
	if half, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}

// setUpstream remembers the connection that kill must close too; false if kill came first.
func (s *session) setUpstream(up net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return false
	}
	s.up = up
	return true
}

func (s *session) kill() {
	s.mu.Lock()
	s.dead = true
	up := s.up
	s.mu.Unlock()
	if up != nil {
		_ = up.Close()
	}
	_ = s.Close()
}

func (p *Proxy) forget(s *session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, s)
	if p.perAddr[s.remote]--; p.perAddr[s.remote] <= 0 {
		delete(p.perAddr, s.remote)
	}
}

// admit decides whether a new connection is served at all; a refused one is closed without a word.
func (p *Proxy) admit(ctx context.Context, raw net.Conn) *session {
	tcp, ok := raw.RemoteAddr().(*net.TCPAddr)
	var remote netip.Addr
	if ok {
		remote, ok = netip.AddrFromSlice(tcp.IP)
	}
	remote = remote.Unmap()
	local := ok && p.isLocal(remote)
	if !ok || !local && (!lanAddr(remote) || p.fails.blocked(remote, time.Now())) {
		_ = raw.Close()
		return nil
	}
	limit := p.maxPerAddr
	if local {
		limit = p.maxPerLocal
	}
	p.mu.Lock()
	if ctx.Err() != nil || len(p.sessions) >= p.maxConns || p.perAddr[remote] >= limit {
		p.mu.Unlock()
		_ = raw.Close()
		return nil
	}
	s := &session{Conn: raw, p: p, ctx: ctx, remote: remote, local: local}
	p.sessions[s] = struct{}{}
	p.perAddr[remote]++
	p.mu.Unlock()
	return s
}

type admitListener struct {
	net.Listener
	p   *Proxy
	ctx context.Context
}

func (l *admitListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if s := l.p.admit(l.ctx, raw); s != nil {
			return s, nil
		}
	}
}

// failureTable counts wrong logins per address.
type failureTable struct {
	mu sync.Mutex
	m  map[netip.Addr]failure
}

type failure struct {
	n     int
	since time.Time
}

const (
	maxFailures   = 5
	failureWindow = time.Minute
)

func (t *failureTable) blocked(address netip.Addr, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.m[address]
	return ok && now.Sub(f.since) < failureWindow && f.n >= maxFailures
}

func (t *failureTable) add(address netip.Addr, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) > 256 { // ponytail: swept when it grows, not on a timer; fine for the few addresses of a home
		for key, f := range t.m {
			if now.Sub(f.since) >= failureWindow {
				delete(t.m, key)
			}
		}
	}
	f := t.m[address]
	if f.n == 0 || now.Sub(f.since) >= failureWindow {
		f = failure{since: now}
	}
	f.n++
	t.m[address] = f
}

func (t *failureTable) clear(address netip.Addr) {
	t.mu.Lock()
	delete(t.m, address)
	t.mu.Unlock()
}
