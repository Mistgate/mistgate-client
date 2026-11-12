package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

// harness is a proxy whose way out is a function of the test: nothing here touches a network but the loopback.
type harness struct {
	t   *testing.T
	p   *Proxy
	dir string

	mu       sync.Mutex
	set      settings.Settings
	dials    []string
	fwCalls  []bool
	dialFunc func(host string, port uint16) (net.Conn, error)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), set: settings.Settings{Proxy: true}}
	h.dialFunc = func(string, uint16) (net.Conn, error) { return echoConn(), nil }
	h.p = New(Config{
		Dir:      h.dir,
		Settings: func() settings.Settings { h.mu.Lock(); defer h.mu.Unlock(); return h.set },
		Dial: func(_ context.Context, host string, port uint16) (net.Conn, error) {
			h.mu.Lock()
			h.dials = append(h.dials, net.JoinHostPort(host, strconv.Itoa(int(port))))
			fn := h.dialFunc
			h.mu.Unlock()
			return fn(host, port)
		},
		Host: func() string { return "192.168.1.5" },
		Firewall: func(allow bool) error {
			h.mu.Lock()
			h.fwCalls = append(h.fwCalls, allow)
			h.mu.Unlock()
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	h.p.socksPort, h.p.httpPort = 0, 0 // any free port
	h.p.failDelay = 20 * time.Millisecond
	h.p.handshake, h.p.dialTimeout = 3*time.Second, 3*time.Second
	t.Cleanup(h.p.Close)
	return h
}

func (h *harness) start() *harness {
	h.t.Helper()
	h.p.Reload()
	if state := h.p.State(); state.Error != "" {
		h.t.Fatalf("proxy did not start: %+v", state)
	}
	return h
}

func (h *harness) setSettings(s settings.Settings) {
	h.mu.Lock()
	h.set = s
	h.mu.Unlock()
}

func (h *harness) dialed() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dials...)
}

func (h *harness) socksAddr() string {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	return h.p.run.listeners[0].Addr().String()
}

func (h *harness) httpAddr() string {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	return h.p.run.listeners[1].Addr().String()
}

func (h *harness) password() string { return h.p.State().Password }

// echoConn is a "target" that sends back what it gets.
func echoConn() net.Conn {
	client, server := net.Pipe()
	go func() {
		_, _ = io.Copy(server, server)
		_ = server.Close()
	}()
	return client
}

func tcp(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func read(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buffer := make([]byte, n)
	if _, err := io.ReadFull(c, buffer); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buffer
}

// closedSoon: the other side closes without sending anything more.
func closedSoon(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection not closed: n=%d err=%v", n, err)
	}
}

// socksOpen does the greeting and, when the proxy picks the login, the login; it returns the method chosen.
func socksOpen(t *testing.T, addr string, methods []byte, user, password string) (net.Conn, byte, bool) {
	t.Helper()
	c := tcp(t, addr)
	_, _ = c.Write(append([]byte{5, byte(len(methods))}, methods...))
	reply := read(t, c, 2)
	if reply[1] != 2 {
		return c, reply[1], false
	}
	login := append([]byte{1, byte(len(user))}, user...)
	login = append(append(login, byte(len(password))), password...)
	_, _ = c.Write(login)
	return c, 2, read(t, c, 2)[1] == 0
}

func socksRequest(t *testing.T, c net.Conn, command byte, host string, port uint16) byte {
	t.Helper()
	request := []byte{5, command, 0}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4() {
			a := address.As4()
			request = append(append(request, 1), a[:]...)
		} else {
			a := address.As16()
			request = append(append(request, 4), a[:]...)
		}
	} else {
		request = append(append(request, 3, byte(len(host))), host...)
	}
	request = append(request, byte(port>>8), byte(port))
	_, _ = c.Write(request)
	return read(t, c, 10)[1]
}

func echoes(t *testing.T, c net.Conn, text string) {
	t.Helper()
	_, _ = c.Write([]byte(text))
	if got := string(read(t, c, len(text))); got != text {
		t.Fatalf("echo = %q, want %q", got, text)
	}
}

func TestSocksConnectByNameAndAddress(t *testing.T) {
	h := newHarness(t).start()
	for _, target := range []struct {
		host string
		want string
	}{
		{"Example.COM", "example.com:443"},
		{"93.184.216.34", "93.184.216.34:443"},
		{"2606:4700::1111", "[2606:4700::1111]:443"},
	} {
		c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
		if rep := socksRequest(t, c, 1, target.host, 443); rep != 0 {
			t.Fatalf("%s: reply %d", target.host, rep)
		}
		echoes(t, c, "ping through "+target.host)
		dials := h.dialed()
		if got := dials[len(dials)-1]; got != target.want {
			t.Fatalf("dialled %q, want %q", got, target.want)
		}
	}
}

func TestSocksNoTunnelAndRefusals(t *testing.T) {
	h := newHarness(t).start()
	h.mu.Lock()
	h.dialFunc = func(string, uint16) (net.Conn, error) { return nil, engine.ErrNoTunnel }
	h.mu.Unlock()
	c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
	if rep := socksRequest(t, c, 1, "example.com", 443); rep != 3 {
		t.Fatalf("no VPN: reply %d, want 3", rep)
	}
	// nothing the proxy refuses on its own reaches the tunnel
	before := len(h.dialed())
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.9.9", "0.0.0.0", "224.0.0.1",
		"::1", "fe80::1", "fd00::1", "100.64.0.1", "::ffff:10.0.0.1", "localhost", "router.lan", "printer.local", "intranet", "2130706433", "0x7f.1"} {
		c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
		if rep := socksRequest(t, c, 1, host, 80); rep != 2 {
			t.Errorf("%s: reply %d, want 2", host, rep)
		}
	}
	if after := len(h.dialed()); after != before {
		t.Fatalf("a refused destination reached the tunnel (%d dials)", after-before)
	}
}

func TestSocksOnlyConnect(t *testing.T) {
	h := newHarness(t).start()
	for _, command := range []byte{2, 3, 9} { // BIND, UDP ASSOCIATE, nonsense
		c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
		if rep := socksRequest(t, c, command, "example.com", 443); rep != 7 {
			t.Fatalf("command %d: reply %d, want 7", command, rep)
		}
	}
	if len(h.dialed()) != 0 {
		t.Fatal("a refused command dialled")
	}
}

func TestSocksLogin(t *testing.T) {
	h := newHarness(t)
	h.p.isLocal = func(netip.Addr) bool { return false } // every client looks like it is from elsewhere
	h.start()
	password := h.password()

	// no login offered: refused outright
	if _, method, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", ""); method != 0xFF {
		t.Fatalf("method %#x, want 0xFF", method)
	}
	// a wrong password: refused, and not at once
	started := time.Now()
	c, _, ok := socksOpen(t, h.socksAddr(), []byte{0, 2}, User, "wrong-password")
	if ok || time.Since(started) < h.p.failDelay {
		t.Fatalf("wrong password: ok=%v after %v", ok, time.Since(started))
	}
	closedSoon(t, c)
	// a wrong user name with the right password
	if _, _, ok := socksOpen(t, h.socksAddr(), []byte{2}, "root", password); ok {
		t.Fatal("wrong user accepted")
	}
	// the right one
	c, _, ok = socksOpen(t, h.socksAddr(), []byte{0, 2}, User, password)
	if !ok {
		t.Fatal("right login refused")
	}
	if rep := socksRequest(t, c, 1, "example.com", 443); rep != 0 {
		t.Fatalf("reply %d", rep)
	}
	echoes(t, c, "hello")
}

func TestSocksThisMachineNeedsNoLoginButAWrongOneFails(t *testing.T) {
	h := newHarness(t).start()
	if _, method, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", ""); method != 0 {
		t.Fatalf("method %#x, want none", method)
	}
	if _, _, ok := socksOpen(t, h.socksAddr(), []byte{0, 2}, User, "stale-password"); ok {
		t.Fatal("a wrong login from this machine was accepted")
	}
	if _, _, ok := socksOpen(t, h.socksAddr(), []byte{0, 2}, User, h.password()); !ok {
		t.Fatal("the right login from this machine was refused")
	}
	// this machine is never locked out of its own proxy
	for range maxFailures + 2 {
		socksOpen(t, h.socksAddr(), []byte{2}, User, "stale-password")
	}
	if _, method, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", ""); method != 0 {
		t.Fatal("this machine was locked out")
	}
}

func TestLockoutAfterWrongLogins(t *testing.T) {
	h := newHarness(t)
	h.p.isLocal = func(netip.Addr) bool { return false }
	h.p.failDelay = time.Millisecond
	h.start()
	for range maxFailures {
		socksOpen(t, h.socksAddr(), []byte{2}, User, "wrong-password")
	}
	// even the right password is not heard now: the connection is dropped without a word
	c := tcp(t, h.socksAddr())
	_, _ = c.Write([]byte{5, 1, 2})
	closedSoon(t, c)
	// and the same for the HTTP port
	c = tcp(t, h.httpAddr())
	_, _ = c.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	closedSoon(t, c)
}

func basic(password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(User+":"+password))
}

func TestHTTPConnect(t *testing.T) {
	h := newHarness(t).start()
	c := tcp(t, h.httpAddr())
	// the first bytes of the tunnel follow the request without waiting for the answer
	_, _ = c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly"))
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT = %v, %v", response, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "early" {
		t.Fatalf("early bytes = %q, %v", got, err)
	}
	_, _ = c.Write([]byte("more"))
	if _, err := io.ReadFull(reader, got[:4]); err != nil || string(got[:4]) != "more" {
		t.Fatalf("echo = %q, %v", got[:4], err)
	}
	if dials := h.dialed(); len(dials) != 1 || dials[0] != "example.com:443" {
		t.Fatalf("dialled %v", dials)
	}
}

func TestHTTPForwardsAPlainRequest(t *testing.T) {
	h := newHarness(t).start()
	seen := make(chan *http.Request, 1)
	h.mu.Lock()
	h.dialFunc = func(string, uint16) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			seen <- request
			reply := "hello from origin"
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n"+reply)
		}()
		return client, nil
	}
	h.mu.Unlock()

	proxyURL := &url.URL{Scheme: "http", Host: h.httpAddr(), User: url.UserPassword(User, h.password())}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	request, _ := http.NewRequest("GET", "http://example.com/path?q=1", nil)
	request.Header.Set("X-Mine", "yes")
	request.Header.Set("Proxy-Connection", "keep-alive")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || string(body) != "hello from origin" {
		t.Fatalf("got %d %q", response.StatusCode, body)
	}
	origin := <-seen
	if origin.URL.RequestURI() != "/path?q=1" || origin.Host != "example.com" || origin.Header.Get("X-Mine") != "yes" {
		t.Fatalf("origin saw %s %s Host=%s", origin.Method, origin.URL, origin.Host)
	}
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Forwarded", "X-Forwarded-For", "Via"} {
		if value := origin.Header.Get(name); value != "" {
			t.Errorf("origin got %s: %s", name, value)
		}
	}
	if dials := h.dialed(); len(dials) != 1 || dials[0] != "example.com:80" {
		t.Fatalf("dialled %v", dials)
	}
}

func TestHTTPLogin(t *testing.T) {
	h := newHarness(t)
	h.p.isLocal = func(netip.Addr) bool { return false }
	h.start()
	ask := func(header string) (int, string) {
		c := tcp(t, h.httpAddr())
		request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
		if header != "" {
			request += "Proxy-Authorization: " + header + "\r\n"
		}
		_, _ = c.Write([]byte(request + "\r\n"))
		response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header.Get("Proxy-Authenticate")
	}
	if status, challenge := ask(""); status != 407 || !strings.HasPrefix(challenge, "Basic") {
		t.Fatalf("no login: %d %q", status, challenge)
	}
	started := time.Now()
	if status, _ := ask(basic("wrong-password")); status != 407 || time.Since(started) < h.p.failDelay {
		t.Fatalf("wrong password: %d after %v", status, time.Since(started))
	}
	if status, _ := ask("Bearer abc"); status != 407 {
		t.Fatalf("other scheme: %d", status)
	}
	if status, _ := ask(basic(h.password())); status != 200 {
		t.Fatalf("right login: %d", status)
	}
}

func TestHTTPThisMachineAndOddRequests(t *testing.T) {
	h := newHarness(t).start()
	roundTrip := func(request string) int {
		c := tcp(t, h.httpAddr())
		_, _ = c.Write([]byte(request))
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode
	}
	// the proxy is not a web server
	if status := roundTrip("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); status != 400 {
		t.Fatalf("origin-form request: %d, want 400", status)
	}
	// a wrong login from this machine is refused all the same
	if status := roundTrip("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: " + basic("stale") + "\r\n\r\n"); status != 407 {
		t.Fatalf("stale login: %d, want 407", status)
	}
	// destinations the proxy will not touch
	for _, request := range []string{
		"GET http://127.0.0.1:8080/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
		"GET http://192.168.1.1/ HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n",
		"CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n",
		"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
		"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
	} {
		if status := roundTrip(request); status != 403 {
			t.Errorf("%q: %d, want 403", strings.SplitN(request, "\r\n", 2)[0], status)
		}
	}
	if len(h.dialed()) != 0 {
		t.Fatal("a refused destination reached the tunnel")
	}
}

func TestHTTPNoTunnel(t *testing.T) {
	h := newHarness(t).start()
	h.mu.Lock()
	h.dialFunc = func(string, uint16) (net.Conn, error) { return nil, engine.ErrNoTunnel }
	h.mu.Unlock()
	for _, request := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		c := tcp(t, h.httpAddr())
		_, _ = c.Write([]byte(request))
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || response.StatusCode != 503 {
			t.Fatalf("%q: %v, %v", request[:7], response, err)
		}
	}
}

func TestLimits(t *testing.T) {
	for _, name := range []string{"total", "per address"} {
		h := newHarness(t)
		if name == "total" {
			h.p.maxConns = 2
		} else {
			h.p.isLocal = func(netip.Addr) bool { return false }
			h.p.maxPerAddr = 2
		}
		h.start()
		// two clients that say nothing hold two places
		first, _ := tcp(t, h.socksAddr()), tcp(t, h.httpAddr())
		waitClients(t, h, 2)
		closedSoon(t, tcp(t, h.socksAddr()))
		closedSoon(t, tcp(t, h.httpAddr()))
		// a place is free again once a client goes
		_ = first.Close()
		waitClients(t, h, 1)
		c, _, _ := socksOpen(t, h.socksAddr(), []byte{0, 2}, User, h.password())
		if rep := socksRequest(t, c, 1, "example.com", 443); rep != 0 {
			t.Fatalf("%s: reply %d after a place was freed", name, rep)
		}
		h.p.Close()
	}
}

func waitClients(t *testing.T, h *harness, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.p.State().Clients != want {
		if time.Now().After(deadline) {
			t.Fatalf("clients = %d, want %d", h.p.State().Clients, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNewPasswordCutsConnectionsFromElsewhere(t *testing.T) {
	h := newHarness(t)
	var thisMachine atomic.Bool
	thisMachine.Store(true)
	h.p.isLocal = func(netip.Addr) bool { return thisMachine.Load() }
	h.start()
	old := h.password()

	here, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
	if rep := socksRequest(t, here, 1, "example.com", 443); rep != 0 {
		t.Fatalf("reply %d", rep)
	}
	thisMachine.Store(false)
	away, _, ok := socksOpen(t, h.socksAddr(), []byte{2}, User, old)
	if !ok || socksRequest(t, away, 1, "example.org", 443) != 0 {
		t.Fatal("could not open the remote tunnel")
	}
	echoes(t, here, "a")
	echoes(t, away, "b")

	state, err := h.p.NewPassword()
	if err != nil || state.Password == old || len(state.Password) != passwordLength {
		t.Fatalf("NewPassword() = %+v, %v", state, err)
	}
	closedSoon(t, away)
	echoes(t, here, "still here")
	// the old password is dead, the new one works
	if _, _, ok := socksOpen(t, h.socksAddr(), []byte{2}, User, old); ok {
		t.Fatal("the old password still works")
	}
	if _, _, ok := socksOpen(t, h.socksAddr(), []byte{2}, User, state.Password); !ok {
		t.Fatal("the new password does not work")
	}
	if readPassword(h.dir) != state.Password {
		t.Fatal("the new password was not saved")
	}
}

func TestPasswordFile(t *testing.T) {
	h := newHarness(t)
	h.setSettings(settings.Settings{})
	h.p.Reload()
	if _, err := os.Stat(filepath.Join(h.dir, passwordFile)); err == nil {
		t.Fatal("a password was made before the proxy was ever on")
	}
	if h.password() != "" {
		t.Fatal("password before first enable")
	}
	h.setSettings(settings.Settings{Proxy: true})
	h.p.Reload()
	password := h.password()
	if len(password) != passwordLength || strings.ContainsAny(password, "0O1lI") || strings.Trim(password, passwordAlphabet) != "" {
		t.Fatalf("password %q is not 16 characters of the alphabet", password)
	}
	data, err := os.ReadFile(filepath.Join(h.dir, passwordFile))
	if err != nil || string(data) != `{"password":"`+password+`"}` {
		t.Fatalf("file = %q, %v", data, err)
	}
	// off and on again, and a new process: the same password
	h.setSettings(settings.Settings{})
	h.p.Reload()
	h.setSettings(settings.Settings{Proxy: true})
	h.p.Reload()
	again := New(Config{Dir: h.dir, Settings: func() settings.Settings { return settings.Settings{} }})
	if h.password() != password || again.State().Password != password {
		t.Fatal("the password changed")
	}
	// a broken file starts a new one
	_ = os.WriteFile(filepath.Join(h.dir, passwordFile), []byte("{"), 0600)
	if New(Config{Dir: h.dir, Settings: func() settings.Settings { return settings.Settings{} }}).State().Password != "" {
		t.Fatal("a broken file gave a password")
	}
}

func TestReloadFollowsTheSettings(t *testing.T) {
	h := newHarness(t)
	h.setSettings(settings.Settings{})
	h.p.Reload()
	if state := h.p.State(); state.On || state.Error != "" || state.Host != "192.168.1.5" || state.User != User {
		t.Fatalf("state = %+v", state)
	}
	h.p.mu.Lock()
	listening := h.p.run != nil
	h.p.mu.Unlock()
	if listening {
		t.Fatal("listening while off")
	}
	// proxy_lan alone does nothing
	h.setSettings(settings.Settings{ProxyLAN: true})
	h.p.Reload()
	if state := h.p.State(); state.On || state.LAN {
		t.Fatalf("state = %+v", state)
	}

	h.setSettings(settings.Settings{Proxy: true})
	h.p.Reload()
	addr := h.socksAddr()
	echoOK := func() {
		c, _, _ := socksOpen(t, addr, []byte{0}, "", "")
		if socksRequest(t, c, 1, "example.com", 443) != 0 {
			t.Fatal("no tunnel")
		}
	}
	echoOK()
	if state := h.p.State(); !state.On || state.LAN || state.Clients < 0 {
		t.Fatalf("state = %+v", state)
	}

	h.setSettings(settings.Settings{Proxy: true, ProxyLAN: true})
	h.p.Reload()
	if state := h.p.State(); !state.LAN {
		t.Fatalf("state = %+v", state)
	}
	addr = h.socksAddr()
	if !strings.HasPrefix(addr, "0.0.0.0:") {
		t.Fatalf("home network on, listening on %s", addr)
	}
	addr = strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
	echoOK()

	h.setSettings(settings.Settings{})
	h.p.Reload()
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("still listening after off")
	}
	h.mu.Lock()
	calls := h.fwCalls
	h.mu.Unlock()
	// the rule is set up once on the first Reload, added for the home network, taken away again: never repeated
	want := []bool{false, true, false}
	if len(calls) != len(want) {
		t.Fatalf("firewall calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("firewall calls = %v, want %v", calls, want)
		}
	}
	h.p.Close()
	h.mu.Lock()
	last := h.fwCalls[len(h.fwCalls)-1]
	h.mu.Unlock()
	if last {
		t.Fatal("Close left the firewall rule")
	}
}

func TestBusyPortIsReportedAndRetried(t *testing.T) {
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port
	h := newHarness(t)
	h.p.socksPort = port
	h.p.Reload()
	state := h.p.State()
	if state.Error != "port_busy" || state.ErrorPort != port {
		t.Fatalf("state = %+v", state)
	}
	h.p.Reload() // still busy: still reported, no crash
	if h.p.State().Error != "port_busy" {
		t.Fatal("error forgotten")
	}
	_ = blocker.Close()
	h.p.Reload()
	if state := h.p.State(); state.Error != "" || state.ErrorPort != 0 {
		t.Fatalf("state = %+v after the port was freed", state)
	}
	// a busy HTTP port is the same
	h2 := newHarness(t)
	blocker2, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer blocker2.Close()
	h2.p.httpPort = blocker2.Addr().(*net.TCPAddr).Port
	h2.p.Reload()
	if state := h2.p.State(); state.Error != "port_busy" || state.ErrorPort != h2.p.httpPort {
		t.Fatalf("state = %+v", state)
	}
	// and the firewall rule is not kept for a proxy that is not listening
	h2.mu.Lock()
	defer h2.mu.Unlock()
	if len(h2.fwCalls) != 1 || h2.fwCalls[0] {
		t.Fatalf("firewall calls = %v", h2.fwCalls)
	}
}

func TestIdleTunnelIsClosed(t *testing.T) {
	h := newHarness(t)
	h.p.idle = 150 * time.Millisecond
	h.start()
	c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
	if socksRequest(t, c, 1, "example.com", 443) != 0 {
		t.Fatal("no tunnel")
	}
	// talking keeps it open past the idle time
	for range 4 {
		time.Sleep(60 * time.Millisecond)
		echoes(t, c, "x")
	}
	closedSoon(t, c)
}

func TestHalfClose(t *testing.T) {
	// a target that answers only after it has seen the end of the request
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("answer to: "), data...))
	}()
	h := newHarness(t).start()
	h.mu.Lock()
	h.dialFunc = func(string, uint16) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }
	h.mu.Unlock()
	c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
	if socksRequest(t, c, 1, "example.com", 80) != 0 {
		t.Fatal("no tunnel")
	}
	_, _ = c.Write([]byte("request"))
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "answer to: request" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTargetClosingEndsTheClient(t *testing.T) {
	h := newHarness(t).start()
	h.mu.Lock()
	h.dialFunc = func(string, uint16) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	h.mu.Unlock()
	c, _, _ := socksOpen(t, h.socksAddr(), []byte{0}, "", "")
	socksRequest(t, c, 1, "example.com", 80)
	closedSoon(t, c) // the target's end of data reaches the client as an end of data...
	_ = c.Close()    // ...and a client that answers with a close frees the place
	waitClients(t, h, 0)
}

func TestDestinationPolicy(t *testing.T) {
	for text, want := range map[string]bool{
		"1.1.1.1": true, "8.8.8.8": true, "93.184.216.34": true, "2606:4700::1111": true, "::ffff:8.8.8.8": true,
		"127.0.0.1": false, "127.5.5.5": false, "0.0.0.0": false, "10.0.0.1": false, "172.31.255.1": false, "192.168.0.1": false,
		"169.254.1.1": false, "224.0.0.251": false, "255.255.255.255": false, "100.100.100.100": false, "198.18.0.1": false,
		"::": false, "::1": false, "fe80::1": false, "fc00::1": false, "ff02::1": false, "2002:a00:1::": false, "64:ff9b::a00:1": false,
		"::ffff:127.0.0.1": false, "fe80::1%eth0": false,
	} {
		address, err := netip.ParseAddr(text)
		if err != nil {
			t.Fatal(text, err)
		}
		if got := AllowedAddr(address); got != want {
			t.Errorf("AllowedAddr(%s) = %v, want %v", text, got, want)
		}
	}
	for host, want := range map[string]bool{
		"example.com": true, "a.b.example.co.uk": true, "xn--80ak6aa92e.com": true, "my_host.example.org": true, "Example.COM.": true,
		"localhost": false, "foo.localhost": false, "printer.local": false, "nas.lan": false, "x.internal": false, "single": false,
		"a..b.com": false, "-a.com": false, "a.com-": false, "exa mple.com": false, "пример.рф": false, "1.2.3": false,
		"127.1": false, "0x7f.0.0.1": false, "2130706433": false, "a.b.123": false, "": false,
	} {
		_, err := cleanTarget(host, 443)
		if (err == nil) != want {
			t.Errorf("cleanTarget(%q) = %v, want ok=%v", host, err, want)
		}
	}
	if _, err := cleanTarget("example.com", 0); err == nil {
		t.Error("port 0 allowed")
	}
	for text, want := range map[string]bool{"127.0.0.1": true, "10.2.3.4": true, "192.168.1.9": true, "172.20.0.1": true, "169.254.3.3": true,
		"8.8.8.8": false, "172.32.0.1": false, "100.64.0.1": false} {
		if got := lanAddr(netip.MustParseAddr(text)); got != want {
			t.Errorf("lanAddr(%s) = %v, want %v", text, got, want)
		}
	}
}
