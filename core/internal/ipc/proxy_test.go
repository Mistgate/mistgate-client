package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/proxy"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func proxyServer(t *testing.T, logs *bytes.Buffer) (*Server, func(method, params string, trusted bool) (any, *RPCError)) {
	t.Helper()
	dataDir := t.TempDir()
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	t.Cleanup(manager.Close)
	local := proxy.New(proxy.Config{
		Dir: dataDir, Settings: settingsStore.Get, SocksPort: freePort(t), HTTPPort: freePort(t),
		Host: func() string { return "192.168.1.5" },
		Dial: func(context.Context, string, uint16) (net.Conn, error) { return nil, engine.ErrNoTunnel },
	})
	t.Cleanup(local.Close)
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := &Server{Manager: manager, Settings: settingsStore, Proxy: local, Logger: logger}
	return server, func(method, params string, trusted bool) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, trusted)
		return result, rpcErr
	}
}

func asObject(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestProxyRPCShapeAndTrust(t *testing.T) {
	var logs bytes.Buffer
	server, call := proxyServer(t, &logs)
	object := asObject(t, mustCall(t, call, "proxy.get"))
	for key, want := range map[string]any{"on": false, "lan": false, "host": "192.168.1.5", "user": "mistgate", "password": "",
		"error": "", "error_port": 0.0, "clients": 0.0} {
		if got, ok := object[key]; !ok || got != want {
			t.Errorf("proxy.get[%q] = %v, want %v", key, got, want)
		}
	}
	if object["socks_port"] == nil || object["http_port"] == nil || len(object) != 10 {
		t.Errorf("proxy.get = %v", object)
	}
	for _, method := range []string{"proxy.get", "proxy.password"} {
		if _, rpcErr := call(method, `{}`, false); rpcErr == nil || rpcErr.Code != "not_trusted" {
			t.Errorf("%s from an untrusted caller: %v", method, rpcErr)
		}
		if _, rpcErr := call(method, `{"x":1}`, true); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("%s with params: %v", method, rpcErr)
		}
	}
	// a service built without the proxy says so
	server.Proxy = nil
	if _, rpcErr := call("proxy.get", `{}`, true); rpcErr == nil || rpcErr.Code != "service_error" {
		t.Errorf("no proxy: %v", rpcErr)
	}
}

func TestProxyPasswordRPCAndTheLogs(t *testing.T) {
	var logs bytes.Buffer
	server, call := proxyServer(t, &logs)
	first, rpcErr := call("proxy.password", `{}`, true)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	password := asObject(t, first)["password"].(string)
	if len(password) != 16 {
		t.Fatalf("password = %q", password)
	}
	if got := asObject(t, mustCall(t, call, "proxy.get"))["password"]; got != password {
		t.Fatalf("proxy.get password = %v, want the one just made", got)
	}
	second := asObject(t, mustCall(t, call, "proxy.password"))["password"].(string)
	if second == password {
		t.Fatal("the password did not change")
	}
	// nothing secret goes to the log, to settings.get or to the settings event
	if strings.Contains(logs.String(), password) || strings.Contains(logs.String(), second) {
		t.Fatalf("the log has a password:\n%s", logs.String())
	}
	encoded, _ := json.Marshal(server.Settings.Get())
	if strings.Contains(string(encoded), second) || strings.Contains(string(encoded), "password") {
		t.Fatalf("settings carry the password: %s", encoded)
	}
}

func mustCall(t *testing.T, call func(string, string, bool) (any, *RPCError), method string) any {
	t.Helper()
	result, rpcErr := call(method, `{}`, true)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	return result
}

func TestSettingsSetStartsAndStopsTheProxy(t *testing.T) {
	var logs bytes.Buffer
	server, call := proxyServer(t, &logs)
	set := func(params string) {
		t.Helper()
		if _, rpcErr := call("settings.set", params, true); rpcErr != nil {
			t.Fatal(rpcErr)
		}
	}
	address := func() string {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(asObject(t, mustCall(t, call, "proxy.get"))["socks_port"].(float64))))
	}
	listening := func() bool {
		conn, err := net.DialTimeout("tcp", address(), time.Second)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}
	if listening() {
		t.Fatal("listening before it was switched on")
	}
	set(`{"proxy":true}`)
	// the answer to the next proxy.get already shows the result
	object := asObject(t, mustCall(t, call, "proxy.get"))
	if object["on"] != true || object["error"] != "" || object["password"] == "" || !listening() {
		t.Fatalf("after proxy=true: %v", object)
	}
	set(`{"proxy_lan":true}`)
	if object := asObject(t, mustCall(t, call, "proxy.get")); object["lan"] != true || !listening() {
		t.Fatalf("after proxy_lan=true: %v", object)
	}
	if _, rpcErr := call("settings.set", `{"proxy":"yes"}`, true); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Fatalf("bad value: %v", rpcErr)
	}
	set(`{"proxy":false}`)
	if object := asObject(t, mustCall(t, call, "proxy.get")); object["on"] != false || object["lan"] != false || listening() {
		t.Fatalf("after proxy=false: %v", object)
	}
	if !server.Settings.Get().ProxyLAN {
		t.Fatal("proxy_lan was not kept")
	}
}
