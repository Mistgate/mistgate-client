package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func TestReadLineFramingAndLimit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr error
	}{
		{name: "newline frame", input: "{\"id\":1}\n", want: len("{\"id\":1}")},
		{name: "exact limit", input: strings.Repeat("x", MaxLineBytes) + "\n", want: MaxLineBytes},
		{name: "over limit", input: strings.Repeat("x", MaxLineBytes+1) + "\n", wantErr: ErrLineTooLong},
		{name: "unterminated", input: "{\"id\":1}", wantErr: ErrUnterminatedLine},
		{name: "empty stream", input: "", wantErr: io.EOF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line, err := ReadLine(bufio.NewReader(strings.NewReader(test.input)))
			if test.wantErr != nil {
				if err != test.wantErr {
					t.Fatalf("ReadLine error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(line) != test.want {
				t.Fatalf("line length = %d, want %d", len(line), test.want)
			}
		})
	}
}

func TestParseRequestAndDispatchErrors(t *testing.T) {
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settings.Defaults)
	defer manager.Close()
	server := &Server{Manager: manager, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tests := []struct {
		name       string
		line       string
		trusted    bool
		wantCode   string
		wantResult bool
	}{
		{name: "unknown method", line: `{"id":7,"method":"unknown","params":{}}`, trusted: true, wantCode: "unknown_method"},
		{name: "bad connect params", line: `{"id":8,"method":"connect","params":{"protocol":"vless"}}`, trusted: true, wantCode: "bad_params"},
		{name: "null connect value", line: `{"id":13,"method":"connect","params":{"server":null}}`, trusted: true, wantCode: "bad_params"},
		{name: "bad JSON params", line: `{"id":9,"method":"hello","params":{"client":7}}`, trusted: true, wantCode: "bad_params"},
		{name: "untrusted connect", line: `{"id":10,"method":"connect","params":{}}`, trusted: false, wantCode: "not_trusted"},
		{name: "untrusted hello", line: `{"id":12,"method":"hello","params":{"client":"0.0.1"}}`, trusted: false, wantCode: "not_trusted"},
		{name: "untrusted status", line: `{"id":11,"method":"status","params":{}}`, trusted: false, wantResult: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, parseErr := ParseRequest([]byte(test.line))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			result, _, rpcErr := server.dispatch(context.Background(), request, test.trusted)
			if test.wantCode != "" {
				if rpcErr == nil || rpcErr.Code != test.wantCode {
					t.Fatalf("dispatch error = %#v, want code %q", rpcErr, test.wantCode)
				}
				return
			}
			if rpcErr != nil || result == nil {
				t.Fatalf("dispatch result = %#v, error = %#v", result, rpcErr)
			}
		})
	}

	if _, err := ParseRequest([]byte(`{"id":{},"method":"status"}`)); err == nil || err.Code != "bad_params" {
		t.Fatalf("invalid request id error = %#v, want bad_params", err)
	}
	if _, err := ParseRequest([]byte(`{"id":1,"method":"status"} {}`)); err == nil || err.Code != "bad_params" {
		t.Fatalf("trailing JSON error = %#v, want bad_params", err)
	}
}

func TestSettingsMethodsAndEvent(t *testing.T) {
	store, err := settings.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), store.Get)
	defer manager.Close()
	wantRoutes := geo.Routes{Mode: "smart", Region: "auto", Effective: "ru", Available: true, Entries: 100, UpdatedUnix: 123}
	server := &Server{Manager: manager, Settings: store, Routes: func() geo.Routes { return wantRoutes }}

	request, parseErr := ParseRequest([]byte(`{"id":1,"method":"settings.get","params":{}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	result, _, rpcErr := server.dispatch(context.Background(), request, true)
	if rpcErr != nil || result != store.Get() {
		t.Fatalf("settings.get = %#v, %#v; want %#v", result, rpcErr, store.Get())
	}

	request, parseErr = ParseRequest([]byte(`{"id":2,"method":"settings.set","params":{"lan":false,"kill_switch":"off"}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	result, _, rpcErr = server.dispatch(context.Background(), request, true)
	want := settings.Settings{KillSwitch: "off", LAN: false, Protocol: "auto", RouteMode: "all", RouteRegion: "auto"}
	if rpcErr != nil || result != want {
		t.Fatalf("settings.set = %#v, %#v; want %#v", result, rpcErr, want)
	}

	for _, raw := range []string{
		`{"id":3,"method":"settings.set","params":{"unknown":true}}`,
		`{"id":4,"method":"settings.set","params":{"game":null}}`,
		`{"id":7,"method":"settings.set","params":{"route_mode":"region"}}`,
		`{"id":8,"method":"settings.set","params":{"route_region":"RU"}}`,
	} {
		request, parseErr = ParseRequest([]byte(raw))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if _, _, rpcErr = server.dispatch(context.Background(), request, true); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Fatalf("settings.set dispatch error = %#v, want bad_params", rpcErr)
		}
	}
	request, parseErr = ParseRequest([]byte(`{"id":9,"method":"settings.set","params":{"route_mode":"smart","route_region":"ru"}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if result, _, rpcErr = server.dispatch(context.Background(), request, true); rpcErr != nil || result != (settings.Settings{KillSwitch: "off", LAN: false, Protocol: "auto", RouteMode: "smart", RouteRegion: "ru"}) {
		t.Fatalf("route settings.set = %#v, %#v", result, rpcErr)
	}
	request, parseErr = ParseRequest([]byte(`{"id":10,"method":"routes.get","params":{}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if result, _, rpcErr = server.dispatch(context.Background(), request, true); rpcErr != nil || result != wantRoutes {
		t.Fatalf("routes.get = %#v, %#v; want %#v", result, rpcErr, wantRoutes)
	}

	request, parseErr = ParseRequest([]byte(`{"id":5,"method":"settings.set","params":{"lan":true}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if _, _, rpcErr = server.dispatch(context.Background(), request, false); rpcErr == nil || rpcErr.Code != "not_trusted" {
		t.Fatalf("untrusted settings.set error = %#v, want not_trusted", rpcErr)
	}

	request, parseErr = ParseRequest([]byte(`{"id":6,"method":"subscribe","params":{"events":["settings","routes"]}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	_, events, rpcErr := server.dispatch(context.Background(), request, true)
	if rpcErr != nil || events == nil {
		t.Fatalf("settings subscribe = %#v, %#v", events, rpcErr)
	}
	defer events.Close()
	manager.Events().Publish("settings", store.Get())
	select {
	case event := <-events.C:
		if event.Name != "settings" || event.Data != store.Get() {
			t.Fatalf("settings event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("settings event was not forwarded")
	}
	manager.Events().Publish("routes", wantRoutes)
	select {
	case event := <-events.C:
		if event.Name != "routes" || event.Data != wantRoutes {
			t.Fatalf("routes event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("routes event was not forwarded")
	}
}

func TestSubscriptionEventAndConnectSelector(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{})
	manager := session.NewManager(fake, settings.Defaults)
	defer manager.Close()
	server := &Server{Manager: manager}

	request, err := ParseRequest([]byte(`{"id":1,"method":"subscribe","params":{"events":["subs"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, events, rpcErr := server.dispatch(context.Background(), request, true)
	if rpcErr != nil || events == nil {
		t.Fatalf("subscribe dispatch = %#v, %#v", events, rpcErr)
	}
	defer events.Close()
	manager.Events().Publish("subs", map[string]any{"subs": []string{"one"}})
	select {
	case event := <-events.C:
		if event.Name != "subs" {
			t.Fatalf("event name = %q", event.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("subs event was not forwarded")
	}

	request, err = ParseRequest([]byte(`{"id":2,"method":"connect","params":{"server":"auto","protocol":"awg","sub":"sub-1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, rpcErr := server.dispatch(context.Background(), request, true); rpcErr != nil {
		t.Fatalf("connect dispatch = %#v", rpcErr)
	}
	deadline := time.After(time.Second)
	for {
		if targets := fake.Targets(); len(targets) > 0 {
			if targets[0].Sub != "sub-1" || targets[0].Protocol != "awg" {
				t.Fatalf("engine target = %#v", targets[0])
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("connect target was not passed to the engine")
		case <-time.After(time.Millisecond * 5):
		}
	}
}

func TestSlowClientIsDroppedWhenWriteQueueFills(t *testing.T) {
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settings.Defaults)
	defer manager.Close()
	server := &Server{Manager: manager, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), QueueSize: 1}
	serverConn, clientConn := netPipe(t)
	serveDone := make(chan struct{})
	go func() {
		server.ServeConn(context.Background(), serverConn, true)
		close(serveDone)
	}()

	request := []byte("{\"id\":1,\"method\":\"status\",\"params\":{}}\n")
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for range 100 {
			if _, err := clientConn.Write(request); err != nil {
				return
			}
		}
	}()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server kept a client whose outbound queue was blocked")
	}
	_ = clientConn.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("client writer stayed blocked after server dropped the connection")
	}
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	return net.Pipe()
}

func TestMarshalResponseIsJSONLine(t *testing.T) {
	line, err := MarshalResponse(Response{ID: json.RawMessage("2"), Result: map[string]bool{"trusted": true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(line), "\n") {
		t.Fatalf("response missing newline: %q", line)
	}
}
