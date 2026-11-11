package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func checkServer(t *testing.T, withCheck bool) (*Server, *settings.Store, func(method, params string) (any, *RPCError)) {
	t.Helper()
	dataDir := t.TempDir()
	geoStore, err := geo.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	t.Cleanup(manager.Close)
	server := &Server{
		Manager:  manager,
		Settings: settingsStore,
		Geo:      geoStore,
		Routes: func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		},
	}
	if withCheck {
		server.Check = func(name string) geo.Check {
			configured := settingsStore.Get()
			return geoStore.CheckName(configured.RouteMode, "ru", name, true)
		}
	}
	call := func(method, params string) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, true)
		return result, rpcErr
	}
	return server, settingsStore, call
}

func TestRoutesSetKeepsBlockWhenAbsentAndReportsBlockActive(t *testing.T) {
	_, settingsStore, call := checkServer(t, true)
	result, rpcErr := call("routes.set", `{"block":{"sites":["Ads.Example"]}}`)
	view, ok := result.(geo.Routes)
	if rpcErr != nil || !ok || len(view.Rules.Block.Sites) != 1 || view.Rules.Block.Sites[0] != "ads.example" {
		t.Fatalf("routes.set block = %#v, %#v", result, rpcErr)
	}
	if view.BlockActive {
		t.Fatal("block_active in mode all")
	}
	// an older window sends only direct and vpn: the block lists stay
	result, rpcErr = call("routes.set", `{"direct":{"sites":["a.example"]},"vpn":{"sites":["b.example"]}}`)
	view = result.(geo.Routes)
	if rpcErr != nil || len(view.Rules.Block.Sites) != 1 || len(view.Rules.Direct.Sites) != 1 || len(view.Rules.VPN.Sites) != 1 {
		t.Fatalf("routes.set without block = %#v, %#v", result, rpcErr)
	}
	// a partial block update merges like the other two
	result, rpcErr = call("routes.set", `{"block":{"collections":[]}}`)
	view = result.(geo.Routes)
	if rpcErr != nil || len(view.Rules.Block.Sites) != 1 {
		t.Fatalf("partial block = %#v, %#v", result, rpcErr)
	}
	result, rpcErr = call("routes.set", `{"block":{"sites":[]}}`)
	if view = result.(geo.Routes); rpcErr != nil || len(view.Rules.Block.Sites) != 0 {
		t.Fatalf("clearing block = %#v, %#v", result, rpcErr)
	}
	for _, bad := range []string{`{"block":null}`, `{"block":{"unknown":[]}}`, `{"block":{"sites":["a b"]}}`, `{"block":{"collections":["geosite:Bad"]}}`} {
		if _, rpcErr := call("routes.set", bad); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("routes.set(%s) = %#v; want bad_params", bad, rpcErr)
		}
	}

	if _, err := settingsStore.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(`"smart"`)}); err != nil {
		t.Fatal(err)
	}
	result, rpcErr = call("routes.get", `{}`)
	if view = result.(geo.Routes); rpcErr != nil || !view.BlockActive {
		t.Fatalf("routes.get in smart = %#v, %#v", result, rpcErr)
	}
	encoded, _ := json.Marshal(view)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	if string(fields["block_active"]) != "true" {
		t.Fatalf("block_active on the wire: %s", fields["block_active"])
	}
}

func TestRoutesCheck(t *testing.T) {
	_, settingsStore, call := checkServer(t, true)
	if _, rpcErr := call("routes.set", `{"direct":{"sites":["direct.example"]},"block":{"sites":["ads.example"]}}`); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	tests := []struct {
		mode, site string
		want       geo.Check
	}{
		{"all", "ads.example", geo.Check{Route: "vpn", By: "mode", Rule: "", DNS: "vpn"}},
		{"smart", "https://Sub.Ads.Example/path", geo.Check{Route: "block", By: "site", Rule: "ads.example", DNS: "vpn"}},
		{"smart", "direct.example", geo.Check{Route: "direct", By: "site", Rule: "direct.example", DNS: "direct"}},
		{"smart", "yandex.ru.", geo.Check{Route: "direct", By: "region", Rule: "", DNS: "direct"}},
		{"smart", "example.com", geo.Check{Route: "vpn", By: "default", Rule: "", DNS: "vpn"}},
		{"selected", "example.com", geo.Check{Route: "direct", By: "default", Rule: "", DNS: "direct"}},
	}
	for _, test := range tests {
		if _, err := settingsStore.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(fmt.Sprintf("%q", test.mode))}); err != nil {
			t.Fatal(err)
		}
		params, _ := json.Marshal(map[string]string{"site": test.site})
		result, rpcErr := call("routes.check", string(params))
		got, ok := result.(geo.Check)
		if rpcErr != nil || !ok || got != test.want {
			t.Errorf("routes.check(%s, %s) = %#v, %#v; want %+v", test.mode, test.site, result, rpcErr, test.want)
		}
	}
	// the wire shape
	if _, err := settingsStore.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(`"smart"`)}); err != nil {
		t.Fatal(err)
	}
	result, _ := call("routes.check", `{"site":"ads.example"}`)
	encoded, _ := json.Marshal(result)
	if string(encoded) != `{"route":"block","by":"site","rule":"ads.example","dns":"vpn"}` {
		t.Errorf("wire = %s", encoded)
	}

	for _, bad := range []string{`{}`, `{"site":""}`, `{"site":"a b"}`, `{"site":"a/b"}`, `{"site":" a.example"}`, `{"site":"http://a.example"}`, `{"site":5}`, `{"site":"a.example","extra":1}`, `null`, `[]`} {
		if _, rpcErr := call("routes.check", bad); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("routes.check(%s) = %#v; want bad_params", bad, rpcErr)
		}
	}
	_, _, without := checkServer(t, false)
	if _, rpcErr := without("routes.check", `{"site":"a.example"}`); rpcErr == nil || rpcErr.Code != "service_error" {
		t.Errorf("routes.check without a checker = %#v", rpcErr)
	}
}
