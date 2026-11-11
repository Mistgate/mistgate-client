package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func TestRoutesDismissAndSuggestShape(t *testing.T) {
	dataDir := t.TempDir()
	geoStore, err := geo.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settingsStore.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(`"selected"`)}); err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	defer manager.Close()
	server := &Server{Manager: manager, Settings: settingsStore, Geo: geoStore, Routes: func() geo.Routes {
		configured := settingsStore.Get()
		return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
	}}
	call := func(method, params string) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, true)
		return result, rpcErr
	}

	result, rpcErr := call("routes.get", `{}`)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	encoded, _ := json.Marshal(result)
	var shape struct {
		Suggest map[string]json.RawMessage `json:"suggest"`
	}
	if json.Unmarshal(encoded, &shape) != nil || string(shape.Suggest["vpn"]) != "[]" || string(shape.Suggest["direct"]) != "[]" {
		t.Fatalf("routes.get suggest = %s", encoded)
	}

	tracker := geoStore.Failures()
	now := time.Now()
	tracker.OK(geo.ViaDirect, "other.org", now)
	for i := 0; i < 3; i++ {
		tracker.Fail(geo.ViaDirect, "example.com", now)
	}
	result, _ = call("routes.get", `{}`)
	if got := result.(geo.Routes).Suggest.VPN; len(got) != 1 || got[0].Site != "example.com" || got[0].Count != 3 {
		t.Fatalf("suggest.vpn = %#v", got)
	}
	for _, params := range []string{`{"route":"both","site":"example.com"}`, `{"route":"vpn","site":"not a site"}`, `{"route":"vpn"}`, `{"site":"example.com"}`} {
		if _, rpcErr := call("routes.dismiss", params); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("routes.dismiss(%s) error = %#v; want bad_params", params, rpcErr)
		}
	}
	result, rpcErr = call("routes.dismiss", `{"route":"vpn","site":"Example.com"}`)
	if rpcErr != nil || len(result.(geo.Routes).Suggest.VPN) != 0 {
		t.Fatalf("routes.dismiss = %#v, %#v", result, rpcErr)
	}
}
