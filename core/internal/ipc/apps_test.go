package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func appsServer(t *testing.T, apps func() []engine.AppInfo) *Server {
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
	return &Server{
		Manager: manager, Settings: settingsStore, Geo: geoStore, Apps: apps,
		Routes: func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		},
	}
}

func call(t *testing.T, server *Server, trusted bool, method, params string) (any, *RPCError) {
	t.Helper()
	line := fmt.Sprintf(`{"id":1,"method":%q`, method)
	if params != "" {
		line += `,"params":` + params
	}
	request, parseErr := ParseRequest([]byte(line + "}"))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	result, _, rpcErr := server.dispatch(context.Background(), request, trusted)
	return result, rpcErr
}

func TestAppsList(t *testing.T) {
	server := appsServer(t, func() []engine.AppInfo {
		return []engine.AppInfo{{Path: `c:\apps\chat.exe`, Name: "Chat", Running: true}, {Path: `c:\apps\old.exe`, Name: "old"}}
	})
	result, rpcErr := call(t, server, true, "apps.list", "")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	encoded, _ := json.Marshal(result)
	want := `{"apps":[{"path":"c:\\apps\\chat.exe","name":"Chat","running":true},{"path":"c:\\apps\\old.exe","name":"old","running":false}]}`
	if string(encoded) != want {
		t.Fatalf("apps.list = %s\nwant       %s", encoded, want)
	}
	if _, rpcErr := call(t, server, true, "apps.list", `{}`); rpcErr != nil {
		t.Fatalf("empty params object: %v", rpcErr)
	}
	if _, rpcErr := call(t, server, true, "apps.list", `{"x":1}`); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Fatalf("params given: %#v; want bad_params", rpcErr)
	}
	if result, rpcErr := call(t, server, false, "apps.list", ""); result != nil || rpcErr == nil || rpcErr.Code != "not_trusted" {
		t.Fatalf("untrusted caller got %#v, %#v; want not_trusted", result, rpcErr)
	}

	// no programs at all is an empty array, never null
	empty := appsServer(t, func() []engine.AppInfo { return nil })
	result, _ = call(t, empty, true, "apps.list", "")
	if encoded, _ = json.Marshal(result); string(encoded) != `{"apps":[]}` {
		t.Fatalf("empty apps.list = %s", encoded)
	}
	if _, rpcErr := call(t, appsServer(t, nil), true, "apps.list", ""); rpcErr == nil || rpcErr.Code != "service_error" {
		t.Fatalf("apps.list without a source: %#v", rpcErr)
	}
}

func TestRoutesSetCarriesPrograms(t *testing.T) {
	server := appsServer(t, nil)
	result, rpcErr := call(t, server, true, "routes.set", `{"direct":{"apps":["C:\\Apps\\Chat.EXE","c:/apps/chat.exe"]},"vpn":{"apps":["c:\\apps\\game.exe"],"sites":["vpn.example"]}}`)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	view := result.(geo.Routes)
	if len(view.Rules.Direct.Apps) != 1 || view.Rules.Direct.Apps[0] != `c:\apps\chat.exe` || view.Rules.VPN.Apps[0] != `c:\apps\game.exe` || view.Rules.VPN.Sites[0] != "vpn.example" {
		t.Fatalf("rules = %+v", view.Rules)
	}
	encoded, _ := json.Marshal(view.Rules)
	if want := `"direct":{"collections":[],"sites":[],"apps":["c:\\apps\\chat.exe"]}`; !strings.Contains(string(encoded), want) {
		t.Fatalf("rules JSON = %s; want to contain %s", encoded, want)
	}

	// a partial update keeps the other selections and the other keys of the same selection
	if _, rpcErr := call(t, server, true, "routes.set", `{"direct":{"sites":["a.example"]}}`); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if rules := server.Geo.GetRules(); len(rules.Direct.Apps) != 1 || rules.Direct.Sites[0] != "a.example" || len(rules.VPN.Apps) != 1 {
		t.Fatalf("partial update lost programs: %+v", rules)
	}
	if _, rpcErr := call(t, server, true, "routes.set", `{"direct":{"apps":[]}}`); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if rules := server.Geo.GetRules(); len(rules.Direct.Apps) != 0 || len(rules.VPN.Apps) != 1 {
		t.Fatalf("clearing direct programs: %+v", rules)
	}

	for i, params := range []string{
		`{"direct":{"apps":null}}`,
		`{"direct":{"apps":"c:\\a.exe"}}`,
		`{"direct":{"apps":["notapath"]}}`,
		`{"direct":{"apps":["c:\\a.dll"]}}`,
		`{"vpn":{"apps":["\\\\server\\share\\a.exe"]}}`,
		`{"block":{"apps":["c:\\a.exe"]}}`,
	} {
		if _, rpcErr := call(t, server, true, "routes.set", params); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("case %d routes.set(%s) = %#v; want bad_params", i, params, rpcErr)
		}
	}
	if rules := server.Geo.GetRules(); len(rules.VPN.Apps) != 1 || len(rules.Block.Apps) != 0 {
		t.Fatalf("a refused call changed the rules: %+v", rules)
	}
}
