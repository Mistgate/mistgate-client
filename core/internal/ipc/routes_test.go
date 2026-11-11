package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func TestRoutesSetValidationPersistenceAndPartialUpdates(t *testing.T) {
	dataDir := t.TempDir()
	geoStore, err := geo.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dataDir, "geo", "site-youtube.list")
	if err := os.WriteFile(cachePath, []byte("youtube.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	defer manager.Close()
	server := &Server{
		Manager:  manager,
		Settings: settingsStore,
		Geo:      geoStore,
		Routes: func() geo.Routes {
			configured := settingsStore.Get()
			return geoStore.Routes(configured.RouteMode, configured.RouteRegion, "")
		},
	}
	dispatch := func(id int, params string) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":%d,"method":"routes.set","params":%s}`, id, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, true)
		return result, rpcErr
	}
	result, rpcErr := dispatch(1, `{"direct":{"collections":["geosite:youtube"],"sites":["https://Example.com/x"]},"vpn":{"sites":["VPN.Example"]}}`)
	view, ok := result.(geo.Routes)
	if rpcErr != nil || !ok {
		t.Fatalf("routes.set = %#v, %#v", result, rpcErr)
	}
	if view.Rules.Direct.Sites[0] != "example.com" || view.Rules.VPN.Sites[0] != "vpn.example" ||
		len(view.Collections) != 1 || view.Collections[0].ID != "geosite:youtube" || !view.Collections[0].Available ||
		view.Collections[0].Entries != 1 || view.Collections[0].UpdatedUnix == 0 {
		t.Fatalf("routes.get after set = %#v", view)
	}
	if _, rpcErr = dispatch(2, `{"direct":{"sites":["Only.Example"]}}`); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	rules := geoStore.GetRules()
	if len(rules.Direct.Collections) != 1 || rules.Direct.Sites[0] != "only.example" || rules.VPN.Sites[0] != "vpn.example" {
		t.Fatalf("partial routes.set rules = %#v", rules)
	}
	reopened, err := geo.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.GetRules(); !sameJSON(got, rules) {
		t.Fatalf("persisted rules = %#v; want %#v", got, rules)
	}

	for i, params := range []string{
		`{"other":{}}`,
		`{"direct":null}`,
		`{"vpn":{"unknown":[]}}`,
		`{"direct":{"sites":["example.com/path"]}}`,
		`{"direct":{"sites":[" example.com "]}}`,
		`{"direct":{"sites":["http://example.com"]}}`,
		`{"vpn":{"collections":["geosite:Bad"]}}`,
		`{"vpn":{"collections":["list:http://example.com/list"]}}`,
		`{"vpn":{"collections":["list:https://user:pass@example.com/list"]}}`,
	} {
		if _, rpcErr := dispatch(3+i, params); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("routes.set(%s) error = %#v; want bad_params", params, rpcErr)
		}
	}
	tooManySites, err := json.Marshal(map[string]any{"direct": map[string]any{"sites": manySites(501)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, rpcErr := dispatch(20, string(tooManySites)); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Errorf("routes.set with 501 sites error = %#v; want bad_params", rpcErr)
	}
	tooManyCollections, err := json.Marshal(map[string]any{"vpn": map[string]any{"collections": manyCollections(201)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, rpcErr := dispatch(21, string(tooManyCollections)); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Errorf("routes.set with 201 collections error = %#v; want bad_params", rpcErr)
	}
}

func manySites(count int) []string {
	items := make([]string, count)
	for i := range items {
		items[i] = fmt.Sprintf("site-%d.example", i)
	}
	return items
}

func manyCollections(count int) []string {
	items := make([]string, count)
	for i := range items {
		items[i] = fmt.Sprintf("geosite:site-%d", i)
	}
	return items
}

func sameJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
