package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func TestRoutesUpdateAndLists(t *testing.T) {
	list := &strings.Builder{}
	for i := 0; i < 100; i++ {
		fmt.Fprintf(list, "10.0.%d.0/24\n", i)
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/geoip/") {
			_, _ = w.Write([]byte(list.String()))
		} else if r.URL.Path == "/site/youtube" {
			_, _ = w.Write([]byte("+.youtube.com\n+.googlevideo.com\n"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer remote.Close()
	dataDir := t.TempDir()
	geoStore, err := geo.Open(dataDir, geo.Options{
		HTTPClient:              remote.Client(),
		PrimaryURLTemplate:      remote.URL + "/geoip/%s",
		FallbackURLTemplate:     remote.URL + "/geoip/%s",
		SitePrimaryURLTemplate:  remote.URL + "/site/%s",
		SiteFallbackURLTemplate: remote.URL + "/site/%s",
	})
	if err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settingsStore.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(`"smart"`), "route_region": json.RawMessage(`"ru"`)}); err != nil {
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
	call := func(method, params string, trusted bool) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, trusted)
		return result, rpcErr
	}
	if _, rpcErr := call("routes.set", `{"direct":{"collections":["geosite:youtube"]}}`, true); rpcErr != nil {
		t.Fatal(rpcErr)
	}

	if _, rpcErr := call("routes.update", `{}`, true); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	geoStore.Update(context.Background(), "ru") // the call does not wait: this waits for its downloads, or makes them
	result, rpcErr := call("routes.get", `{}`, true)
	view, ok := result.(geo.Routes)
	if rpcErr != nil || !ok || !view.Available || view.Entries != 100 || len(view.Collections) != 1 || view.Collections[0].Entries != 2 {
		t.Fatalf("routes.update = %#v, %#v", result, rpcErr)
	}
	result, rpcErr = call("routes.lists", `{}`, true)
	encoded, _ := json.Marshal(result)
	var got struct {
		Lists []map[string]any `json:"lists"`
	}
	if rpcErr != nil || json.Unmarshal(encoded, &got) != nil || len(got.Lists) != 2 ||
		got.Lists[0]["id"] != "region:ru" || got.Lists[0]["entries"] != 100.0 || got.Lists[0]["updated_unix"] == 0.0 || got.Lists[0]["error"] != "" ||
		got.Lists[1]["id"] != "geosite:youtube" || got.Lists[1]["entries"] != 2.0 || len(got.Lists[1]) != 4 ||
		!strings.HasSuffix(string(encoded), `"unique":2,"duplicates":0}`) {
		t.Fatalf("routes.lists = %s, %#v", encoded, rpcErr)
	}

	for _, method := range []string{"routes.update", "routes.lists"} {
		if _, rpcErr := call(method, `{"x":1}`, true); rpcErr == nil || rpcErr.Code != "bad_params" {
			t.Errorf("%s with params = %#v; want bad_params", method, rpcErr)
		}
		if _, rpcErr := call(method, `{}`, false); rpcErr == nil || rpcErr.Code != "not_trusted" {
			t.Errorf("%s untrusted = %#v; want not_trusted", method, rpcErr)
		}
	}
}
