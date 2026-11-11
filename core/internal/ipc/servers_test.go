package ipc

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

// subsServer is a server over a store holding one AmneziaWG subscription (the only kind that needs no network).
func subsServer(t *testing.T, ping PingFunc) (subs.Subscription, func(method, params string) (any, *RPCError)) {
	t.Helper()
	dataDir := t.TempDir()
	store, err := subs.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	added, err := store.Add(context.Background(), "[Interface]\nAddress = 10.66.4.3/32\nPrivateKey = "+key+"\n[Peer]\nPublicKey = "+key+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820")
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	t.Cleanup(manager.Close)
	server := &Server{Manager: manager, Subs: store, Settings: settingsStore, Ping: ping}
	return added, func(method, params string) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, true)
		return result, rpcErr
	}
}

func TestServersPing(t *testing.T) {
	added, call := subsServer(t, func(_ context.Context, p profile.Profile, _ time.Duration) (time.Duration, error) {
		return 0, nil // under a millisecond: the answer is rounded up to 1
	})
	id := added.Servers[0].ID
	for _, params := range []string{`{"sub":"` + added.ID + `"}`, `{}`, `{"sub":"` + added.ID + `","servers":["` + id + `","other"]}`} {
		result, rpcErr := call("servers.ping", params)
		rtt, ok := result.(map[string]any)["rtt"].(map[string]int64)
		if rpcErr != nil || !ok || len(rtt) != 1 || rtt[id] != 1 {
			t.Fatalf("servers.ping %s = %#v, %#v", params, result, rpcErr)
		}
	}
	if result, _ := call("servers.ping", `{"sub":"`+added.ID+`","servers":["other"]}`); len(result.(map[string]any)["rtt"].(map[string]int64)) != 0 {
		t.Fatalf("unknown server was measured: %#v", result)
	}
	if _, rpcErr := call("servers.ping", `{"sub":"missing"}`); rpcErr == nil || rpcErr.Code != "unknown_subscription" {
		t.Fatalf("unknown subscription = %#v", rpcErr)
	}
	if _, rpcErr := call("servers.ping", `{"servers":"x"}`); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Fatalf("bad params = %#v", rpcErr)
	}
}

func TestSubsLink(t *testing.T) {
	added, call := subsServer(t, nil)
	// an AmneziaWG config has no link; the url kind is covered by the store's own test
	if _, rpcErr := call("subs.link", `{"id":"`+added.ID+`"}`); rpcErr == nil || rpcErr.Code != "no_link" {
		t.Fatalf("subs.link of a config = %#v", rpcErr)
	}
	if _, rpcErr := call("subs.link", `{"id":"missing"}`); rpcErr == nil || rpcErr.Code != "unknown_subscription" {
		t.Fatalf("subs.link of a missing subscription = %#v", rpcErr)
	}
	if _, rpcErr := call("subs.link", `{}`); rpcErr == nil || rpcErr.Code != "bad_params" {
		t.Fatalf("subs.link without id = %#v", rpcErr)
	}
}
