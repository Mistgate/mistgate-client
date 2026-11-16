package ipc

import (
	"context"
	"fmt"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

// last_on is what lets a restarted service tell "the person had the VPN on" from "the person turned it off": connect
// sets it, only an explicit disconnect clears it, and the manager closing with the service does not.
func TestLastOnFollowsConnectAndDisconnect(t *testing.T) {
	dataDir := t.TempDir()
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	server := &Server{Manager: manager, Settings: settingsStore}
	call := func(method, params string) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, rpcErr := server.dispatch(context.Background(), request, true); rpcErr != nil {
			t.Fatalf("%s: %#v", method, rpcErr)
		}
	}

	if settingsStore.Get().LastOn {
		t.Fatal("last_on starts set")
	}
	call("connect", `{"server":"server-a"}`)
	if got := settingsStore.Get(); !got.LastOn || got.LastServer != "server-a" {
		t.Fatalf("after connect: last_on %v, last_server %q", got.LastOn, got.LastServer)
	}
	call("disconnect", `{}`)
	if settingsStore.Get().LastOn {
		t.Fatal("an explicit disconnect left last_on set")
	}

	call("connect", `{"server":"server-a"}`)
	manager.Close() // the service ending: not the person's disconnect
	if !settingsStore.Get().LastOn {
		t.Fatal("the service stopping cleared last_on")
	}
	reopened, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Get(); !got.LastOn || got.LastServer != "server-a" {
		t.Fatalf("after a restart: last_on %v, last_server %q", got.LastOn, got.LastServer)
	}
}
