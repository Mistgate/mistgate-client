package ipc

import (
	"context"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/version"
)

// What the window learns from hello is the shared service version.
func TestHelloReportsServiceVersion(t *testing.T) {
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settings.Defaults)
	defer manager.Close()
	request, parseErr := ParseRequest([]byte(`{"id":1,"method":"hello","params":{"client":"0.0.1"}}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	result, _, rpcErr := (&Server{Manager: manager}).dispatch(context.Background(), request, true)
	hello, ok := result.(map[string]any)
	if rpcErr != nil || !ok || hello["service"] != version.Service || hello["trusted"] != true {
		t.Fatalf("hello = %#v, %#v", result, rpcErr)
	}
}
