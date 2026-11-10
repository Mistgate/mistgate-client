package session

import (
	"context"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

func TestSessionScenarios(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "connect disconnect event order", run: testConnectDisconnectEventOrder},
		{name: "replace connecting attempt", run: testConnectingAttemptIsReplaced},
		{name: "engine failure code", run: testEngineFailureSetsErrorCode},
		{name: "missing engine", run: testMissingEngineReturnsNoSubscription},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testConnectDisconnectEventOrder(t *testing.T) {
	manager := NewManager(engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond}))
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()

	status, err := manager.Connect(context.Background(), engine.Target{Server: "auto", Protocol: "auto"})
	if err != nil || status.State != "connecting" {
		t.Fatalf("Connect() = %#v, %v; want connecting", status, err)
	}
	want := []struct{ state, step string }{
		{"connecting", "resolve"},
		{"connecting", "handshake"},
		{"connecting", "tunnel"},
		{"connecting", "verify"},
		{"connected", ""},
	}
	for _, expected := range want {
		got := receiveStatus(t, subscription.C)
		if got.State != expected.state || got.Step != expected.step {
			t.Fatalf("status event = %q/%q, want %q/%q", got.State, got.Step, expected.state, expected.step)
		}
	}

	status, err = manager.Disconnect(context.Background())
	if err != nil || status.State != "off" {
		t.Fatalf("Disconnect() = %#v, %v; want off", status, err)
	}
	if got := receiveStatus(t, subscription.C); got.State != "off" || got.SinceUnix != 0 {
		t.Fatalf("disconnect event = %#v, want zero off status", got)
	}
}

func testConnectingAttemptIsReplaced(t *testing.T) {
	manager := NewManager(engine.NewFake(engine.FakeConfig{StepDelay: 35 * time.Millisecond}))
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()

	if _, err := manager.Connect(context.Background(), engine.Target{Server: "first"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "second"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event, ok := <-subscription.C:
			if !ok {
				t.Fatal("status subscription closed before connection completed")
			}
			status := event.Data.(Status)
			if status.State == "connected" {
				if status.Server != "second" {
					t.Fatalf("connected server = %q, want replacement target", status.Server)
				}
				return
			}
		case <-deadline:
			t.Fatal("replacement did not connect")
		}
	}
}

func testEngineFailureSetsErrorCode(t *testing.T) {
	manager := NewManager(engine.NewFake(engine.FakeConfig{FailAt: engine.StepHandshake, FailCode: "offline"}))
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for {
		select {
		case event := <-subscription.C:
			status := event.Data.(Status)
			if status.State == "error" {
				if status.Error != "offline" || status.Step != "" {
					t.Fatalf("failure status = %#v", status)
				}
				return
			}
		case <-deadline:
			t.Fatal("engine failure status was not published")
		}
	}
}

func testMissingEngineReturnsNoSubscription(t *testing.T) {
	manager := NewManager(nil)
	defer manager.Close()
	status, err := manager.Connect(context.Background(), engine.Target{})
	codeError, ok := err.(*CodeError)
	if !ok || codeError.Code != "no_subscription" {
		t.Fatalf("Connect() error = %#v, want no_subscription", err)
	}
	if status.State != "error" || status.Error != "no_subscription" {
		t.Fatalf("Connect() status = %#v, want no_subscription error", status)
	}
}

func receiveStatus(t *testing.T, events <-chan Event) Status {
	t.Helper()
	select {
	case event, ok := <-events:
		if !ok {
			t.Fatal("status subscription closed")
		}
		return event.Data.(Status)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for status event")
		return Status{}
	}
}
