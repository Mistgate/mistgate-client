package session

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/settings"
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
		{name: "dead tunnel reconnects with event order", run: testDeadTunnelReconnectsWithEventOrder},
		{name: "fatal retry blocks and connect retries", run: testFatalRetryBlocksAndConnectRetries},
		{name: "route change makes probe failure immediate", run: testRouteChangeMakesProbeFailureImmediate},
		{name: "disconnect cancels retry wait", run: testDisconnectCancelsRetryWait},
		{name: "always holds at start and through disconnect", run: testAlwaysHoldsAtStartAndDisconnect},
		{name: "always failed connect blocks without retries", run: testAlwaysFailedConnectBlocks},
		{name: "always unavailable hold is not reported as blocked", run: testAlwaysUnavailableHoldIsNotBlocked},
		{name: "settings changes apply hold transitions", run: testSettingsChangesApplyHoldTransitions},
		{name: "off reconnect does not hold", run: testOffReconnectDoesNotHold},
		{name: "connected settings reapply firewall", run: testConnectedSettingsReapplyFirewall},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func testAlwaysHoldsAtStartAndDisconnect(t *testing.T) {
	store := testSettings(t, "always")
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "blocked" || status.Error != "kill_switch" {
		t.Fatalf("startup status = %#v, %v; want blocked/kill_switch", status, err)
	}
	if got := fake.HoldCount(); got != 1 {
		t.Fatalf("startup Hold() calls = %d, want 1", got)
	}
	status, err = manager.Disconnect(context.Background())
	if err != nil || status.State != "blocked" || status.Error != "kill_switch" {
		t.Fatalf("Disconnect() = %#v, %v; want blocked/kill_switch", status, err)
	}
	status, err = manager.Connect(context.Background(), engine.Target{Server: "server-a"})
	if err != nil || status.State != "connecting" {
		t.Fatalf("Connect() = %#v, %v; want normal connect", status, err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if targets := fake.Targets(); len(targets) != 1 || !targets[0].Hold {
		t.Fatalf("Start targets = %#v, want Hold true", targets)
	}
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := receiveStatus(t, subscription.C); got.State != "blocked" || got.Error != "kill_switch" {
		t.Fatalf("disconnect event = %#v, want blocked/kill_switch", got)
	}
	fake.SetFailStartCode("offline")
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-b"}); err != nil {
		t.Fatal(err)
	}
	blocked := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "blocked" && status.Error == "offline" })
	if blocked.Error != "offline" {
		t.Fatalf("failed retry status = %#v, want blocked/offline", blocked)
	}
}

func testAlwaysFailedConnectBlocks(t *testing.T) {
	store := testSettings(t, "always")
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailStartCode: "offline"})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	blocked := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "blocked" && status.Error == "offline" })
	if blocked.Error != "offline" {
		t.Fatalf("blocked error = %q, want offline", blocked.Error)
	}
	if got := fake.StartCount(); got != 1 {
		t.Fatalf("Start() calls = %d, want no automatic retry", got)
	}
}

func testAlwaysUnavailableHoldIsNotBlocked(t *testing.T) {
	store := testSettings(t, "always")
	holdResult := false
	fake := engine.NewFake(engine.FakeConfig{HoldResult: &holdResult, FailStartCode: "offline"})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "off" {
		t.Fatalf("startup status = %#v, %v; want ordinary off", status, err)
	}
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	status = waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "error" })
	if status.Error != "offline" {
		t.Fatalf("failure status = %#v, want ordinary error/offline", status)
	}
	if got := fake.HoldCount(); got < 2 {
		t.Fatalf("Hold() calls = %d, want startup and failed attempt", got)
	}
}

func testSettingsChangesApplyHoldTransitions(t *testing.T) {
	store := testSettings(t, "while")
	fake := engine.NewFake(engine.FakeConfig{})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	setKillSwitch(t, store, "always")
	manager.SettingsChanged()
	status := waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "blocked" })
	if status.Error != "kill_switch" {
		t.Fatalf("status = %#v, want blocked/kill_switch", status)
	}
	setKillSwitch(t, store, "while")
	manager.SettingsChanged()
	status = waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "off" })
	if status.Error != "" {
		t.Fatalf("status after leaving always = %#v, want off", status)
	}
}

func testOffReconnectDoesNotHold(t *testing.T) {
	store := testSettings(t, "off")
	changed := make(chan struct{}, 1)
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, Changed: changed})
	manager := newManager(fake, store.Get, time.Hour, []time.Duration{time.Second})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetProbeErr(errors.New("dead tunnel"))
	changed <- struct{}{}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if targets := fake.Targets(); len(targets) != 2 || targets[0].Hold || targets[1].Hold {
		t.Fatalf("Start targets = %#v, want unheld initial and retry", targets)
	}
}

func testConnectedSettingsReapplyFirewall(t *testing.T) {
	store := testSettings(t, "while")
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if _, err := store.Set(map[string]json.RawMessage{"lan": json.RawMessage(`false`)}); err != nil {
		t.Fatal(err)
	}
	manager.SettingsChanged()
	deadline := time.After(time.Second)
	for fake.ReapplyCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Reapply() was not called")
		case <-time.After(time.Millisecond):
		}
	}
}

func testSettings(t *testing.T, killSwitch string) *settings.Store {
	t.Helper()
	store, err := settings.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if killSwitch != "while" {
		setKillSwitch(t, store, killSwitch)
	}
	return store
}

func setKillSwitch(t *testing.T, store *settings.Store, value string) {
	t.Helper()
	if _, err := store.Set(map[string]json.RawMessage{"kill_switch": json.RawMessage(`"` + value + `"`)}); err != nil {
		t.Fatal(err)
	}
}

func waitForManagerStatus(t *testing.T, manager *Manager, match func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if match(status) {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for manager status")
	return Status{}
}

func testConnectDisconnectEventOrder(t *testing.T) {
	manager := NewManager(engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond}), settings.Defaults)
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
	manager := NewManager(engine.NewFake(engine.FakeConfig{StepDelay: 35 * time.Millisecond}), settings.Defaults)
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
				if status.Server != "second" || status.Protocol != "auto" {
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
	manager := NewManager(engine.NewFake(engine.FakeConfig{FailAt: engine.StepHandshake, FailCode: "offline"}), settings.Defaults)
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
	manager := NewManager(nil, settings.Defaults)
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

func testDeadTunnelReconnectsWithEventOrder(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: 5 * time.Millisecond})
	manager := newManager(fake, settings.Defaults, 5*time.Millisecond, []time.Duration{10 * time.Millisecond})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()

	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
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
			t.Fatalf("initial status event = %q/%q, want %q/%q", got.State, got.Step, expected.state, expected.step)
		}
	}

	fake.SetProbeErr(errors.New("tunnel is dead"))
	got := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Step == "" })
	if got.Error != "" {
		t.Fatalf("first reconnect status error = %q, want empty before an attempt fails", got.Error)
	}
	fake.SetProbeErr(nil)
	for _, expected := range []struct{ state, step string }{
		{"reconnecting", "resolve"},
		{"reconnecting", "handshake"},
		{"reconnecting", "tunnel"},
		{"reconnecting", "verify"},
		{"connected", ""},
	} {
		got := receiveStatus(t, subscription.C)
		if got.State != expected.state || got.Step != expected.step {
			t.Fatalf("reconnect status event = %q/%q, want %q/%q", got.State, got.Step, expected.state, expected.step)
		}
	}
	targets := fake.Targets()
	if len(targets) != 2 || targets[0].Hold || !targets[1].Hold {
		t.Fatalf("Start targets = %#v, want initial open attempt then held retry", targets)
	}
}

func testFatalRetryBlocksAndConnectRetries(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := newManager(fake, settings.Defaults, 5*time.Millisecond, []time.Duration{10 * time.Millisecond})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-a", Protocol: "awg"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailStartCode("auth_rejected")
	fake.SetProbeErr(errors.New("tunnel is dead"))
	blocked := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "blocked" })
	if blocked.Error != "auth_rejected" {
		t.Fatalf("blocked status error = %q, want auth_rejected", blocked.Error)
	}

	fake.SetFailStartCode("")
	fake.SetProbeErr(nil)
	status, err := manager.Connect(context.Background(), engine.Target{})
	if err != nil || status.State != "reconnecting" {
		t.Fatalf("Connect() from blocked = %#v, %v; want reconnecting", status, err)
	}
	connected := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if connected.Server != "server-a" || connected.Protocol != "awg" {
		t.Fatalf("manual retry connected to %q/%q, want retained target", connected.Server, connected.Protocol)
	}
	status, err = manager.Disconnect(context.Background())
	if err != nil || status.State != "off" {
		t.Fatalf("Disconnect() = %#v, %v; want off", status, err)
	}
	targets := fake.Targets()
	if len(targets) != 3 || !targets[1].Hold || !targets[2].Hold {
		t.Fatalf("Start targets = %#v, want held automatic and manual retries", targets)
	}
}

func testRouteChangeMakesProbeFailureImmediate(t *testing.T) {
	changed := make(chan struct{}, 1)
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, Changed: changed})
	manager := newManager(fake, settings.Defaults, time.Hour, []time.Duration{time.Second})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetProbeErr(errors.New("tunnel is dead"))
	changed <- struct{}{}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if got := fake.ProbeCount(); got != 1 {
		t.Fatalf("Probe() calls = %d, want exactly one route-triggered failure", got)
	}
	targets := fake.Targets()
	if len(targets) != 2 || !targets[1].Hold {
		t.Fatalf("Start targets = %#v, want a held retry", targets)
	}
}

func testDisconnectCancelsRetryWait(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := newManager(fake, settings.Defaults, 5*time.Millisecond, []time.Duration{40 * time.Millisecond})
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailStartCode("offline")
	fake.SetProbeErr(errors.New("tunnel is dead"))
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Error == "offline" })
	if got := fake.StartCount(); got != 2 {
		t.Fatalf("Start() calls before disconnect = %d, want initial plus one retry", got)
	}
	status, err := manager.Disconnect(context.Background())
	if err != nil || status.State != "off" {
		t.Fatalf("Disconnect() = %#v, %v; want off", status, err)
	}
	starts := fake.StartCount()
	timer := time.NewTimer(60 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if got := fake.StartCount(); got != starts {
		t.Fatalf("Start() calls after disconnect = %d, want %d", got, starts)
	}
}

func waitForStatus(t *testing.T, events <-chan Event, match func(Status) bool) Status {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("status subscription closed before matching status")
			}
			status := event.Data.(Status)
			if match(status) {
				return status
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for matching status")
			return Status{}
		}
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
