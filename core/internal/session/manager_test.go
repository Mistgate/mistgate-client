package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
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
		{name: "one failed probe recovers without status change", run: testOneProbeFailureRecoversWithoutStatusChange},
		{name: "probe failures beyond the window reconnect", run: testProbeFailuresBeyondWindowReconnect},
		{name: "received tunnel bytes prevent reconnect", run: testReceivedTunnelBytesPreventReconnect},
		{name: "short sleep probes immediately with short patience", run: testShortSleepProbesImmediately},
		{name: "long sleep reconnects at once", run: testLongSleepReconnects},
		{name: "disconnect cancels retry wait", run: testDisconnectCancelsRetryWait},
		{name: "always holds at start and through disconnect", run: testAlwaysHoldsAtStartAndDisconnect},
		{name: "always failed connect blocks without retries", run: testAlwaysFailedConnectBlocks},
		{name: "always unavailable hold is not reported as blocked", run: testAlwaysUnavailableHoldIsNotBlocked},
		{name: "settings changes apply hold transitions", run: testSettingsChangesApplyHoldTransitions},
		{name: "off reconnect does not hold", run: testOffReconnectDoesNotHold},
		{name: "connected settings reapply firewall", run: testConnectedSettingsReapplyFirewall},
		{name: "route rules and list refresh do not reconnect", run: testRouteChangesDoNotReconnect},
		{name: "only AmneziaWG path transition reconnects", run: testOnlyAWGPathTransitionReconnects},
		{name: "next server after two failures, wrapping around", run: testNextServerAfterTwoFailures},
		{name: "reconnect keeps the same server", run: testReconnectKeepsTheServer},
		{name: "next needs another server", run: testNextNeedsAnotherServer},
		{name: "first connect failure does not move on", run: testFirstConnectFailureStays},
		{name: "user connect after a switch goes to the chosen server", run: testConnectAfterSwitchGoesToChosen},
		{name: "dns and mtu changes restart the attempt", run: testDNSAndMTUChangesReconnect},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestProbeIsDead(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if probeIsDead(now.Add(19*time.Second), now, 0, 0, time.Time{}, 5, 20*time.Second, 30*time.Second) {
		t.Fatal("probe streak was dead before 20 seconds")
	}
	if !probeIsDead(now.Add(20*time.Second), now, 0, 0, time.Time{}, 5, 20*time.Second, 30*time.Second) {
		t.Fatal("probe streak was not dead after 20 seconds")
	}
	if !probeIsDead(now.Add(5*time.Second), now, 0, 0, now, 2, 20*time.Second, 30*time.Second) {
		t.Fatal("two failures after a recent network event were not dead")
	}
	if probeIsDead(now.Add(5*time.Second), now, 0, 1024, now, 5, 20*time.Second, 30*time.Second) {
		t.Fatal("received tunnel bytes did not suppress the dead decision")
	}
	if probeIsDead(now.Add(31*time.Second), now.Add(15*time.Second), 0, 0, now, 1, 20*time.Second, 30*time.Second) {
		t.Fatal("old network event incorrectly used short patience")
	}
}

func testRouteChangesDoNotReconnect(t *testing.T) {
	store := testSettings(t, "off")
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	var available atomic.Bool
	var version atomic.Uint64
	routeState := RouteState{
		Effective: func(configured settings.Settings) string {
			if configured.RouteMode == "smart" && configured.RouteRegion == "ru" && available.Load() {
				return "smart:ru"
			}
			return "all"
		},
		Snapshot: func() geo.Routes {
			configured := store.Get()
			effective := "none"
			if available.Load() {
				effective = "ru"
			}
			return geo.Routes{Mode: configured.RouteMode, Region: configured.RouteRegion, Effective: effective, Available: available.Load(), Version: version.Load()}
		},
	}
	manager := NewManager(fake, store.Get, routeState)
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-a"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if _, err := store.Set(map[string]json.RawMessage{
		"route_mode":   json.RawMessage(`"smart"`),
		"route_region": json.RawMessage(`"ru"`),
	}); err != nil {
		t.Fatal(err)
	}
	manager.SettingsChanged()
	time.Sleep(25 * time.Millisecond)
	if fake.StartCount() != 1 {
		t.Fatalf("unavailable region caused reconnect: starts=%d", fake.StartCount())
	}
	available.Store(true)
	manager.SettingsChanged()
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" && status.Route == "smart:ru" })
	if got := fake.StartCount(); got != 1 {
		t.Fatalf("region availability caused reconnect: starts=%d", got)
	}
	version.Add(1)
	manager.RoutesChanged()
	time.Sleep(25 * time.Millisecond)
	if got := fake.StartCount(); got != 1 {
		t.Fatalf("region-list refresh caused reconnect: starts=%d", got)
	}
}

func testOnlyAWGPathTransitionReconnects(t *testing.T) {
	store := testSettings(t, "off")
	path := func(configured settings.Settings, target engine.Target, protocol string) string {
		if protocol == "" || protocol == "auto" {
			protocol = target.Protocol
		}
		if protocol == "awg" && configured.RouteMode == "all" {
			return "native"
		}
		return "forwarder"
	}
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := NewManager(fake, store.Get, RouteState{Path: path})
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "server-a", Protocol: "awg"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "connected" })
	setRouteMode(t, store, "smart")
	manager.SettingsChanged()
	waitForStarts(t, fake, 2)
	waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "connected" })
	if targets := fake.Targets(); len(targets) != 2 || !targets[1].Hold {
		t.Fatalf("AWG path transition targets = %#v; want held reconnect", targets)
	}
	setRouteMode(t, store, "selected")
	manager.SettingsChanged()
	time.Sleep(25 * time.Millisecond)
	if got := fake.StartCount(); got != 2 {
		t.Fatalf("smart-to-selected change reconnected AWG: starts=%d", got)
	}

	hy2Settings := testSettings(t, "off")
	hy2 := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	hy2Manager := NewManager(hy2, hy2Settings.Get, RouteState{Path: path})
	defer hy2Manager.Close()
	if _, err := hy2Manager.Connect(context.Background(), engine.Target{Server: "server-b", Protocol: "hysteria2"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, hy2Manager, func(status Status) bool { return status.State == "connected" })
	setRouteMode(t, hy2Settings, "selected")
	hy2Manager.SettingsChanged()
	time.Sleep(25 * time.Millisecond)
	if got := hy2.StartCount(); got != 1 {
		t.Fatalf("Hysteria2 route change reconnected: starts=%d", got)
	}
}

func setRouteMode(t *testing.T, store *settings.Store, mode string) {
	t.Helper()
	encoded, err := json.Marshal(mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set(map[string]json.RawMessage{"route_mode": encoded}); err != nil {
		t.Fatal(err)
	}
}

func waitForStarts(t *testing.T, fake *engine.Fake, want uint64) {
	t.Helper()
	deadline := time.After(time.Second)
	for fake.StartCount() < want {
		select {
		case <-deadline:
			t.Fatalf("engine starts = %d; want at least %d", fake.StartCount(), want)
		case <-time.After(time.Millisecond):
		}
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
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = time.Hour
	timing.networkEventGrace = time.Second
	manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{time.Second})
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

func waitForProbeCount(t *testing.T, fake *engine.Fake, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fake.ProbeCount() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Probe() calls = %d, want at least %d", fake.ProbeCount(), want)
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
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = 25 * time.Millisecond
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{10 * time.Millisecond})
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
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 2 * time.Millisecond
	timing.probeFailureWindow = time.Millisecond
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{10 * time.Millisecond})
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
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = time.Hour
	timing.networkEventGrace = time.Second
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{time.Second})
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
	if got := fake.ProbeCount(); got != 2 {
		t.Fatalf("Probe() calls = %d, want two route-triggered failures", got)
	}
	targets := fake.Targets()
	if len(targets) != 2 || !targets[1].Hold {
		t.Fatalf("Start targets = %#v, want a held retry", targets)
	}
}

func testOneProbeFailureRecoversWithoutStatusChange(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{
		StepDelay: time.Millisecond,
		ProbeErrs: []error{errors.New("transient probe loss"), nil},
	})
	timing := defaultManagerTiming()
	timing.probeInterval = 10 * time.Millisecond
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = 100 * time.Millisecond
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{time.Second})
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "connected" })
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	waitForProbeCount(t, fake, 2)
	select {
	case event := <-subscription.C:
		t.Fatalf("unexpected status change after a failed probe and recovery: %#v", event.Data)
	case <-time.After(20 * time.Millisecond):
	}
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "connected" {
		t.Fatalf("status after recovery = %#v, %v; want connected", status, err)
	}
}

func testProbeFailuresBeyondWindowReconnect(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErr: errors.New("dead tunnel")})
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = 25 * time.Millisecond
	timing.networkEventGrace = time.Second
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{time.Second})
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
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
	fake.SetProbeErr(nil)
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	targets := fake.Targets()
	if len(targets) != 2 || !targets[1].Hold {
		t.Fatalf("Start targets = %#v, want held reconnect after sustained probe failures", targets)
	}
}

func testReceivedTunnelBytesPreventReconnect(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErr: errors.New("probe unavailable")})
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 5 * time.Millisecond
	timing.probeFailureWindow = 25 * time.Millisecond
	timing.networkEventGrace = time.Second
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{time.Second})
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "connected" })
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		var received uint64
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				received += receivedAliveThreshold
				fake.SetReceived(received)
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	status, err := manager.Status(context.Background())
	close(stop)
	<-done
	if err != nil || status.State != "connected" {
		t.Fatalf("status while tunnel bytes arrived = %#v, %v; want connected", status, err)
	}
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func testShortSleepProbesImmediately(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, ProbeErr: errors.New("dead tunnel")})
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	timing.probeRetryInterval = 15 * time.Millisecond
	timing.probeFailureWindow = time.Hour
	timing.networkEventGrace = time.Second
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{time.Second})
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
	manager.NetworkChanged("resume", 119*time.Second)
	waitForProbeCount(t, fake, 1)
	status, err := manager.Status(context.Background())
	if err != nil || status.State != "connected" {
		t.Fatalf("status after first wake probe = %#v, %v; want connected", status, err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
	if got := fake.ProbeCount(); got != 2 {
		t.Fatalf("Probe() calls after short wake = %d, want two failures", got)
	}
}

func testLongSleepReconnects(t *testing.T) {
	for _, killSwitch := range []string{"off", "while"} {
		longSleepReconnects(t, killSwitch)
	}
}

func longSleepReconnects(t *testing.T, killSwitch string) {
	store := testSettings(t, killSwitch)
	fake := engine.NewFake(engine.FakeConfig{StepDelay: 3 * time.Millisecond})
	timing := defaultManagerTiming()
	timing.probeInterval = time.Hour
	manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{time.Second})
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
	manager.NetworkChanged("resume", 120*time.Second)
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" })
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	targets := fake.Targets()
	if len(targets) != 2 || targets[1].Hold != (killSwitch != "off") {
		t.Fatalf("kill switch %s: Start targets = %#v, want an immediate reconnect, held only with the kill switch", killSwitch, targets)
	}
	if got := fake.ProbeCount(); got != 0 {
		t.Fatalf("Probe() calls after long sleep = %d, want immediate reconnect without probing", got)
	}
}

func testDisconnectCancelsRetryWait(t *testing.T) {
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 2 * time.Millisecond
	timing.probeFailureWindow = time.Millisecond
	manager := newManagerWithTimings(fake, settings.Defaults, timing, []time.Duration{40 * time.Millisecond})
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

// downedManager connects to server "a" with a dead link and failing attempts; servers are a, b, c in the fake.
func downedManager(t *testing.T, onServerDown string, servers ...string) (*Manager, *engine.Fake, *Subscription) {
	t.Helper()
	store := testSettings(t, "off")
	if _, err := store.Set(map[string]json.RawMessage{"on_server_down": json.RawMessage(`"` + onServerDown + `"`)}); err != nil {
		t.Fatal(err)
	}
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	fake.SetServers(servers...)
	timing := defaultManagerTiming()
	timing.probeInterval = 5 * time.Millisecond
	timing.probeRetryInterval = 2 * time.Millisecond
	timing.probeFailureWindow = time.Millisecond
	manager := newManagerWithTimings(fake, store.Get, timing, []time.Duration{2 * time.Millisecond})
	t.Cleanup(manager.Close)
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subscription.Close)
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "a"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	fake.SetFailStartCode("offline")
	fake.SetProbeErr(errors.New("tunnel is dead"))
	return manager, fake, subscription
}

func attemptedServers(fake *engine.Fake) string {
	var out string
	for _, target := range fake.Targets() {
		out += target.Server
	}
	return out
}

func testNextServerAfterTwoFailures(t *testing.T) {
	manager, fake, subscription := downedManager(t, "next", "a", "b", "c")
	// the status names the server being tried
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Server == "b" })
	waitForStarts(t, fake, 10)
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// connect, then two attempts on each server of the ring, wrapping back to the chosen one
	if got := attemptedServers(fake); len(got) < 10 || got[:10] != "aaabbccaab" {
		t.Fatalf("attempted servers = %q, want prefix aaabbccaab", got)
	}
}

func testReconnectKeepsTheServer(t *testing.T) {
	manager, fake, _ := downedManager(t, "reconnect", "a", "b", "c")
	waitForStarts(t, fake, 8)
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, target := range fake.Targets() {
		if target.Server != "a" {
			t.Fatalf("attempt %d went to %q, want a", i, target.Server)
		}
	}
}

func testNextNeedsAnotherServer(t *testing.T) {
	manager, fake, _ := downedManager(t, "next", "a")
	waitForStarts(t, fake, 8)
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, target := range fake.Targets() {
		if target.Server != "a" {
			t.Fatalf("attempt %d went to %q, want a", i, target.Server)
		}
	}
}

func testFirstConnectFailureStays(t *testing.T) {
	store := testSettings(t, "off")
	if _, err := store.Set(map[string]json.RawMessage{"on_server_down": json.RawMessage(`"next"`)}); err != nil {
		t.Fatal(err)
	}
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond, FailStartCode: "offline"})
	fake.SetServers("a", "b")
	manager := newManagerWithTimings(fake, store.Get, defaultManagerTiming(), []time.Duration{2 * time.Millisecond})
	defer manager.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "a"}); err != nil {
		t.Fatal(err)
	}
	waitForManagerStatus(t, manager, func(status Status) bool { return status.State == "error" && status.Error == "offline" })
	time.Sleep(30 * time.Millisecond)
	if got := attemptedServers(fake); got != "a" {
		t.Fatalf("attempted servers = %q, want a single attempt on a", got)
	}
}

func testConnectAfterSwitchGoesToChosen(t *testing.T) {
	manager, fake, subscription := downedManager(t, "next", "a", "b", "c")
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "reconnecting" && status.Server == "b" })
	fake.SetFailStartCode("")
	fake.SetProbeErr(nil)
	if _, err := manager.Connect(context.Background(), engine.Target{}); err != nil {
		t.Fatal(err)
	}
	connected := waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	if connected.Server != "a" {
		t.Fatalf("connected to %q after the user's connect, want the chosen server a", connected.Server)
	}
	targets := fake.Targets()
	if last := targets[len(targets)-1]; last.Server != "a" {
		t.Fatalf("last attempt went to %q, want a", last.Server)
	}
}

func testDNSAndMTUChangesReconnect(t *testing.T) {
	store := testSettings(t, "off")
	fake := engine.NewFake(engine.FakeConfig{StepDelay: time.Millisecond})
	manager := NewManager(fake, store.Get)
	defer manager.Close()
	subscription, err := manager.Events().Subscribe([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if _, err := manager.Connect(context.Background(), engine.Target{Server: "a"}); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	set := func(key, value string) {
		t.Helper()
		if _, err := store.Set(map[string]json.RawMessage{key: json.RawMessage(value)}); err != nil {
			t.Fatal(err)
		}
		manager.SettingsChanged()
	}
	set("last_on", "true") // not a connection setting
	set("restore", "true")
	set("on_server_down", `"next"`)
	time.Sleep(25 * time.Millisecond)
	if got := fake.StartCount(); got != 1 {
		t.Fatalf("unrelated settings caused a reconnect: starts=%d", got)
	}
	for i, change := range []struct{ key, value string }{{"dns", `"9.9.9.9"`}, {"mtu", `1400`}} {
		set(change.key, change.value)
		waitForStarts(t, fake, uint64(i+2))
		waitForStatus(t, subscription.C, func(status Status) bool { return status.State == "connected" })
	}
	if targets := fake.Targets(); !targets[1].Hold || !targets[2].Hold {
		t.Fatalf("Start targets = %#v, want held restarts", targets)
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
