package session

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

type Status struct {
	State           string `json:"state"`
	Step            string `json:"step"`
	SinceUnix       int64  `json:"since_unix"`
	Server          string `json:"server"`
	ServerID        string `json:"server_id"` // while connected: the id of the server in use
	Protocol        string `json:"protocol"`
	Route           string `json:"route"`
	Error           string `json:"error"`
	Purpose         string `json:"purpose,omitempty"`
	WhitelistByRule bool   `json:"whitelist_by_rule,omitempty"`
	WhitelistHint   bool   `json:"whitelist_hint,omitempty"`
}

type RouteState struct {
	Effective func(settings.Settings) string
	Path      func(settings.Settings, engine.Target, string) string
	Snapshot  func() geo.Routes
	Refresh   func(func())
}

type CodeError struct {
	Code string
}

func (e *CodeError) Error() string { return e.Code }

type Manager struct {
	engine             engine.Engine
	getSettings        func() settings.Settings
	routes             RouteState
	lastRoutes         geo.Routes
	hasRoutes          bool
	hub                *Hub
	commands           chan any
	done               chan struct{}
	once               sync.Once
	probeInterval      time.Duration
	probeRetryInterval time.Duration
	probeFailureWindow time.Duration
	networkEventGrace  time.Duration
	longSleepThreshold time.Duration
	backoff            []time.Duration
}

type statusRequest struct{ reply chan Status }
type connectRequest struct {
	target engine.Target
	reply  chan connectReply
}
type connectReply struct {
	status Status
	err    error
}
type disconnectRequest struct{ reply chan Status }
type settingsChangedRequest struct{}
type subscriptionsChangedRequest struct{}
type networkChangedRequest struct {
	reason string
	asleep time.Duration
}
type attemptStep struct {
	generation uint64
	step       engine.Step
}
type attemptResult struct {
	generation uint64
	info       engine.Info
	err        error
	server     string // the server the attempt picked for itself ("fastest"), "" if it did not
}
type probeResult struct {
	generation uint64
	at         time.Time
	received   uint64
	err        error
}
type closeRequest struct{ reply chan (<-chan struct{}) }

type actorState struct {
	status             Status
	target             engine.Target
	generation         uint64
	runCancel          context.CancelFunc
	probeCancel        context.CancelFunc
	workerDone         <-chan struct{}
	routeSettings      settings.Settings
	attemptPath        string
	holdReconnect      bool
	probeFailures      int
	probeStreakStart   time.Time
	probeReceivedStart uint64
	lastNetworkEvent   time.Time
	probePending       bool
	retryIndex         int
	// userServer is what the user asked for; state.target.Server moves off it when on_server_down is "next".
	userServer string
	// failures counts failed reconnect attempts in a row on state.target.Server.
	failures int
	// fastest: the next attempt picks the quickest server itself (on_server_down "fastest" after two failures).
	fastest   bool
	selection engine.Selection
	// A round is complete after each ordinary path in the selected failover order has failed twice.
	roundFailures   map[string]int
	whitelistManual bool
}

func (s *actorState) noFailures() { s.failures, s.fastest = 0, false }

type managerTiming struct {
	probeInterval      time.Duration
	probeRetryInterval time.Duration
	probeFailureWindow time.Duration
	networkEventGrace  time.Duration
	longSleepThreshold time.Duration
}

func defaultManagerTiming() managerTiming {
	return managerTiming{
		// Measured on the dev stand under packet loss (2026-11): the 20 s window is what keeps a live AmneziaWG link from
		// being torn down (it fails single probes, up to three in a row, with no loss at all); the period only moves
		// how soon a real cut is noticed (27 to 37 s with these values).
		probeInterval:      10 * time.Second,
		probeRetryInterval: 5 * time.Second,
		probeFailureWindow: 20 * time.Second,
		networkEventGrace:  30 * time.Second,
		longSleepThreshold: 120 * time.Second,
	}
}

func NewManager(eng engine.Engine, getSettings func() settings.Settings, routes ...RouteState) *Manager {
	return newManager(eng, getSettings, 0, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		15 * time.Second, 30 * time.Second,
	}, routes...)
}

func newManager(eng engine.Engine, getSettings func() settings.Settings, probeInterval time.Duration, backoff []time.Duration, routes ...RouteState) *Manager {
	timing := defaultManagerTiming()
	if probeInterval > 0 {
		timing.probeInterval = probeInterval
	}
	return newManagerWithTimings(eng, getSettings, timing, backoff, routes...)
}

func newManagerWithTimings(eng engine.Engine, getSettings func() settings.Settings, timing managerTiming, backoff []time.Duration, routes ...RouteState) *Manager {
	defaults := defaultManagerTiming()
	if timing.probeInterval <= 0 {
		timing.probeInterval = defaults.probeInterval
	}
	if timing.probeRetryInterval <= 0 {
		timing.probeRetryInterval = defaults.probeRetryInterval
	}
	if timing.probeFailureWindow <= 0 {
		timing.probeFailureWindow = defaults.probeFailureWindow
	}
	if timing.networkEventGrace <= 0 {
		timing.networkEventGrace = defaults.networkEventGrace
	}
	if timing.longSleepThreshold <= 0 {
		timing.longSleepThreshold = defaults.longSleepThreshold
	}
	if len(backoff) == 0 {
		backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second}
	}
	m := &Manager{
		engine:             eng,
		getSettings:        getSettings,
		hub:                NewHub(DefaultEventQueue),
		commands:           make(chan any, 32),
		done:               make(chan struct{}),
		probeInterval:      timing.probeInterval,
		probeRetryInterval: timing.probeRetryInterval,
		probeFailureWindow: timing.probeFailureWindow,
		networkEventGrace:  timing.networkEventGrace,
		longSleepThreshold: timing.longSleepThreshold,
		backoff:            append([]time.Duration(nil), backoff...),
	}
	if len(routes) != 0 {
		m.routes = routes[0]
	}
	go m.run()
	return m
}

func (m *Manager) Events() *Hub { return m.hub }

func (m *Manager) SettingsChanged() {
	select {
	case m.commands <- settingsChangedRequest{}:
	case <-m.done:
	}
}

func (m *Manager) SubscriptionsChanged() {
	select {
	case m.commands <- subscriptionsChangedRequest{}:
	case <-m.done:
	}
}

func (m *Manager) NetworkChanged(reason string, asleep time.Duration) {
	select {
	case m.commands <- networkChangedRequest{reason: reason, asleep: asleep}:
	case <-m.done:
	}
}

func (m *Manager) RoutesChanged() {
	if m.routes.Refresh != nil {
		m.routes.Refresh(m.SettingsChanged)
	} else {
		m.SettingsChanged()
	}
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	reply := make(chan Status, 1)
	if err := m.send(ctx, statusRequest{reply: reply}); err != nil {
		return Status{}, err
	}
	select {
	case status := <-reply:
		return status, nil
	case <-ctx.Done():
		return Status{}, ctx.Err()
	case <-m.done:
		return Status{}, errors.New("session manager stopped")
	}
}

func (m *Manager) Connect(ctx context.Context, target engine.Target) (Status, error) {
	reply := make(chan connectReply, 1)
	if err := m.send(ctx, connectRequest{target: target, reply: reply}); err != nil {
		return Status{}, err
	}
	select {
	case result := <-reply:
		return result.status, result.err
	case <-ctx.Done():
		return Status{}, ctx.Err()
	case <-m.done:
		return Status{}, errors.New("session manager stopped")
	}
}

func (m *Manager) Disconnect(ctx context.Context) (Status, error) {
	reply := make(chan Status, 1)
	if err := m.send(ctx, disconnectRequest{reply: reply}); err != nil {
		return Status{}, err
	}
	select {
	case status := <-reply:
		return status, nil
	case <-ctx.Done():
		return Status{}, ctx.Err()
	case <-m.done:
		return Status{}, errors.New("session manager stopped")
	}
}

func (m *Manager) send(ctx context.Context, command any) error {
	select {
	case m.commands <- command:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return errors.New("session manager stopped")
	}
}

func (m *Manager) Close() {
	m.once.Do(func() {
		reply := make(chan (<-chan struct{}), 1)
		var workerDone <-chan struct{}
		select {
		case m.commands <- closeRequest{reply: reply}:
			workerDone = <-reply
		case <-m.done:
		}
		<-m.done
		if workerDone != nil {
			<-workerDone
		}
	})
}

func (m *Manager) run() {
	// This goroutine owns actorState; engine workers report through commands.
	defer close(m.done)
	defer m.hub.Close()
	state := actorState{status: Status{State: "off"}}
	if m.routes.Snapshot != nil {
		m.lastRoutes = m.routes.Snapshot()
		m.hasRoutes = true
	}
	if m.engine != nil && m.currentSettings().KillSwitch == "always" && m.engine.Hold() {
		state.status = Status{State: "blocked", SinceUnix: time.Now().Unix(), Error: "kill_switch"}
		m.hub.Publish("status", state.status)
	}
	traffic := time.NewTicker(time.Second)
	defer traffic.Stop()
	var healthTimer, retryTimer *time.Timer
	var healthC, retryC <-chan time.Time
	changed := (<-chan struct{})(nil)
	if m.engine != nil {
		changed = m.engine.Changed()
	}
	clearTimer := func(timer **time.Timer, ch *<-chan time.Time) {
		if *timer != nil && !(*timer).Stop() {
			select {
			case <-(*timer).C:
			default:
			}
		}
		*ch = nil
	}
	resetTimer := func(timer **time.Timer, ch *<-chan time.Time, delay time.Duration) {
		if *timer == nil {
			*timer = time.NewTimer(delay)
		} else {
			if !(*timer).Stop() {
				select {
				case <-(*timer).C:
				default:
				}
			}
			(*timer).Reset(delay)
		}
		*ch = (*timer).C
	}
	defer clearTimer(&healthTimer, &healthC)
	defer clearTimer(&retryTimer, &retryC)

	for {
		select {
		case raw := <-m.commands:
			switch request := raw.(type) {
			case statusRequest:
				request.reply <- state.status
			case connectRequest:
				clearTimer(&healthTimer, &healthC)
				clearTimer(&retryTimer, &retryC)
				status, err := m.connect(&state, request.target)
				request.reply <- connectReply{status: status, err: err}
			case disconnectRequest:
				clearTimer(&healthTimer, &healthC)
				clearTimer(&retryTimer, &retryC)
				m.stop(&state)
				request.reply <- state.status
			case settingsChangedRequest:
				m.settingsChanged(&state)
			case subscriptionsChangedRequest:
				m.subscriptionsChanged(&state)
			case networkChangedRequest:
				clearTimer(&healthTimer, &healthC)
				clearTimer(&retryTimer, &retryC)
				m.networkChanged(&state, request.reason, request.asleep, time.Now())
			case attemptStep:
				if request.generation == state.generation && (state.status.State == "connecting" || state.status.State == "reconnecting") && state.status.Step != string(request.step) {
					state.status.Step = string(request.step)
					m.hub.Publish("status", state.status)
				}
			case attemptResult:
				if request.generation != state.generation || (state.status.State != "connecting" && state.status.State != "reconnecting") {
					continue
				}
				state.status.Step = ""
				state.fastest = false
				if request.server != "" {
					// the attempt moved itself to another server; the retries and a later reconnect stay there
					state.target.Server, state.status.Server = request.server, request.server
					state.failures = 0
					m.setPurpose(&state, state.target)
				}
				if request.err != nil {
					if state.runCancel != nil {
						state.runCancel()
						state.runCancel = nil
					}
					code := engine.ErrorCode(request.err)
					// the reason is the engine's own fixed wording; any other error may name an address
					var failed *engine.Failure
					reason := ""
					if errors.As(request.err, &failed) {
						reason = failed.Error()
					}
					// in the message itself: the log ring keeps the message only
					slog.Warn("connect failed: " + code + " (" + state.status.Protocol + "; " + reason + ")")
					if m.currentSettings().KillSwitch == "always" {
						if m.engine != nil && m.engine.Hold() {
							state.status.State = "blocked"
						} else {
							state.status.State = "error"
						}
						state.status.Error = code
						state.status.Purpose = ""
						if !fatalReconnectCode(code) {
							m.offerWhitelist(&state)
						}
						clearTimer(&retryTimer, &retryC)
					} else if state.status.State == "reconnecting" {
						state.status.Error = code
						if fatalReconnectCode(code) {
							state.status.State = "blocked"
							state.status.Purpose = ""
							clearTimer(&retryTimer, &retryC)
						} else {
							failedServer := request.info.ServerID
							if failedServer == "" {
								failedServer = state.target.Server
							}
							m.serverDown(&state, failedServer)
							delay := m.backoffAt(state.retryIndex)
							if state.retryIndex < len(m.backoff)-1 {
								state.retryIndex++
							}
							resetTimer(&retryTimer, &retryC, delay)
						}
					} else {
						state.status.State = "error"
						state.status.Error = code
						state.status.Purpose = ""
						if !fatalReconnectCode(code) {
							m.offerWhitelist(&state)
						}
					}
					m.hub.Publish("status", state.status)
				} else {
					state.status.State = "connected"
					state.status.Error = ""
					state.status.Server = request.info.Server
					state.status.ServerID = request.info.ServerID
					state.status.Protocol = request.info.Protocol
					state.status.Route = request.info.Route
					state.status.Purpose = request.info.Purpose
					state.status.WhitelistHint = false
					if state.status.Route == "" && m.routes.Effective != nil {
						state.status.Route = m.routes.Effective(m.currentSettings())
					}
					state.attemptPath = m.routePath(m.currentSettings(), state.target, state.status.Protocol)
					state.status.SinceUnix = time.Now().Unix()
					resetProbeStreak(&state)
					state.retryIndex = 0
					state.failures = 0
					state.roundFailures = make(map[string]int)
					state.holdReconnect = false
					state.runCancel = nil
					m.hub.Publish("status", state.status)
					resetTimer(&healthTimer, &healthC, m.probeInterval)
				}
				m.publishRoutes(&state)
			case probeResult:
				if request.generation != state.generation || state.status.State != "connected" {
					continue
				}
				if state.probeCancel != nil {
					state.probeCancel()
				}
				state.probeCancel = nil
				if request.err == nil {
					resetProbeStreak(&state)
				} else {
					received := state.probeFailures > 0 && receivedSince(state.probeReceivedStart, request.received) >= receivedAliveThreshold
					if received {
						resetProbeStreak(&state)
					} else {
						if state.probeFailures == 0 {
							state.probeStreakStart = request.at
							state.probeReceivedStart = request.received
						}
						state.probeFailures++
					}
				}
				pending := state.probePending
				state.probePending = false
				if request.err != nil && probeIsDead(request.at, state.probeStreakStart, state.probeReceivedStart, request.received, state.lastNetworkEvent, state.probeFailures, m.probeFailureWindow, m.networkEventGrace) {
					clearTimer(&healthTimer, &healthC)
					m.beginReconnect(&state, false)
					continue
				}
				if pending {
					m.startProbe(&state)
				} else if request.err != nil {
					resetTimer(&healthTimer, &healthC, m.probeRetryInterval)
				} else {
					resetTimer(&healthTimer, &healthC, m.probeInterval)
				}
			case closeRequest:
				workerDone := state.workerDone
				clearTimer(&healthTimer, &healthC)
				clearTimer(&retryTimer, &retryC)
				m.stop(&state)
				request.reply <- workerDone
				return
			}
		case <-traffic.C:
			if state.status.State == "connected" && m.engine != nil {
				m.hub.Publish("traffic", m.engine.Stats())
			}
		case <-healthC:
			healthC = nil
			if state.status.State == "connected" && state.probeCancel == nil {
				m.startProbe(&state)
			}
		case <-retryC:
			retryC = nil
			if state.status.State == "reconnecting" && state.runCancel == nil {
				target := state.target
				target.Hold = state.holdReconnect || holdFor(m.currentSettings(), true)
				m.startAttempt(&state, target)
			}
		case _, ok := <-changed:
			if !ok {
				changed = nil
				continue
			}
			clearTimer(&healthTimer, &healthC)
			clearTimer(&retryTimer, &retryC)
			m.networkChanged(&state, "network", 0, time.Now())
		}
	}
}

func (m *Manager) connect(state *actorState, target engine.Target) (Status, error) {
	reconnecting := state.status.State == "reconnecting" || state.status.State == "blocked" && state.status.Error != "kill_switch"
	settingsNow := m.currentSettings()
	// StepVerify means an in-progress attempt has brought its tunnel up; replacing it must keep the firewall closed.
	connectingWithTunnel := state.status.State == "connecting" &&
		(state.target.Hold || state.status.Step == string(engine.StepVerify))
	switching := (state.status.State == "connected" || connectingWithTunnel) && settingsNow.KillSwitch != "off"
	if reconnecting || state.status.State == "blocked" {
		if target.Server == "" || target.Server == "auto" {
			target.Server = state.userServer // not state.target.Server: that may be a server "next" moved to
		}
		if target.Protocol == "" || target.Protocol == "auto" {
			target.Protocol = state.target.Protocol
		}
	}
	if target.Server == "" {
		target.Server = "auto"
	}
	if target.Protocol == "" {
		target.Protocol = "auto"
	}
	target.Hold = state.holdReconnect || holdFor(settingsNow, reconnecting) || switching
	if m.engine == nil {
		state.generation++
		state.status = Status{State: "error", SinceUnix: time.Now().Unix(), Server: target.Server, Protocol: target.Protocol, Error: "no_subscription"}
		m.hub.Publish("status", state.status)
		return state.status, &CodeError{Code: "no_subscription"}
	}
	m.setChoice(state, target)

	if reconnecting {
		if state.runCancel != nil {
			state.runCancel()
			state.runCancel = nil
		}
		if state.probeCancel != nil {
			state.probeCancel()
			state.probeCancel = nil
		}
		if state.status.State == "blocked" {
			state.status.State = "reconnecting"
			state.status.Step = ""
			state.status.SinceUnix = time.Now().Unix()
			m.hub.Publish("status", state.status)
		}
		state.retryIndex = 0
		state.noFailures()
		state.userServer = target.Server
		state.target = target
		m.startAttempt(state, target)
		return state.status, nil
	}

	if state.runCancel != nil || state.status.State == "connected" || state.status.State == "connecting" {
		if state.runCancel != nil {
			state.runCancel()
			state.runCancel = nil
		}
		if target.Hold {
			m.engine.Hold()
		} else {
			m.engine.Stop()
		}
	}
	if state.probeCancel != nil {
		state.probeCancel()
		state.probeCancel = nil
	}
	state.userServer = target.Server
	state.target = target
	state.holdReconnect = false
	resetProbeStreak(state)
	state.probePending = false
	state.retryIndex = 0
	state.noFailures()
	state.status = Status{
		State:     "connecting",
		Step:      string(engine.StepResolve),
		SinceUnix: time.Now().Unix(),
		Server:    target.Server,
		Protocol:  target.Protocol,
		Purpose:   state.selection.Home.Purpose,
	}
	m.hub.Publish("status", state.status)
	m.startAttempt(state, target)
	return state.status, nil
}

func (m *Manager) setChoice(state *actorState, target engine.Target) {
	state.selection = engine.Selection{}
	if m.engine != nil {
		if selected, ok := m.engine.Select(target); ok {
			state.selection = selected
		}
	}
	state.roundFailures = make(map[string]int)
	state.whitelistManual = target.Server != "" && target.Server != "auto" && state.selection.Home.Purpose == profile.PurposeWhitelist
	state.status.Purpose = state.selection.Home.Purpose
	state.status.WhitelistByRule = false
	state.status.WhitelistHint = false
}

func (m *Manager) setPurpose(state *actorState, target engine.Target) {
	state.status.Purpose = ""
	if m.engine != nil {
		if selected, ok := m.engine.Select(target); ok {
			state.status.Purpose = selected.Home.Purpose
		}
	}
}

func (m *Manager) subscriptionsChanged(state *actorState) {
	hadHint := state.status.WhitelistHint
	state.status.WhitelistHint = false
	if !state.status.WhitelistByRule {
		choice := state.target
		if state.userServer != "" {
			choice.Server = state.userServer
		}
		m.setChoice(state, choice)
		m.setPurpose(state, state.target)
	}
	if hadHint {
		m.hub.Publish("status", state.status)
	}
}

func (m *Manager) startAttempt(state *actorState, target engine.Target) {
	previousDone := state.workerDone
	state.generation++
	generation := state.generation
	ctx, cancel := context.WithCancel(context.Background())
	state.runCancel = cancel
	state.target = target
	state.routeSettings = m.currentSettings()
	state.attemptPath = m.routePath(state.routeSettings, target, "")
	if state.status.Step != string(engine.StepResolve) {
		state.status.Step = string(engine.StepResolve)
		m.hub.Publish("status", state.status)
	}
	done := make(chan struct{})
	state.workerDone = done
	pick, home := state.fastest, target
	home.Server = state.userServer
	go func() {
		defer close(done)
		if previousDone != nil {
			<-previousDone
		}
		// the pick takes up to a few seconds of handshakes, which the actor must not wait for
		var picked string
		if pick {
			if picked = m.fastest(ctx, home, target.Server); picked != "" {
				target.Server = picked
			}
		}
		if err := ctx.Err(); err != nil {
			return
		}
		info, err := m.engine.Start(ctx, target, func(step engine.Step) {
			select {
			case m.commands <- attemptStep{generation: generation, step: step}:
			case <-ctx.Done():
			case <-m.done:
			}
		})
		select {
		case m.commands <- attemptResult{generation: generation, info: info, err: err, server: picked}:
		case <-m.done:
		}
	}()
}

func (m *Manager) startProbe(state *actorState) {
	previousDone := state.workerDone
	state.generation++
	generation := state.generation
	ctx, cancel := context.WithCancel(context.Background())
	state.probeCancel = cancel
	done := make(chan struct{})
	state.workerDone = done
	go func() {
		defer close(done)
		if previousDone != nil {
			<-previousDone
		}
		if err := ctx.Err(); err != nil {
			return
		}
		err := m.engine.Probe(ctx)
		result := probeResult{generation: generation, at: time.Now(), received: m.engine.Received(), err: err}
		select {
		case m.commands <- result:
		case <-m.done:
		}
	}()
}

func (m *Manager) networkChanged(state *actorState, _ string, asleep time.Duration, now time.Time) {
	active := state.status.State == "connected" || state.status.State == "connecting" || state.status.State == "reconnecting"
	if !active {
		return
	}
	state.lastNetworkEvent = now
	resetProbeStreak(state)
	state.probePending = false
	if asleep >= m.longSleepThreshold {
		// held only if the kill switch says so: "off" must not cut the internet when the server is out of reach
		m.beginReconnect(state, false)
		return
	}
	if state.status.State == "connected" {
		if state.probeCancel != nil {
			state.probePending = true
		} else {
			m.startProbe(state)
		}
	} else if state.status.State == "reconnecting" && state.runCancel == nil {
		target := state.target
		target.Hold = state.holdReconnect || holdFor(m.currentSettings(), true)
		m.startAttempt(state, target)
	}
}

func (m *Manager) beginReconnect(state *actorState, hold bool) {
	if state.status.State != "connected" && state.status.State != "connecting" && state.status.State != "reconnecting" {
		return
	}
	state.holdReconnect = state.holdReconnect || hold
	target := state.target
	target.Hold = state.holdReconnect || holdFor(m.currentSettings(), true)
	if target.Hold && m.engine != nil {
		m.engine.Hold()
	}
	if state.runCancel != nil {
		state.runCancel()
		state.runCancel = nil
	}
	if state.probeCancel != nil {
		state.probeCancel()
		state.probeCancel = nil
	}
	state.probePending = false
	resetProbeStreak(state)
	state.status.State = "reconnecting"
	state.status.Step = ""
	state.status.Route = ""
	state.status.Error = ""
	state.status.SinceUnix = time.Now().Unix()
	state.retryIndex = 0
	state.noFailures()
	m.hub.Publish("status", state.status)
	m.startAttempt(state, target)
}

const receivedAliveThreshold uint64 = 1024

func receivedSince(start, current uint64) uint64 {
	if current < start {
		return 0
	}
	return current - start
}

func resetProbeStreak(state *actorState) {
	state.probeFailures = 0
	state.probeStreakStart = time.Time{}
	state.probeReceivedStart = 0
}

func probeIsDead(now, streakStart time.Time, receivedAtStart, receivedNow uint64, lastNetworkEvent time.Time, failures int, failureWindow, eventGrace time.Duration) bool {
	if failures == 0 || streakStart.IsZero() || receivedSince(receivedAtStart, receivedNow) >= receivedAliveThreshold {
		return false
	}
	if !lastNetworkEvent.IsZero() {
		age := now.Sub(lastNetworkEvent)
		if age >= 0 && age < eventGrace && failures >= 2 {
			return true
		}
	}
	return now.Sub(streakStart) >= failureWindow
}

func (m *Manager) stop(state *actorState) {
	if state.runCancel != nil {
		state.runCancel()
		state.runCancel = nil
	}
	if state.probeCancel != nil {
		state.probeCancel()
		state.probeCancel = nil
	}
	held := m.engine != nil && m.currentSettings().KillSwitch == "always" && m.engine.Hold()
	state.generation++
	if held {
		state.status = Status{State: "blocked", SinceUnix: time.Now().Unix(), Error: "kill_switch"}
	} else {
		if m.engine != nil {
			m.engine.Stop()
		}
		state.status = Status{State: "off"}
		state.target = engine.Target{}
	}
	resetProbeStreak(state)
	state.probePending = false
	state.retryIndex = 0
	state.noFailures()
	state.holdReconnect = false
	m.hub.Publish("status", state.status)
}

func (m *Manager) settingsChanged(state *actorState) {
	configured := m.currentSettings()
	if configured.WhitelistAuto && state.status.WhitelistHint && !state.status.WhitelistByRule && !state.whitelistManual && state.selection.Whitelist != "" {
		m.chooseWhitelist(state)
		m.hub.Publish("status", state.status)
	}
	routeSettingsChanged := state.routeSettings.RouteMode != configured.RouteMode || state.routeSettings.RouteRegion != configured.RouteRegion
	// The adapter takes its DNS and MTU when it is configured, so a new value needs a new attempt, held like a path change.
	adapterChanged := state.routeSettings.DNS != configured.DNS || state.routeSettings.MTU != configured.MTU
	switch state.status.State {
	case "connected":
		path := m.routePath(configured, state.target, state.status.Protocol)
		if state.attemptPath != "" && path != state.attemptPath || adapterChanged {
			m.reconnectRoute(state, configured)
		} else {
			state.routeSettings = configured
			state.attemptPath = path
			if m.routes.Effective != nil {
				if route := m.routes.Effective(configured); route != state.status.Route {
					state.status.Route = route
					m.hub.Publish("status", state.status)
				}
			}
			if m.engine != nil {
				m.engine.Reapply()
			}
		}
	case "connecting", "reconnecting":
		path := m.routePath(configured, state.target, "")
		if state.attemptPath != "" && path != state.attemptPath || adapterChanged {
			m.reconnectRoute(state, configured)
		} else {
			state.routeSettings = configured
			state.attemptPath = path
		}
		state.target.Hold = state.holdReconnect || holdFor(configured, true)
		if configured.KillSwitch == "off" && !state.holdReconnect && state.status.State == "reconnecting" {
			wasRunning := state.runCancel != nil
			if wasRunning {
				state.runCancel()
				state.runCancel = nil
			}
			if m.engine != nil {
				m.engine.Stop()
			}
			if wasRunning {
				m.startAttempt(state, state.target)
			}
		}
	case "off", "error":
		if configured.KillSwitch == "always" && m.engine != nil && m.engine.Hold() {
			state.status = Status{State: "blocked", SinceUnix: time.Now().Unix(), Error: "kill_switch"}
			m.hub.Publish("status", state.status)
		}
	case "blocked":
		if state.status.Error == "kill_switch" && configured.KillSwitch != "always" {
			if m.engine != nil {
				m.engine.Stop()
			}
			state.generation++
			state.status = Status{State: "off"}
			state.target = engine.Target{}
			m.hub.Publish("status", state.status)
		} else if configured.KillSwitch == "always" && m.engine != nil {
			m.engine.Reapply()
		}
	}
	if routeSettingsChanged && configured.RouteMode == "smart" && (configured.RouteRegion == "" || configured.RouteRegion == "auto") && m.routes.Refresh != nil {
		go m.routes.Refresh(m.SettingsChanged)
	}
	m.publishRoutes(state)
}

func (m *Manager) reconnectRoute(state *actorState, configured settings.Settings) {
	target := state.target
	target.Hold = true
	wasConnected := state.status.State == "connected"
	wasHeld := state.holdReconnect
	state.holdReconnect = true
	state.routeSettings = configured
	if m.engine != nil && (wasConnected || !wasHeld) {
		m.engine.Hold()
	}
	if state.runCancel != nil {
		state.runCancel()
		state.runCancel = nil
	}
	if state.probeCancel != nil {
		state.probeCancel()
		state.probeCancel = nil
	}
	if wasConnected {
		state.status.State = "reconnecting"
		state.status.SinceUnix = time.Now().Unix()
		state.status.Error = ""
		state.status.Step = ""
		state.status.Route = ""
		m.hub.Publish("status", state.status)
	}
	state.retryIndex = 0
	state.noFailures()
	m.startAttempt(state, target)
}

// serverDown counts a failed reconnect attempt. After two failures, "next" walks the round and "fastest" checks its
// other paths. The backoff goes on as it was.
func (m *Manager) serverDown(state *actorState, failedServer string) {
	if state.status.WhitelistByRule {
		return
	}
	state.failures++
	configured := m.currentSettings()
	mode := configured.OnServerDown
	if !state.whitelistManual && failedServer != "" {
		for _, server := range state.selection.Order {
			if server == failedServer {
				state.roundFailures[server]++
				break
			}
		}
	}
	if m.roundFailed(state) {
		if !state.whitelistManual && state.selection.Whitelist != "" {
			if configured.WhitelistAuto {
				m.chooseWhitelist(state)
				return
			}
			state.status.WhitelistHint = true
		}
		state.roundFailures = make(map[string]int)
	}
	if state.failures < 2 {
		return
	}
	if mode == "reconnect" && !configured.WhitelistAuto {
		// only this server is tried in this mode: its two failures are all there is to learn
		m.offerWhitelist(state)
	}
	if mode == "fastest" {
		state.fastest = true
		return
	}
	// "reconnect" keeps to its server; it walks the round only when the switch is on and the round has a marked path to
	// end at.
	if mode != "next" && !(configured.WhitelistAuto && mode == "reconnect" && state.selection.Whitelist != "") {
		return
	}
	chosen := state.target
	chosen.Server = state.userServer
	if next, ok := m.engine.Next(chosen, state.target.Server); ok {
		state.target.Server = next
		state.status.Server = next
		state.failures = 0
		m.setPurpose(state, state.target)
	}
}

// offerWhitelist raises the hint "the ordinary servers do not answer": an ordinary server was asked for, it failed for
// a reason of the network (not a refused account), and the subscription has a path for allowlists.
// ponytail: a connect that fails outright only offers, also with the switch on: the switch acts on a session that was
// up and lost its servers. Starting the marked path from a failed first connect is the upgrade.
func (m *Manager) offerWhitelist(state *actorState) {
	if state.whitelistManual || state.status.WhitelistByRule || state.selection.Whitelist == "" || state.selection.Home.Purpose == profile.PurposeWhitelist {
		return
	}
	state.status.WhitelistHint = true
}

func (m *Manager) roundFailed(state *actorState) bool {
	if state.whitelistManual || len(state.selection.Order) == 0 {
		return false
	}
	for _, server := range state.selection.Order {
		if state.roundFailures[server] < 2 {
			return false
		}
	}
	return true
}

func (m *Manager) chooseWhitelist(state *actorState) {
	if state.selection.Whitelist == "" || state.whitelistManual {
		return
	}
	// ponytail: stay here until an outside-tunnel probe can prove an ordinary path works; that return path is a later step.
	state.target.Server = state.selection.Whitelist
	state.status.Server = state.selection.Whitelist
	state.status.ServerID = ""
	state.status.Purpose = profile.PurposeWhitelist
	state.status.WhitelistByRule = true
	state.status.WhitelistHint = false
	state.failures, state.fastest = 0, false
	state.roundFailures = make(map[string]int)
}

// fastest is the quickest other server of the round, or Next's pick when none answers; "" when there is neither.
func (m *Manager) fastest(ctx context.Context, home engine.Target, except string) string {
	if server, ok := m.engine.Fastest(ctx, home, except); ok {
		return server
	}
	server, _ := m.engine.Next(home, except)
	return server
}

func (m *Manager) publishRoutes(state *actorState) {
	if m.routes.Snapshot == nil {
		return
	}
	routes := m.routes.Snapshot()
	objectChanged := !m.hasRoutes || !reflect.DeepEqual(m.lastRoutes, routes)
	m.lastRoutes, m.hasRoutes = routes, true
	if objectChanged {
		m.hub.Publish("routes", routes)
	}
}

func (m *Manager) routePath(configured settings.Settings, target engine.Target, protocol string) string {
	if m.routes.Path == nil {
		return ""
	}
	return m.routes.Path(configured, target, protocol)
}

func (m *Manager) currentSettings() settings.Settings {
	if m.getSettings == nil {
		return settings.Defaults()
	}
	return m.getSettings()
}

func holdFor(configured settings.Settings, reconnecting bool) bool {
	return configured.KillSwitch == "always" || reconnecting && configured.KillSwitch != "off"
}

func (m *Manager) backoffAt(index int) time.Duration {
	if index >= len(m.backoff) {
		return m.backoff[len(m.backoff)-1]
	}
	return m.backoff[index]
}

func fatalReconnectCode(code string) bool {
	switch code {
	case "auth_rejected", "no_subscription", "unsupported_os":
		return true
	default:
		return false
	}
}
