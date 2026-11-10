package session

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/engine"
)

type Status struct {
	State     string `json:"state"`
	Step      string `json:"step"`
	SinceUnix int64  `json:"since_unix"`
	Server    string `json:"server"`
	Protocol  string `json:"protocol"`
	Error     string `json:"error"`
}

type CodeError struct {
	Code string
}

func (e *CodeError) Error() string { return e.Code }

type Manager struct {
	engine        engine.Engine
	hub           *Hub
	commands      chan any
	done          chan struct{}
	once          sync.Once
	probeInterval time.Duration
	backoff       []time.Duration
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
type attemptStep struct {
	generation uint64
	step       engine.Step
}
type attemptResult struct {
	generation uint64
	info       engine.Info
	err        error
}
type probeResult struct {
	generation uint64
	urgent     bool
	err        error
}
type closeRequest struct{ reply chan (<-chan struct{}) }

type actorState struct {
	status           Status
	target           engine.Target
	generation       uint64
	runCancel        context.CancelFunc
	probeCancel      context.CancelFunc
	workerDone       <-chan struct{}
	probeFailures    int
	probePending     bool
	probePendingFast bool
	retryIndex       int
}

func NewManager(eng engine.Engine) *Manager {
	return newManager(eng, 5*time.Second, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		15 * time.Second, 30 * time.Second,
	})
}

func newManager(eng engine.Engine, probeInterval time.Duration, backoff []time.Duration) *Manager {
	if probeInterval <= 0 {
		probeInterval = 5 * time.Second
	}
	if len(backoff) == 0 {
		backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second}
	}
	m := &Manager{
		engine:        eng,
		hub:           NewHub(DefaultEventQueue),
		commands:      make(chan any, 32),
		done:          make(chan struct{}),
		probeInterval: probeInterval,
		backoff:       append([]time.Duration(nil), backoff...),
	}
	go m.run()
	return m
}

func (m *Manager) Events() *Hub { return m.hub }

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
				if request.err != nil {
					if state.runCancel != nil {
						state.runCancel()
						state.runCancel = nil
					}
					code := engine.ErrorCode(request.err)
					if state.status.State == "reconnecting" {
						state.status.Error = code
						if fatalReconnectCode(code) {
							state.status.State = "blocked"
							clearTimer(&retryTimer, &retryC)
						} else {
							delay := m.backoffAt(state.retryIndex)
							if state.retryIndex < len(m.backoff)-1 {
								state.retryIndex++
							}
							resetTimer(&retryTimer, &retryC, delay)
						}
					} else {
						state.status.State = "error"
						state.status.Error = code
					}
					m.hub.Publish("status", state.status)
				} else {
					state.status.State = "connected"
					state.status.Error = ""
					state.status.Server = request.info.Server
					state.status.Protocol = request.info.Protocol
					state.status.SinceUnix = time.Now().Unix()
					state.probeFailures = 0
					state.retryIndex = 0
					m.hub.Publish("status", state.status)
					resetTimer(&healthTimer, &healthC, m.probeInterval)
				}
			case probeResult:
				if request.generation != state.generation || state.status.State != "connected" {
					continue
				}
				if state.probeCancel != nil {
					state.probeCancel()
				}
				state.probeCancel = nil
				urgent := request.urgent || state.probePendingFast
				if request.err == nil {
					state.probeFailures = 0
				} else {
					state.probeFailures++
				}
				pending, pendingFast := state.probePending, state.probePendingFast
				state.probePending, state.probePendingFast = false, false
				if request.err != nil && (urgent || state.probeFailures >= 2) {
					clearTimer(&healthTimer, &healthC)
					state.status.State = "reconnecting"
					state.status.Step = ""
					state.status.Error = ""
					state.status.SinceUnix = time.Now().Unix()
					state.probeFailures = 0
					state.retryIndex = 0
					if state.runCancel != nil {
						state.runCancel()
						state.runCancel = nil
					}
					m.hub.Publish("status", state.status)
					target := state.target
					target.Hold = true
					m.startAttempt(&state, target)
					continue
				}
				if pending {
					m.startProbe(&state, pendingFast)
				} else if request.err != nil {
					// one failure may be a lost packet: ask again soon instead of waiting a whole interval
					resetTimer(&healthTimer, &healthC, m.probeInterval/5)
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
				m.startProbe(&state, false)
			}
		case <-retryC:
			retryC = nil
			if state.status.State == "reconnecting" && state.runCancel == nil {
				target := state.target
				target.Hold = true
				m.startAttempt(&state, target)
			}
		case _, ok := <-changed:
			if !ok {
				changed = nil
				continue
			}
			if state.status.State == "connected" {
				clearTimer(&healthTimer, &healthC)
				if state.probeCancel != nil {
					state.probePending = true
					state.probePendingFast = true
				} else {
					m.startProbe(&state, true)
				}
			} else if state.status.State == "reconnecting" && state.runCancel == nil {
				clearTimer(&retryTimer, &retryC)
				target := state.target
				target.Hold = true
				m.startAttempt(&state, target)
			}
		}
	}
}

func (m *Manager) connect(state *actorState, target engine.Target) (Status, error) {
	reconnecting := state.status.State == "reconnecting" || state.status.State == "blocked"
	if reconnecting {
		if target.Server == "" || target.Server == "auto" {
			target.Server = state.target.Server
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
	target.Hold = reconnecting
	if m.engine == nil {
		state.generation++
		state.status = Status{State: "error", SinceUnix: time.Now().Unix(), Server: target.Server, Protocol: target.Protocol, Error: "no_subscription"}
		m.hub.Publish("status", state.status)
		return state.status, &CodeError{Code: "no_subscription"}
	}

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
		state.target = target
		m.startAttempt(state, target)
		return state.status, nil
	}

	if state.runCancel != nil {
		state.runCancel()
		state.runCancel = nil
		m.engine.Stop()
	}
	if state.probeCancel != nil {
		state.probeCancel()
		state.probeCancel = nil
	}
	state.target = target
	state.probeFailures = 0
	state.probePending, state.probePendingFast = false, false
	state.retryIndex = 0
	state.status = Status{
		State:     "connecting",
		Step:      string(engine.StepResolve),
		SinceUnix: time.Now().Unix(),
		Server:    target.Server,
		Protocol:  target.Protocol,
	}
	m.hub.Publish("status", state.status)
	m.startAttempt(state, target)
	return state.status, nil
}

func (m *Manager) startAttempt(state *actorState, target engine.Target) {
	previousDone := state.workerDone
	state.generation++
	generation := state.generation
	ctx, cancel := context.WithCancel(context.Background())
	state.runCancel = cancel
	state.target = target
	if state.status.Step != string(engine.StepResolve) {
		state.status.Step = string(engine.StepResolve)
		m.hub.Publish("status", state.status)
	}
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
		info, err := m.engine.Start(ctx, target, func(step engine.Step) {
			select {
			case m.commands <- attemptStep{generation: generation, step: step}:
			case <-ctx.Done():
			case <-m.done:
			}
		})
		select {
		case m.commands <- attemptResult{generation: generation, info: info, err: err}:
		case <-m.done:
		}
	}()
}

func (m *Manager) startProbe(state *actorState, urgent bool) {
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
		select {
		case m.commands <- probeResult{generation: generation, urgent: urgent, err: err}:
		case <-m.done:
		}
	}()
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
	if m.engine != nil {
		m.engine.Stop()
	}
	state.generation++
	state.status = Status{State: "off"}
	state.target = engine.Target{}
	state.probeFailures = 0
	state.probePending, state.probePendingFast = false, false
	state.retryIndex = 0
	m.hub.Publish("status", state.status)
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
