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
	engine   engine.Engine
	hub      *Hub
	commands chan any
	done     chan struct{}
	once     sync.Once
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
	err        error
}
type closeRequest struct{ reply chan (<-chan struct{}) }

type actorState struct {
	status      Status
	generation  uint64
	cancel      context.CancelFunc
	attemptDone <-chan struct{}
}

func NewManager(eng engine.Engine) *Manager {
	m := &Manager{
		engine:   eng,
		hub:      NewHub(DefaultEventQueue),
		commands: make(chan any, 32),
		done:     make(chan struct{}),
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
		var attemptDone <-chan struct{}
		select {
		case m.commands <- closeRequest{reply: reply}:
			attemptDone = <-reply
		case <-m.done:
		}
		<-m.done
		if attemptDone != nil {
			<-attemptDone
		}
	})
}

func (m *Manager) run() {
	// This goroutine owns actorState; engine workers report through commands.
	defer close(m.done)
	defer m.hub.Close()
	state := actorState{status: Status{State: "off"}}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case raw := <-m.commands:
			switch request := raw.(type) {
			case statusRequest:
				request.reply <- state.status
			case connectRequest:
				status, err := m.connect(&state, request.target)
				request.reply <- connectReply{status: status, err: err}
			case disconnectRequest:
				m.stop(&state)
				request.reply <- state.status
			case attemptStep:
				if request.generation == state.generation && state.status.State == "connecting" {
					if state.status.Step != string(request.step) {
						state.status.Step = string(request.step)
						m.hub.Publish("status", state.status)
					}
				}
			case attemptResult:
				if request.generation == state.generation {
					if request.err != nil {
						if state.cancel != nil {
							state.cancel()
							state.cancel = nil
						}
						state.status.State = "error"
						state.status.Step = ""
						state.status.Error = engine.ErrorCode(request.err)
					} else {
						state.status.State = "connected"
						state.status.Step = ""
						state.status.Error = ""
						state.status.SinceUnix = time.Now().Unix()
					}
					m.hub.Publish("status", state.status)
				}
			case closeRequest:
				attemptDone := state.attemptDone
				m.stop(&state)
				request.reply <- attemptDone
				return
			}
		case <-ticker.C:
			if state.status.State == "connected" && m.engine != nil {
				m.hub.Publish("traffic", m.engine.Stats())
			}
		}
	}
}

func (m *Manager) connect(state *actorState, target engine.Target) (Status, error) {
	if target.Server == "" {
		target.Server = "auto"
	}
	if target.Protocol == "" {
		target.Protocol = "auto"
	}
	if m.engine == nil {
		state.generation++
		state.status = Status{State: "error", SinceUnix: time.Now().Unix(), Server: target.Server, Protocol: target.Protocol, Error: "no_subscription"}
		m.hub.Publish("status", state.status)
		return state.status, &CodeError{Code: "no_subscription"}
	}

	previousDone := state.attemptDone
	if state.cancel != nil {
		state.cancel()
		m.engine.Stop()
	}
	state.generation++
	generation := state.generation
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	done := make(chan struct{})
	state.attemptDone = done
	state.status = Status{
		State:     "connecting",
		Step:      string(engine.StepResolve),
		SinceUnix: time.Now().Unix(),
		Server:    target.Server,
		Protocol:  target.Protocol,
	}
	m.hub.Publish("status", state.status)
	go func() {
		defer close(done)
		if previousDone != nil {
			select {
			case <-previousDone:
			case <-ctx.Done():
				return
			}
		}
		if err := ctx.Err(); err != nil {
			return
		}
		err := m.engine.Start(ctx, target, func(step engine.Step) {
			select {
			case m.commands <- attemptStep{generation: generation, step: step}:
			case <-ctx.Done():
			case <-m.done:
			}
		})
		select {
		case m.commands <- attemptResult{generation: generation, err: err}:
		case <-m.done:
		}
	}()
	return state.status, nil
}

func (m *Manager) stop(state *actorState) {
	if state.cancel != nil {
		state.cancel()
		state.cancel = nil
		m.engine.Stop()
	}
	state.generation++
	state.status = Status{State: "off"}
	m.hub.Publish("status", state.status)
}
