package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type FakeConfig struct {
	StepDelay     time.Duration
	StepDelays    map[Step]time.Duration
	FailAt        Step
	FailCode      string
	FailStartCode string
	ProbeErr      error
	Changed       chan struct{}
}

type Fake struct {
	mu            sync.RWMutex
	config        FakeConfig
	probeErr      error
	failStartCode string
	changed       chan struct{}
	targets       []Target
	starts        atomic.Uint64
	probes        atomic.Uint64
}

func NewFake(config FakeConfig) *Fake {
	changed := config.Changed
	if changed == nil {
		changed = make(chan struct{}, 1)
	}
	return &Fake{config: config, probeErr: config.ProbeErr, failStartCode: config.FailStartCode, changed: changed}
}

func (f *Fake) Start(ctx context.Context, target Target, report func(Step)) (Info, error) {
	f.starts.Add(1)
	f.mu.Lock()
	f.targets = append(f.targets, target)
	config, failStartCode := f.config, f.failStartCode
	f.mu.Unlock()
	steps := [...]Step{StepResolve, StepHandshake, StepTunnel, StepVerify}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return Info{}, err
		}
		if report != nil {
			report(step)
		}
		if step == StepResolve && failStartCode != "" {
			return Info{}, &Failure{Code: failStartCode, Err: errors.New("fake engine failure")}
		}
		delay := config.StepDelays[step]
		if delay == 0 {
			delay = config.StepDelay
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return Info{}, ctx.Err()
			}
		}
		if config.FailAt == step {
			code := config.FailCode
			if code == "" {
				code = "no_server_answers"
			}
			return Info{}, &Failure{Code: code, Err: errors.New("fake engine failure")}
		}
	}
	return Info{Server: target.Server, Protocol: target.Protocol}, ctx.Err()
}

func (*Fake) Stop() {}

func (*Fake) Stats() Traffic { return Traffic{} }

func (f *Fake) Probe(ctx context.Context) error {
	f.probes.Add(1)
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.RLock()
	err := f.probeErr
	f.mu.RUnlock()
	return err
}

func (f *Fake) Changed() <-chan struct{} { return f.changed }

func (f *Fake) SetProbeErr(err error) {
	f.mu.Lock()
	f.probeErr = err
	f.mu.Unlock()
}

func (f *Fake) SetFailStartCode(code string) {
	f.mu.Lock()
	f.failStartCode = code
	f.mu.Unlock()
}

func (f *Fake) StartCount() uint64 { return f.starts.Load() }

func (f *Fake) ProbeCount() uint64 { return f.probes.Load() }

func (f *Fake) Targets() []Target {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]Target(nil), f.targets...)
}
