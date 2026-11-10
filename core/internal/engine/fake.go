package engine

import (
	"context"
	"errors"
	"time"
)

type FakeConfig struct {
	StepDelay  time.Duration
	StepDelays map[Step]time.Duration
	FailAt     Step
	FailCode   string
}

type Fake struct {
	config FakeConfig
}

func NewFake(config FakeConfig) *Fake { return &Fake{config: config} }

func (f *Fake) Start(ctx context.Context, target Target, report func(Step)) (Info, error) {
	steps := [...]Step{StepResolve, StepHandshake, StepTunnel, StepVerify}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return Info{}, err
		}
		if report != nil {
			report(step)
		}
		delay := f.config.StepDelays[step]
		if delay == 0 {
			delay = f.config.StepDelay
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
		if f.config.FailAt == step {
			code := f.config.FailCode
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
