package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

type FakeConfig struct {
	StepDelay     time.Duration
	StepDelays    map[Step]time.Duration
	FailAt        Step
	FailCode      string
	FailStartCode string
	HoldResult    *bool
	ProbeErr      error
	ProbeErrs     []error
	Changed       chan struct{}
}

type Fake struct {
	mu            sync.RWMutex
	config        FakeConfig
	probeErr      error
	probeErrs     []error
	failStartCode string
	changed       chan struct{}
	targets       []Target
	servers       []string
	profiles      []profile.Profile
	fastest       string
	starts        atomic.Uint64
	probes        atomic.Uint64
	received      atomic.Uint64
	holds         atomic.Uint64
	reapplies     atomic.Uint64
}

func NewFake(config FakeConfig) *Fake {
	changed := config.Changed
	if changed == nil {
		changed = make(chan struct{}, 1)
	}
	return &Fake{
		config:        config,
		probeErr:      config.ProbeErr,
		probeErrs:     append([]error(nil), config.ProbeErrs...),
		failStartCode: config.FailStartCode,
		changed:       changed,
	}
}

func (f *Fake) Start(ctx context.Context, target Target, report func(Step)) (Info, error) {
	f.starts.Add(1)
	f.received.Store(0)
	f.mu.Lock()
	f.targets = append(f.targets, target)
	config, failStartCode := f.config, f.failStartCode
	hasProfiles := len(f.profiles) != 0
	f.mu.Unlock()
	info, ok := f.Select(target)
	if !ok || !hasProfiles {
		info.Home = Info{Server: target.Server, Protocol: target.Protocol}
	}
	steps := [...]Step{StepResolve, StepHandshake, StepTunnel, StepVerify}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return info.Home, err
		}
		if report != nil {
			report(step)
		}
		if step == StepResolve && failStartCode != "" {
			return info.Home, &Failure{Code: failStartCode, Err: errors.New("fake engine failure")}
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
				return info.Home, ctx.Err()
			}
		}
		if config.FailAt == step {
			code := config.FailCode
			if code == "" {
				code = "no_server_answers"
			}
			return info.Home, &Failure{Code: code, Err: errors.New("fake engine failure")}
		}
	}
	return info.Home, ctx.Err()
}

func (*Fake) Stop() {}

func (f *Fake) Hold() bool {
	f.holds.Add(1)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.config.HoldResult == nil {
		return true
	}
	return *f.config.HoldResult
}

func (f *Fake) Reapply() { f.reapplies.Add(1) }

func (*Fake) Stats() Traffic { return Traffic{} }

func (f *Fake) Received() uint64 { return f.received.Load() }

func (f *Fake) Probe(ctx context.Context) error {
	f.probes.Add(1)
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	err := f.probeErr
	if len(f.probeErrs) != 0 {
		err = f.probeErrs[0]
		f.probeErrs = f.probeErrs[1:]
	}
	f.mu.Unlock()
	return err
}

func (f *Fake) Changed() <-chan struct{} { return f.changed }

func (f *Fake) Next(target Target, after string) (string, bool) {
	f.mu.RLock()
	profiles := append([]profile.Profile(nil), f.profiles...)
	servers := append([]string(nil), f.servers...)
	defer f.mu.RUnlock()
	if len(profiles) != 0 {
		return profile.Next(profiles, target.Server, target.Protocol, target.Sub, "auto", false, after)
	}
	if len(servers) < 2 {
		return "", false
	}
	for i, server := range servers {
		if server == after {
			return servers[(i+1)%len(servers)], true
		}
	}
	return servers[1], true // "auto" or unknown: the first server is the pick
}

// SetFastest is the server Fastest answers with; "" means none answers. It is skipped when it is `except`.
func (f *Fake) SetFastest(server string) {
	f.mu.Lock()
	f.fastest = server
	f.mu.Unlock()
}

func (f *Fake) Fastest(_ context.Context, target Target, except string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.fastest == "" || f.fastest == except {
		return "", false
	}
	if len(f.profiles) != 0 {
		for _, candidate := range profile.Others(f.profiles, target.Server, target.Protocol, target.Sub, "auto", false, except) {
			if candidate.ID == f.fastest {
				return f.fastest, true
			}
		}
		return "", false
	}
	return f.fastest, true
}

func (f *Fake) Select(target Target) (Selection, bool) {
	f.mu.RLock()
	profiles := append([]profile.Profile(nil), f.profiles...)
	servers := append([]string(nil), f.servers...)
	f.mu.RUnlock()
	if len(profiles) != 0 {
		home, ring, ok := profile.Ring(profiles, target.Server, target.Protocol, target.Sub, "auto", false)
		if !ok {
			return Selection{}, false
		}
		name := home.Name
		if name == "" {
			name = home.ID
		}
		selection := Selection{Home: Info{Server: name, ServerID: home.ID, Protocol: home.Protocol, Purpose: home.Purpose}, Order: make([]string, 0, len(ring))}
		for _, p := range ring {
			selection.Order = append(selection.Order, p.ID)
		}
		for _, p := range profiles {
			if p.Sub == home.Sub && p.Purpose == profile.PurposeWhitelist {
				selection.Whitelist = p.ID
				break
			}
		}
		return selection, true
	}
	if len(servers) == 0 {
		return Selection{}, false
	}
	server := target.Server
	if server == "" || server == "auto" {
		server = servers[0]
	}
	for _, id := range servers {
		if id == server {
			return Selection{Home: Info{Server: id, ServerID: id, Protocol: target.Protocol}, Order: servers}, true
		}
	}
	return Selection{}, false
}

// SetServers is the server list of the one fake subscription, in order.
func (f *Fake) SetServers(servers ...string) {
	f.mu.Lock()
	f.servers = append([]string(nil), servers...)
	f.mu.Unlock()
}

func (f *Fake) SetProfiles(profiles ...profile.Profile) {
	f.mu.Lock()
	f.profiles = append([]profile.Profile(nil), profiles...)
	f.mu.Unlock()
}

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

func (f *Fake) SetReceived(received uint64) { f.received.Store(received) }

func (f *Fake) HoldCount() uint64 { return f.holds.Load() }

func (f *Fake) ReapplyCount() uint64 { return f.reapplies.Load() }

func (f *Fake) SetHoldResult(hold bool) {
	f.mu.Lock()
	f.config.HoldResult = &hold
	f.mu.Unlock()
}

func (f *Fake) Targets() []Target {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]Target(nil), f.targets...)
}

// DialVPN: the fake has no tunnel to dial through.
func (*Fake) DialVPN(context.Context, string, uint16) (net.Conn, error) { return nil, ErrNoTunnel }
