package engine

import (
	"context"
	"errors"
	"net"
	"slices"
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
	failing       []string
	stale         bool
	starts        atomic.Uint64
	probes        atomic.Uint64
	received      atomic.Uint64
	sent          atomic.Uint64
	rttMS         atomic.Int64
	proofs        map[string]string
	current       string // the path of the last Start
	proofCalls    atomic.Uint64
	holds         atomic.Uint64
	stops         atomic.Uint64
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
	f.sent.Store(0)
	f.mu.Lock()
	f.targets = append(f.targets, target)
	config, failStartCode := f.config, f.failStartCode
	hasProfiles := len(f.profiles) != 0
	f.stale = false // a new tunnel is built from the subscriptions as they are now
	f.mu.Unlock()
	info, ok := f.Select(target)
	if !ok || !hasProfiles {
		info.Home = Info{Server: target.Server, Protocol: target.Protocol}
	}
	used := target.Server
	if (target.Server == "" || target.Server == "auto") && ok && len(info.Order) != 0 {
		info.Home = f.pickAuto(target, info)
		used = info.Home.ServerID
	}
	f.mu.Lock()
	f.current = used
	f.mu.Unlock()
	f.mu.RLock()
	failing := slices.Contains(f.failing, used)
	f.mu.RUnlock()
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
		if config.FailAt == step || failing && step == StepHandshake {
			code := config.FailCode
			if code == "" {
				code = "no_server_answers"
			}
			return info.Home, &Failure{Code: code, Err: errors.New("fake engine failure")}
		}
	}
	return info.Home, ctx.Err()
}

// pickAuto is the path Auto takes: the one asked for (Target.Prefer), else the first of the order that is not to be
// avoided, the first when all are. The fake does no race: a test sees one in Target.Prefer being empty.
func (f *Fake) pickAuto(target Target, selection Selection) Info {
	pick := selection.Order[0]
	if i := slices.IndexFunc(selection.Order, target.takes); i >= 0 {
		pick = selection.Order[i]
	} else {
		for _, id := range selection.Order {
			if !slices.Contains(target.Avoid, id) {
				pick = id
				break
			}
		}
	}
	if pick == selection.Home.ServerID {
		return selection.Home
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, p := range f.profiles {
		if p.ID == pick {
			name := p.Name
			if name == "" {
				name = p.ID
			}
			return Info{Server: name, ServerID: p.ID, Protocol: p.Protocol, Purpose: p.Purpose}
		}
	}
	return Info{Server: pick, ServerID: pick, Protocol: selection.Home.Protocol}
}

func (f *Fake) Stop() { f.stops.Add(1) }

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

func (f *Fake) Stats() Traffic { return Traffic{RTTMS: f.rttMS.Load()} }

// SetRTT is the round trip, in ms, that Stats reports.
func (f *Fake) SetRTT(ms int64) { f.rttMS.Store(ms) }

func (f *Fake) Received() uint64 { return f.received.Load() }

func (f *Fake) Sent() uint64 { return f.sent.Load() }

func (f *Fake) SetSent(sent uint64) { f.sent.Store(sent) }

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

// SetProof is what Proof answers while the path (a server id) is the one in use; "" as the path is the answer for any
// other. Without it Proof knows nothing ("").
func (f *Fake) SetProof(path, answer string) {
	f.mu.Lock()
	if f.proofs == nil {
		f.proofs = map[string]string{}
	}
	f.proofs[path] = answer
	f.mu.Unlock()
}

func (f *Fake) Proof(ctx context.Context) string {
	f.proofCalls.Add(1)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if ctx.Err() != nil {
		return ""
	}
	if answer, ok := f.proofs[f.current]; ok {
		return answer
	}
	return f.proofs[""]
}

func (f *Fake) ProofCount() uint64 { return f.proofCalls.Load() }

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
			selection.add(p)
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

// SetFailing makes the attempts that go to these servers fail at the handshake (FakeConfig.FailCode, or no_server_answers).
func (f *Fake) SetFailing(servers ...string) {
	f.mu.Lock()
	f.failing = append([]string(nil), servers...)
	f.mu.Unlock()
}

// SetStale is what Stale answers until the next Start, which builds a tunnel from the subscriptions as they are.
func (f *Fake) SetStale(stale bool) {
	f.mu.Lock()
	f.stale = stale
	f.mu.Unlock()
}

func (f *Fake) Stale() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.stale
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

func (f *Fake) StopCount() uint64 { return f.stops.Load() }

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
