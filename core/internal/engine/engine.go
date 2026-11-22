package engine

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

type Step string

const (
	StepResolve   Step = "resolve"
	StepHandshake Step = "handshake"
	StepTunnel    Step = "tunnel"
	StepVerify    Step = "verify"
)

type Target struct {
	Server   string
	Protocol string
	Sub      string
	Hold     bool // Keep the network closed during this attempt and if it fails.
	// Avoid are the paths Auto should not pick now (they failed lately); a named server ignores it.
	Avoid []string
	// Prefer is the path Auto goes to at once, with no race of handshakes, as if it had been named: the one that
	// worked lately in this network. It is used only when it is among the candidates and not in Avoid; a named server
	// ignores it.
	Prefer string
}

// takes: Auto goes straight to the path with this id.
func (t Target) takes(id string) bool {
	return t.Prefer != "" && id == t.Prefer && !slices.Contains(t.Avoid, id)
}

type Info struct {
	Server   string
	ServerID string // the profile in use: names repeat (two servers of one country), ids do not
	Protocol string
	Route    string
	Purpose  string
}

// Selection is the selected path and Next's round; non-home whitelist paths are excluded.
type Selection struct {
	Home      Info
	Order     []string
	Whitelist string
	// Via is how a path of Order reaches its server (relay, warp) where that is known; a path that is not here is direct.
	Via map[string]string
}

// add puts p at the end of the order.
func (s *Selection) add(p profile.Profile) {
	s.Order = append(s.Order, p.ID)
	if p.Via != "" {
		if s.Via == nil {
			s.Via = map[string]string{}
		}
		s.Via[p.ID] = p.Via
	}
}

type Traffic struct {
	RXBPS int64 `json:"rx_bps"`
	TXBPS int64 `json:"tx_bps"`
	RTTMS int64 `json:"rtt_ms"`
}

type Engine interface {
	Start(ctx context.Context, target Target, report func(Step)) (Info, error)
	// Stop must be safe to call while Start is running and opens the network.
	Stop()
	Hold() bool
	Reapply()
	Stats() Traffic
	Received() uint64
	// Sent is Received's counterpart: the bytes that went out to the VPN side since this tunnel came up.
	Sent() uint64
	Probe(ctx context.Context) error
	// Proof downloads a little data through the tunnel that is up: "ok" (it came), "freeze" (it began and was stalled
	// or cut) or "" (not known). Longer than a probe: it takes seconds.
	Proof(ctx context.Context) string
	Changed() <-chan struct{}
	// Next names the server after `after` in the subscription of target's server, wrapping around.
	// `after` "" or "auto" stands for the server target itself picks. ok is false when there is no other server.
	Next(target Target, after string) (server string, ok bool)
	// Fastest names the server of Next's round, except `except`, that answers a handshake soonest right now. ok is
	// false when none answers in time (or there is no other server): the caller then falls back to Next. The paths in
	// target.Avoid are left out of the round.
	Fastest(ctx context.Context, target Target, except string) (server string, ok bool)
	// Measure makes one handshake outside the tunnel to each of the named paths, the way Fastest does, and returns the
	// round trip of each that answered; one that is not in the map did not answer. skipped are the paths that were not
	// tried at all: the key of the live AmneziaWG tunnel must not be handshaken twice.
	Measure(ctx context.Context, ids []string) (rtts map[string]time.Duration, skipped []string)
	// Select returns the path that an automatic target names and the paths it can fail over through.
	Select(target Target) (Selection, bool)
	// Stale: a tunnel is up, and the path it was built from is, in the subscriptions now, another or gone.
	Stale() bool
}

// pathChanged: the profile a tunnel was built from is gone from profiles, or is not the same path any more. A new
// name is not a new path.
// ponytail: DeepEqual tells a nil list from an empty one; at worst a sync that only changes that restarts the tunnel once.
func pathChanged(started profile.Profile, profiles []profile.Profile) bool {
	started.Name = ""
	for _, p := range profiles {
		if p.ID == started.ID && p.Sub == started.Sub {
			p.Name = ""
			return !reflect.DeepEqual(started, p)
		}
	}
	return true
}

// ErrNoTunnel: DialVPN has no tunnel that is up. ErrBlockedDest: the destination is one the proxy may not reach.
var (
	ErrNoTunnel    = errors.New("no tunnel")
	ErrBlockedDest = errors.New("destination not allowed")
)

type Failure struct {
	Code string
	Err  error
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return f.Err.Error()
	}
	return f.Code
}

func (f *Failure) Unwrap() error { return f.Err }

func ErrorCode(err error) string {
	var failure *Failure
	if errors.As(err, &failure) && failure.Code != "" {
		return failure.Code
	}
	return "engine_failure"
}
