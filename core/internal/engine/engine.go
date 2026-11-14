package engine

import (
	"context"
	"errors"
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
}

type Info struct {
	Server   string
	ServerID string // the profile in use: names repeat (two servers of one country), ids do not
	Protocol string
	Route    string
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
	Probe(ctx context.Context) error
	Changed() <-chan struct{}
	// Next names the server after `after` in the subscription of target's server, wrapping around.
	// `after` "" or "auto" stands for the server target itself picks. ok is false when there is no other server.
	Next(target Target, after string) (server string, ok bool)
	// Fastest names the server of Next's round, except `except`, that answers a handshake soonest right now. ok is
	// false when none answers in time (or there is no other server): the caller then falls back to Next.
	Fastest(ctx context.Context, target Target, except string) (server string, ok bool)
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
