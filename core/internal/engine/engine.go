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
}

type Info struct {
	Server   string
	Protocol string
}

type Traffic struct {
	RXBPS int64 `json:"rx_bps"`
	TXBPS int64 `json:"tx_bps"`
	RTTMS int64 `json:"rtt_ms"`
}

type Engine interface {
	Start(ctx context.Context, target Target, report func(Step)) (Info, error)
	// Stop must be safe to call while Start is running.
	Stop()
	Stats() Traffic
}

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
