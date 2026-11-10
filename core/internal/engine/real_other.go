//go:build !windows

package engine

import (
	"context"
	"errors"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

type Real struct{}

func NewReal(_ func() ([]profile.Profile, error), _ func() settings.Settings, _ ...string) *Real {
	return &Real{}
}

func (*Real) Start(context.Context, Target, func(Step)) (Info, error) {
	return Info{}, &Failure{Code: "unsupported_os", Err: errors.New("real engine requires Windows")}
}

func (*Real) Stop()                       {}
func (*Real) Hold() bool                  { return false }
func (*Real) Reapply()                    {}
func (*Real) Stats() Traffic              { return Traffic{} }
func (*Real) Probe(context.Context) error { return errors.New("real engine requires Windows") }
func (*Real) Changed() <-chan struct{}    { return nil }
