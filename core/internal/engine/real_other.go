//go:build !windows

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

type Real struct {
	geo       *geo.Store
	AllowDest func(netip.Addr) bool
}

func NewReal(_ func() ([]profile.Profile, error), _ func() settings.Settings, geoStore *geo.Store, _ ...string) *Real {
	return &Real{geo: geoStore}
}

func (*Real) Start(context.Context, Target, func(Step)) (Info, error) {
	return Info{}, &Failure{Code: "unsupported_os", Err: errors.New("real engine requires Windows")}
}

func (*Real) Stop()                                   {}
func (*Real) Hold() bool                              { return false }
func (*Real) Reapply()                                {}
func (*Real) Stats() Traffic                          { return Traffic{} }
func (*Real) Received() uint64                        { return 0 }
func (*Real) Probe(context.Context) error             { return errors.New("real engine requires Windows") }
func (*Real) Changed() <-chan struct{}                { return nil }
func (*Real) Next(Target, string) (string, bool)      { return "", false }
func (*Real) EffectiveRoute(settings.Settings) string { return "all" }
func (r *Real) Routes(configured settings.Settings) geo.Routes {
	return r.geo.Routes(configured.RouteMode, configured.RouteRegion, "")
}
func (r *Real) CheckSite(configured settings.Settings, name string) geo.Check {
	return r.geo.CheckName(configured.RouteMode, "", name, false)
}
func (*Real) RefreshAutoRegion(onChange func()) {
	if onChange != nil {
		onChange()
	}
}

func (*Real) Fastest(context.Context, Target, string) (string, bool) { return "", false }

func (*Real) DialVPN(context.Context, string, uint16) (net.Conn, error) { return nil, ErrNoTunnel }
func (*Real) HomeAddr() string                                          { return "" }
