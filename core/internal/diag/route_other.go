//go:build !windows

package diag

import (
	"context"
	"net/netip"
	"time"
)

func icmpEcho(context.Context, netip.Addr, int, time.Duration) hopAnswer { return hopSilent }
