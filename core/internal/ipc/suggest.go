package ipc

import (
	"context"
	"reflect"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/geo"
	"github.com/mistgate/mistgate-client/core/internal/session"
)

const suggestEvery = 5 * time.Second

// publishSuggestions sends a routes event when the "doesn't open?" lists change. Failures arrive on the path of
// every flow, so they only mark the tracker; looking at it every 5 s is also the event rate limit.
func publishSuggestions(ctx context.Context, hub *session.Hub, store *geo.Store, routes func() geo.Routes) {
	if routes == nil {
		return
	}
	tick := time.NewTicker(suggestEvery)
	defer tick.Stop()
	last := store.Failures().List(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if now := store.Failures().List(time.Now()); !reflect.DeepEqual(now, last) {
				last = now
				hub.Publish("routes", routes())
			}
		}
	}
}
