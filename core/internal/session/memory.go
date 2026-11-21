package session

import (
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
)

// AutoMemory is what Auto remembers from one connection to the next (package auto). The zero value remembers nothing.
type AutoMemory struct {
	Paths *auto.Memory
	// NetworkKey names the network the machine is on (diag.NetworkKey with the memory's salt); "" when there is none.
	// It reads the routing table and asks the network for nothing, but it still runs in an attempt's goroutine, not in
	// the actor.
	NetworkKey func() (key, kind string)
	// PathIDs are the ids of every path of every subscription: what Keep leaves in the memory.
	PathIDs func() []string
	Now     func() time.Time // time.Now when nil
}

func (a AutoMemory) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// consult adds what the memory knows of this network to an attempt of Auto: the paths in quarantine to avoid, and the
// known good path to go to at once (candidates is nil when the round has already failed once: then it is a race).
// It returns the key and kind of the network. Runs in the attempt's goroutine.
func (a AutoMemory) consult(target *engine.Target, candidates []auto.Path) (key, kind string) {
	if a.Paths == nil || a.NetworkKey == nil {
		return "", ""
	}
	key, kind = a.NetworkKey()
	if !isAuto(target.Server) {
		return key, kind
	}
	now := a.now()
	avoid := slices.Concat(target.Avoid, a.Paths.Avoid(key, now))
	slices.Sort(avoid)
	target.Avoid = slices.Compact(avoid)
	if len(candidates) != 0 {
		target.Prefer, _ = a.Paths.Known(key, candidates, now)
	}
	return key, kind
}

// pathUp notes a connection that came up: the path worked in this network, and the status says how Auto came to it. The
// actor calls it; the memory only takes its own lock, and the file is written from another goroutine.
func (m *Manager) pathUp(state *actorState, r attemptResult) {
	path := r.info.ServerID
	var rtt int64
	if r.net != "" && path != "" && m.engine != nil {
		// ponytail: the engine knows the round trip of a path only for AmneziaWG at this point; the others are noted
		// at the first good health probe (see noteRTT). Unknown is 0.
		rtt = m.engine.Stats().RTTMS
		m.auto.Paths.Success(r.net, path, int(rtt), m.auto.now())
		state.autoNet, state.autoPath = r.net, path
	}
	state.status.Auto, state.status.Reason = false, ""
	if isAuto(state.target.Server) {
		failover := len(state.roundFailures) > 0 || state.deadPath != "" && state.deadPath != path
		state.status.Auto = true
		state.status.Reason = autoReason(r.prefer, path, len(state.selection.Order), failover)
		logPick(path, state.status.Reason, rtt, r.kind)
	}
	state.deadPath = ""
}

// noteRTT: the first good probe of a connection that came up, by when the engine has measured the path's round trip.
func (m *Manager) noteRTT(state *actorState) {
	if state.autoPath == "" {
		return
	}
	if rtt := m.engine.Stats().RTTMS; rtt > 0 {
		m.auto.Paths.Success(state.autoNet, state.autoPath, int(rtt), m.auto.now())
	}
	state.autoNet, state.autoPath = "", ""
}

// autoReason says why Auto took the path: "known" (the memory named it), "only" (the one candidate), "failover" (another
// path failed in this round, or the connection died on another path), else "fastest" (the race).
func autoReason(prefer, path string, candidates int, failover bool) string {
	switch {
	case prefer != "" && prefer == path:
		return "known"
	case candidates == 1:
		return "only"
	case failover:
		return "failover"
	}
	return "fastest"
}

// logPick is the one line of a connection that Auto made. The ring of the log keeps the message only, so the facts
// are in it; they are the path's id, the reason, the round trip in ms (0 when not known) and the kind of network.
func logPick(path, reason string, rttMS int64, kind string) {
	if kind == "" {
		kind = "other"
	}
	slog.Info("auto: pick path=" + path + " reason=" + reason + " ms=" + strconv.FormatInt(rttMS, 10) + " net=" + kind)
}
