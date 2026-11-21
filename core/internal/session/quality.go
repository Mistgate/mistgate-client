package session

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

// What the actor keeps of a connection that Auto made and watches (state.live*): liveID changes with every connection and
// every end of one, so a result of a worker that belonged to an older one is told by it; liveCtx ends with it, so that
// its workers stop. All of it is Auto's with a memory: a named server, and Auto with no memory, are left as they were.

// proofSkipBytes: a connection that has already received this much has shown that data goes through it.
const proofSkipBytes = 256 << 10

type proofResult struct {
	live      uint64
	net, path string
	verdict   string
}

// beginLive starts the watch of a connection that came up (net is the memory's key of the network, "" when there is none).
func (m *Manager) beginLive(state *actorState, net string) {
	m.endLive(state)
	state.liveCtx, state.liveCancel = context.WithCancel(context.Background())
	state.liveNet = net
}

// endLive ends the watch: the connection is over (or replaced), and what was running for it is stopped.
func (m *Manager) endLive(state *actorState) {
	if state.liveCancel != nil {
		state.liveCancel()
	}
	state.liveID++
	state.liveCtx, state.liveCancel, state.liveNet = nil, nil, ""
}

// autoOwn: the connection is Auto's own pick, on a network the memory knows, and not on the path for allowlists.
func (m *Manager) autoOwn(state *actorState) bool {
	return state.status.State == "connected" && state.liveNet != "" && isAuto(state.userServer) && isAuto(state.target.Server) &&
		!state.status.WhitelistByRule && state.status.Purpose != profile.PurposeWhitelist
}

// autoLive: autoOwn, and there is another path to go to.
func (m *Manager) autoLive(state *actorState) bool {
	return m.autoOwn(state) && len(state.selection.Order) > 1
}

// proofDelay is how long after the connection came up the check of data goes: 2 to 5 s, by chance, so that a crowd of
// clients that came back together does not download together.
func (m *Manager) proofDelay() time.Duration {
	low, high := m.timing.proofDelayMin, m.timing.proofDelayMax
	if high <= low {
		return low
	}
	return low + rand.N(high-low)
}

// startProof asks the engine, in a goroutine, whether data goes through the connection, unless it is known to or the
// person plays (the download would sit in the way of the game).
func (m *Manager) startProof(state *actorState) {
	if !m.autoLive(state) || m.currentSettings().Game {
		return
	}
	path, now := state.status.ServerID, m.auto.now()
	if m.auto.Paths.Proved(state.liveNet, path, now) || m.engine.Received() >= proofSkipBytes {
		return
	}
	live, net, ctx := state.liveID, state.liveNet, state.liveCtx
	go func() {
		verdict := m.engine.Proof(ctx)
		select {
		case m.commands <- proofResult{live: live, net: net, path: path, verdict: verdict}:
		case <-ctx.Done():
		case <-m.done:
		}
	}()
}

// proofDone: data went ("ok": the path is marked), or the connection started and carried nothing ("freeze": the path is
// marked, with a failure, and Auto goes to another one). Only one such move is made in a row: when the next path does
// not pass either, the network or the target of the check is more likely at fault than the path, and it stays.
func (m *Manager) proofDone(state *actorState, r proofResult) {
	if r.live != state.liveID || state.status.State != "connected" || r.verdict != "ok" && r.verdict != "freeze" {
		return
	}
	slog.Info("auto: proof path=" + r.path + " state=" + r.verdict)
	if r.verdict == "ok" {
		m.auto.Paths.Prove(r.net, r.path, m.auto.now())
		state.proofFreezes = 0
		return
	}
	if state.proofFreezes > 0 {
		return
	}
	state.proofFreezes++
	m.auto.Paths.Freeze(r.net, r.path, m.auto.now())
	m.leave(state, "freeze", "")
}

// leave takes Auto off the path in use, with the network held as a change of route does: the next attempt avoids the
// path, goes to prefer when that is named (else it is a race), and the status says reason once it is up.
func (m *Manager) leave(state *actorState, reason, prefer string) {
	state.roundFailures[state.status.ServerID] = 2
	state.nextReason, state.prefer = reason, prefer
	m.reconnectRoute(state, m.currentSettings())
}
