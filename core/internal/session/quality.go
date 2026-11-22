package session

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strconv"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/settings"
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
	state.liveNet, state.liveSince = net, m.auto.now()
}

// endLive ends the watch: the connection is over (or replaced), and what was running for it is stopped.
func (m *Manager) endLive(state *actorState) {
	if state.liveCancel != nil {
		state.liveCancel()
	}
	state.liveID++
	state.liveCtx, state.liveCancel, state.liveNet = nil, nil, ""
	state.samples, state.counters, state.stalled = nil, nil, false
	state.searching, state.candidate, state.quietSince, state.nextSearch = false, "", time.Time{}, time.Time{}
	state.measuring, state.nextMeasure = false, time.Time{}
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
		state.proofFreezes, state.returned = 0, false
		return
	}
	if state.proofFreezes > 0 {
		return
	}
	state.proofFreezes++
	m.auto.Paths.Freeze(r.net, r.path, m.auto.now())
	if state.returned {
		// a return from the path for allowlists that carries nothing goes back to it, not on to another ordinary path
		m.auto.Paths.Failure(r.net, r.path, m.auto.now())
		state.returned = false
		m.chooseWhitelist(state)
	}
	m.leave(state, "freeze", "")
}

// leave takes Auto off the path in use, with the network held as a change of route does: the next attempt avoids the
// path, goes to prefer when that is named (else it is a race), and the status says reason once it is up.
func (m *Manager) leave(state *actorState, reason, prefer string) {
	state.roundFailures[state.status.ServerID] = 2
	state.nextReason, state.prefer = reason, prefer
	m.reconnectRoute(state, m.currentSettings())
}

// stallSent is how much data must go out, with none coming back, for a silence to be a stall and not an idle line.
const stallSent = 32 << 10

// counterSample is what the engine's counters said at a time.
type counterSample struct {
	at             time.Time
	sent, received uint64
}

// stalled: from base to cur at least window passed, stallSent bytes went out and not one came back.
func stalled(base, cur counterSample, window time.Duration) bool {
	return cur.at.Sub(base.at) >= window && cur.sent >= base.sent && cur.sent-base.sent >= stallSent && cur.received == base.received
}

// stalledDead is the quick death of a connection: two probes in a row failed while data goes out and none comes back,
// so the window that probeIsDead waits out is not needed. The bytes that came since the streak began still save it.
// Two, not one: the forwarder counts bytes of streams, so a long upload looks like a stall, and one probe may fail on a
// line that an upload fills.
func stalledDead(failures int, streakStart time.Time, receivedAtStart, receivedNow uint64, stall bool) bool {
	return stall && failures >= 2 && !streakStart.IsZero() && receivedSince(receivedAtStart, receivedNow) < receivedAliveThreshold
}

// quietBPS is the speed below which the line is quiet, in bits per second as Traffic has it: 64 KB/s.
const quietBPS = (64 << 10) * 8

type searchResult struct {
	live   uint64
	server string // "" when none was found
}

// returnSettle: a return from the path for allowlists that has lasted this long is an ordinary connection.
const returnSettle = time.Minute

// onWhitelist: the connection is on the path for allowlists that the rule chose (whitelist_auto), for an Auto that has a
// memory of this network.
func (m *Manager) onWhitelist(state *actorState) bool {
	return state.status.State == "connected" && state.liveNet != "" && isAuto(state.userServer) && state.status.WhitelistByRule
}

// watch is what the actor does with an Auto connection at every tick of the counters (stats are the same tick's): it
// reads them, moves a poor connection to a better path at a quiet moment, probes the other paths now and then, moves an
// idle healthy one to a much quicker path, and takes the path for allowlists back to an ordinary path that answers.
func (m *Manager) watch(state *actorState, stats engine.Traffic) {
	now := m.auto.now()
	if m.onWhitelist(state) {
		m.watchWhitelist(state, stats, now)
		return
	}
	if !m.autoOwn(state) {
		return
	}
	if state.returned && now.Sub(state.liveSince) >= returnSettle {
		state.returned = false
	}
	m.sampleCounters(state, now)
	configured := m.currentSettings()
	switch {
	case state.candidate != "":
		m.waitQuiet(state, stats, now)
	case !state.searching:
		m.maybeSearch(state, now)
	}
	poor, mode := m.poor(state, now, configured), auto.ModeHealthy
	if poor {
		mode = auto.ModeDegraded
	}
	m.maybeMeasure(state, now, mode)
	if state.candidate == "" && !state.searching {
		m.maybeUpgrade(state, stats, now, configured, poor)
	}
}

// alternatives are the paths Auto may go to from the one in use.
func (m *Manager) alternatives(state *actorState) []auto.Path {
	var paths []auto.Path
	for _, id := range state.selection.Order {
		if id != state.status.ServerID {
			paths = append(paths, auto.Path{ID: id, Via: state.selection.Via[id]})
		}
	}
	return paths
}

// watchWhitelist: on the path for allowlists, the best ordinary paths are probed (see maybeMeasure), and when one has
// answered twice, 5 minutes apart, since the session came here, the session goes back to it at a quiet moment (waitQuiet,
// returnNow). The setting auto_switch does not stop it: this path is an emergency one.
func (m *Manager) watchWhitelist(state *actorState, stats engine.Traffic, now time.Time) {
	if state.candidate != "" {
		m.waitQuiet(state, stats, now)
	} else if to := auto.ReturnTo(m.alternatives(state), m.auto.Paths.Stats(state.liveNet), state.measured, state.liveNet,
		state.whitelistSince, now); to != "" {
		state.candidate, state.candidateSince, state.quietSince = to, now, time.Time{}
	}
	m.maybeMeasure(state, now, auto.ModeWhitelist)
}

// returnNow goes back from the path for allowlists to the ordinary path that has answered, after a last look at the
// quarantine. The attempt goes to that path at once (Prefer), as a move by choice does. If it fails, or the data check
// finds the connection frozen, the session is on the path for allowlists again (serverDown, proofDone) and the path is
// marked in the memory: its quarantine is what keeps the next return from going to it at once.
func (m *Manager) returnNow(state *actorState, now time.Time) {
	to := state.candidate
	state.candidate, state.quietSince = "", time.Time{}
	if m.auto.Paths.Stats(state.liveNet)[to].Until > now.Unix() {
		return
	}
	slog.Info("auto: switch path=" + to + " reason=upgrade")
	state.returned, state.proofFreezes = true, 0
	state.target.Server, state.status.Server = state.userServer, state.userServer
	state.status.WhitelistByRule = false
	m.setPurpose(state, state.target)
	m.leave(state, "upgrade", to)
}

// maybeUpgrade moves a healthy connection that is idle to a path that has proved much quicker (auto.Upgrade says when).
// The line is idle when it has stayed under 4 KB/s; the move is not forced by waiting.
func (m *Manager) maybeUpgrade(state *actorState, stats engine.Traffic, now time.Time, configured settings.Settings, poor bool) {
	state.noteQuiet(stats, now, auto.UpgradeQuietBPS)
	var quiet time.Duration
	if !state.quietSince.IsZero() {
		quiet = now.Sub(state.quietSince)
	}
	to, ok := auto.Upgrade(auto.UpgradeInput{
		Poor: poor, Game: configured.Game, AutoSwitch: configured.AutoSwitch,
		OnPath: now.Sub(state.liveSince), MinOnPath: m.timing.upgradeOnPath, Quiet: quiet,
		Cur:   time.Duration(stats.RTTMS) * time.Millisecond,
		Paths: m.alternatives(state), Stats: m.auto.Paths.Stats(state.liveNet), History: state.measured,
		Switches: state.switches, Net: state.liveNet, Now: now,
	})
	if !ok {
		return
	}
	state.switches = auto.Moved(state.switches, now, state.status.ServerID)
	slog.Info("auto: switch path=" + to + " reason=upgrade")
	m.leave(state, "upgrade", to)
}

// noteQuiet keeps since when the speed (rx and tx together) has been under bps.
func (state *actorState) noteQuiet(stats engine.Traffic, now time.Time, bps int64) {
	switch {
	case stats.RXBPS+stats.TXBPS >= bps:
		state.quietSince = time.Time{}
	case state.quietSince.IsZero():
		state.quietSince = now
	}
}

// poor: the connection is bad enough to look for another path. The game mode takes only a heavy loss: a move would cost
// it more than the loss does.
func (m *Manager) poor(state *actorState, now time.Time, configured settings.Settings) bool {
	if configured.Game {
		return auto.Heavy(state.samples, now)
	}
	return auto.Degraded(state.samples, state.status.Protocol == "awg", now)
}

// maybeSearch begins the search for a replacement (the engine's Fastest, off the actor) when the connection is poor and
// a move is allowed.
func (m *Manager) maybeSearch(state *actorState, now time.Time) {
	configured := m.currentSettings()
	if !configured.AutoSwitch || len(state.selection.Order) < 2 || now.Before(state.nextSearch) ||
		!m.poor(state, now, configured) || !auto.MaySwitch(state.switches, "", now) {
		return
	}
	path, w := state.status.ServerID, auto.Look(state.samples, auto.ProbeSpan, now)
	slog.Info("auto: degraded path=" + path + " count=" + strconv.Itoa(w.Fails) + " ms=" + strconv.FormatInt(w.Median.Milliseconds(), 10))
	state.searching = true
	// the quarantine of the memory and the paths left lately are not candidates
	home := state.target
	home.Server, home.Prefer = state.userServer, ""
	home.Avoid = slices.Concat(m.auto.Paths.Avoid(state.liveNet, now), auto.Left(state.switches, now))
	live, ctx := state.liveID, state.liveCtx
	go func() {
		server, _ := m.engine.Fastest(ctx, home, path)
		select {
		case m.commands <- searchResult{live: live, server: server}:
		case <-ctx.Done():
		case <-m.done:
		}
	}()
}

// searchDone: a replacement was found (it waits for a quiet moment), or none was and the next search is not before
// searchEvery.
func (m *Manager) searchDone(state *actorState, r searchResult) {
	if r.live != state.liveID || state.status.State != "connected" {
		return
	}
	now := m.auto.now()
	state.searching = false
	if r.server == "" {
		state.nextSearch = now.Add(m.timing.searchEvery)
		return
	}
	state.candidate, state.candidateSince, state.quietSince = r.server, now, time.Time{}
}

// waitQuiet moves to the replacement once the speed has stayed under quietBPS for quietFor, or after quietLimit anyway:
// a poor connection to a better path (switchNow), the path for allowlists back to an ordinary one (returnNow).
func (m *Manager) waitQuiet(state *actorState, stats engine.Traffic, now time.Time) {
	state.noteQuiet(stats, now, quietBPS)
	if !state.quietSince.IsZero() && now.Sub(state.quietSince) >= m.timing.quietFor || now.Sub(state.candidateSince) >= m.timing.quietLimit {
		if m.onWhitelist(state) {
			m.returnNow(state, now)
		} else {
			m.switchNow(state, now)
		}
	}
}

// switchNow makes the move, after a last look: the setting must still be on, the connection still poor, and the limits
// must still allow it. It is alive (watch runs only for a connected one); a connection that is dying has the death of a
// connection to deal with, and goes to a path that was already found just the same.
func (m *Manager) switchNow(state *actorState, now time.Time) {
	to := state.candidate
	state.candidate, state.quietSince = "", time.Time{}
	configured := m.currentSettings()
	if !configured.AutoSwitch || !m.poor(state, now, configured) || !auto.MaySwitch(state.switches, to, now) {
		return
	}
	state.switches = auto.Moved(state.switches, now, state.status.ServerID)
	slog.Info("auto: switch path=" + to + " reason=degraded")
	m.leave(state, "degraded", to)
}

// sampleCounters reads the counters and says whether the connection is in a stall; the start of one is a sample.
func (m *Manager) sampleCounters(state *actorState, now time.Time) {
	cur := counterSample{at: now, sent: m.engine.Sent(), received: m.engine.Received()}
	state.counters = append(state.counters, cur)
	// the base is the newest sample that is a window old; what is before it is of no use
	for i := len(state.counters) - 1; i > 0; i-- {
		if now.Sub(state.counters[i].at) >= m.timing.stallFor {
			state.counters = state.counters[i:]
			break
		}
	}
	stall := stalled(state.counters[0], cur, m.timing.stallFor)
	if stall && !state.stalled {
		state.samples = append(auto.Trim(state.samples, now), auto.Sample{At: now, Stall: true})
	}
	state.stalled = stall
}

// noteProbe keeps the outcome of a probe of an Auto connection.
func (m *Manager) noteProbe(state *actorState, r probeResult) {
	if m.autoOwn(state) {
		now := m.auto.now()
		state.samples = append(auto.Trim(state.samples, now), auto.Sample{At: now, Fail: r.err != nil, Took: r.took})
	}
}

// diedStalled: a failed probe on an Auto connection that is in a stall. The path is marked as failed (an ordinary death
// is not: a change of Wi-Fi is no fault of the server).
func (m *Manager) diedStalled(state *actorState, r probeResult) bool {
	if !m.autoOwn(state) {
		return false
	}
	m.sampleCounters(state, m.auto.now())
	if !stalledDead(state.probeFailures, state.probeStreakStart, state.probeReceivedStart, r.received, state.stalled) {
		return false
	}
	path := state.status.ServerID
	m.auto.Paths.Failure(state.liveNet, path, m.auto.now())
	slog.Info("auto: dead path=" + path + " reason=stall")
	return true
}

// measureResult is the answer of a round of background probes (Engine.Measure), which ran off the actor.
type measureResult struct {
	live    uint64
	net     string
	ids     []string
	rtts    map[string]time.Duration
	skipped []string
}

// jitter is d, by 70 to 130 percent, so that the clients of one server do not probe together.
func jitter(d time.Duration) time.Duration { return d*7/10 + rand.N(max(d*6/10, 1)) }

// maybeMeasure makes a round of background probes of the other paths when one is due: a handshake to each, outside the
// tunnel (the engine's Measure, off the actor), for what the memory and a later move by choice go by. Which paths and how
// often is auto.Probes'; the round comes about every 30 minutes, and every 10 while the connection is poor.
func (m *Manager) maybeMeasure(state *actorState, now time.Time, mode string) {
	every := m.timing.measureHealthy
	if mode != auto.ModeHealthy {
		every = m.timing.measureBad
	}
	if state.nextMeasure.IsZero() || mode != state.measureMode {
		if due := now.Add(jitter(every)); state.nextMeasure.IsZero() || due.Before(state.nextMeasure) {
			state.nextMeasure = due
		}
	}
	state.measureMode = mode
	if now.Before(state.nextMeasure) || state.measuring {
		return
	}
	state.nextMeasure = now.Add(jitter(every))
	// while the connection's own probes fail in a row, a path that does not answer may be a cut network, not the path's fault
	if state.probeFailures >= 2 {
		return
	}
	ids := auto.Probes(auto.ProbeInput{Paths: m.alternatives(state), Stats: m.auto.Paths.Stats(state.liveNet), History: state.measured,
		Net: state.liveNet, Now: now, Mode: mode, Game: m.currentSettings().Game})
	if len(ids) == 0 {
		return
	}
	state.measuring = true
	live, net, ctx := state.liveID, state.liveNet, state.liveCtx
	go func() {
		rtts, skipped := m.engine.Measure(ctx, ids)
		select {
		case m.commands <- measureResult{live: live, net: net, ids: ids, rtts: rtts, skipped: skipped}:
		case <-ctx.Done():
		case <-m.done:
		}
	}()
}

// measureDone writes the round to the memory and to the history: a path that answered is a success with its round trip, one
// that did not is a failure (unless the connection's own probes fail now: see maybeMeasure), one that was skipped nothing.
func (m *Manager) measureDone(state *actorState, r measureResult) {
	if r.live != state.liveID || state.status.State != "connected" {
		return
	}
	state.measuring = false
	now, count := m.auto.now(), 0
	state.measured = auto.TrimProbes(state.measured, now)
	for _, id := range r.ids {
		rtt, answered := r.rtts[id]
		probe := auto.Probe{At: now, Net: r.net, Path: id, RTT: rtt}
		switch {
		case slices.Contains(r.skipped, id):
			probe.Skipped = true
		case answered:
			m.auto.Paths.Success(r.net, id, int(rtt.Milliseconds()), now)
		case state.probeFailures < 2:
			m.auto.Paths.Failure(r.net, id, now)
		default:
			continue
		}
		state.measured = append(state.measured, probe)
		if !probe.Skipped {
			count++
		}
	}
	if count != 0 {
		slog.Info("auto: probed count=" + strconv.Itoa(count))
	}
}
