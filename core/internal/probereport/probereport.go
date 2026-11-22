// Package probereport turns the last finished network check, and what Auto learned in a network, into the panel's block
// report, "probe v1" (docs/client-api.md), and sends it. Only fields the client really measured go in; the rest is left out.
package probereport

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

const (
	version    = 1
	maxServers = 256            // the panel's limit
	maxAge     = 24 * time.Hour // an older check says nothing about now, and the panel stamps a report with its arrival
)

// Body is the report exactly as the panel reads it. Its parser refuses unknown fields, so this struct is the whole list:
// the client has no flaky, tcp_*, dl_bytes or dns data per server (dl_stalled only from what Auto learned), and does not
// know the operator, country or region.
type Body struct {
	V             int      `json:"v"`
	VPN           bool     `json:"vpn"`
	DirectChecked bool     `json:"direct_checked"`
	Network       Network  `json:"network"`
	Servers       []Server `json:"servers"`
}

type Network struct {
	ASN  uint32 `json:"asn,omitempty"`
	Type string `json:"type,omitempty"`
}

type Server struct {
	Type      string  `json:"type"`
	Host      string  `json:"host"`
	Port      uint16  `json:"port"`
	Verdict   string  `json:"verdict"`
	DelayMS   *uint32 `json:"delay_ms,omitempty"`
	DLStalled *bool   `json:"dl_stalled,omitempty"` // only what Auto learned: see BuildAuto
}

// verdict is the panel's word for what the check found, or "" when the check's word has no honest match (the server is
// then left out: less is better than untrue).
//
//	ok                           -> ok
//	blocked / udp_no_answer      -> handshake_failed (the host answers, the Hysteria2 or AmneziaWG handshake does not)
//	down / no_answer             -> no_answer (nothing answers, neither the handshake nor TCP)
//	blocked / no_answer (VLESS, TrustTunnel) -> left out: the check cannot tell a cut TCP connect from a failed handshake
//	down / not_found, config, app -> left out: our name lookup, our settings or our engine, not the network
//
// freeze and tcp_blocked are never sent from a network check: its freeze check is not per server, and it has no TCP-only
// probe. (What Auto learned has a per-server freeze: see BuildAuto.)
func verdict(s diag.Server) string {
	switch {
	case s.Verdict == "ok":
		return "ok"
	case s.Verdict == "blocked" && s.Reason == "udp_no_answer":
		return "handshake_failed"
	case s.Verdict == "down" && s.Reason == "no_answer":
		return "no_answer"
	}
	return ""
}

// Build makes the report of a finished check of one subscription. profiles are all the client's profiles: host and
// port come from the profile of the path, as the subscription gave them. asn is the panel's word for this device's
// network, 0 when it did not say.
func Build(res *diag.Result, profiles []profile.Profile, asn uint32) Body {
	body := Body{V: version, VPN: res.VPN, Servers: []Server{}}
	body.Network.ASN = asn
	if res.Network.Kind == "mobile" { // wifi and ethernet could be a home or an office, so they are not guessed
		body.Network.Type = "mobile"
	}
	paths := map[string]profile.Profile{}
	for _, p := range profiles {
		if p.Sub == res.Sub {
			paths[p.ID] = p
		}
	}
	for _, s := range res.Servers {
		p, ok := paths[s.ID]
		v := verdict(s)
		// The live tunnel's own AmneziaWG path was not tried outside it; a relay path dials the relay, not the node, and the
		// panel would match its address to the wrong server.
		if !ok || v == "" || s.ID == res.Live || p.Via == "relay" || p.Purpose == profile.PurposeWhitelist {
			continue
		}
		out, ok := serverOf(p, v)
		if !ok {
			continue
		}
		if len(body.Servers) == maxServers { // ponytail: the first 256 paths; the panel takes no more
			break
		}
		if v == "ok" && s.RTTMS > 0 && s.RTTMS <= 120000 { // the round trip of the handshake, outside the tunnel
			ms := uint32(s.RTTMS)
			out.DelayMS = &ms
		}
		body.Servers = append(body.Servers, out)
	}
	// Every server above was dialled from the physical adapter, not through the tunnel (diag.checkProfile).
	body.DirectChecked = len(body.Servers) > 0
	return body
}

func ptr(b bool) *bool { return &b }

// serverOf is the line of a path as the subscription gave its host and port; false when the endpoint is not readable.
func serverOf(p profile.Profile, verdict string) (Server, bool) {
	host, port, err := p.Endpoint()
	if err != nil {
		return Server{}, false
	}
	return Server{Type: p.Protocol, Host: strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")), Port: port, Verdict: verdict}, true
}

const (
	autoOKFresh    = time.Hour      // a success older than this says nothing about now
	autoOKEvery    = 24 * time.Hour // the panel counts reports, so a path's "ok" goes at most once a day
	autoFreezeFor  = 24 * time.Hour // as long as Auto itself holds a freeze mark against a path
	autoMaxRTTMS   = 120000
	autoProofFresh = 24 * time.Hour
)

// Sent is what this process has sent of one path (kept in memory, per subscription). The panel counts reports, not
// events, so one finding goes out once.
type Sent struct {
	Last  string    // the verdict of the latest line of the path
	Froze int64     // the Froze mark of the latest freeze line
	OK    int64     // the success time of the latest ok line
	OKAt  time.Time // when that ok line went
}

// BuildAuto makes the report of what Auto learned in one network: stats are its memory of the network's paths, profiles
// are all the client's profiles, sent is what was already sent for this subscription. mobile is the network's kind
// (like Build, only "mobile" is said), asn is the one the panel gave in this very network (0: none). It also returns
// the accounting of the lines it made, to be merged into sent once the panel has accepted them.
//
// Only what the client really measured goes in, one line per path:
//   - freeze + dl_stalled=true: the session's own check downloaded 128 KiB through this server, from the person's
//     network, and the connection started and then carried nothing (stat.Froze, under a day old, not followed by a
//     check that passed). Once per new Froze mark. The size of what came is not kept, so no dl_bytes; the check is
//     through the tunnel, so no delay_ms.
//   - ok + delay_ms: the handshake round trip outside the tunnel, noted by Auto at a success under an hour old that no
//     failure followed. Only when the success is newer than the one sent, and a day after the last ok line of the path.
//     dl_stalled=false is added when the data check of that path passed in this network within a day; with no check the
//     field is left out.
//
// Failures and quarantine are not sent: Auto makes no TCP probe, so it cannot say honestly whether the host answers
// (handshake_failed) or nothing does (no_answer). ponytail: send them when Auto gets a TCP probe, or the contract a
// verdict for "the path failed to carry a connection".
//
// Relay and allowlist paths are left out like in Build. direct_checked is true with any line: the handshakes left the
// physical adapter, and the data check went through the server itself from the person's network, not through someone
// else's VPN.
func BuildAuto(stats map[string]auto.Stat, profiles []profile.Profile, sub string, sent map[string]Sent, asn uint32, mobile bool, now time.Time) (Body, map[string]Sent) {
	body := Body{V: version, VPN: true, Network: Network{ASN: asn}, Servers: []Server{}}
	if mobile {
		body.Network.Type = "mobile"
	}
	marks := map[string]Sent{}
	age := func(unix int64) time.Duration { return now.Sub(time.Unix(unix, 0)) }
	for _, p := range profiles {
		s, found := stats[p.ID]
		if !found || p.Sub != sub || p.Via == "relay" || p.Purpose == profile.PurposeWhitelist {
			continue
		}
		prev, mark := sent[p.ID], sent[p.ID]
		var verdict string
		var stalled *bool
		switch {
		case s.Froze != 0 && age(s.Froze) < autoFreezeFor && s.Froze > s.Proved && s.Froze > prev.Froze:
			stalled = ptr(true)
			verdict, mark.Last, mark.Froze = "freeze", "freeze", s.Froze
		case s.OK != 0 && age(s.OK) < autoOKFresh && s.Streak == 0 && s.Bad <= s.OK && s.RTT > 0 && s.RTT <= autoMaxRTTMS &&
			s.OK > prev.OK && (prev.Last != "ok" || now.Sub(prev.OKAt) >= autoOKEvery):
			verdict, mark.Last, mark.OK, mark.OKAt = "ok", "ok", s.OK, now
			if s.Proved != 0 && age(s.Proved) < autoProofFresh && s.Proved > s.Froze {
				stalled = ptr(false) // the data went
			}
		default:
			continue
		}
		out, ok := serverOf(p, verdict)
		if !ok {
			continue
		}
		if len(body.Servers) == maxServers { // ponytail: the first 256 paths; the panel takes no more
			break
		}
		out.DLStalled = stalled
		if verdict == "ok" {
			ms := uint32(s.RTT)
			out.DelayMS = &ms
		}
		body.Servers = append(body.Servers, out)
		marks[p.ID] = mark
	}
	body.DirectChecked = len(body.Servers) > 0
	return body, marks
}

// Reporter builds and sends reports. The limits and the last outcome live in the store; the reporter itself keeps only
// what it sent of Auto's findings.
type Reporter struct {
	Subs   *subs.Store
	Log    *slog.Logger // may be nil; gets a fact and a code, never a link, a host, an ASN or the body
	Memory *auto.Memory // Auto's memory, for SendAuto; may be nil

	mu   sync.Mutex
	sent map[string]map[string]Sent // subscription -> path -> what went; ponytail: lost at a restart, so the first report after it may repeat ok lines
}

// Preview is the report that would go out for a subscription, from the check res.
func (r *Reporter) Preview(res *diag.Result, sub string) (Body, error) {
	// ponytail: the ASN is the one of the last sync outside the tunnel, which may be another network than the check's;
	// SendAuto checks the network (auto.Memory.ASNNet), this path does not. Upgrade = the same check with the key of
	// the network the check ran in.
	_, asn, ok := r.Subs.ReportState(sub)
	if !ok {
		return Body{}, &subs.Error{Code: "unknown_subscription"}
	}
	if res == nil || res.Sub != sub || res.AtUnix > 0 && time.Since(time.Unix(res.AtUnix, 0)) > maxAge {
		return Body{}, &subs.Error{Code: "no_check"}
	}
	profiles, err := r.Subs.Profiles()
	if err != nil {
		return Body{}, &subs.Error{Code: "service_error"}
	}
	return Build(res, profiles, asn), nil
}

// Send builds the report from res and posts it. An error is a refusal before anything went out; otherwise the outcome
// says how it ended.
func (r *Reporter) Send(ctx context.Context, res *diag.Result, sub string) (subs.ReportOutcome, error) {
	body, err := r.Preview(res, sub)
	if err != nil {
		r.logFailed(err.Error())
		return subs.ReportOutcome{}, err
	}
	if len(body.Servers) == 0 {
		r.logFailed("no_servers")
		return subs.ReportOutcome{Code: "no_servers"}, nil
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return subs.ReportOutcome{}, &subs.Error{Code: "service_error"}
	}
	out := r.Subs.SendReport(ctx, sub, raw)
	if out.Code != "" {
		r.logFailed(out.Code)
	} else if r.Log != nil {
		r.Log.Info("block report sent: accepted " + strconv.Itoa(out.Accepted))
	}
	return out, nil
}

// Auto sends the report of a check that has just finished, when the person has the switch on and the panel takes reports.
func (r *Reporter) Auto(ctx context.Context, res *diag.Result) {
	if res == nil {
		return
	}
	if sub, _, ok := r.Subs.ReportState(res.Sub); ok && sub.Report && sub.Probe.Usable() {
		_, _ = r.Send(ctx, res, res.Sub)
	}
}

// SendAuto sends what Auto learned in the network netKey (diag.NetworkKey; mobile says its kind), when the person has the
// switch on and the panel takes reports. Lines already sent are not sent again (see BuildAuto); what the panel did not
// accept is not noted as sent, so it goes at the next call. The panel's rate limit (429, with its Retry-After) is kept by
// the store: SendReport makes one request and no retry. The ASN goes in only when the panel gave it in this network.
func (r *Reporter) SendAuto(ctx context.Context, sub, netKey string, mobile bool, now time.Time) {
	if netKey == "" {
		return
	}
	s, asn, ok := r.Subs.ReportState(sub)
	if !ok || !s.Report || !s.Probe.Usable() {
		return
	}
	profiles, err := r.Subs.Profiles()
	if err != nil {
		return
	}
	if r.Memory.ASNNet(sub) != netKey {
		asn = 0
	}
	r.mu.Lock()
	prev := maps.Clone(r.sent[sub])
	r.mu.Unlock()
	body, marks := BuildAuto(r.Memory.Stats(netKey), profiles, sub, prev, asn, mobile, now)
	if len(body.Servers) == 0 {
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return
	}
	if out := r.Subs.SendReport(ctx, sub, raw); out.Code != "" {
		r.logFailed(out.Code)
		return
	} else if r.Log != nil {
		r.Log.Info("block report sent: accepted " + strconv.Itoa(out.Accepted))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sent == nil {
		r.sent = map[string]map[string]Sent{}
	}
	if r.sent[sub] == nil {
		r.sent[sub] = map[string]Sent{}
	}
	maps.Copy(r.sent[sub], marks)
}

func (r *Reporter) logFailed(code string) {
	if r.Log != nil {
		r.Log.Warn("block report failed: " + code)
	}
}
