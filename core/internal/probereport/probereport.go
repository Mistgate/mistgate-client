// Package probereport turns the last finished network check into the panel's block report, "probe v1"
// (docs/client-api.md), and sends it. Only fields the check really measured go in; the rest is left out.
package probereport

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

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
// the client has no flaky, tcp_*, dl_* or dns data per server, and does not know the operator, country or region.
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
	Type    string  `json:"type"`
	Host    string  `json:"host"`
	Port    uint16  `json:"port"`
	Verdict string  `json:"verdict"`
	DelayMS *uint32 `json:"delay_ms,omitempty"`
}

// verdict is the panel's word for what the check found, or "" when the check's word has no honest match (the server is
// then left out: less is better than untrue).
//
//	ok                           -> ok
//	blocked / udp_no_answer      -> handshake_failed (the host answers, the Hysteria2 or AmneziaWG handshake does not)
//	down / no_answer             -> no_answer (nothing answers, neither the handshake nor TCP)
//	blocked / no_answer (VLESS)  -> left out: the check cannot tell a cut TCP connect from a failed handshake
//	down / not_found, config, app -> left out: our name lookup, our settings or our engine, not the network
//
// freeze and tcp_blocked are never sent: the client's freeze check is not per server, and it has no TCP-only probe.
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
		if !ok || v == "" || s.ID == res.Live || p.Via == "relay" {
			continue
		}
		host, port, err := diag.Endpoint(p)
		if err != nil {
			continue
		}
		if len(body.Servers) == maxServers { // ponytail: the first 256 paths; the panel takes no more
			break
		}
		out := Server{Type: p.Protocol, Host: strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")), Port: port, Verdict: v}
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

// Reporter builds and sends reports. It keeps nothing: the limits and the last outcome live in the store.
type Reporter struct {
	Subs *subs.Store
	Log  *slog.Logger // may be nil; gets a fact and a code, never a link, a host, an ASN or the body
}

// Preview is the report that would go out for a subscription, from the check res.
func (r *Reporter) Preview(res *diag.Result, sub string) (Body, error) {
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

func (r *Reporter) logFailed(code string) {
	if r.Log != nil {
		r.Log.Warn("block report failed: " + code)
	}
}
