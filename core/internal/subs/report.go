package subs

// Block reports (docs/client-api.md, "probe: v1"): what the panel's sync says about them, the person's switch, and the
// one call that sends a report. The body is built elsewhere (probereport); this file only carries it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// reportEvery is the least time between two reports of one subscription: the panel allows two at once and then one in
// 10 minutes, and the client keeps to the slower rule.
const reportEvery = 10 * time.Minute

// Probe is what the panel's sync says of reports: whether its owner takes them, and the newest version it reads.
type Probe struct {
	Intake bool `json:"intake"`
	V      int  `json:"v"`
}

// ReportLast is the end of the latest send of a subscription. It is kept in memory only. Error is empty on success.
type ReportLast struct {
	AtUnix   int64  `json:"at_unix"`
	Accepted int    `json:"accepted"`
	Error    string `json:"error"`
}

// ReportOutcome is the end of one send. Code is empty on success; otherwise the panel's code, or one of ours: "offline",
// "fetch_failed", "decoy" (the panel answered like a normal page), "retry", "too_soon", "probe_off", "no_link".
type ReportOutcome struct {
	Code     string
	RetryS   int // seconds until the next send may start
	Accepted int // servers the panel kept (success)
}

type reportState struct {
	last *ReportLast
	next time.Time // no send before this
}

// Usable says whether reports can go to this subscription now: the panel takes them and reads version 1.
func (p *Probe) Usable() bool { return p != nil && p.Intake && p.V >= 1 }

// panelProbe keeps the probe part of a sync answer; nil when the panel did not say.
func panelProbe(in *struct {
	Intake bool `json:"intake"`
	V      int  `json:"v"`
}) *Probe {
	if in == nil {
		return nil
	}
	return &Probe{Intake: in.Intake, V: min(max(in.V, 0), 1000)}
}

// panelASN reads the top-level asn of a sync answer; 0 when it is absent or not a plain number.
func panelASN(raw json.RawMessage) uint32 {
	n, err := strconv.ParseUint(string(raw), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func (s *Store) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// withLast is a subscription as the window sees it: with the end of its latest send, if there was one.
func (s *Store) withLast(sub Subscription) Subscription {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	if st := s.reports[sub.ID]; st != nil && st.last != nil {
		last := *st.last
		sub.ReportLast = &last
	}
	return sub
}

func (s *Store) forgetReport(id string) {
	s.reportMu.Lock()
	delete(s.reports, id)
	s.reportMu.Unlock()
}

// SetReport switches the person's block reports of a subscription. On needs a panel that takes reports.
func (s *Store) SetReport(id string, on bool) (Subscription, error) {
	s.mu.Lock()
	candidate := cloneState(s.state)
	var found *storedSubscription
	for i := range candidate.Subscriptions {
		if candidate.Subscriptions[i].ID == id {
			found = &candidate.Subscriptions[i]
		}
	}
	if found == nil {
		s.mu.Unlock()
		return Subscription{}, &Error{Code: "unknown_subscription"}
	}
	if on && !found.Probe.Usable() {
		s.mu.Unlock()
		return Subscription{}, &Error{Code: "probe_off"}
	}
	if found.Report != on {
		found.Report = on
		if err := s.save(candidate); err != nil {
			s.mu.Unlock()
			return Subscription{}, err
		}
		s.state = candidate
	}
	result := publicCopy(found.Subscription)
	s.mu.Unlock()
	s.changed()
	return s.withLast(result), nil
}

// ReportState is what a report needs of a subscription: the subscription itself and the ASN the panel gave this device.
func (s *Store) ReportState(id string) (Subscription, uint32, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.state.Subscriptions {
		if sub.ID == id {
			return publicCopy(sub.Subscription), sub.ASN, true
		}
	}
	return Subscription{}, 0, false
}

var reportCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// SendReport posts a built report to the panel that issued the subscription: POST <link>/probe, with the token in the
// link as the only authorisation. The link, the body and the answer never reach the log. At most one send in
// reportEvery per subscription, and none before a Retry-After has passed.
func (s *Store) SendReport(ctx context.Context, id string, body []byte) ReportOutcome {
	var link string
	var usable bool
	s.mu.RLock()
	for _, sub := range s.state.Subscriptions {
		if sub.ID == id {
			link, usable = sub.URL, sub.Probe.Usable()
		}
	}
	s.mu.RUnlock()
	if !usable {
		return ReportOutcome{Code: "probe_off"}
	}
	target, err := url.JoinPath(link, "probe")
	if link == "" || err != nil {
		return ReportOutcome{Code: "no_link"}
	}
	// The slot is taken before the request, so that two sends at once cannot both go out.
	now := s.now()
	s.reportMu.Lock()
	if s.reports == nil {
		s.reports = map[string]*reportState{}
	}
	st := s.reports[id]
	if st == nil {
		st = &reportState{}
		s.reports[id] = st
	}
	if now.Before(st.next) {
		wait := int((st.next.Sub(now) + time.Second - 1) / time.Second)
		s.reportMu.Unlock()
		return ReportOutcome{Code: "too_soon", RetryS: wait}
	}
	before := st.next
	st.next = now.Add(reportEvery)
	s.reportMu.Unlock()

	out, hold := s.postReport(ctx, target, body)
	s.reportMu.Lock()
	if out.Code == "offline" || out.Code == "fetch_failed" { // nothing reached the panel: no reason to wait
		st.next = before
	} else if hold > reportEvery {
		st.next = now.Add(hold)
	}
	st.last = &ReportLast{AtUnix: s.now().Unix(), Accepted: out.Accepted, Error: out.Code}
	out.RetryS = max(int((st.next.Sub(now)+time.Second-1)/time.Second), 0)
	s.reportMu.Unlock()
	if out.Code == "probe_off" { // the owner switched it off; the person's wish stays, and the next sync says the rest
		s.panelSaidOff(id)
	}
	s.changed()
	return out
}

// postReport makes the request. hold is the least time before the next one, when the panel asked for a wait.
func (s *Store) postReport(ctx context.Context, target string, body []byte) (ReportOutcome, time.Duration) {
	r, err := s.call(ctx, http.MethodPost, target, "", body, 15*time.Second, "", "Probe-Report", "1")
	if err != nil {
		return ReportOutcome{Code: fetchErrorCode(err)}, 0
	}
	if r.status == http.StatusOK {
		var answer struct {
			Accepted *int `json:"accepted"`
		}
		if json.Unmarshal(r.body, &answer) != nil || answer.Accepted == nil || *answer.Accepted < 0 {
			return ReportOutcome{Code: "decoy"}, 0
		}
		return ReportOutcome{Accepted: *answer.Accepted}, 0
	}
	out := ReportOutcome{Code: replyCode(r.body)}
	var hold time.Duration
	if n, err := strconv.Atoi(r.header.Get("Retry-After")); err == nil && n > 0 && (r.status == 429 || r.status == 503) {
		out.RetryS = min(n, maxRetryAfter)
		hold = time.Duration(out.RetryS) * time.Second
	}
	switch {
	case out.Code == "" && (r.status == 429 || r.status == 503): // a rate limit may come without a body
		out.Code = "retry"
	case !reportCode.MatchString(out.Code): // a page that is not the panel's JSON, or a code that is not a word
		out.Code = "decoy"
	}
	return out, hold
}

// panelSaidOff takes the panel's refusal as the news it is: the switch cannot be turned on until a sync says otherwise.
func (s *Store) panelSaidOff(id string) {
	s.mu.Lock()
	candidate := cloneState(s.state)
	for i := range candidate.Subscriptions {
		if sub := &candidate.Subscriptions[i]; sub.ID == id && sub.Probe != nil && sub.Probe.Intake {
			sub.Probe.Intake, sub.ETag = false, "" // "not changed" would keep the old answer
			if s.save(candidate) == nil {
				s.state = candidate
			}
		}
	}
	s.mu.Unlock()
}
