package subs

// Debug logs (docs/client-api.md, "debug"): what the panel's sync says about them, and the two calls that answer.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Debug is what the panel offers: whether it takes debug logs, whether the person may send on their own, and support's
// open request, if any.
type Debug struct {
	Intake  bool          `json:"intake"`
	Unasked bool          `json:"unasked"`
	Request *DebugRequest `json:"request,omitempty"`
}

type DebugRequest struct {
	ID          string `json:"id"`
	Level       string `json:"level"` // info or debug
	Note        string `json:"note"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// DebugOutcome is the end of one debug call. Code is empty on success; otherwise the panel's code, "offline" when the
// panel could not be reached, or "decoy" when it answered like a normal page.
type DebugOutcome struct {
	Code   string
	RetryS int    // Retry-After, seconds
	ID     string // the panel's request id (success)
	Lines  int    // lines the panel kept (send, success)
}

var debugRequestID = regexp.MustCompile(`^dbr_[A-Za-z0-9_-]{1,64}$`)

// panelDebug keeps the debug part of a sync answer; a request the client cannot use is dropped.
func panelDebug(in *struct {
	Intake  bool `json:"intake"`
	Unasked bool `json:"unasked"`
	Request *struct {
		ID          string `json:"id"`
		Level       string `json:"level"`
		Note        string `json:"note"`
		ExpiresUnix int64  `json:"expires_unix"`
	} `json:"request"`
}) *Debug {
	if in == nil {
		return nil
	}
	out := &Debug{Intake: in.Intake}
	if !in.Intake {
		return out
	}
	out.Unasked = in.Unasked
	if r := in.Request; r != nil && debugRequestID.MatchString(r.ID) && (r.Level == "info" || r.Level == "debug") && r.ExpiresUnix > 0 {
		out.Request = &DebugRequest{ID: r.ID, Level: r.Level, Note: shortTextN(r.Note, 300), ExpiresUnix: r.ExpiresUnix}
	}
	return out
}

// SendDebug posts a gzipped NDJSON bundle; request is the id of the request it answers ("" for the person's own send).
func (s *Store) SendDebug(ctx context.Context, sub, request string, gz []byte) DebugOutcome {
	headers := []string{"Content-Type", "application/x-ndjson", "Content-Encoding", "gzip"}
	if request != "" {
		headers = append(headers, "X-Mistgate-Debug-Request", request)
	}
	return s.debugCall(ctx, sub, "debug", gz, headers, func(body []byte) (string, int, bool) {
		var answer struct {
			ID    string `json:"id"`
			Lines int    `json:"lines"`
		}
		return answer.ID, answer.Lines, json.Unmarshal(body, &answer) == nil && debugRequestID.MatchString(answer.ID)
	})
}

// DeclineDebug tells the panel the person does not want to answer a request.
func (s *Store) DeclineDebug(ctx context.Context, sub, request string) DebugOutcome {
	return s.debugCall(ctx, sub, "debug/decline", nil, []string{"X-Mistgate-Debug-Request", request}, func(body []byte) (string, int, bool) {
		var answer struct {
			ID       string `json:"id"`
			Declined bool   `json:"declined"`
		}
		return answer.ID, 0, json.Unmarshal(body, &answer) == nil && answer.Declined && debugRequestID.MatchString(answer.ID)
	})
}

func (s *Store) debugCall(ctx context.Context, sub, path string, body []byte, headers []string, parse func([]byte) (string, int, bool)) DebugOutcome {
	var base, key string
	s.mu.RLock()
	for _, item := range s.state.Subscriptions {
		if item.ID == sub {
			base, key = item.Base, item.Key
		}
	}
	s.mu.RUnlock()
	target, err := url.JoinPath(base, path)
	if key == "" || err != nil {
		return DebugOutcome{Code: "no_device"}
	}
	r, err := s.call(ctx, http.MethodPost, target, key, body, 60*time.Second, "", headers...)
	if err != nil {
		return DebugOutcome{Code: "offline"}
	}
	if r.status == http.StatusOK {
		if id, lines, ok := parse(r.body); ok {
			s.answered(sub)
			return DebugOutcome{ID: id, Lines: lines}
		}
		return DebugOutcome{Code: "decoy"}
	}
	out := DebugOutcome{Code: replyCode(r.body)}
	if n, err := strconv.Atoi(r.header.Get("Retry-After")); err == nil && n > 0 && (r.status == 429 || r.status == 503) {
		out.RetryS = min(n, maxRetryAfter)
	}
	if out.Code == "" { // a page that is not the panel's JSON
		out.Code = "decoy"
		if r.status == 429 || r.status == 503 { // a rate limit or a busy panel may come without a body
			out.Code = "retry"
		}
	}
	return out
}

// answered drops the open request at once and syncs in the background, so that the panel's view replaces ours.
func (s *Store) answered(id string) {
	s.mu.Lock()
	candidate := cloneState(s.state)
	for i := range candidate.Subscriptions {
		if sub := &candidate.Subscriptions[i]; sub.ID == id && sub.Debug != nil {
			sub.Debug.Request, sub.ETag = nil, "" // "not changed" would keep an open request
		}
	}
	if s.save(candidate) == nil {
		s.state = candidate
	}
	s.mu.Unlock()
	s.changed()
	go func() { _, _ = s.Refresh(context.Background(), id) }()
}
