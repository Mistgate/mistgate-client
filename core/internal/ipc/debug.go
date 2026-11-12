package ipc

// Debug logs: debug.preview builds the bundle and keeps the latest one in memory; debug.send sends exactly that one.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/debugsend"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

const snapshotTTL = 10 * time.Minute

// debugSnapshot is what the person saw in the preview and what goes out when they press send.
type debugSnapshot struct {
	id, sub, request string
	gz               []byte
	lines            int
	expires          time.Time
}

func (s *Server) handleDebug(ctx context.Context, request Request) (any, *RPCError) {
	if s.Subs == nil {
		return nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
	}
	switch request.Method {
	case "debug.preview":
		var params struct {
			Sub     string   `json:"sub"`
			Parts   []string `json:"parts"`
			Note    string   `json:"note"`
			Request string   `json:"request"`
		}
		if !decodeParams(request.Params, &params) || params.Sub == "" {
			return nil, badParams()
		}
		sub, rpcError := s.debugSub(params.Sub, params.Request)
		if rpcError != nil {
			return nil, rpcError
		}
		return s.debugPreview(ctx, sub, params.Parts, params.Note, params.Request)
	case "debug.send":
		var params struct {
			ID string `json:"id"`
		}
		if !decodeParams(request.Params, &params) || params.ID == "" {
			return nil, badParams()
		}
		// taken, not read: two calls with one id must not both send it
		s.debugMu.Lock()
		snap := s.debugSnap
		if snap == nil || snap.id != params.ID || time.Now().After(snap.expires) {
			s.debugMu.Unlock()
			return map[string]any{"ok": false, "code": "expired", "retry_s": 0}, nil
		}
		s.debugSnap = nil
		s.debugMu.Unlock()
		out := s.Subs.SendDebug(ctx, snap.sub, snap.request, snap.gz)
		if out.Code != "" {
			s.debugMu.Lock()
			if s.debugSnap == nil { // back for another try, unless a newer preview took its place
				s.debugSnap = snap
			}
			s.debugMu.Unlock()
			return map[string]any{"ok": false, "code": out.Code, "retry_s": out.RetryS}, nil
		}
		return map[string]any{"ok": true, "id": out.ID, "lines": out.Lines}, nil
	default: // debug.decline
		var params struct {
			Sub     string `json:"sub"`
			Request string `json:"request"`
		}
		if !decodeParams(request.Params, &params) || params.Sub == "" || params.Request == "" {
			return nil, badParams()
		}
		if _, rpcError := s.debugSub(params.Sub, params.Request); rpcError != nil {
			if rpcError.Code == "no_request" { // the panel would say the same
				return map[string]any{"ok": false, "code": "no_request", "retry_s": 0}, nil
			}
			return nil, rpcError
		}
		out := s.Subs.DeclineDebug(ctx, params.Sub, params.Request)
		if out.Code != "" {
			return map[string]any{"ok": false, "code": out.Code, "retry_s": out.RetryS}, nil
		}
		return map[string]any{"ok": true}, nil
	}
}

// debugSub finds the subscription; a request id, when given, must be its open request (so it is also a safe header value).
func (s *Server) debugSub(id, request string) (subs.Subscription, *RPCError) {
	for _, sub := range s.Subs.List() {
		if sub.ID != id {
			continue
		}
		switch {
		case sub.Debug == nil || !sub.Debug.Intake:
			return sub, &RPCError{Code: "debug_off", Message: "this subscription does not take debug logs"}
		case request != "" && (sub.Debug.Request == nil || sub.Debug.Request.ID != request):
			return sub, &RPCError{Code: "no_request", Message: "no such open request"}
		}
		return sub, nil
	}
	return subs.Subscription{}, &RPCError{Code: "not_found", Message: "unknown subscription"}
}

func (s *Server) debugPreview(ctx context.Context, sub subs.Subscription, parts []string, note, request string) (any, *RPCError) {
	in := debugsend.Input{Parts: parts, Note: note, Version: ServiceVersion, Vias: map[string]string{}}
	if status, err := s.Manager.Status(ctx); err == nil {
		in.State, in.Protocol = status.State, status.Protocol
	}
	if s.Settings != nil {
		in.Mode = s.Settings.Get().RouteMode
	}
	if s.Diag != nil {
		// only this subscription's check: another one's servers are not this admin's to see
		if r := s.Diag.Get().Result; r != nil && r.Sub == sub.ID {
			in.Checks = r
		}
	}
	for _, server := range sub.Servers {
		in.Vias[server.ID] = server.Via
	}
	if s.Logs != nil {
		for _, e := range s.Logs.Entries() {
			in.Logs = append(in.Logs, debugsend.Entry{TMS: e.TUnixMS, Level: e.Level, Src: e.Src, Msg: e.Msg})
		}
	}
	bundle, err := debugsend.Build(in)
	if errors.Is(err, debugsend.ErrTooLarge) {
		return nil, &RPCError{Code: "too_large", Message: "the bundle is too large"}
	}
	if err != nil {
		return nil, badParams() // a part this build does not know
	}
	if len(bundle.Lines) == 0 {
		return nil, badParams()
	}
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	snap := &debugSnapshot{id: hex.EncodeToString(raw), sub: sub.ID, request: request, gz: bundle.GZ, lines: len(bundle.Lines), expires: time.Now().Add(snapshotTTL)}
	s.debugMu.Lock()
	s.debugSnap = snap
	s.debugMu.Unlock()
	return map[string]any{"id": snap.id, "count": snap.lines, "bytes": len(snap.gz), "lines": bundle.Lines}, nil
}
