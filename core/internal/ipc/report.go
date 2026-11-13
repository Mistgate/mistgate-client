package ipc

// Block reports: report.set is the person's switch, report.preview shows the exact body that would go out, report.send
// sends it now. The automatic send after a finished check is in the service (probereport.Reporter.Auto).

import (
	"context"

	"github.com/mistgate/mistgate-client/core/internal/diag"
)

func (s *Server) handleReport(ctx context.Context, request Request) (any, *RPCError) {
	if s.Subs == nil || s.Report == nil {
		return nil, &RPCError{Code: "service_error", Message: "subscription store is unavailable"}
	}
	var params struct {
		Sub string `json:"sub"`
		On  *bool  `json:"on"`
	}
	if !decodeParams(request.Params, &params) || params.Sub == "" || request.Method == "report.set" != (params.On != nil) {
		return nil, badParams()
	}
	switch request.Method {
	case "report.set":
		sub, err := s.Subs.SetReport(params.Sub, *params.On)
		if err != nil {
			return nil, subscriptionRPCError(err)
		}
		return sub, nil
	case "report.preview":
		body, err := s.Report.Preview(s.lastCheck(), params.Sub)
		if err != nil {
			return nil, subscriptionRPCError(err)
		}
		return map[string]any{"body": body, "servers": len(body.Servers)}, nil
	default: // report.send
		out, err := s.Report.Send(ctx, s.lastCheck(), params.Sub)
		if err != nil {
			return nil, subscriptionRPCError(err)
		}
		if out.Code != "" {
			return map[string]any{"ok": false, "code": out.Code, "retry_s": out.RetryS}, nil
		}
		return map[string]any{"ok": true, "accepted": out.Accepted}, nil
	}
}

// lastCheck is the last finished network check; the report code matches it to the subscription.
// ponytail: the runner keeps one result, so a check of another subscription replaces it.
func (s *Server) lastCheck() *diag.Result {
	if s.Diag == nil {
		return nil
	}
	return s.Diag.Get().Result
}
