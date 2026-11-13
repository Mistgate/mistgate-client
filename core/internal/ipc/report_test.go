package ipc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/probereport"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

func TestReportCalls(t *testing.T) {
	var intake atomic.Bool
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/client/enrol"):
			_, _ = fmt.Fprintf(w, `{"base":"https://%s/client"}`, r.Host)
		case strings.HasSuffix(r.URL.Path, "/client/sync"):
			_, _ = fmt.Fprintf(w, `{"v":1,"status":"active","sync_every_s":3600,"servers":[],"probe":{"intake":%t,"v":1}}`, intake.Load())
		default:
			w.Header().Set("Mistgate-Client-Api", "1")
			_, _ = w.Write([]byte("hy2://a@plain.example:443#Plain"))
		}
	}))
	t.Cleanup(tls.Close)
	old := http.DefaultTransport // the store's client uses it
	http.DefaultTransport = tls.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	dataDir := t.TempDir()
	store, err := subs.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	settingsStore, err := settings.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sub, err := store.Add(ctx, tls.URL+"/sub/tok")
	if err != nil || sub.Probe == nil || sub.Probe.Intake {
		t.Fatalf("add = %#v, %v", sub, err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	t.Cleanup(manager.Close)
	server := &Server{Manager: manager, Subs: store, Settings: settingsStore, Report: &probereport.Reporter{Subs: store}}
	call := func(method, params string) (any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(ctx, request, true)
		return result, rpcErr
	}
	code := func(rpcErr *RPCError) string {
		if rpcErr == nil {
			return ""
		}
		return rpcErr.Code
	}
	quoted := fmt.Sprintf("%q", sub.ID)

	// the owner takes no reports: the switch stays off
	if _, e := call("report.set", `{"sub":`+quoted+`,"on":true}`); code(e) != "probe_off" {
		t.Fatalf("set while off: %v", e)
	}
	intake.Store(true)
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	result, e := call("report.set", `{"sub":`+quoted+`,"on":true}`)
	if got, ok := result.(subs.Subscription); e != nil || !ok || !got.Report || got.Probe == nil || !got.Probe.Intake {
		t.Fatalf("set = %#v, %v", result, e)
	}
	if _, e = call("report.set", `{"sub":`+quoted+`,"on":false}`); e != nil || store.List()[0].Report {
		t.Fatalf("off: %v", e)
	}
	if _, e = call("report.set", `{"sub":"nope","on":true}`); code(e) != "unknown_subscription" {
		t.Fatalf("unknown: %v", e)
	}
	// no check has run: nothing to show and nothing to send
	for _, method := range []string{"report.preview", "report.send"} {
		if _, e = call(method, `{"sub":`+quoted+`}`); code(e) != "no_check" {
			t.Fatalf("%s without a check: %v", method, e)
		}
	}
	// the parameters are exact
	for method, params := range map[string]string{
		"report.set": `{"sub":` + quoted + `}`, "report.preview": `{"sub":` + quoted + `,"on":true}`, "report.send": `{"on":true}`,
	} {
		if _, e = call(method, params); code(e) != "bad_params" {
			t.Fatalf("%s %s: %v", method, params, e)
		}
	}
	if _, e = call("report.set", `{"sub":`+quoted+`,"on":true,"extra":1}`); code(e) != "bad_params" {
		t.Fatalf("extra field: %v", e)
	}
}
