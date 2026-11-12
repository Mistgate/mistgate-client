package ipc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/debugsend"
	"github.com/mistgate/mistgate-client/core/internal/engine"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

// debugPanel is a Mistgate panel with one open debug request.
type debugPanel struct {
	mu      sync.Mutex
	syncs   int
	status  int // answer for the debug calls; 0 = 200
	retry   string
	calls   []*http.Request
	bodies  [][]byte
	request string
}

func (p *debugPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/client/enrol"):
		_, _ = fmt.Fprintf(w, `{"base":"https://%s/client"}`, r.Host)
	case strings.HasSuffix(r.URL.Path, "/client/sync"):
		p.syncs++
		_, _ = fmt.Fprintf(w, `{"v":1,"status":"active","sync_every_s":3600,"servers":[],"debug":{"intake":true,"unasked":true,"request":{"id":"dbr_abc","level":"info","note":"please send","expires_unix":%d}}}`, time.Now().Add(time.Hour).Unix())
	case strings.Contains(r.URL.Path, "/client/debug"):
		body, _ := io.ReadAll(r.Body)
		p.calls, p.bodies = append(p.calls, r), append(p.bodies, body)
		if p.status != 0 {
			w.Header().Set("Retry-After", p.retry)
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(`{"error":"too_many_requests"}`))
		} else if strings.HasSuffix(r.URL.Path, "/decline") {
			_, _ = w.Write([]byte(`{"id":"dbr_abc","declined":true}`))
		} else {
			_, _ = w.Write([]byte(`{"id":"dbr_abc","lines":3,"dropped_kv":0}`))
		}
	default: // the plain subscription
		w.Header().Set("Mistgate-Client-Api", "1")
		_, _ = w.Write([]byte("hy2://a@plain.example:443#Plain"))
	}
}

func (p *debugPanel) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *debugPanel) count() (syncs int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.syncs
}

// debugServer is a server over a store with a managed subscription (open debug request) and an AmneziaWG one.
func debugServer(t *testing.T) (*Server, *debugPanel, string, string, func(method, params string) (map[string]any, *RPCError)) {
	t.Helper()
	panel := &debugPanel{}
	tls := httptest.NewTLSServer(panel)
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
	managed, err := store.Add(context.Background(), tls.URL+"/sub/tok")
	if err != nil || managed.Debug == nil || managed.Debug.Request == nil {
		t.Fatalf("managed add = %#v, %v", managed, err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	plain, err := store.Add(context.Background(), "[Interface]\nAddress = 10.66.4.3/32\nPrivateKey = "+key+"\n[Peer]\nPublicKey = "+key+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820")
	if err != nil || plain.Debug != nil {
		t.Fatalf("plain add = %#v, %v", plain, err)
	}
	manager := session.NewManager(engine.NewFake(engine.FakeConfig{}), settingsStore.Get)
	t.Cleanup(manager.Close)
	logs := NewLogStore()
	logs.add(LogEntry{TUnixMS: time.Now().UnixMilli(), Level: "info", Msg: "tunnel to 198.51.100.7 is up", Src: "engine"})
	server := &Server{Manager: manager, Subs: store, Settings: settingsStore, Logs: logs}
	return server, panel, managed.ID, plain.ID, func(method, params string) (map[string]any, *RPCError) {
		t.Helper()
		request, err := ParseRequest([]byte(fmt.Sprintf(`{"id":1,"method":%q,"params":%s}`, method, params)))
		if err != nil {
			t.Fatal(err)
		}
		result, _, rpcErr := server.dispatch(context.Background(), request, true)
		if rpcErr != nil {
			return nil, rpcErr
		}
		out, _ := result.(map[string]any)
		return out, nil
	}
}

func (p *debugPanel) waitSync(t *testing.T, after int) {
	t.Helper()
	for i := 0; p.count() <= after && i < 300; i++ { // the sync that follows an answer
		time.Sleep(10 * time.Millisecond)
	}
	if p.count() <= after {
		t.Fatal("no sync after the answer")
	}
}

func TestDebugPreviewAndSend(t *testing.T) {
	_, panel, sub, plain, call := debugServer(t)
	preview := fmt.Sprintf(`{"sub":%q,"parts":["system","log"],"note":"it drops","request":"dbr_abc"}`, sub)
	for params, code := range map[string]string{
		`{"sub":"nope","parts":["system"]}`:                              "not_found",
		`{"sub":"` + plain + `","parts":["system"]}`:                     "debug_off",
		`{"sub":"` + sub + `","parts":["system"],"request":"dbr_other"}`: "no_request",
		`{"sub":"` + sub + `","parts":[]}`:                               "bad_params",
		`{"sub":"` + sub + `","parts":["secrets"]}`:                      "bad_params",
	} {
		if _, rpcErr := call("debug.preview", params); rpcErr == nil || rpcErr.Code != code {
			t.Fatalf("preview %s = %v, want %s", params, rpcErr, code)
		}
	}

	result, rpcErr := call("debug.preview", preview)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	lines := result["lines"].([]debugsend.Line)
	var texts []string
	for _, l := range lines {
		texts = append(texts, l.Msg)
	}
	if result["count"] != 3 || len(lines) != 3 || !strings.Contains(strings.Join(texts, "|"), "tunnel to [removed] is up") || lines[2].Src != "note" && lines[1].Src != "note" {
		t.Fatalf("preview = %#v", texts)
	}
	id := result["id"].(string)

	before := panel.count()
	sent, rpcErr := call("debug.send", `{"id":"`+id+`"}`)
	if rpcErr != nil || sent["ok"] != true || sent["id"] != "dbr_abc" || sent["lines"] != 3 {
		t.Fatalf("send = %#v, %v", sent, rpcErr)
	}
	panel.waitSync(t, before)
	panel.mu.Lock()
	body, header := panel.bodies[0], panel.calls[0].Header
	panel.mu.Unlock()
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(reader)
	if len(body) != result["bytes"] || bytes.Count(raw, []byte("\n")) != 3 || header.Get("X-Mistgate-Debug-Request") != "dbr_abc" || header.Get("Content-Encoding") != "gzip" || header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("panel got %d bytes, %d lines, %v", len(body), bytes.Count(raw, []byte("\n")), header)
	}
	// sent once: the snapshot is gone
	if again, _ := call("debug.send", `{"id":"`+id+`"}`); again["ok"] != false || again["code"] != "expired" {
		t.Fatalf("second send = %#v", again)
	}
}

func TestDebugSendRefusedKeepsSnapshotAndExpires(t *testing.T) {
	server, panel, sub, _, call := debugServer(t)
	result, rpcErr := call("debug.preview", fmt.Sprintf(`{"sub":%q,"parts":["system"]}`, sub)) // the person's own send
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	id := result["id"].(string)
	panel.mu.Lock()
	panel.status, panel.retry = 429, "600"
	panel.mu.Unlock()
	if sent, _ := call("debug.send", `{"id":"`+id+`"}`); sent["ok"] != false || sent["code"] != "too_many_requests" || sent["retry_s"] != 600 {
		t.Fatalf("429 = %#v", sent)
	}
	panel.mu.Lock()
	panel.status = 0
	named := panel.calls[0].Header.Get("X-Mistgate-Debug-Request")
	panel.mu.Unlock()
	if named != "" {
		t.Fatalf("own send names a request: %q", named)
	}
	server.debugMu.Lock()
	server.debugSnap.expires = time.Now().Add(-time.Second)
	server.debugMu.Unlock()
	if sent, _ := call("debug.send", `{"id":"`+id+`"}`); sent["ok"] != false || sent["code"] != "expired" {
		t.Fatalf("expired send = %#v", sent)
	}
}

func TestDebugDeclineAndLogClear(t *testing.T) {
	server, panel, sub, _, call := debugServer(t)
	if out, _ := call("debug.decline", fmt.Sprintf(`{"sub":%q,"request":"dbr_other"}`, sub)); out["ok"] != false || out["code"] != "no_request" || panel.callCount() != 0 {
		t.Fatalf("decline of another request = %#v", out)
	}
	before := panel.count()
	if out, rpcErr := call("debug.decline", fmt.Sprintf(`{"sub":%q,"request":"dbr_abc"}`, sub)); rpcErr != nil || out["ok"] != true {
		t.Fatalf("decline = %#v, %v", out, rpcErr)
	}
	panel.waitSync(t, before)
	panel.mu.Lock()
	path := panel.calls[0].URL.Path
	panel.mu.Unlock()
	if !strings.HasSuffix(path, "/client/debug/decline") {
		t.Fatalf("path = %s", path)
	}

	if len(server.Logs.Entries()) == 0 {
		t.Fatal("no log entries to clear")
	}
	if out, rpcErr := call("log.clear", `{}`); rpcErr != nil || len(out) != 0 || len(server.Logs.Entries()) != 0 {
		t.Fatalf("log.clear = %#v, %v", out, rpcErr)
	}
	if got, _ := call("log.get", `{}`); len(got["entries"].([]LogEntry)) != 0 {
		t.Fatalf("log.get after clear = %#v", got)
	}
}
