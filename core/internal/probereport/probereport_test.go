package probereport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/diag"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

func hy2Path(id, host string, port uint16, via string) profile.Profile {
	return profile.Profile{ID: id, Sub: "s", Protocol: "hysteria2", Via: via, Hy2: &profile.Hy2{Host: host, Port: port}}
}

func TestBuild(t *testing.T) {
	profiles := []profile.Profile{
		hy2Path("ok", "Oslo.Example", 443, "direct"),
		hy2Path("blocked", "blocked.example", 8443, "direct"),
		{ID: "dead", Sub: "s", Protocol: "awg", AWG: &profile.AWG{EndpointHost: "2001:DB8::7", EndpointPort: 51820}},
		{ID: "vless", Sub: "s", Protocol: "vless", VLESS: &profile.VLESS{Host: "vless.example", Port: 443}},
		hy2Path("lost", "lost.example", 443, "direct"),
		hy2Path("config", "config.example", 443, "direct"),
		{ID: "live", Sub: "s", Protocol: "awg", AWG: &profile.AWG{EndpointHost: "live.example", EndpointPort: 51820}},
		hy2Path("relay", "relay.example", 443, "relay"),
		hy2Path("warp", "warp.example", 443, "warp"),
		{ID: "other", Sub: "other", Protocol: "hysteria2", Hy2: &profile.Hy2{Host: "other.example", Port: 443}},
	}
	res := &diag.Result{Sub: "s", VPN: true, Live: "live", Servers: []diag.Server{
		{ID: "ok", Protocol: "hysteria2", Verdict: "ok", RTTMS: 42},
		{ID: "blocked", Protocol: "hysteria2", Verdict: "blocked", Reason: "udp_no_answer"},
		{ID: "dead", Protocol: "awg", Verdict: "down", Reason: "no_answer"},
		{ID: "vless", Protocol: "vless", Verdict: "blocked", Reason: "no_answer"}, // cut connect or failed handshake: unknown
		{ID: "lost", Protocol: "hysteria2", Verdict: "down", Reason: "not_found"}, // our lookup failed
		{ID: "config", Protocol: "hysteria2", Verdict: "config", Reason: "auth_rejected"},
		{ID: "live", Protocol: "awg", Verdict: "ok", RTTMS: 9}, // answered from the live tunnel
		{ID: "relay", Protocol: "hysteria2", Verdict: "ok", RTTMS: 5},
		{ID: "warp", Protocol: "hysteria2", Verdict: "ok"},            // under a millisecond: no delay
		{ID: "gone", Protocol: "hysteria2", Verdict: "ok", RTTMS: 5},  // not in the profiles any more
		{ID: "other", Protocol: "hysteria2", Verdict: "ok", RTTMS: 5}, // another subscription's profile
		{ID: "app", Protocol: "hysteria2", Verdict: "app", Reason: "engine_error"},
	}}
	res.Network.Kind = "mobile"
	raw, _ := json.Marshal(Build(res, profiles, 64500))
	want := `{"v":1,"vpn":true,"direct_checked":true,"network":{"asn":64500,"type":"mobile"},"servers":[` +
		`{"type":"hysteria2","host":"oslo.example","port":443,"verdict":"ok","delay_ms":42},` +
		`{"type":"hysteria2","host":"blocked.example","port":8443,"verdict":"handshake_failed"},` +
		`{"type":"awg","host":"2001:db8::7","port":51820,"verdict":"no_answer"},` +
		`{"type":"hysteria2","host":"warp.example","port":443,"verdict":"ok"}]}`
	if string(raw) != want {
		t.Fatalf("body:\n%s\nwant:\n%s", raw, want)
	}

	// home or office networks are not guessed, an unknown ASN and an empty report say nothing
	res = &diag.Result{Sub: "s", Servers: []diag.Server{{ID: "app", Verdict: "app"}}}
	res.Network.Kind = "wifi"
	raw, _ = json.Marshal(Build(res, profiles, 0))
	if string(raw) != `{"v":1,"vpn":false,"direct_checked":false,"network":{},"servers":[]}` {
		t.Fatalf("empty body = %s", raw)
	}
}

// panelReport is the panel's own parser of a report (internal/panel/clientprobe/report.go), copied field by field.
type panelReport struct {
	V             int  `json:"v"`
	VPN           bool `json:"vpn"`
	DirectChecked bool `json:"direct_checked"`
	Network       struct {
		ASN      uint32 `json:"asn"`
		Operator string `json:"operator"`
		Country  string `json:"country"`
		Region   string `json:"region"`
		Type     string `json:"type"`
	} `json:"network"`
	Servers []struct {
		Type      string  `json:"type"`
		Host      string  `json:"host"`
		Port      uint16  `json:"port"`
		Verdict   string  `json:"verdict"`
		Flaky     bool    `json:"flaky"`
		TCPOK     *uint8  `json:"tcp_ok,omitempty"`
		TCPTries  *uint8  `json:"tcp_tries,omitempty"`
		TCPMS     *uint32 `json:"tcp_ms,omitempty"`
		DelayMS   *uint32 `json:"delay_ms,omitempty"`
		DLBytes   *uint64 `json:"dl_bytes,omitempty"`
		DLStalled *bool   `json:"dl_stalled,omitempty"`
		DNS       *string `json:"dns,omitempty"`
	} `json:"servers"`
}

func TestBodyPassesThePanelsStrictParse(t *testing.T) {
	var profiles []profile.Profile
	res := &diag.Result{Sub: "s"}
	res.Network.Kind = "mobile"
	for i := 0; i < 300; i++ { // more than the panel takes
		id := fmt.Sprintf("p%d", i)
		profiles = append(profiles, hy2Path(id, fmt.Sprintf("h%d.example", i), 443, "direct"))
		res.Servers = append(res.Servers, diag.Server{ID: id, Verdict: "ok", RTTMS: 30})
	}
	raw, err := json.Marshal(Build(res, profiles, 64500))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 128<<10 {
		t.Fatalf("body is %d bytes", len(raw))
	}
	var got panelReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("the panel would refuse it: %v", err)
	}
	if got.V != 1 || got.Network.Type != "mobile" || got.Network.ASN != 64500 || len(got.Servers) != 256 {
		t.Fatalf("parsed = %#v", got)
	}
	for _, s := range got.Servers {
		if s.Host != strings.ToLower(s.Host) || s.Port == 0 || s.Type == "" || s.Verdict != "ok" || s.DelayMS == nil || *s.DelayMS > 120000 {
			t.Fatalf("server = %#v", s)
		}
	}
}

// reportPanel plays a panel: a managed subscription whose sync carries the probe part, and the report endpoint.
type reportPanel struct {
	mu     sync.Mutex
	probes []probeCall
	status map[string]int // token -> status of its report answer; absent = 200
}

type probeCall struct {
	path   string
	header http.Header
	body   []byte
}

func (p *reportPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/client/enrol"):
		_, _ = fmt.Fprintf(w, `{"base":"https://%s%s"}`, r.Host, strings.TrimSuffix(r.URL.Path, "/enrol"))
	case strings.HasSuffix(r.URL.Path, "/client/sync"):
		_, _ = w.Write([]byte(`{"v":1,"status":"active","sync_every_s":3600,"asn":64500,"probe":{"intake":true,"v":1},"servers":[` +
			`{"id":"srv_1","city":"Oslo","country":"NO","paths":[` + hy2JSON("pth_ok", "oslo.example", "direct") + `,` + hy2JSON("pth_block", "block.example", "direct") +
			`,` + hy2JSON("pth_relay", "relay.example", "relay") + `,` + hy2JSON("pth_config", "config.example", "direct") + `]}]}`))
	case strings.HasSuffix(r.URL.Path, "/probe"):
		body, _ := io.ReadAll(r.Body)
		p.probes = append(p.probes, probeCall{r.URL.Path, r.Header.Clone(), body})
		token := strings.Split(r.URL.Path, "/")[2]
		if status := p.status[token]; status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"probe_off"}`))
			return
		}
		_, _ = w.Write([]byte(`{"accepted":2}`))
	default:
		w.Header().Set("Mistgate-Client-Api", "1")
		_, _ = w.Write([]byte("hy2://a@plain.example:443#Plain"))
	}
}

func hy2JSON(id, host, via string) string {
	return fmt.Sprintf(`{"id":%q,"protocol":"hysteria2","via":%q,"settings":{"server":%q,"port":443,"auth":"x","tls":"ca"}}`, id, via, host)
}

func (p *reportPanel) bodies() []probeCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]probeCall(nil), p.probes...)
}

func TestReporterSendsOnlyWhatThePersonAllowed(t *testing.T) {
	panel := &reportPanel{status: map[string]int{"tok403": 403}}
	server := httptest.NewTLSServer(panel)
	t.Cleanup(server.Close)
	old := http.DefaultTransport // the store's client uses it
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	store, err := subs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	reporter := &Reporter{Subs: store, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	ctx := context.Background()
	add := func(token string) subs.Subscription {
		t.Helper()
		sub, err := store.Add(ctx, server.URL+"/sub/"+token)
		if err != nil || sub.Probe == nil || !sub.Probe.Intake || len(sub.Servers) != 4 {
			t.Fatalf("add = %#v, %v", sub, err)
		}
		return sub
	}
	check := func(sub string, age time.Duration) *diag.Result {
		res := &diag.Result{Sub: sub, AtUnix: time.Now().Add(-age).Unix(), Servers: []diag.Server{
			{ID: "pth_ok", Protocol: "hysteria2", Verdict: "ok", RTTMS: 40},
			{ID: "pth_block", Protocol: "hysteria2", Verdict: "blocked", Reason: "udp_no_answer"},
			{ID: "pth_relay", Protocol: "hysteria2", Verdict: "ok", RTTMS: 40},
			{ID: "pth_config", Protocol: "hysteria2", Verdict: "config", Reason: "bad_config"},
		}}
		res.Network.Kind = "mobile"
		return res
	}
	sub := add("tok")

	// the preview is the body that goes out; no check, another subscription's check or an old one is no check
	preview, err := reporter.Preview(check(sub.ID, time.Minute), sub.ID)
	if err != nil || len(preview.Servers) != 2 || preview.Network.ASN != 64500 || preview.Network.Type != "mobile" {
		t.Fatalf("preview = %#v, %v", preview, err)
	}
	for name, res := range map[string]*diag.Result{"none": nil, "other sub": check("other", time.Minute), "old": check(sub.ID, 25*time.Hour)} {
		if _, err := reporter.Preview(res, sub.ID); err == nil || err.Error() != "no_check" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := reporter.Preview(check("nope", 0), "nope"); err == nil || err.Error() != "unknown_subscription" {
		t.Fatalf("unknown: %v", err)
	}

	// the switch is off: a finished check sends nothing
	reporter.Auto(ctx, check(sub.ID, 0))
	if len(panel.bodies()) != 0 {
		t.Fatal("sent with the switch off")
	}
	if _, err := store.SetReport(sub.ID, true); err != nil {
		t.Fatal(err)
	}
	reporter.Auto(ctx, check(sub.ID, 0))
	calls := panel.bodies()
	want, _ := json.Marshal(preview)
	if len(calls) != 1 || calls[0].path != "/sub/tok/probe" || calls[0].header.Get("Probe-Report") != "1" || !bytes.Equal(calls[0].body, want) {
		t.Fatalf("calls = %#v, want body %s", calls, want)
	}
	if last := store.List()[0].ReportLast; last == nil || last.Accepted != 2 || last.Error != "" {
		t.Fatalf("last = %#v", last)
	}
	// a second check right away: once in 10 minutes
	reporter.Auto(ctx, check(sub.ID, 0))
	if len(panel.bodies()) != 1 {
		t.Fatal("sent twice in a row")
	}
	// a manual send is the person's own act: it needs no switch, but the same limit holds
	out, err := reporter.Send(ctx, check(sub.ID, 0), sub.ID)
	if err != nil || out.Code != "too_soon" || out.RetryS < 590 {
		t.Fatalf("manual = %#v, %v", out, err)
	}
	// nothing to say: no request
	empty := &diag.Result{Sub: sub.ID, AtUnix: time.Now().Unix(), Servers: []diag.Server{{ID: "pth_config", Verdict: "config"}}}
	if out, err = reporter.Send(ctx, empty, sub.ID); err != nil || out.Code != "no_servers" || len(panel.bodies()) != 1 {
		t.Fatalf("empty = %#v, %v", out, err)
	}

	// the log holds facts and codes, never the link, a host, an ASN, a path or the body
	text := logs.String()
	for _, line := range []string{"block report sent: accepted 2", "block report failed: too_soon", "block report failed: no_servers"} {
		if !strings.Contains(text, line) {
			t.Errorf("log lacks %q:\n%s", line, text)
		}
	}
	for _, leak := range []string{"tok", server.URL, "127.0.0.1", "example", "64500", "pth_", "mobile", "hysteria2"} {
		if strings.Contains(text, leak) {
			t.Errorf("log leaks %q:\n%s", leak, text)
		}
	}

	// the owner turned reports off since the sync: 403 drops the intake, the person's switch stays
	other := add("tok403")
	if _, err := store.SetReport(other.ID, true); err != nil {
		t.Fatal(err)
	}
	reporter.Auto(ctx, check(other.ID, 0))
	var got subs.Subscription
	for _, s := range store.List() {
		if s.ID == other.ID {
			got = s
		}
	}
	if got.Probe == nil || got.Probe.Intake || !got.Report || got.ReportLast == nil || got.ReportLast.Error != "probe_off" {
		t.Fatalf("after 403: %#v %#v", got.Probe, got.ReportLast)
	}
	if !strings.Contains(logs.String(), "block report failed: probe_off") {
		t.Errorf("log lacks the refusal:\n%s", logs.String())
	}
	n := len(panel.bodies())
	reporter.Auto(ctx, check(other.ID, 0)) // the intake is off: nothing is asked again
	if len(panel.bodies()) != n {
		t.Fatal("sent after probe_off")
	}
}
