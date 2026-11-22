package probereport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/auto"
	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/subs"
)

var now0 = time.Unix(1_700_000_000, 0)

func ago(d time.Duration) int64 { return now0.Add(-d).Unix() }

func TestBuildAuto(t *testing.T) {
	const line = `{"type":"hysteria2","host":"a.example","port":443,"verdict":`
	cases := []struct {
		name string
		stat auto.Stat
		sent Sent
		want string // the server line; "" when the path is not reported
	}{
		{"freeze", auto.Stat{Froze: ago(time.Hour), Streak: 1, Bad: ago(time.Hour)}, Sent{}, line + `"freeze","dl_stalled":true}`},
		{"freeze wins over an ok", auto.Stat{Froze: ago(10 * time.Minute), OK: ago(5 * time.Minute), RTT: 40}, Sent{}, line + `"freeze","dl_stalled":true}`},
		{"freeze older than a day", auto.Stat{Froze: ago(25 * time.Hour)}, Sent{}, ""},
		{"freeze already sent", auto.Stat{Froze: ago(time.Hour)}, Sent{Last: "freeze", Froze: ago(time.Hour)}, ""},
		{"a new freeze of the same path", auto.Stat{Froze: ago(time.Hour)}, Sent{Last: "freeze", Froze: ago(2 * time.Hour)}, line + `"freeze","dl_stalled":true}`},
		{"data went after the freeze", auto.Stat{Froze: ago(2 * time.Hour), Proved: ago(time.Hour), OK: ago(10 * time.Minute), RTT: 40}, Sent{}, line + `"ok","delay_ms":40,"dl_stalled":false}`},
		{"old freeze, sent: the path goes as an ok", auto.Stat{Froze: ago(time.Hour), OK: ago(10 * time.Minute), RTT: 40}, Sent{Last: "freeze", Froze: ago(time.Hour)}, line + `"ok","delay_ms":40}`},
		{"ok", auto.Stat{OK: ago(10 * time.Minute), RTT: 40}, Sent{}, line + `"ok","delay_ms":40}`},
		{"ok, the data check passed", auto.Stat{OK: ago(10 * time.Minute), RTT: 40, Proved: ago(3 * time.Hour)}, Sent{}, line + `"ok","delay_ms":40,"dl_stalled":false}`},
		{"ok, the data check is old", auto.Stat{OK: ago(10 * time.Minute), RTT: 40, Proved: ago(25 * time.Hour)}, Sent{}, line + `"ok","delay_ms":40}`},
		{"ok with an old success", auto.Stat{OK: ago(2 * time.Hour), RTT: 40}, Sent{}, ""},
		{"ok without a round trip", auto.Stat{OK: ago(10 * time.Minute)}, Sent{}, ""},
		{"ok with an absurd round trip", auto.Stat{OK: ago(10 * time.Minute), RTT: 120001}, Sent{}, ""},
		{"a failure after the success", auto.Stat{OK: ago(10 * time.Minute), RTT: 40, Bad: ago(5 * time.Minute), Streak: 1}, Sent{}, ""},
		{"quarantine is not sent", auto.Stat{Bad: ago(time.Minute), Streak: 3, Until: ago(-time.Hour)}, Sent{}, ""},
		{"no finding at all", auto.Stat{}, Sent{}, ""},
		{"ok sent, no new success", auto.Stat{OK: ago(10 * time.Minute), RTT: 40}, Sent{Last: "ok", OK: ago(10 * time.Minute), OKAt: now0.Add(-25 * time.Hour)}, ""},
		{"ok sent an hour ago, a new success", auto.Stat{OK: ago(10 * time.Minute), RTT: 40}, Sent{Last: "ok", OK: ago(70 * time.Minute), OKAt: now0.Add(-time.Hour)}, ""},
		{"ok sent a day ago, a new success", auto.Stat{OK: ago(10 * time.Minute), RTT: 40}, Sent{Last: "ok", OK: ago(25 * time.Hour), OKAt: now0.Add(-24 * time.Hour)}, line + `"ok","delay_ms":40}`},
		{"ok after a freeze line", auto.Stat{OK: ago(10 * time.Minute), RTT: 40}, Sent{Last: "freeze", Froze: ago(time.Hour), OK: ago(2 * time.Hour), OKAt: now0.Add(-3 * time.Hour)}, line + `"ok","delay_ms":40}`},
	}
	profiles := []profile.Profile{hy2Path("p", "A.Example", 443, "direct")}
	for _, c := range cases {
		body, marks := BuildAuto(map[string]auto.Stat{"p": c.stat}, profiles, "s", map[string]Sent{"p": c.sent}, 0, false, now0)
		raw, _ := json.Marshal(body.Servers)
		want := "[]"
		if c.want != "" {
			want = "[" + c.want + "]"
		}
		if string(raw) != want {
			t.Errorf("%s:\n%s\nwant:\n%s", c.name, raw, want)
		}
		if body.DirectChecked != (c.want != "") || (len(marks) != 0) != (c.want != "") {
			t.Errorf("%s: direct_checked %v, marks %v", c.name, body.DirectChecked, marks)
		}
	}
}

func TestBuildAutoLeavesOutAndLimits(t *testing.T) {
	profiles := []profile.Profile{
		hy2Path("ok", "ok.example", 443, "direct"),
		hy2Path("relay", "relay.example", 443, "relay"),
		{ID: "whitelist", Sub: "s", Protocol: "hysteria2", Purpose: profile.PurposeWhitelist, Hy2: &profile.Hy2{Host: "allowlist.example", Port: 443}},
		{ID: "bad", Sub: "s", Protocol: "hysteria2", Hy2: &profile.Hy2{}}, // an endpoint that cannot be read
		{ID: "other", Sub: "other", Protocol: "hysteria2", Hy2: &profile.Hy2{Host: "other.example", Port: 443}},
		hy2Path("nostat", "nostat.example", 443, "direct"),
	}
	good := auto.Stat{OK: ago(time.Minute), RTT: 30}
	stats := map[string]auto.Stat{"ok": good, "relay": good, "whitelist": good, "bad": good, "other": good}
	body, _ := BuildAuto(stats, profiles, "s", nil, 64500, true, now0)
	raw, _ := json.Marshal(body)
	want := `{"v":1,"vpn":true,"direct_checked":true,"network":{"asn":64500,"type":"mobile"},"servers":[` +
		`{"type":"hysteria2","host":"ok.example","port":443,"verdict":"ok","delay_ms":30}]}`
	if string(raw) != want {
		t.Fatalf("body:\n%s\nwant:\n%s", raw, want)
	}

	// no lines: the body says no checks were made, and nothing is sent by the caller
	body, marks := BuildAuto(nil, profiles, "s", nil, 0, false, now0)
	raw, _ = json.Marshal(body)
	if string(raw) != `{"v":1,"vpn":true,"direct_checked":false,"network":{},"servers":[]}` || len(marks) != 0 {
		t.Fatalf("empty body = %s, %v", raw, marks)
	}

	// the panel takes 256 lines, and its strict parser takes ours
	var many []profile.Profile
	stats = map[string]auto.Stat{}
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("p%d", i)
		many = append(many, hy2Path(id, fmt.Sprintf("h%d.example", i), 443, "direct"))
		stats[id] = good
	}
	stats["p0"] = auto.Stat{Froze: ago(time.Minute)}
	body, marks = BuildAuto(stats, many, "s", nil, 64500, true, now0)
	if len(body.Servers) != 256 || len(marks) != 256 {
		t.Fatalf("lines = %d, marks = %d", len(body.Servers), len(marks))
	}
	raw, _ = json.Marshal(body)
	var parsed panelReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatalf("the panel would refuse it: %v", err)
	}
	if s := parsed.Servers[0]; s.Verdict != "freeze" || s.DLStalled == nil || !*s.DLStalled || s.DelayMS != nil || s.DLBytes != nil {
		t.Fatalf("freeze line = %#v", s)
	}
}

func TestSendAutoSendsEachFindingOnce(t *testing.T) {
	panel := &reportPanel{status: map[string]int{}}
	server := httptest.NewTLSServer(panel)
	t.Cleanup(server.Close)
	old := http.DefaultTransport // the store's client uses it
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	store, err := subs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.Direct = func() bool { return true } // the VPN is off: the ASN comes with the sync
	now := now0
	store.SetClock(func() time.Time { return now })
	memory := auto.Open("")
	reporter := &Reporter{Subs: store, Memory: memory}
	ctx := context.Background()
	sub, err := store.Add(ctx, server.URL+"/sub/tok")
	if err != nil || sub.Probe == nil || !sub.Probe.Intake {
		t.Fatalf("add = %#v, %v", sub, err)
	}
	memory.SetASNNet(sub.ID, "net") // the panel gave the ASN in this network
	step := func(d time.Duration) { now = now.Add(d) }
	tick := func(net string, mobile bool) { reporter.SendAuto(ctx, sub.ID, net, mobile, now) }
	body := func(i int) string {
		t.Helper()
		calls := panel.bodies()
		if i >= len(calls) {
			t.Fatalf("call %d: only %d were made", i, len(calls))
		}
		var parsed panelReport
		dec := json.NewDecoder(bytes.NewReader(calls[i].body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&parsed); err != nil {
			t.Fatalf("the panel would refuse call %d: %v", i, err)
		}
		return string(calls[i].body)
	}
	const head = `{"v":1,"vpn":true,"direct_checked":true,"network":{"asn":64500,"type":"mobile"},"servers":[`
	const ok = `{"type":"hysteria2","host":"oslo.example","port":443,"verdict":"ok","delay_ms":40}`
	const freeze = `{"type":"hysteria2","host":"oslo.example","port":443,"verdict":"freeze","dl_stalled":true}`
	calls := func(want int, why string) {
		t.Helper()
		if got := len(panel.bodies()); got != want {
			t.Fatalf("%s: %d requests, want %d", why, got, want)
		}
	}

	memory.Success("net", "pth_ok", 40, now)
	tick("net", true) // the switch is off
	calls(0, "switch off")
	if _, err := store.SetReport(sub.ID, true); err != nil {
		t.Fatal(err)
	}
	tick("", true) // no network key
	calls(0, "no network")
	tick("net", true)
	calls(1, "first ok")
	if got := body(0); got != head+ok+`]}` {
		t.Fatalf("first body = %s", got)
	}

	step(time.Hour) // a new success an hour on: the same path says "ok" once a day
	memory.Success("net", "pth_ok", 41, now)
	tick("net", true)
	calls(1, "ok again within a day")

	memory.Freeze("net", "pth_ok", now) // data did not go through the path
	tick("net", true)
	calls(2, "freeze")
	if got := body(1); got != head+freeze+`]}` {
		t.Fatalf("freeze body = %s", got)
	}
	step(time.Hour)
	tick("net", true)
	calls(2, "the same freeze again")

	step(time.Hour) // a new freeze mark of the same path, but the panel is busy
	memory.Freeze("net", "pth_ok", now)
	panel.mu.Lock()
	panel.status["tok"] = http.StatusTooManyRequests
	panel.mu.Unlock()
	tick("net", true)
	calls(3, "refused")
	step(time.Hour) // the next tick: the refusal did not count as sent
	panel.mu.Lock()
	delete(panel.status, "tok")
	panel.mu.Unlock()
	tick("net", true)
	calls(4, "after the refusal")
	if body(2) != body(3) || body(3) != head+freeze+`]}` {
		t.Fatalf("the line after the refusal: %s, was %s", body(3), body(2))
	}
	step(time.Hour)
	tick("net", true)
	calls(4, "accepted at last")

	// another network: its own memory, and the ASN is not the one of this network
	step(time.Hour)
	memory.Success("net2", "pth_block", 20, now)
	tick("net2", false)
	calls(5, "another network")
	if got, want := body(4), `{"v":1,"vpn":true,"direct_checked":true,"network":{},"servers":[`+
		`{"type":"hysteria2","host":"block.example","port":443,"verdict":"ok","delay_ms":20}]}`; got != want {
		t.Fatalf("other network body = %s", got)
	}
}
