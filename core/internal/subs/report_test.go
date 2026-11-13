package subs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func withProbe(doc, probe string) string {
	return strings.Replace(doc, `"v":1`, `"v":1,`+probe, 1)
}

func TestProbeSyncParsing(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	if sub.Probe != nil || store.state.Subscriptions[0].ASN != 0 {
		t.Fatalf("no probe in the answer, got %#v", sub.Probe)
	}
	base := panel.syncBody
	refresh := func(extra string) Subscription {
		t.Helper()
		panel.set(func() { panel.syncBody = withProbe(base, extra) })
		got, err := store.Refresh(ctx, sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	got := refresh(`"probe":{"intake":true,"v":1},"asn":64500`)
	if got.Probe == nil || !got.Probe.Intake || got.Probe.V != 1 || store.state.Subscriptions[0].ASN != 64500 {
		t.Fatalf("probe = %#v, asn = %d", got.Probe, store.state.Subscriptions[0].ASN)
	}
	// the window gets the probe part, never the ASN
	encoded, _ := json.Marshal(store.List())
	if !strings.Contains(string(encoded), `"probe":{"intake":true,"v":1}`) || strings.Contains(string(encoded), "64500") || !strings.Contains(string(encoded), `"report":false`) {
		t.Fatalf("list = %s", encoded)
	}
	// not a number: the sync still works, the ASN is just not there
	if got = refresh(`"probe":{"intake":false,"v":1},"asn":"AS1"`); got.Probe == nil || got.Probe.Intake || store.state.Subscriptions[0].ASN != 0 {
		t.Fatalf("probe = %#v, asn = %d", got.Probe, store.state.Subscriptions[0].ASN)
	}
	// the panel says nothing: the field goes away
	if got = refresh(`"x":1`); got.Probe != nil {
		t.Fatalf("probe = %#v", got.Probe)
	}
}

func TestReportSwitch(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	base := panel.syncBody
	sync := func(probe string) {
		t.Helper()
		panel.set(func() { panel.syncBody = withProbe(base, probe) })
		if _, err := store.Refresh(ctx, sub.ID); err != nil {
			t.Fatal(err)
		}
	}
	for len(store.Changes()) > 0 {
		<-store.Changes()
	}
	if _, err := store.SetReport(sub.ID, true); errorCode(err) != "probe_off" { // the panel did not say
		t.Fatalf("on without a probe part: %v", err)
	}
	sync(`"probe":{"intake":false,"v":1}`)
	if _, err := store.SetReport(sub.ID, true); errorCode(err) != "probe_off" {
		t.Fatalf("on while the owner takes no reports: %v", err)
	}
	sync(`"probe":{"intake":true,"v":0}`)
	if _, err := store.SetReport(sub.ID, true); errorCode(err) != "probe_off" {
		t.Fatalf("on with no version: %v", err)
	}
	if _, err := store.SetReport("nope", false); errorCode(err) != "unknown_subscription" {
		t.Fatalf("unknown: %v", err)
	}
	sync(`"probe":{"intake":true,"v":1}`)
	for len(store.Changes()) > 0 {
		<-store.Changes()
	}
	got, err := store.SetReport(sub.ID, true)
	if err != nil || !got.Report || len(store.Changes()) != 1 || !store.List()[0].Report {
		t.Fatalf("on = %#v, %v", got, err)
	}
	// the owner switches reports off: the switch cannot be turned on, and the person's wish stays
	sync(`"probe":{"intake":false,"v":1}`)
	if list := store.List(); !list[0].Report || list[0].Probe.Intake {
		t.Fatalf("after the owner's off: %#v", list[0])
	}
	if got, err = store.SetReport(sub.ID, false); err != nil || got.Report {
		t.Fatalf("off is always allowed: %#v, %v", got, err)
	}
	// the switch is saved with the store
	sync(`"probe":{"intake":true,"v":1}`)
	if _, err = store.SetReport(sub.ID, true); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(store.dir, identityProtection, identityProtection, func(string) error { return nil })
	if err != nil || !reopened.List()[0].Report {
		t.Fatalf("reopened: %v", err)
	}
}

func TestSendReport(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	panel.set(func() { panel.syncBody = withProbe(panel.syncBody, `"probe":{"intake":true,"v":1}`) })
	if _, err := store.Refresh(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	store.clock = func() time.Time { return now }
	body := []byte(`{"v":1}`)
	calls := func() []debugCall {
		var c []debugCall
		panel.set(func() { c = append(c, panel.probeCalls...) })
		return c
	}
	last := func() *ReportLast { return store.List()[0].ReportLast }

	// 200: the request is the contract's, and the end is kept
	out := store.SendReport(ctx, sub.ID, body)
	c := calls()
	if out.Code != "" || out.Accepted != 2 || len(c) != 1 || c[0].path != "/sub/tok/probe" || string(c[0].body) != string(body) ||
		c[0].header.Get("Probe-Report") != "1" || c[0].header.Get("Content-Type") != "application/json" || c[0].header.Get("Authorization") != "" {
		t.Fatalf("send = %#v, calls = %#v", out, c)
	}
	if l := last(); l == nil || l.AtUnix != now.Unix() || l.Accepted != 2 || l.Error != "" {
		t.Fatalf("last = %#v", l)
	}

	// once in 10 minutes: no request, and the wait is told
	now = now.Add(9*time.Minute + 30*time.Second)
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "too_soon" || out.RetryS != 30 || len(calls()) != 1 {
		t.Fatalf("too soon = %#v, %d calls", out, len(calls()))
	}
	if l := last(); l.AtUnix == now.Unix() || l.Error != "" { // a refused attempt is not an end
		t.Fatalf("last = %#v", l)
	}
	now = now.Add(31 * time.Second)
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "" || len(calls()) != 2 {
		t.Fatalf("after 10 minutes = %#v", out)
	}

	// 429 with Retry-After: the next attempt waits for it, even past the 10 minutes
	now = now.Add(11 * time.Minute)
	panel.set(func() {
		panel.probeStatus, panel.probeBody, panel.probeRetry = 429, `{"error":"too_many_requests"}`, "1800"
	})
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "too_many_requests" || out.RetryS != 1800 {
		t.Fatalf("429 = %#v", out)
	}
	if l := last(); l.Error != "too_many_requests" || l.Accepted != 0 {
		t.Fatalf("last = %#v", l)
	}
	now = now.Add(25 * time.Minute)
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "too_soon" || out.RetryS != 300 || len(calls()) != 3 {
		t.Fatalf("inside Retry-After = %#v, %d calls", out, len(calls()))
	}
	// a 429 without a body, and answers that are not the panel's
	now = now.Add(6 * time.Minute)
	panel.set(func() { panel.probeStatus, panel.probeBody, panel.probeRetry = 429, "", "" })
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "retry" || out.RetryS != 600 {
		t.Fatalf("bare 429 = %#v", out)
	}
	for _, page := range []string{"<html>not found</html>", `{"error":"has space and http://x"}`} {
		now = now.Add(11 * time.Minute)
		panel.set(func() { panel.probeStatus, panel.probeBody = 404, page })
		if out = store.SendReport(ctx, sub.ID, body); out.Code != "decoy" {
			t.Fatalf("%q = %#v", page, out)
		}
	}
	now = now.Add(11 * time.Minute)
	panel.set(func() { panel.probeStatus, panel.probeBody = 409, `{"error":"user_inactive"}` })
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "user_inactive" {
		t.Fatalf("409 = %#v", out)
	}
	now = now.Add(11 * time.Minute)
	panel.set(func() { panel.probeStatus, panel.probeBody = 200, `not json` })
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "decoy" {
		t.Fatalf("200 that is not an answer = %#v", out)
	}

	// 403 probe_off: the intake is dropped until the next sync, the person's switch stays, and nothing more is sent
	if _, err := store.SetReport(sub.ID, true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	panel.set(func() { panel.probeStatus, panel.probeBody = 403, `{"error":"probe_off"}` })
	sent := len(calls())
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "probe_off" || len(calls()) != sent+1 {
		t.Fatalf("403 = %#v", out)
	}
	if list := store.List(); list[0].Probe == nil || list[0].Probe.Intake || !list[0].Report || list[0].ReportLast.Error != "probe_off" {
		t.Fatalf("after probe_off: %#v %#v", list[0].Probe, list[0].ReportLast)
	}
	now = now.Add(11 * time.Minute)
	if out = store.SendReport(ctx, sub.ID, body); out.Code != "probe_off" || len(calls()) != sent+1 {
		t.Fatalf("after the intake is dropped = %#v", out)
	}
	if _, err := store.SetReport(sub.ID, true); errorCode(err) != "probe_off" {
		t.Fatalf("switch: %v", err)
	}
	// the next sync brings it back (the stored ETag was dropped, so it is not "not changed")
	panel.set(func() { panel.etag = `"e1"`; panel.probeStatus = 0 })
	if got, err := store.Refresh(ctx, sub.ID); err != nil || got.Probe == nil || !got.Probe.Intake {
		t.Fatalf("sync after probe_off: %#v, %v", got.Probe, err)
	}

	// nothing reaches the panel: no answer, and no wait for the next try
	now = now.Add(11 * time.Minute)
	panel.server.Close()
	for i := 0; i < 2; i++ {
		if out = store.SendReport(ctx, sub.ID, body); out.Code != "offline" && out.Code != "fetch_failed" {
			t.Fatalf("closed panel = %#v", out)
		}
	}

	// an unknown subscription
	if out = store.SendReport(ctx, "nope", body); out.Code != "probe_off" {
		t.Fatalf("unknown = %#v", out)
	}
}
