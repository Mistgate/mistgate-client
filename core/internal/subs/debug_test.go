package subs

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func withDebug(doc, debug string) string {
	return strings.Replace(doc, `"v":1`, `"v":1,"debug":`+debug, 1)
}

func TestDebugSyncParsing(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	if sub.Debug != nil {
		t.Fatalf("no debug in the answer, got %#v", sub.Debug)
	}
	base := panel.syncBody
	future := time.Now().Add(time.Hour).Unix()
	refresh := func(debug string) *Debug {
		t.Helper()
		panel.set(func() { panel.syncBody = withDebug(base, debug) })
		got, err := store.Refresh(ctx, sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Debug
	}

	note := strings.Repeat("n", 400)
	d := refresh(fmt.Sprintf(`{"intake":true,"unasked":true,"request":{"id":"dbr_a-1","level":"debug","note":%q,"expires_unix":%d}}`, note, future))
	if d == nil || !d.Intake || !d.Unasked || d.Request == nil || d.Request.ID != "dbr_a-1" || d.Request.Level != "debug" || len(d.Request.Note) != 300 || d.Request.ExpiresUnix != future {
		t.Fatalf("debug = %#v %#v", d, d.Request)
	}
	// a request past its time is not shown, an unusable one is dropped, the rest stays
	for name, request := range map[string]string{
		"expired": fmt.Sprintf(`{"id":"dbr_a","level":"info","expires_unix":%d}`, time.Now().Add(-time.Minute).Unix()),
		"bad id":  fmt.Sprintf(`{"id":"x_a","level":"info","expires_unix":%d}`, future),
		"level":   fmt.Sprintf(`{"id":"dbr_a","level":"trace","expires_unix":%d}`, future),
	} {
		if d = refresh(`{"intake":true,"request":` + request + `}`); d == nil || !d.Intake || d.Unasked || d.Request != nil {
			t.Fatalf("%s: debug = %#v", name, d)
		}
	}
	if d = refresh(`{"intake":false,"unasked":true}`); d == nil || d.Intake || d.Unasked {
		t.Fatalf("edge panel: debug = %#v", d)
	}
}

func TestDebugSendAndDecline(t *testing.T) {
	ctx := context.Background()
	panel, store, sub := managedStore(t)
	future := time.Now().Add(time.Hour).Unix()
	var plain string
	panel.set(func() {
		plain = panel.syncBody
		panel.syncBody = withDebug(panel.syncBody, fmt.Sprintf(`{"intake":true,"request":{"id":"dbr_abc","level":"info","expires_unix":%d}}`, future))
	})
	if got, _ := store.Refresh(ctx, sub.ID); got.Debug == nil || got.Debug.Request == nil {
		t.Fatalf("request not seen: %#v", got.Debug)
	}
	key := store.state.Subscriptions[0].Key
	calls := func() []debugCall {
		var c []debugCall
		panel.set(func() { c = append(c, panel.debugCalls...) })
		return c
	}
	syncs := func() int {
		n := 0
		panel.set(func() { n = len(panel.syncAuth) })
		return n
	}

	// answering the request: the bundle goes out as it is, with the request header; the request then goes away
	gz := []byte{0x1f, 0x8b, 1, 2, 3}
	before := syncs()
	panel.set(func() { panel.syncBody = withDebug(plain, `{"intake":true}`) })
	out := store.SendDebug(ctx, sub.ID, "dbr_abc", gz)
	if out.Code != "" || out.ID != "dbr_abc" || out.Lines != 3 {
		t.Fatalf("send = %#v", out)
	}
	c := calls()[0]
	if !strings.HasSuffix(c.path, "/client/debug") || !bytes.Equal(c.body, gz) || c.header.Get("Authorization") != "Bearer "+key ||
		c.header.Get("Content-Type") != "application/x-ndjson" || c.header.Get("Content-Encoding") != "gzip" || c.header.Get("X-Mistgate-Debug-Request") != "dbr_abc" {
		t.Fatalf("call = %#v", c)
	}
	if list := store.List(); list[0].Debug == nil || list[0].Debug.Request != nil {
		t.Fatalf("request still open: %#v", list[0].Debug)
	}
	for i := 0; syncs() == before && i < 200; i++ { // the background sync
		time.Sleep(10 * time.Millisecond)
	}
	if syncs() == before {
		t.Fatal("no sync after the send")
	}

	// the person's own send carries no request header
	if out = store.SendDebug(ctx, sub.ID, "", gz); out.Code != "" {
		t.Fatal(out)
	}
	if h := calls()[1].header; h.Get("X-Mistgate-Debug-Request") != "" {
		t.Fatalf("own send names a request: %v", h)
	}

	// refusals: the panel's code and Retry-After, a decoy, a plain 429 without a body
	for _, tc := range []struct {
		status      int
		body, retry string
		code        string
		wantRetry   int
	}{
		{429, `{"error":"too_many_requests"}`, "600", "too_many_requests", 600},
		{409, `{"error":"no_request"}`, "", "no_request", 0},
		{503, `{"error":"debug_full"}`, "30", "debug_full", 30},
		{404, "<html>not found</html>", "", "decoy", 0},
		{429, "", "45", "retry", 45},
	} {
		panel.set(func() { panel.debugStatus, panel.debugBody, panel.debugRetry = tc.status, tc.body, tc.retry })
		if out = store.SendDebug(ctx, sub.ID, "", gz); out.Code != tc.code || out.RetryS != tc.wantRetry {
			t.Fatalf("%d %q: %#v", tc.status, tc.body, out)
		}
	}
	panel.set(func() { panel.debugStatus = 0 })

	// decline: no body, the request header, and the same outcomes
	if out = store.DeclineDebug(ctx, sub.ID, "dbr_abc"); out.Code != "" || out.ID != "dbr_abc" {
		t.Fatalf("decline = %#v", out)
	}
	if c = calls()[len(calls())-1]; !strings.HasSuffix(c.path, "/client/debug/decline") || c.hadBody || c.header.Get("X-Mistgate-Debug-Request") != "dbr_abc" {
		t.Fatalf("decline call = %#v", c)
	}
	panel.set(func() { panel.debugStatus, panel.debugBody = 409, `{"error":"no_request"}` })
	if out = store.DeclineDebug(ctx, sub.ID, "dbr_abc"); out.Code != "no_request" {
		t.Fatalf("decline = %#v", out)
	}

	panel.server.Close()
	if out = store.SendDebug(ctx, sub.ID, "", gz); out.Code != "offline" {
		t.Fatalf("closed panel = %#v", out)
	}
}
