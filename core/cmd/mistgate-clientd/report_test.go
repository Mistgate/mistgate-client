package main

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/session"
)

func TestReportFindingsOnlyOnAnAutoPath(t *testing.T) {
	var sent []string
	run := func(status session.Status, key, kind string) {
		sent = nil
		reportFindings(context.Background(), func() (session.Status, error) { return status, nil },
			func(id string) string { return map[string]string{"srv": "sub"}[id] },
			func() (string, string) { return key, kind },
			func(_ context.Context, sub, key string, mobile bool) {
				sent = append(sent, sub+" "+key+" "+strconv.FormatBool(mobile))
			})
	}
	connected := session.Status{State: "connected", ServerID: "srv", Auto: true}
	run(connected, "net", "mobile")
	if !slices.Equal(sent, []string{"sub net true"}) {
		t.Fatalf("auto path: %v", sent)
	}
	pinned := connected
	pinned.Auto = false // the person named the server
	for name, tc := range map[string]struct {
		status    session.Status
		key, kind string
	}{
		"pinned":       {pinned, "net", "wifi"},
		"not up":       {session.Status{State: "reconnecting", ServerID: "srv", Auto: true}, "net", "wifi"},
		"no network":   {connected, "", ""},
		"unknown path": {session.Status{State: "connected", ServerID: "other", Auto: true}, "net", "wifi"},
	} {
		if run(tc.status, tc.key, tc.kind); len(sent) != 0 {
			t.Errorf("%s: sent %v", name, sent)
		}
	}
	run(connected, "net", "wifi")
	if !slices.Equal(sent, []string{"sub net false"}) {
		t.Fatalf("wifi: %v", sent)
	}
}
