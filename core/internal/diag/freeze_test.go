package diag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFreezeVerdict(t *testing.T) {
	done := transfer{Bytes: freezeBytes, Done: true}
	stalled := func(bytes int) transfer {
		return transfer{Bytes: bytes, Stalled: true, Replied: true, Idle: freezeIdle}
	}
	blocked := transfer{}
	cases := []struct {
		name    string
		control transfer
		targets []transfer
		overall string
		each    []string
	}{
		{"all complete", done, []transfer{done, done}, "ok", []string{"ok", "ok"}},
		{"one stalls early", done, []transfer{stalled(15062), done}, "freeze", []string{"freeze", "ok"}},
		{"stall at the window's edge", done, []transfer{stalled(65535)}, "freeze", []string{"freeze"}},
		{"stall past the window", done, []transfer{stalled(65536)}, "unknown", []string{"unknown"}},
		{"no byte at all", done, []transfer{stalled(0)}, "unknown", []string{"unknown"}},
		{"refused or timed out", done, []transfer{blocked, done}, "blocked", []string{"blocked", "ok"}},
		{"freeze outranks blocked", done, []transfer{blocked, stalled(100)}, "freeze", []string{"blocked", "freeze"}},
		{"host answered with an error", done, []transfer{{Replied: true}}, "unknown", []string{"unknown"}},
		{"reset in the middle, no stall", done, []transfer{{Bytes: 9000, Replied: true}}, "unknown", []string{"unknown"}},
		{"control stalled", stalled(8000), []transfer{stalled(8000), done}, "unknown", []string{"unknown", "unknown"}},
		{"control blocked", blocked, []transfer{blocked, blocked}, "unknown", []string{"unknown", "unknown"}},
		{"no targets", done, nil, "unknown", []string{}},
	}
	for _, c := range cases {
		overall, each := freezeVerdict(c.control, c.targets)
		if overall != c.overall || len(each) != len(c.each) {
			t.Errorf("%s: got %s %v, want %s %v", c.name, overall, each, c.overall, c.each)
			continue
		}
		for i := range each {
			if each[i] != c.each[i] {
				t.Errorf("%s: got %s %v, want %s %v", c.name, overall, each, c.overall, c.each)
			}
		}
	}
}

// fetch against a local server: complete, stalled after 16 KiB, a 404, and nothing listening.
func TestFetchMeasuresStallAndCompletion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/full", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, freezeBytes)) })
	mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 16<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	get := func(path string) transfer {
		return fetch(context.Background(), server.Client(), server.URL+path, freezeBytes, time.Second, 150*time.Millisecond)
	}
	if got := get("/full"); transferVerdict(got) != "ok" || got.Bytes != freezeBytes {
		t.Errorf("full = %+v", got)
	}
	if got := get("/stall"); transferVerdict(got) != "freeze" || got.Bytes != 16<<10 || got.Idle < 150*time.Millisecond {
		t.Errorf("stall = %+v", got)
	}
	if got := get("/missing"); transferVerdict(got) != "unknown" || got.Bytes != 0 {
		t.Errorf("missing = %+v", got)
	}
	server.Close()
	if got := get("/full"); transferVerdict(got) != "blocked" {
		t.Errorf("closed server = %+v", got)
	}
}
