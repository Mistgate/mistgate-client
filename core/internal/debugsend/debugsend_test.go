package debugsend

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mistgate/mistgate-client/core/internal/diag"
)

func TestScrub(t *testing.T) {
	for in, want := range map[string]string{
		"connect to 203.0.113.7 failed":                 "connect to [removed] failed",
		"peer 2001:db8::1 and fe80::1%eth0 and ::1":     "peer [removed] and [removed]%eth0 and [removed]",
		"full 2001:0db8:0000:0000:0000:ff00:0042:8329":  "full [removed]",
		"fetch https://panel.example/sub/abc failed":    "fetch [removed] failed",
		"mail me@example.com now":                       "mail [removed] now",
		`open C:\Users\Alice\AppData\x.log`:             "open [removed]",
		"mac 00:1A:2b:3c:4d:5e up":                      "mac [removed] up",
		"key " + strings.Repeat("aB3/", 10) + " end":    "key [removed] end",
		"tunnel up at 12:30:45, retry 3, version 0.0.1": "tunnel up at 12:30:45, retry 3, version 0.0.1",
		"line\x00one\ntwo":                              "line one two",
	} {
		if got := scrub(in); got != want {
			t.Errorf("scrub(%q) = %q, want %q", in, got, want)
		}
	}
}

func decode(t *testing.T, gz []byte) []Line {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(reader)
	var lines []Line
	for _, raw := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		var l Line
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("line %q: %v", raw, err)
		}
		lines = append(lines, l)
	}
	return lines
}

func TestBuildParts(t *testing.T) {
	now := time.Now()
	var result diag.Result
	result.AtUnix = now.Unix() - 60
	result.Route.Verdict, result.DNS.Verdict = "ok", "replaced"
	result.Servers = []diag.Server{{ID: "pth_1", Protocol: "hysteria2", Verdict: "ok", RTTMS: 41, Reason: "dial 198.51.100.9:443 refused"}}
	long := strings.Repeat("é", 700) // 1400 bytes
	b, err := Build(Input{
		Now: now, Parts: []string{"system", "checks", "log"}, Note: "  it drops at 203.0.113.5  ",
		Version: "0.0.1", Mode: "smart", State: "connected", Protocol: "hysteria2", Checks: &result,
		Vias: map[string]string{"pth_1": "relay"},
		Logs: []Entry{
			{TMS: now.UnixMilli() - 1000, Level: "WARN", Src: "Engine", Msg: "late"},
			{TMS: now.UnixMilli() - 2000, Level: "weird", Src: "bad src!", Msg: long},
			{TMS: now.Add(-25 * time.Hour).UnixMilli(), Level: "info", Src: "engine", Msg: "too old"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(t, b.GZ); len(got) != len(b.Lines) {
		t.Fatalf("wire has %d lines, preview %d", len(got), len(b.Lines))
	}
	var seen []string
	for i, l := range b.Lines {
		seen = append(seen, l.Src+":"+l.Msg[:min(len(l.Msg), 12)])
		if i > 0 && l.TS < b.Lines[i-1].TS {
			t.Errorf("line %d out of order", i)
		}
		if len(l.Msg) > 1024 || !utf8.ValidString(l.Msg) || len(l.KV) > 16 {
			t.Errorf("limits: %#v", l)
		}
		switch {
		case strings.Contains(l.Msg, "too old"):
			t.Error("old log line kept")
		case l.Src == "system":
			if !strings.HasPrefix(l.Msg, "mistgate 0.0.1 ") || l.KV["mode"] != "smart" || l.KV["state"] != "connected" || l.KV["protocol"] != "hysteria2" || l.KV["version"] != "0.0.1" {
				t.Errorf("system line %#v", l)
			}
		case l.Src == "note" && l.Msg != "it drops at [removed]":
			t.Errorf("note %q", l.Msg)
		case l.Msg == "server path" && (l.KV["server"] != "pth_1" || l.KV["via"] != "relay" || l.KV["ms"] != "41" || l.KV["reason"] != "dial [removed]:443 refused"):
			t.Errorf("server line %#v", l)
		case l.Src == "core" && (l.Lvl != "info" || len(l.Msg) != 1024):
			t.Errorf("fallback src line %#v", l)
		case l.Msg == "late" && (l.Src != "engine" || l.Lvl != "warn"):
			t.Errorf("log line %#v", l)
		}
	}
	// system, 2 network verdicts, 1 server path, 2 log lines, note
	if len(b.Lines) != 7 {
		t.Fatalf("lines = %v", seen)
	}
	// only the allowed keys, no other part without being asked
	l := line(1, "info", "x", "m", map[string]string{"host": "h", "server": "s", "k1": "a"})
	if len(l.KV) != 1 || l.KV["server"] != "s" {
		t.Errorf("kv = %v", l.KV)
	}
	if _, err = Build(Input{Parts: []string{"everything"}}); err == nil {
		t.Error("unknown part accepted")
	}
}

func TestBuildFitsTheWire(t *testing.T) {
	now := time.Now()
	rng := rand.New(rand.NewPCG(1, 2))
	word := func() string {
		b := make([]byte, 3+rng.IntN(6))
		for i := range b {
			b[i] = byte('a' + rng.IntN(26))
		}
		return string(b)
	}
	var logs []Entry
	for i := range 30000 {
		var msg []string
		for range 30 {
			msg = append(msg, word())
		}
		logs = append(logs, Entry{TMS: now.UnixMilli() - int64(30000-i)*100, Level: "info", Src: "engine", Msg: strings.Join(msg, " ")})
	}
	b, err := Build(Input{Now: now, Parts: []string{"log"}, Logs: logs})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.GZ) > 1<<20 || len(b.Lines) > 20000 || len(b.Lines) == 0 {
		t.Fatalf("%d lines, %d bytes", len(b.Lines), len(b.GZ))
	}
	if b.Lines[len(b.Lines)-1].Msg != logs[len(logs)-1].Msg {
		t.Error("the newest line was dropped")
	}
	if got := decode(t, b.GZ); len(got) != len(b.Lines) {
		t.Errorf("wire %d, preview %d", len(got), len(b.Lines))
	}
}

func TestScrubPathsAndHosts(t *testing.T) {
	got := scrub(`app d:\games\play.exe asked vpn.example.com twice, version 0.0.1`)
	if strings.Contains(got, "play") || strings.Contains(got, "example") || !strings.Contains(got, "0.0.1") || !strings.Contains(got, "twice") {
		t.Fatalf("scrub = %q", got)
	}
}
