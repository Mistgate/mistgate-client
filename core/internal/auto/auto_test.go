package auto

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

func TestScore(t *testing.T) {
	tests := []struct {
		name string
		stat Stat
		via  string
		want float64
	}{
		{"recent direct", Stat{OK: t0.Unix(), RTT: 50}, "", 50},
		{"direct is spelled out", Stat{OK: t0.Unix(), RTT: 50}, "direct", 50},
		{"relay", Stat{OK: t0.Unix(), RTT: 50}, "relay", 70},
		{"warp", Stat{OK: t0.Unix(), RTT: 50}, "warp", 80},
		{"failures cost", Stat{OK: t0.Unix(), RTT: 100, Fail: 0.5}, "", 250},
		{"unknown round trip is 300", Stat{OK: t0.Unix()}, "", 300},
		{"old success", Stat{OK: t0.Add(-7 * time.Hour).Unix(), RTT: 50}, "", 110},
		{"success at the edge is not old", Stat{OK: t0.Add(-6 * time.Hour).Unix(), RTT: 50}, "", 50},
		{"a fresh freeze costs 400", Stat{OK: t0.Unix(), RTT: 50, Froze: t0.Add(-time.Hour).Unix()}, "", 450},
		{"a freeze a little under a day old still costs", Stat{OK: t0.Unix(), RTT: 50, Froze: t0.Add(-23 * time.Hour).Unix()}, "", 450},
		{"a freeze a day old costs nothing", Stat{OK: t0.Unix(), RTT: 50, Froze: t0.Add(-24 * time.Hour).Unix()}, "", 50},
	}
	for _, test := range tests {
		if got := Score(test.stat, test.via, t0); math.Abs(got-test.want) > 1e-6 {
			t.Errorf("%s: score = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestFreezeAndProve(t *testing.T) {
	m := Open("")
	if m.Proved("n", "a", t0) {
		t.Fatal("proved with nothing known")
	}
	m.Success("n", "a", 50, t0)
	m.Prove("n", "a", t0)
	if !m.Proved("n", "a", t0.Add(23*time.Hour)) || m.Proved("n", "a", t0.Add(24*time.Hour)) || m.Proved("other", "a", t0) {
		t.Fatal("the mark of data is not a day of one network")
	}
	m.Freeze("n", "a", t0.Add(time.Minute))
	stat := m.nets["n"].Paths["a"]
	if stat.Froze != t0.Add(time.Minute).Unix() || stat.Streak != 1 || stat.Proved != 0 || m.Proved("n", "a", t0.Add(time.Minute)) {
		t.Fatalf("after a freeze: %+v", stat)
	}
	if _, ok := m.Known("n", []Path{{ID: "a"}}, t0.Add(time.Minute)); ok {
		t.Fatal("a frozen path is still known")
	}
	m.Success("n", "a", 50, t0.Add(2*time.Minute)) // it connects again, which proves nothing about data
	if stat = m.nets["n"].Paths["a"]; stat.Froze == 0 || Score(stat, "", t0.Add(2*time.Minute)) < frozenCost {
		t.Fatalf("a connect lifted the freeze: %+v", stat)
	}
	m.Prove("n", "a", t0.Add(3*time.Minute))
	if stat = m.nets["n"].Paths["a"]; stat.Froze != 0 {
		t.Fatalf("data did not lift the freeze: %+v", stat)
	}
	var nilMemory *Memory
	nilMemory.Prove("n", "a", t0)
	nilMemory.Freeze("n", "a", t0)
	if nilMemory.Proved("n", "a", t0) {
		t.Fatal("a nil memory proved something")
	}
}

func TestFailDecays(t *testing.T) {
	m := Open("")
	m.Failure("n", "p", t0)
	m.Failure("n", "p", t0) // 0.3, then 0.3*0.7+0.3
	stat := m.nets["n"].Paths["p"]
	if math.Abs(stat.Fail-0.51) > 1e-9 {
		t.Fatalf("fail = %v, want 0.51", stat.Fail)
	}
	if got := decayed(stat, t0.Add(6*time.Hour)); math.Abs(got-0.255) > 1e-9 {
		t.Fatalf("after one half-life fail = %v, want 0.255", got)
	}
	if got := decayed(stat, t0.Add(-time.Hour)); got != stat.Fail {
		t.Fatalf("a clock gone back changed fail to %v", got)
	}
	// a success moves it the other way, from the decayed value
	m.Success("n", "p", 40, t0.Add(6*time.Hour))
	if got := m.nets["n"].Paths["p"].Fail; math.Abs(got-0.255*0.7) > 1e-9 {
		t.Fatalf("fail after a success = %v", got)
	}
}

func TestQuarantine(t *testing.T) {
	m := Open("")
	now := t0
	want := []time.Duration{0, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute, 120 * time.Minute, 120 * time.Minute}
	for i, d := range want {
		m.Failure("n", "p", now)
		avoided := m.Avoid("n", now)
		if d == 0 {
			if len(avoided) != 0 {
				t.Fatalf("failure %d: avoided %v, want none", i+1, avoided)
			}
			continue
		}
		if !slices.Equal(avoided, []string{"p"}) || len(m.Avoid("n", now.Add(d-time.Second))) != 1 || len(m.Avoid("n", now.Add(d))) != 0 {
			t.Fatalf("failure %d: quarantine is not %v", i+1, d)
		}
	}
	m.Success("n", "p", 30, now)
	if len(m.Avoid("n", now)) != 0 {
		t.Fatal("a success left the path in quarantine")
	}
	m.Failure("n", "p", now)
	m.Failure("n", "p", now)
	if len(m.Avoid("n", now.Add(2*time.Minute))) != 0 {
		t.Fatal("the steps did not start again after a success")
	}
	if len(m.Avoid("", now)) != 0 || len(m.Avoid("other", now)) != 0 {
		t.Fatal("another network's quarantine leaked")
	}
}

func TestKnown(t *testing.T) {
	both := []Path{{ID: "a"}, {ID: "b"}}
	tests := []struct {
		name  string
		setup func(m *Memory)
		cands []Path
		want  string
	}{
		{"a fresh success", func(m *Memory) { m.Success("n", "a", 50, t0) }, both, "a"},
		{"nothing known", func(*Memory) {}, both, ""},
		{"a failure after the success", func(m *Memory) {
			m.Success("n", "a", 50, t0)
			m.Failure("n", "a", t0.Add(time.Second))
		}, both, ""},
		{"a success after the failure", func(m *Memory) {
			m.Failure("n", "a", t0)
			m.Success("n", "a", 50, t0)
		}, both, "a"},
		{"a success older than a day", func(m *Memory) { m.Success("n", "a", 50, t0.Add(-25*time.Hour)) }, both, ""},
		{"a success a little under a day old", func(m *Memory) { m.Success("n", "a", 50, t0.Add(-23*time.Hour)) }, both, "a"},
		{"in quarantine", func(m *Memory) {
			m.Success("n", "a", 50, t0.Add(-time.Hour))
			m.nets["n"].Paths["a"] = Stat{OK: t0.Add(-time.Hour).Unix(), Until: t0.Add(time.Minute).Unix()}
		}, both, ""},
		{"the quicker of two", func(m *Memory) {
			m.Success("n", "a", 80, t0)
			m.Success("n", "b", 30, t0)
		}, both, "b"},
		{"a failure share costs", func(m *Memory) {
			m.Success("n", "a", 40, t0)
			m.Success("n", "b", 50, t0)
			m.nets["n"].Paths["a"] = Stat{OK: t0.Unix(), RTT: 40, Fail: 0.5}
		}, both, "b"},
		{"direct beats a relay at equal figures", func(m *Memory) {
			m.Success("n", "a", 50, t0)
			m.Success("n", "b", 50, t0)
		}, []Path{{ID: "a", Via: "relay"}, {ID: "b", Via: "direct"}}, "b"},
		{"the later success wins a tie", func(m *Memory) {
			m.Success("n", "a", 50, t0.Add(-time.Minute))
			m.Success("n", "b", 50, t0)
		}, both, "b"},
		{"not among the candidates", func(m *Memory) { m.Success("n", "a", 50, t0) }, []Path{{ID: "b"}}, ""},
		{"another network", func(m *Memory) { m.Success("other", "a", 50, t0) }, both, ""},
	}
	for _, test := range tests {
		m := Open("")
		test.setup(m)
		id, ok := m.Known("n", test.cands, t0)
		if id != test.want || ok != (test.want != "") {
			t.Errorf("%s: known = %q, %v; want %q", test.name, id, ok, test.want)
		}
	}
}

func TestKnownKeepsLastRTTWhenUnknown(t *testing.T) {
	m := Open("")
	m.Success("n", "a", 70, t0)
	m.Success("n", "a", 0, t0)
	if got := m.nets["n"].Paths["a"].RTT; got != 70 {
		t.Fatalf("rtt = %d, want the last known 70", got)
	}
}

func TestLimits(t *testing.T) {
	m := Open("")
	for i := 0; i < maxNets+3; i++ {
		m.Success(fmt.Sprint("net", i), "p", 10, t0.Add(time.Duration(i)*time.Minute))
	}
	if len(m.nets) != maxNets {
		t.Fatalf("%d networks kept, want %d", len(m.nets), maxNets)
	}
	for i := 0; i < 3; i++ {
		if m.nets[fmt.Sprint("net", i)] != nil {
			t.Fatalf("net%d, the longest unused, is still there", i)
		}
	}
	if m.nets["net3"] == nil || m.nets["net18"] == nil {
		t.Fatal("a recent network was evicted")
	}
	for i := 0; i < maxPaths+5; i++ {
		m.Success("net18", fmt.Sprint("p", i), 10, t0.Add(time.Hour+time.Duration(i)*time.Second))
	}
	paths := m.nets["net18"].Paths
	if len(paths) != maxPaths || paths["p0"].OK != 0 || paths["p132"].OK == 0 {
		t.Fatalf("%d paths kept; the oldest must go first", len(paths))
	}
}

func TestKeep(t *testing.T) {
	m := Open("")
	m.Success("n", "a", 10, t0)
	m.Success("n", "b", 10, t0)
	m.Success("other", "b", 10, t0)
	m.Success("third", "c", 10, t0)
	m.Keep(nil) // no list is no news
	if len(m.nets["n"].Paths) != 2 {
		t.Fatal("an empty list emptied the memory")
	}
	m.Keep([]string{"a"})
	if _, ok := m.Known("n", []Path{{ID: "a"}, {ID: "b"}}, t0); !ok || len(m.nets["n"].Paths) != 1 {
		t.Fatal("a is gone or b is still there")
	}
	if m.nets["other"] != nil || m.nets["third"] != nil {
		t.Fatal("networks left with no path were kept")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	m := Open(dir)
	m.Success("n", "a", 42, t0)
	m.Failure("n", "b", t0)
	m.Failure("n", "b", t0)
	m.Flush()
	again := Open(dir)
	if string(again.Salt()) != string(m.Salt()) || len(again.Salt()) != 32 {
		t.Fatal("the salt did not survive")
	}
	if id, ok := again.Known("n", []Path{{ID: "a"}, {ID: "b"}}, t0); !ok || id != "a" || again.nets["n"].Paths["a"].RTT != 42 {
		t.Fatalf("known after a restart = %q, %v", id, ok)
	}
	if got := again.Avoid("n", t0); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("avoid after a restart = %v", got)
	}
	data, err := os.ReadFile(filepath.Join(dir, "auto.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\r") {
		t.Fatal("the file has CR")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".auto-*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestSavesByItself(t *testing.T) {
	dir := t.TempDir()
	m := Open(dir)
	m.Success("n", "a", 10, t0)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "auto.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first change was not saved")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// within a minute of that save the next one waits
	m.mu.Lock()
	m.saved = time.Now()
	m.mu.Unlock()
	m.Success("n", "b", 10, t0)
	m.mu.Lock()
	waiting := m.timer != nil && m.dirty
	m.mu.Unlock()
	if !waiting {
		t.Fatal("the second change was not left for later")
	}
	m.Flush()
	if _, ok := Open(dir).Known("n", []Path{{ID: "b"}}, t0); !ok {
		t.Fatal("Flush did not write the waiting change")
	}
}

func TestBrokenFile(t *testing.T) {
	for _, content := range []string{"", "{", `{"salt":"zz","nets":{"n":{"paths":{"a":{"ok":1}}}}}`, `{"salt":"00","nets":{}}`, "null"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "auto.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		m := Open(dir)
		if len(m.nets) != 0 || len(m.Salt()) != 32 {
			t.Fatalf("%q: %d networks, salt of %d bytes", content, len(m.nets), len(m.Salt()))
		}
		m.Success("n", "a", 10, t0) // and it works
		m.Flush()
	}
	if len(Open(t.TempDir()).nets) != 0 {
		t.Fatal("a missing file is not empty")
	}
}

func TestLoadClamps(t *testing.T) {
	dir := t.TempDir()
	salt := strings.Repeat("ab", 32)
	body := `{"salt":"` + salt + `","nets":{"n":{"seen":1,"paths":{"a":{"ok":5,"fail":7},"":{"ok":1}}},"":{"paths":{"a":{}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "auto.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Open(dir)
	if len(m.nets) != 1 || len(m.nets["n"].Paths) != 1 || m.nets["n"].Paths["a"].Fail != 1 {
		t.Fatalf("loaded %+v", m.nets)
	}
}

func TestNilAndRAMOnly(t *testing.T) {
	var m *Memory
	m.Success("n", "a", 1, t0)
	m.Failure("n", "a", t0)
	m.Keep([]string{"a"})
	m.Flush()
	if id, ok := m.Known("n", []Path{{ID: "a"}}, t0); ok || id != "" || m.Avoid("n", t0) != nil || m.Salt() != nil {
		t.Fatal("a nil memory remembered something")
	}
	ram := Open("")
	ram.Success("", "a", 1, t0) // no network: nothing
	ram.Success("n", "a", 1, t0)
	ram.Flush() // no file to write
	if len(ram.Salt()) != 32 || len(ram.nets) != 1 {
		t.Fatal("RAM memory is not working")
	}
	if string(Open("").Salt()) == string(ram.Salt()) {
		t.Fatal("two processes shared a salt")
	}
}
