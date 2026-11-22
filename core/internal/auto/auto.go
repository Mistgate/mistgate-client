// Package auto is the memory of Auto: for each network, which paths worked lately and which did not. A network is an
// opaque key (see diag.NetworkKey) and a path an id; nothing else is kept, so the file has no addresses, no names of
// networks and no hosts.
package auto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	maxNets      = 16 // a network not used for the longest is forgotten first
	maxPaths     = 128
	halfLife     = 6 * time.Hour  // of Stat.Fail
	freshFor     = 24 * time.Hour // a success older than this is not "known"
	staleAfter   = 6 * time.Hour  // a success older than this costs staleCost in the score
	staleCost    = 60
	frozenCost   = 400 // a path that let a connection start and carried nothing, for a day
	unknownRTT   = 300 // ms: the score of a path whose round trip was never seen
	saveEvery    = time.Minute
	failWeight   = 0.3 // how much one outcome moves Fail
	quarantineAt = 2   // failures in a row that put a path aside
)

// quarantine is how long a path stays aside after its 2nd, 3rd, ... failure in a row (the last step repeats).
var quarantine = [...]time.Duration{2 * time.Minute, 10 * time.Minute, 30 * time.Minute, 120 * time.Minute}

// Path is a candidate of Known: the id of a path and how it reaches its server (profile.Via; "" and "direct" are direct).
type Path struct{ ID, Via string }

// Stat is what is known of one path in one network. Times are Unix seconds.
type Stat struct {
	OK     int64   `json:"ok,omitempty"`     // the last success
	Bad    int64   `json:"bad,omitempty"`    // the last failure
	Fail   float64 `json:"fail,omitempty"`   // share of failures, as of the later of the two times above; halves every 6 h
	RTT    int     `json:"rtt,omitempty"`    // ms of the last success; 0 when not known
	Streak int     `json:"streak,omitempty"` // failures in a row
	Until  int64   `json:"until,omitempty"`  // the end of the quarantine
	Proved int64   `json:"proved,omitempty"` // the last time data was seen to go through the path (the session's own download)
	Froze  int64   `json:"froze,omitempty"`  // the last time a connection through it started and then carried nothing
}

type network struct {
	Seen  int64           `json:"seen"`
	Paths map[string]Stat `json:"paths"`
}

type file struct {
	Salt string              `json:"salt"`
	Nets map[string]*network `json:"nets"`
}

// Memory is safe for concurrent use. A nil *Memory remembers nothing, and so does an empty network key.
type Memory struct {
	mu    sync.Mutex
	salt  []byte
	nets  map[string]*network
	path  string // "": only in memory
	dirty bool
	timer *time.Timer // a save is waiting
	saved time.Time
	io    sync.Mutex // one file write at a time; taken before mu, and never by a caller of the methods below
}

// Open reads dir/auto.json. A missing or unreadable file is an empty memory. dir "" keeps everything in memory only.
func Open(dir string) *Memory {
	m := &Memory{nets: map[string]*network{}}
	if dir != "" {
		m.path = filepath.Join(dir, "auto.json")
		if data, err := os.ReadFile(m.path); err == nil {
			m.load(data)
		}
	}
	if len(m.salt) == 0 {
		m.salt = make([]byte, 32)
		_, _ = rand.Read(m.salt)
	}
	return m
}

func (m *Memory) load(data []byte) {
	var f file
	if json.Unmarshal(data, &f) != nil {
		return
	}
	salt, err := hex.DecodeString(f.Salt)
	if err != nil || len(salt) != 32 {
		return // without its salt the keys mean nothing
	}
	m.salt = salt
	for key, n := range f.Nets {
		if n == nil || key == "" {
			continue
		}
		clean := &network{Seen: n.Seen, Paths: map[string]Stat{}}
		for id, s := range n.Paths {
			if id != "" {
				s.Fail = math.Min(1, math.Max(0, s.Fail))
				clean.Paths[id] = s
			}
		}
		m.nets[key] = clean
		m.trimPaths(clean)
	}
	for len(m.nets) > maxNets {
		m.evictNet()
	}
}

// Salt is the install's random salt for network keys.
func (m *Memory) Salt() []byte {
	if m == nil {
		return nil
	}
	return m.salt
}

// Success notes that a connection through the path came up; rttMs is its round trip, 0 when not known.
func (m *Memory) Success(net, id string, rttMs int, now time.Time) {
	m.record(net, id, now, func(s *Stat) {
		s.Fail = decayed(*s, now) * (1 - failWeight)
		s.OK, s.Streak, s.Until = now.Unix(), 0, 0
		if rttMs > 0 {
			s.RTT = rttMs
		}
	})
}

// Failure notes that the path did not carry a connection in this network.
func (m *Memory) Failure(net, id string, now time.Time) {
	m.record(net, id, now, func(s *Stat) {
		s.Fail = decayed(*s, now)*(1-failWeight) + failWeight
		s.Bad = now.Unix()
		if s.Streak++; s.Streak >= quarantineAt {
			step := min(s.Streak-quarantineAt, len(quarantine)-1)
			s.Until = now.Add(quarantine[step]).Unix()
		}
	})
}

// Prove notes that data went through the path; it ends a freeze mark.
func (m *Memory) Prove(net, id string, now time.Time) {
	m.record(net, id, now, func(s *Stat) { s.Proved, s.Froze = now.Unix(), 0 })
}

// Freeze notes that a connection through the path started and then carried nothing: a failure of the path, and a mark
// that costs it frozenCost in Score for a day.
func (m *Memory) Freeze(net, id string, now time.Time) {
	m.Failure(net, id, now)
	m.record(net, id, now, func(s *Stat) { s.Froze, s.Proved = now.Unix(), 0 })
}

// Proved says whether data was seen to go through the path in this network within a day.
func (m *Memory) Proved(net, id string, now time.Time) bool {
	if m == nil || net == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nets[net]
	if n == nil {
		return false
	}
	s := n.Paths[id]
	return s.Proved != 0 && now.Sub(time.Unix(s.Proved, 0)) < freshFor
}

func (m *Memory) record(net, id string, now time.Time, update func(*Stat)) {
	if m == nil || net == "" || id == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nets[net]
	if n == nil {
		for len(m.nets) >= maxNets {
			m.evictNet()
		}
		n = &network{Paths: map[string]Stat{}}
		m.nets[net] = n
	}
	n.Seen = now.Unix()
	s := n.Paths[id]
	update(&s)
	n.Paths[id] = s
	m.trimPaths(n)
	m.touch()
}

// Avoid are the paths of the network that are in quarantine now.
func (m *Memory) Avoid(net string, now time.Time) []string {
	if m == nil || net == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	if n := m.nets[net]; n != nil {
		for id, s := range n.Paths {
			if s.Until > now.Unix() {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Known is the best of the candidates that has worked in this network within a day, has not failed since, and is not in
// quarantine. ok is false when there is none.
func (m *Memory) Known(net string, candidates []Path, now time.Time) (id string, ok bool) {
	if m == nil || net == "" {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nets[net]
	if n == nil {
		return "", false
	}
	var bestScore float64
	var bestStat Stat
	for _, c := range candidates {
		s, found := n.Paths[c.ID]
		if !found || s.OK == 0 || now.Sub(time.Unix(s.OK, 0)) >= freshFor || s.Streak > 0 || s.Until > now.Unix() {
			continue
		}
		score := Score(s, c.Via, now)
		if !ok || score < bestScore || score == bestScore && s.OK > bestStat.OK {
			id, ok, bestScore, bestStat = c.ID, true, score, s
		}
	}
	return id, ok
}

// Score is how bad a path looks (lower is better): its round trip, worse the more it failed, plus what a relay or a
// WARP exit costs over a direct path, a penalty for a success that is not recent and one for a freeze within a day.
// ponytail: a round trip never seen counts as 300 ms; the engine hands over none for most protocols yet.
func Score(s Stat, via string, now time.Time) float64 {
	rtt := float64(s.RTT)
	if rtt <= 0 {
		rtt = unknownRTT
	}
	score := rtt * (1 + 3*decayed(s, now))
	switch via {
	case "relay":
		score += 20
	case "warp":
		score += 30
	}
	if s.OK == 0 || now.Sub(time.Unix(s.OK, 0)) > staleAfter {
		score += staleCost
	}
	if s.Froze != 0 && now.Sub(time.Unix(s.Froze, 0)) < freshFor {
		score += frozenCost
	}
	return score
}

// Stats are what is known of each path of the network now (a copy).
func (m *Memory) Stats(net string) map[string]Stat {
	if m == nil || net == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.nets[net]; n != nil {
		return maps.Clone(n.Paths)
	}
	return nil
}

// Keep forgets the paths that are not in ids any more (removed from the subscriptions). An empty list is no news: it is
// what a subscription that failed to load looks like.
func (m *Memory) Keep(ids []string) {
	if m == nil || len(ids) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, n := range m.nets {
		for id := range n.Paths {
			if !slices.Contains(ids, id) {
				delete(n.Paths, id)
				m.touch()
			}
		}
		if len(n.Paths) == 0 {
			delete(m.nets, key)
		}
	}
}

func decayed(s Stat, now time.Time) float64 {
	dt := now.Sub(time.Unix(max(s.OK, s.Bad), 0))
	if dt <= 0 || s.Fail <= 0 {
		return s.Fail
	}
	return s.Fail * math.Pow(0.5, float64(dt)/float64(halfLife))
}

func (m *Memory) evictNet() {
	oldest, key := int64(math.MaxInt64), ""
	for k, n := range m.nets {
		if n.Seen < oldest || n.Seen == oldest && k < key {
			oldest, key = n.Seen, k
		}
	}
	delete(m.nets, key)
}

func (m *Memory) trimPaths(n *network) {
	for len(n.Paths) > maxPaths {
		oldest, key := int64(math.MaxInt64), ""
		for id, s := range n.Paths {
			if at := max(s.OK, s.Bad); at < oldest || at == oldest && id < key {
				oldest, key = at, id
			}
		}
		delete(n.Paths, key)
	}
}

// touch asks for a save: soon, but not within a minute of the last one. The caller holds mu.
func (m *Memory) touch() {
	m.dirty = true
	if m.path == "" || m.timer != nil {
		return
	}
	m.timer = time.AfterFunc(max(0, saveEvery-time.Since(m.saved)), m.Flush)
}

// Flush writes the memory now if it changed. The service calls it when it stops.
func (m *Memory) Flush() {
	if m == nil || m.path == "" {
		return
	}
	m.io.Lock()
	defer m.io.Unlock()
	m.mu.Lock()
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	if !m.dirty {
		m.mu.Unlock()
		return
	}
	data, err := json.Marshal(file{Salt: hex.EncodeToString(m.salt), Nets: m.nets})
	m.dirty, m.saved = false, time.Now()
	m.mu.Unlock()
	if err == nil && save(m.path, data) != nil {
		m.mu.Lock()
		m.dirty = true // the next change tries again
		m.mu.Unlock()
	}
}

// save replaces the file whole: a crash leaves the old one or the new one.
func save(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".auto-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
