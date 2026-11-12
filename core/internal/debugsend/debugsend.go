// Package debugsend builds the debug bundle the person may send to the panel (docs/client-api.md, "debug"): NDJSON
// lines in the panel's schema, scrubbed once more, gzipped, within the panel's limits.
package debugsend

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mistgate/mistgate-client/core/internal/diag"
)

// The panel's limits.
const (
	maxWire     = 1 << 20
	maxRaw      = 4 << 20
	maxLines    = 20000
	maxLine     = 8192
	maxMsg      = 1024
	maxNote     = 1000
	maxKV       = 16
	maxValue    = 160
	logWindow   = 24 * time.Hour
	removedText = "[removed]"
)

var ErrTooLarge = errors.New("bundle too large")

// Line is one NDJSON line.
type Line struct {
	TS  int64             `json:"ts"` // unix ms
	Lvl string            `json:"lvl"`
	Src string            `json:"src"`
	Msg string            `json:"msg"`
	KV  map[string]string `json:"kv,omitempty"`
}

// Entry is one line of the service log.
type Entry struct {
	TMS             int64
	Level, Src, Msg string
}

// Input is everything a bundle is made of. Parts are "system", "checks" and "log".
type Input struct {
	Now                            time.Time
	Parts                          []string
	Note                           string
	Version, Mode, State, Protocol string
	Checks                         *diag.Result      // the last finished check; nil when none ran
	Vias                           map[string]string // server (path) id -> direct, relay or warp
	Logs                           []Entry
}

type Bundle struct {
	Lines []Line
	GZ    []byte
}

type item struct {
	line Line
	raw  []byte
	log  bool // may be dropped when the bundle is too big
}

var allowedKV = map[string]bool{"path": true, "server": true, "protocol": true, "via": true, "engine": true, "phase": true,
	"state": true, "reason": true, "code": true, "err": true, "mode": true, "version": true, "count": true, "ms": true,
	"bytes": true, "attempt": true, "net": true, "event": true, "status": true, "http": true}

var (
	srcName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	reLink  = regexp.MustCompile(`\S*://\S*`)
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reUser  = regexp.MustCompile(`(?i)(?:[a-z]:)?[\\/]+users[\\/]+[^"'<>|]*`)
	reMAC   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	reIPv4  = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	reToken = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
	reIPv6  = regexp.MustCompile(`(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|::)`)
	// any path on a drive (a program's file) and any dotted name that ends like a host name: the log should hold
	// neither, and a method or file name lost to this costs less than a site name sent
	// A path may hold spaces (a person's name, "Program Files"), so it runs to the end of the text or to a quote.
	rePath    = regexp.MustCompile(`(?i)(?:\b[a-z]:[\\/]|\\\\|\\device\\)[^"'<>|]*`)
	reHost    = regexp.MustCompile(`(?:[\p{L}0-9-]+\.)+\p{L}{2,}`)
	scrubbers = []*regexp.Regexp{reLink, reEmail, reUser, rePath, reMAC, reHost}
)

// scrub takes out what must not leave the machine: addresses, links, e-mail addresses, user paths, MAC addresses and
// long tokens. The logs should be clean already; this is the second lock.
func scrub(text string) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(text, "?"))
	for _, re := range scrubbers {
		text = re.ReplaceAllString(text, removedText)
	}
	text = reIPv4.ReplaceAllString(text, removedText) // first: an IPv4 tail inside an IPv6 address goes whole
	text = reIPv6.ReplaceAllString(text, removedText)
	return reToken.ReplaceAllString(text, removedText)
}

// cut keeps at most n bytes, ending on a character.
func cut(text string, n int) string {
	if len(text) <= n {
		return text
	}
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n]
}

func level(text string) string {
	switch text = strings.ToLower(text); text {
	case "debug", "info", "error":
		return text
	case "warn", "warning":
		return "warn"
	}
	return "info"
}

func clean(src string) string {
	if src = strings.ToLower(src); srcName.MatchString(src) {
		return src
	}
	return "core"
}

// line makes a wire line from raw parts: msg and every value pass through scrub, the keys are the allowed ones.
func line(ts int64, lvl, src, msg string, kv map[string]string) Line {
	l := Line{TS: ts, Lvl: level(lvl), Src: clean(src), Msg: cut(scrub(msg), maxMsg)}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		if allowedKV[k] && kv[k] != "" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys[:min(len(keys), maxKV)] {
		if l.KV == nil {
			l.KV = map[string]string{}
		}
		l.KV[k] = cut(scrub(kv[k]), maxValue)
	}
	return l
}

// encode is the line as the panel reads it (with its newline); nil when it cannot be made small enough.
func encode(l Line) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(l)
	if buf.Len() > maxLine && l.KV != nil {
		l.KV = nil
		return encode(l)
	}
	if buf.Len() > maxLine {
		return nil
	}
	return buf.Bytes()
}

// Build makes the bundle. A part that is not known is an error.
func Build(in Input) (Bundle, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	var items []item
	add := func(l Line, log bool) {
		if raw := encode(l); raw != nil {
			items = append(items, item{l, raw, log})
		}
	}
	for _, part := range in.Parts {
		switch part {
		case "system":
			msg := fmt.Sprintf("mistgate %s %s %s %s", in.Version, runtime.GOOS, osBuild(), runtime.GOARCH)
			add(line(now.UnixMilli(), "info", "system", msg, map[string]string{"version": in.Version, "mode": in.Mode, "state": in.State, "protocol": in.Protocol}), false)
		case "checks":
			// a check from days ago says nothing about now, and the panel refuses old lines
			if r := in.Checks; r != nil && (r.AtUnix == 0 || now.Sub(time.Unix(r.AtUnix, 0)) <= logWindow) {
				ts := now.UnixMilli()
				if r.AtUnix > 0 {
					ts = r.AtUnix * 1000
				}
				for _, verdict := range [][2]string{{"route", r.Route.Verdict}, {"udp", r.UDP.Verdict}, {"nat", r.NAT.Verdict}, {"dns", r.DNS.Verdict}, {"foreign", r.Foreign.Verdict}, {"freeze", r.Freeze.Verdict}} {
					if verdict[1] != "" {
						add(line(ts, "info", "check", "network "+verdict[0], map[string]string{"status": verdict[1]}), false)
					}
				}
				for _, server := range r.Servers {
					add(line(ts, "info", "check", "server path", map[string]string{"server": server.ID, "protocol": server.Protocol,
						"via": in.Vias[server.ID], "status": server.Verdict, "reason": server.Reason, "ms": fmt.Sprint(server.RTTMS)}), false)
				}
			}
		case "log":
			since, until := now.Add(-logWindow).UnixMilli(), now.Add(24*time.Hour).UnixMilli()
			for _, e := range in.Logs {
				if e.TMS >= since && e.TMS <= until {
					add(line(e.TMS, e.Level, e.Src, e.Msg, nil), true)
				}
			}
		default:
			return Bundle{}, fmt.Errorf("unknown part %q", part)
		}
	}
	if note := strings.TrimSpace(in.Note); note != "" {
		l := line(now.UnixMilli(), "info", "note", "", nil)
		l.Msg = cut(scrub(note), maxNote)
		add(l, false)
	}
	slices.SortStableFunc(items, func(a, b item) int {
		switch {
		case a.line.TS < b.line.TS:
			return -1
		case a.line.TS > b.line.TS:
			return 1
		}
		return 0
	})
	for {
		raw := 0
		for _, it := range items {
			raw += len(it.raw)
		}
		if raw <= maxRaw && len(items) <= maxLines {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			for _, it := range items {
				_, _ = w.Write(it.raw)
			}
			_ = w.Close()
			if buf.Len() <= maxWire {
				lines := make([]Line, len(items))
				for i, it := range items {
					lines[i] = it.line
				}
				return Bundle{Lines: lines, GZ: buf.Bytes()}, nil
			}
		}
		// ponytail: drops an eighth of the log lines (the oldest) per round; a smarter cut if bundles are often big.
		drop := max(1, len(items)/8)
		kept := items[:0]
		for _, it := range items {
			if it.log && drop > 0 {
				drop--
				continue
			}
			kept = append(kept, it)
		}
		if len(kept) == len(items) {
			return Bundle{}, ErrTooLarge
		}
		items = kept
	}
}
