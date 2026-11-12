package ipc

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	TUnixMS int64  `json:"t_unix_ms"`
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	Src     string `json:"src"`
}

type LogStore struct {
	mu      sync.Mutex
	entries []LogEntry
}

func NewLogStore() *LogStore { return &LogStore{} }

func (s *LogStore) Entries() []LogEntry {
	if s == nil {
		return []LogEntry{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]LogEntry, len(s.entries))
	copy(entries, s.entries)
	return entries
}

// Clear forgets every entry.
func (s *LogStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.entries = nil
	s.mu.Unlock()
}

type eventLogHandler struct {
	inner   slog.Handler
	publish func(any)
	store   *LogStore
	src     string
}

func NewEventLogger(publish func(any), stores ...*LogStore) *slog.Logger {
	var store *LogStore
	if len(stores) > 0 {
		store = stores[0]
	}
	inner := slog.NewTextHandler(os.Stderr, nil)
	return slog.New(&eventLogHandler{inner: inner, publish: publish, store: store, src: "ipc"})
}

func (h *eventLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *eventLogHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.inner.Handle(ctx, record)
	when := record.Time
	if when.IsZero() {
		when = time.Now()
	}
	entry := LogEntry{
		TUnixMS: when.UnixMilli(),
		Level:   strings.ToLower(record.Level.String()),
		Msg:     record.Message,
		Src:     h.source(record),
	}
	if h.store != nil {
		h.store.add(entry)
	}
	if h.publish != nil {
		h.publish(map[string]any{
			"t_unix_ms": when.UnixMilli(),
			"level":     entry.Level,
			"msg":       entry.Msg,
			"src":       entry.Src,
		})
	}
	return err
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	src := h.src
	for _, attr := range attrs {
		if attr.Key == "src" && attr.Value.Kind() == slog.KindString {
			src = attr.Value.String()
		}
	}
	return &eventLogHandler{inner: h.inner.WithAttrs(attrs), publish: h.publish, store: h.store, src: src}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{inner: h.inner.WithGroup(name), publish: h.publish, store: h.store, src: h.src}
}

func (h *eventLogHandler) source(record slog.Record) string {
	src := h.src
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "src" && attr.Value.Kind() == slog.KindString {
			src = attr.Value.String()
		}
		return true
	})
	return src
}

func (s *LogStore) add(entry LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) < 500 {
		s.entries = append(s.entries, entry)
		return
	}
	copy(s.entries, s.entries[1:])
	s.entries[len(s.entries)-1] = entry
}
