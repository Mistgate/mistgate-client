package ipc

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"
)

type eventLogHandler struct {
	inner   slog.Handler
	publish func(any)
}

func NewEventLogger(publish func(any)) *slog.Logger {
	inner := slog.NewTextHandler(os.Stderr, nil)
	return slog.New(&eventLogHandler{inner: inner, publish: publish})
}

func (h *eventLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *eventLogHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.inner.Handle(ctx, record)
	if h.publish != nil {
		when := record.Time
		if when.IsZero() {
			when = time.Now()
		}
		h.publish(map[string]any{
			"t_unix_ms": when.UnixMilli(),
			"level":     strings.ToLower(record.Level.String()),
			"msg":       record.Message,
		})
	}
	return err
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{inner: h.inner.WithAttrs(attrs), publish: h.publish}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{inner: h.inner.WithGroup(name), publish: h.publish}
}
