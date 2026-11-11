package engine

import (
	"testing"
	"time"
)

func TestDebounceDelay(t *testing.T) {
	last := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	quiet := time.Second
	if got := debounceDelay(last, last.Add(250*time.Millisecond), quiet); got != 750*time.Millisecond {
		t.Fatalf("delay after first notification = %s, want 750ms", got)
	}
	burst := last.Add(600 * time.Millisecond)
	if got := debounceDelay(burst, last.Add(900*time.Millisecond), quiet); got != 700*time.Millisecond {
		t.Fatalf("delay after burst notification = %s, want 700ms", got)
	}
	if got := debounceDelay(burst, last.Add(1600*time.Millisecond), quiet); got != 0 {
		t.Fatalf("delay after quiet period = %s, want 0", got)
	}
}
