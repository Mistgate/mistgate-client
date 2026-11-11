//go:build windows

package main

import (
	"testing"
	"time"
)

func TestSleptDuration(t *testing.T) {
	resume := time.Date(2026, time.January, 1, 0, 1, 0, 0, time.UTC)
	if got := sleptDuration(time.Time{}, resume); got != 120*time.Second {
		t.Fatalf("unknown sleep duration = %s, want 2m", got)
	}
	suspend := resume.Add(-75 * time.Second)
	if got := sleptDuration(suspend, resume); got != 75*time.Second {
		t.Fatalf("sleep duration = %s, want 75s", got)
	}
}
