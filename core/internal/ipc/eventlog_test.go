package ipc

import (
	"fmt"
	"testing"
)

func TestEventLogKeepsLatest500WithSource(t *testing.T) {
	store := NewLogStore()
	logger := NewEventLogger(nil, store).With("src", "diag")
	for i := 0; i < 502; i++ {
		logger.Info(fmt.Sprintf("entry-%03d", i))
	}
	entries := store.Entries()
	if len(entries) != 500 {
		t.Fatalf("entry count = %d", len(entries))
	}
	if entries[0].Msg != "entry-002" || entries[499].Msg != "entry-501" || entries[0].Src != "diag" {
		t.Fatalf("unexpected retained entries: first=%#v last=%#v", entries[0], entries[499])
	}
}
