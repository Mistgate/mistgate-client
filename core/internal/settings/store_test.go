package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTripAndChanges(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Get(); got != Defaults() {
		t.Fatalf("initial settings = %#v, want defaults", got)
	}
	patch := map[string]json.RawMessage{
		"kill_switch": json.RawMessage(`"always"`),
		"lan":         json.RawMessage(`false`),
		"protocol":    json.RawMessage(`"awg"`),
		"game":        json.RawMessage(`true`),
	}
	if got, err := store.Set(patch); err != nil || got != (Settings{KillSwitch: "always", LAN: false, Protocol: "awg", Game: true}) {
		t.Fatalf("Set() = %#v, %v", got, err)
	}
	select {
	case <-store.Changes():
	default:
		t.Fatal("Set() did not signal Changes")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Get(); got != store.Get() {
		t.Fatalf("reopened settings = %#v, want %#v", got, store.Get())
	}
}

func TestStoreDefaultsOnBrokenFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(`{"kill_switch":`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Get(); got != Defaults() {
		t.Fatalf("settings = %#v, want defaults", got)
	}
}

func TestStoreRejectsUnknownAndBadValues(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, patch := range []map[string]json.RawMessage{
		{"unknown": json.RawMessage(`true`)},
		{"lan": json.RawMessage(`null`)},
		{"kill_switch": json.RawMessage(`"sometimes"`)},
	} {
		if _, err := store.Set(patch); err != ErrBadParams {
			t.Fatalf("Set(%v) error = %v, want ErrBadParams", patch, err)
		}
	}
	if got := store.Get(); got != Defaults() {
		t.Fatalf("invalid patch changed settings: %#v", got)
	}
}
