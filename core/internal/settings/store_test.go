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
		"kill_switch":  json.RawMessage(`"always"`),
		"lan":          json.RawMessage(`false`),
		"protocol":     json.RawMessage(`"awg"`),
		"game":         json.RawMessage(`true`),
		"route_mode":   json.RawMessage(`"smart"`),
		"route_region": json.RawMessage(`"ru"`),
	}
	if got, err := store.Set(patch); err != nil || got != (Settings{KillSwitch: "always", LAN: false, Protocol: "awg", Game: true, RouteMode: "smart", RouteRegion: "ru", OnServerDown: "reconnect", DNS: "auto"}) {
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
	if got, err := reopened.Set(map[string]json.RawMessage{"route_mode": json.RawMessage(`"selected"`)}); err != nil || got.RouteMode != "selected" {
		t.Fatalf("selected route mode = %#v, %v", got, err)
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

func TestStoreConnectionSettings(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	good := []struct{ key, in, want string }{
		{"dns", `"1.1.1.1"`, "1.1.1.1"},
		{"dns", `" 9.9.9.9 , 2001:4860:4860:0:0:0:0:8888 "`, "9.9.9.9,2001:4860:4860::8888"},
		{"dns", `"::ffff:8.8.8.8"`, "8.8.8.8"},
		{"dns", `"auto"`, "auto"},
	}
	for _, c := range good {
		got, err := store.Set(map[string]json.RawMessage{c.key: json.RawMessage(c.in)})
		if err != nil || got.DNS != c.want {
			t.Fatalf("dns %s = %q, %v; want %q", c.in, got.DNS, err, c.want)
		}
	}
	got, err := store.Set(map[string]json.RawMessage{
		"on_server_down": json.RawMessage(`"next"`), "restore": json.RawMessage(`true`),
		"last_on": json.RawMessage(`true`), "mtu": json.RawMessage(`1400`),
	})
	if err != nil || got.OnServerDown != "next" || !got.Restore || !got.LastOn || got.MTU != 1400 {
		t.Fatalf("Set() = %#v, %v", got, err)
	}
	if got, err = store.Set(map[string]json.RawMessage{"mtu": json.RawMessage(`0`)}); err != nil || got.MTU != 0 {
		t.Fatalf("mtu 0 = %#v, %v", got, err)
	}
	for _, patch := range []map[string]json.RawMessage{
		{"on_server_down": json.RawMessage(`"fastest"`)},
		{"restore": json.RawMessage(`null`)},
		{"mtu": json.RawMessage(`1279`)},
		{"mtu": json.RawMessage(`1501`)},
		{"mtu": json.RawMessage(`null`)},
		{"mtu": json.RawMessage(`1400.5`)},
		{"mtu": json.RawMessage(`"1400"`)},
		{"dns": json.RawMessage(`""`)},
		{"dns": json.RawMessage(`null`)},
		{"dns": json.RawMessage(`"1.1.1.1,"`)},
		{"dns": json.RawMessage(`"1.1.1.1,8.8.8.8,9.9.9.9"`)},
		{"dns": json.RawMessage(`"1.1.1.1:53"`)},
		{"dns": json.RawMessage(`"dns.example"`)},
		{"dns": json.RawMessage(`"0.0.0.0"`)},
		{"dns": json.RawMessage(`"::"`)},
		{"dns": json.RawMessage(`"127.0.0.1"`)},
		{"dns": json.RawMessage(`"::1"`)},
		{"dns": json.RawMessage(`"fe80::1%eth0"`)},
	} {
		if _, err := store.Set(patch); err != ErrBadParams {
			t.Fatalf("Set(%s) error = %v, want ErrBadParams", patch, err)
		}
	}
	if addrs := (Settings{DNS: "9.9.9.9,2001:db8::1"}).DNSAddrs(); len(addrs) != 2 || addrs[1].String() != "2001:db8::1" {
		t.Fatalf("DNSAddrs = %v", addrs)
	}
	if addrs := Defaults().DNSAddrs(); addrs != nil {
		t.Fatalf("auto DNSAddrs = %v, want nil", addrs)
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
		{"route_mode": json.RawMessage(`"regional"`)},
		{"route_region": json.RawMessage(`"RU"`)},
		{"route_region": json.RawMessage(`"usa"`)},
		{"route_region": json.RawMessage(`"u1"`)},
	} {
		if _, err := store.Set(patch); err != ErrBadParams {
			t.Fatalf("Set(%v) error = %v, want ErrBadParams", patch, err)
		}
	}
	if got := store.Get(); got != Defaults() {
		t.Fatalf("invalid patch changed settings: %#v", got)
	}
}
