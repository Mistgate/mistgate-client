package main

import (
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
)

func TestShouldConnectAtStart(t *testing.T) {
	for _, c := range []struct {
		name string
		s    settings.Settings
		want bool
	}{
		{"nothing set", settings.Settings{LastServer: "a"}, false},
		{"autoconnect", settings.Settings{LastServer: "a", Autoconnect: true}, true},
		{"autoconnect, user had disconnected", settings.Settings{LastServer: "a", Autoconnect: true, LastOn: false}, true},
		{"restore and was on", settings.Settings{LastServer: "a", Restore: true, LastOn: true}, true},
		{"restore but was off", settings.Settings{LastServer: "a", Restore: true}, false},
		{"was on but restore is off", settings.Settings{LastServer: "a", LastOn: true}, false},
		{"no last server", settings.Settings{Autoconnect: true, Restore: true, LastOn: true}, false},
	} {
		if got := shouldConnectAtStart(c.s); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestShouldResumeAtStart(t *testing.T) {
	for _, c := range []struct {
		name string
		s    settings.Settings
		want bool
	}{
		{"was on, kill switch while", settings.Settings{LastServer: "a", LastUp: true, KillSwitch: "while"}, true},
		{"was on, kill switch always", settings.Settings{LastServer: "a", LastUp: true, KillSwitch: "always"}, true},
		{"was on, kill switch off", settings.Settings{LastServer: "a", LastUp: true, KillSwitch: "off"}, false},
		{"asked for, never up", settings.Settings{LastServer: "a", LastOn: true, KillSwitch: "while"}, false},
		{"was off (the person disconnected), kill switch while", settings.Settings{LastServer: "a", KillSwitch: "while"}, false},
		{"was off, kill switch always", settings.Settings{LastServer: "a", KillSwitch: "always"}, false},
		{"was on, no last server", settings.Settings{LastUp: true, KillSwitch: "while"}, false},
		{"restore and autoconnect do not matter", settings.Settings{LastServer: "a", LastUp: true, KillSwitch: "while", Restore: false, Autoconnect: false}, true},
	} {
		if got := shouldResumeAtStart(c.s); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestKeepLastUpFollowsTheSession(t *testing.T) {
	store, err := settings.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	step := func(state string, want bool) {
		t.Helper()
		events := make(chan session.Event, 1)
		events <- session.Event{Name: "status", Data: session.Status{State: state}}
		close(events)
		keepLastUp(events, store)
		if got := store.Get().LastUp; got != want {
			t.Fatalf("after %q last_up = %v, want %v", state, got, want)
		}
	}
	step("connecting", false)
	step("error", false) // a connect that never came up
	step("connected", true)
	step("reconnecting", true)
	step("blocked", true) // held: the next start holds too
	step("off", true)     // the service stopping says "off" as well
	step("error", false)
}
