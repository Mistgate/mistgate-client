package main

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/session"
	"github.com/mistgate/mistgate-client/core/internal/settings"
	"github.com/mistgate/mistgate-client/core/internal/subs"
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

func TestSavedServerGone(t *testing.T) {
	list := []profile.Profile{{ID: "a", Sub: "s1", Protocol: "awg"}}
	for _, c := range []struct {
		name string
		s    settings.Settings
		want bool
	}{
		{"the server is there", settings.Settings{LastServer: "a"}, false},
		{"the server is there in its subscription", settings.Settings{LastServer: "a", LastSub: "s1"}, false},
		{"auto and a server exists", settings.Settings{LastServer: "auto"}, false},
		{"the server was removed", settings.Settings{LastServer: "b"}, true},
		{"the subscription was removed", settings.Settings{LastServer: "a", LastSub: "s2"}, true},
	} {
		if got := savedServerGone(c.s, func() ([]profile.Profile, error) { return list, nil }); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if savedServerGone(settings.Settings{LastServer: "b"}, func() ([]profile.Profile, error) { return nil, errors.New("unreadable") }) {
		t.Error("unreadable profiles: the engine decides, the resume goes on")
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

func TestRefreshOnRejectionAsksOncePerWindow(t *testing.T) {
	rejected := func(state string) session.Event {
		return session.Event{Name: "status", Data: session.Status{State: state, Error: "auth_rejected", ServerID: "path-a"}}
	}
	list := []subs.Subscription{{ID: "s1", Servers: []subs.Server{{ID: "path-a"}}}, {ID: "s2"}}
	at := time.Unix(1_700_000_000, 0)
	var asked []string
	statuses, done := make(chan session.Event), make(chan struct{})
	go func() {
		defer close(done)
		refreshOnRejection(statuses, func(serverID string) string { return subscriptionOf(list, serverID, "") },
			func(sub string) { asked = append(asked, sub) }, func() time.Time { return at })
	}()
	// an event that is no status: once the loop has taken it, it is done with the one before
	send := func(event session.Event) {
		statuses <- event
		statuses <- session.Event{Name: "log"}
	}
	send(rejected("reconnecting"))
	send(rejected("reconnecting"))
	send(rejected("error"))
	if !slices.Equal(asked, []string{"s1"}) {
		t.Fatalf("refreshed %v, want s1 once", asked)
	}
	at = at.Add(refreshAfterRejection - time.Second)
	send(rejected("reconnecting"))
	if len(asked) != 1 {
		t.Fatalf("a refusal inside the window refreshed again: %v", asked)
	}
	at = at.Add(time.Second)
	send(rejected("reconnecting"))
	close(statuses)
	<-done
	if !slices.Equal(asked, []string{"s1", "s1"}) {
		t.Fatalf("refreshed %v, want s1 again once the window is over", asked)
	}
}

func TestRefreshOnRejectionIgnoresOtherStatuses(t *testing.T) {
	events := []session.Event{
		{Name: "status", Data: session.Status{State: "reconnecting", Error: "no_server_answers", ServerID: "path-a"}},
		{Name: "status", Data: session.Status{State: "connected", ServerID: "path-a"}},
		{Name: "status", Data: session.Status{State: "blocked", Error: "auth_rejected", ServerID: "path-a"}},
		{Name: "status", Data: session.Status{State: "reconnecting", Error: "auth_rejected"}}, // no server, no last subscription
	}
	statuses := make(chan session.Event, len(events))
	for _, event := range events {
		statuses <- event
	}
	close(statuses)
	refreshOnRejection(statuses, func(string) string { return "" }, func(sub string) { t.Errorf("refreshed %q", sub) }, time.Now)
}

func TestSubscriptionOf(t *testing.T) {
	list := []subs.Subscription{{ID: "s1", Servers: []subs.Server{{ID: "path-a"}}}, {ID: "s2", Servers: []subs.Server{{ID: "path-b"}}}}
	for _, c := range []struct{ server, last, want string }{
		{"path-b", "s1", "s2"}, // the path in use wins over the setting
		{"", "s1", "s1"},       // a first connect that failed
		{"gone", "s2", "s2"},
		{"", "", ""},
	} {
		if got := subscriptionOf(list, c.server, c.last); got != c.want {
			t.Errorf("subscriptionOf(%q, %q) = %q, want %q", c.server, c.last, got, c.want)
		}
	}
}
