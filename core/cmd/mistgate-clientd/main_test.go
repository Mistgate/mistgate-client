package main

import (
	"testing"

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
