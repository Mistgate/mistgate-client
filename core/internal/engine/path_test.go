package engine

import (
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

func TestPathChanged(t *testing.T) {
	started := profile.Profile{ID: "a", Name: "Alpha", Sub: "sub", Protocol: "hysteria2", Hy2: &profile.Hy2{Host: "a.example", Port: 443}}
	with := func(edit func(*profile.Profile)) []profile.Profile {
		p := started
		hy2 := *started.Hy2
		p.Hy2 = &hy2
		edit(&p)
		return []profile.Profile{{ID: "other", Sub: "sub"}, p}
	}
	tests := []struct {
		name     string
		profiles []profile.Profile
		want     bool
	}{
		{"same", with(func(*profile.Profile) {}), false},
		{"renamed", with(func(p *profile.Profile) { p.Name = "Beta" }), false},
		{"port changed", with(func(p *profile.Profile) { p.Hy2.Port = 8443 }), true},
		{"gone", []profile.Profile{{ID: "other", Sub: "sub"}}, true},
		{"moved to another subscription", with(func(p *profile.Profile) { p.Sub = "elsewhere" }), true},
	}
	for _, test := range tests {
		if got := pathChanged(started, test.profiles); got != test.want {
			t.Errorf("%s: pathChanged = %v, want %v", test.name, got, test.want)
		}
	}
}
