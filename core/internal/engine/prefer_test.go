package engine

import (
	"context"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/profile"
)

func TestAutoPrefer(t *testing.T) {
	fake := NewFake(FakeConfig{})
	fake.SetProfiles(
		profile.Profile{ID: "p1", Sub: "sub", Protocol: "hysteria2"},
		profile.Profile{ID: "p2", Sub: "sub", Protocol: "hysteria2", Via: "relay"},
		profile.Profile{ID: "p3", Sub: "sub", Protocol: "hysteria2"},
	)
	tests := []struct {
		name   string
		target Target
		want   string
	}{
		{"no hint", Target{}, "p1"},
		{"the preferred path", Target{Prefer: "p3"}, "p3"},
		{"a preferred path to avoid", Target{Prefer: "p3", Avoid: []string{"p3", "p1"}}, "p2"},
		{"a preferred path that is not there", Target{Prefer: "gone"}, "p1"},
	}
	for _, test := range tests {
		test.target.Server, test.target.Sub = "auto", "sub"
		info, err := fake.Start(context.Background(), test.target, nil)
		if err != nil || info.ServerID != test.want {
			t.Errorf("%s: went to %q (%v), want %q", test.name, info.ServerID, err, test.want)
		}
	}
	// a named server takes no hint
	if info, _ := fake.Start(context.Background(), Target{Server: "p2", Sub: "sub", Prefer: "p3"}, nil); info.ServerID != "p2" {
		t.Errorf("a named server went to %q", info.ServerID)
	}
	selection, ok := fake.Select(Target{Server: "auto", Sub: "sub"})
	if !ok || len(selection.Via) != 1 || selection.Via["p2"] != "relay" {
		t.Errorf("via = %v", selection.Via)
	}
}
