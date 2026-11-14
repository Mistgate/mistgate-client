package subs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/ipcsize"
)

func TestProviderFieldsCannotOversizePublicSubscription(t *testing.T) {
	long := strings.Repeat("x", 40000)
	notice, refused := refusedProfile([]any{map[string]any{"server": "0.0.0.0", "name": long}})
	if !refused || len([]rune(notice)) > maxNotice {
		t.Fatal("provider refusal notice was not bounded")
	}
	servers := make([]Server, maxServers)
	for i := range servers {
		servers[i] = Server{
			ID: long, Name: long, Protocol: long, Node: long, Country: long, City: long, Via: long,
			Version: long, Load: long, Label: long, NodeLabel: long, ViaCountry: "US",
		}
	}
	telegram := make([]Telegram, 40)
	for i := range telegram {
		telegram[i] = Telegram{Node: long, City: long, Via: long, Link: "tg://proxy?server=example&secret=" + strings.Repeat("a", 2100)}
	}
	request := &DebugRequest{ID: long, Level: long, Note: long, ExpiresUnix: 1<<62 - 1}
	sub := Subscription{
		ID: long, Kind: long, Name: long, Host: long, Error: long, Notice: long,
		Servers: servers, Telegram: telegram, Debug: &Debug{Intake: true, Request: request},
		ReportLast: &ReportLast{Error: long}, UnsupportedKinds: map[string]int{long: 1, "vless (transport)": 1},
	}
	store := &Store{state: diskState{Subscriptions: []storedSubscription{{Subscription: sub}}}}
	listed := store.List()
	line, err := json.Marshal(map[string]any{"id": 1, "result": map[string]any{"subs": listed}})
	if err != nil {
		t.Fatal("could not encode the bounded subscription list")
	}
	if len(line) > ipcsize.MaxLineBytes {
		t.Fatalf("public subscription list is %d bytes; limit is %d", len(line), ipcsize.MaxLineBytes)
	}
	if len(listed) != 1 || len(listed[0].Servers) == 0 || len(listed[0].Servers) >= maxServers {
		t.Fatalf("the public server list was not shortened to fit its bound")
	}
	got := listed[0]
	if len([]rune(got.Host)) > 64 || len([]rune(got.Servers[0].Node)) > 64 || len([]rune(got.Servers[0].Via)) > 64 ||
		len([]rune(got.Telegram[0].Node)) > 64 || len([]rune(got.Telegram[0].Via)) > 64 || len(got.Telegram[0].Link) > 2048 || len([]rune(got.ReportLast.Error)) > 64 {
		t.Fatal("a provider-controlled public field exceeded its bound")
	}
}
