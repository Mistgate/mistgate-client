package safe

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchClientRefusesLinkLocal(t *testing.T) {
	for address, refused := range map[string]bool{
		"169.254.169.254:80": true, "[fe80::1%1]:443": true, "[::ffff:169.254.1.1]:80": true,
		"127.0.0.1:80": false, "192.168.1.10:443": false, "[2001:db8::1]:443": false, "203.0.113.5:443": false,
	} {
		if got := noLinkLocal("tcp", address, nil) != nil; got != refused {
			t.Errorf("%s: refused = %v, want %v", address, got, refused)
		}
	}
	// through the client itself: the refusal reaches the caller, and a loopback server still answers
	client := FetchClient(3 * time.Second)
	if _, err := client.Get("http://169.254.169.254/latest/"); !errors.Is(err, ErrLinkLocal) {
		t.Errorf("metadata address: %v, want the refusal", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	response, err := client.Get(server.URL)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("loopback server: %v", err)
	}
	_ = response.Body.Close()
}
