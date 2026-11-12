package ipc

import (
	"context"
	"testing"
)

// A call that panics (here: a server with nothing behind it) is that call's error, not a crash.
func TestDispatchSurvivesPanic(t *testing.T) {
	_, _, err := (&Server{}).dispatch(context.Background(), Request{Method: "status"}, true)
	if err == nil || err.Code != "service_error" {
		t.Fatalf("err = %+v; want service_error", err)
	}
}
