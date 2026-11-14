package diag

import (
	"strings"
	"testing"
	"time"

	"github.com/mistgate/mistgate-client/core/internal/profile"
	"github.com/mistgate/mistgate-client/core/internal/safe"
)

type recoveryOutput chan string

func (out recoveryOutput) Write(data []byte) (int, error) {
	out <- string(data)
	return len(data), nil
}

func TestRunnerRecoversPanicFromProfileProvider(t *testing.T) {
	previous := safe.Out
	out := make(recoveryOutput, 1)
	safe.Out = out
	defer func() { safe.Out = previous }()

	runner := NewRunner(Config{Profiles: func() ([]profile.Profile, error) {
		panic("provider failed")
	}}, nil)
	runner.Start("sub")
	select {
	case report := <-out:
		if !strings.Contains(report, "panic in diag: string") {
			t.Fatal("the diagnostic panic was not recovered")
		}
	case <-time.After(time.Second):
		t.Fatal("the diagnostic panic was not reported")
	}
}
