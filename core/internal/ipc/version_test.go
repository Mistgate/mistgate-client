package ipc

import (
	"testing"

	"github.com/mistgate/mistgate-client/core/internal/version"
)

func TestIPCServiceVersionUsesSharedVersion(t *testing.T) {
	if ServiceVersion != version.Service {
		t.Fatal("IPC service version differs from the shared service version")
	}
}
