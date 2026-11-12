// Package safe keeps a panic in the work for one flow or one request from taking the whole service down.
// ponytail: only such goroutines use it. The loops everything hangs on (the packet pump, the session manager) still
// crash the process on purpose: Windows restarts the service, which is a cleaner state than a tunnel left half alive.
package safe

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
)

// Recover is deferred directly: `defer safe.Recover("socks")`.
func Recover(what string) {
	if r := recover(); r != nil {
		Report(what, r)
	}
}

// Report writes the panic and its stack where a crash would have gone (stderr is crash.log in the service); the log
// the window shows gets the place only, as the value may name a host.
func Report(what string, r any) {
	fmt.Fprintf(os.Stderr, "panic in %s: %v\n%s\n", what, r, debug.Stack())
	slog.Error("a task failed and was dropped", "in", what)
}
