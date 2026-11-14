package ipc

import (
	"strings"
	"sync"

	"github.com/mistgate/mistgate-client/core/internal/users"
)

const PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

type CallerFacts struct {
	PID                     uint32
	ServicePath             string
	CallerPath              string
	ServiceSigned           bool
	ServiceSignatureValid   bool
	ServiceSignerThumbprint string
	CallerSigned            bool
	CallerSignatureValid    bool
	CallerSignerThumbprint  string
	DevelopmentClientPath   string
}

func IsCallerTrusted(facts CallerFacts) bool {
	if facts.ServiceSigned {
		return facts.ServiceSignatureValid && facts.CallerSigned && facts.CallerSignatureValid &&
			facts.ServiceSignerThumbprint != "" &&
			strings.EqualFold(facts.ServiceSignerThumbprint, facts.CallerSignerThumbprint)
	}

	if facts.DevelopmentClientPath != "" && sameWindowsPath(facts.CallerPath, facts.DevelopmentClientPath) {
		return true
	}
	base := windowsBase(facts.CallerPath)
	return (strings.EqualFold(base, "Mistgate.exe") || strings.EqualFold(base, "mistgate.exe")) &&
		sameWindowsPath(windowsDir(facts.CallerPath), windowsDir(facts.ServicePath))
}

// IsCallerTrustedForSID is the connection trust decision before any first-use account is recorded.
func IsCallerTrustedForSID(facts CallerFacts, callerSID string, allowedSIDs []string) bool {
	if !IsCallerTrusted(facts) {
		return false
	}
	canonicalSID, ok := users.ValidateSID(callerSID)
	if !ok {
		return false
	}
	return len(allowedSIDs) == 0 || users.Contains(allowedSIDs, canonicalSID)
}

// CallerAccess holds the service's one-time account list for the lifetime of its pipe server.
type CallerAccess struct {
	mu          sync.Mutex
	allowedSIDs []string
	persist     func([]string) error
}

func NewCallerAccess(allowedSIDs []string, persist func([]string) error) *CallerAccess {
	return &CallerAccess{allowedSIDs: normalizeCallerSIDs(allowedSIDs), persist: persist}
}

func (a *CallerAccess) AllowedSIDs() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.allowedSIDs...)
}

// IsTrusted checks path and signature facts, then applies the account list. An empty list uses deliberate
// trust-on-first-use: the first passing caller is recorded under the lock, and the pipe DACL narrows next start.
func (a *CallerAccess) IsTrusted(facts CallerFacts, callerSID string) (bool, error) {
	if a == nil {
		return IsCallerTrusted(facts), nil
	}
	canonicalSID, ok := users.ValidateSID(callerSID)
	if !ok {
		return false, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if !IsCallerTrustedForSID(facts, canonicalSID, a.allowedSIDs) {
		return false, nil
	}
	if len(a.allowedSIDs) > 0 {
		return true, nil
	}

	// The first valid trusted account wins even if its disk write fails. This keeps the running service from
	// admitting another account while allowing service startup to continue.
	a.allowedSIDs = []string{canonicalSID}
	if a.persist == nil {
		return true, nil
	}
	return true, a.persist(append([]string(nil), a.allowedSIDs...))
}

// PipeSDDLForUsers grants the window rights only to listed accounts, or keeps the legacy interactive-user DACL
// while an empty list is in use.
func PipeSDDLForUsers(allowedSIDs []string) string {
	sids := normalizeCallerSIDs(allowedSIDs)
	if len(sids) == 0 {
		return PipeSDDL
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	for _, sid := range sids {
		sddl += "(A;;GRGW;;;" + sid + ")"
	}
	return sddl
}

func normalizeCallerSIDs(sids []string) []string {
	var normalized []string
	for _, sid := range sids {
		canonical, ok := users.ValidateSID(sid)
		if !ok || users.Contains(normalized, canonical) {
			continue
		}
		normalized = append(normalized, canonical)
	}
	return normalized
}

func sameWindowsPath(left, right string) bool {
	return strings.EqualFold(cleanWindowsPath(left), cleanWindowsPath(right))
}

func cleanWindowsPath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	for strings.Contains(path, `\\`) && !strings.HasPrefix(path, `\\`) {
		path = strings.ReplaceAll(path, `\\`, `\`)
	}
	return strings.TrimRight(path, `\`)
}

func windowsBase(path string) string {
	path = cleanWindowsPath(path)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[index+1:]
	}
	return path
}

func windowsDir(path string) string {
	path = cleanWindowsPath(path)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[:index]
	}
	return ""
}
