package ipc

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCallerTrustDecision(t *testing.T) {
	base := CallerFacts{
		ServicePath:             `C:\Mistgate\mistgate-clientd.exe`,
		CallerPath:              `C:\Mistgate\Mistgate.exe`,
		ServiceSigned:           true,
		ServiceSignatureValid:   true,
		ServiceSignerThumbprint: "AABBCC",
		CallerSigned:            true,
		CallerSignatureValid:    true,
		CallerSignerThumbprint:  "aabbcc",
	}
	tests := []struct {
		name    string
		facts   CallerFacts
		trusted bool
	}{
		{name: "matching valid signer", facts: base, trusted: true},
		{name: "different signer", facts: with(base, func(f *CallerFacts) { f.CallerSignerThumbprint = "112233" })},
		{name: "invalid caller signature", facts: with(base, func(f *CallerFacts) { f.CallerSignatureValid = false })},
		{name: "unsigned caller under signed service", facts: with(base, func(f *CallerFacts) { f.CallerSigned = false })},
		{name: "unsigned development peer beside service", facts: with(base, func(f *CallerFacts) {
			f.ServiceSigned = false
			f.CallerSigned = false
			f.CallerPath = `c:/mistgate/mIsTgAtE.exe`
		}), trusted: true},
		{name: "unsigned peer outside service directory", facts: with(base, func(f *CallerFacts) {
			f.ServiceSigned = false
			f.CallerSigned = false
			f.CallerPath = `C:\Other\Mistgate.exe`
		})},
		{name: "development override", facts: with(base, func(f *CallerFacts) {
			f.ServiceSigned = false
			f.CallerSigned = false
			f.CallerPath = `D:\debug\window.exe`
			f.DevelopmentClientPath = `d:/DEBUG/WINDOW.EXE`
		}), trusted: true},
		{name: "override ignored by signed build", facts: with(base, func(f *CallerFacts) {
			f.CallerSigned = false // an unsigned window: under a signed service only the signer counts, never the path
			f.CallerPath = `D:\debug\window.exe`
			f.DevelopmentClientPath = `D:\debug\window.exe`
		})},
		{name: "invalid service signature", facts: with(base, func(f *CallerFacts) { f.ServiceSignatureValid = false })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsCallerTrusted(test.facts); got != test.trusted {
				t.Fatalf("IsCallerTrusted() = %v, want %v", got, test.trusted)
			}
		})
	}
}

func TestCallerTrustWithSID(t *testing.T) {
	facts := CallerFacts{
		ServicePath:             `C:\Mistgate\mistgate-clientd.exe`,
		CallerPath:              `C:\Mistgate\Mistgate.exe`,
		ServiceSigned:           true,
		ServiceSignatureValid:   true,
		ServiceSignerThumbprint: "AABBCC",
		CallerSigned:            true,
		CallerSignatureValid:    true,
		CallerSignerThumbprint:  "aabbcc",
	}
	allowedSID := "S-1-5-21-111-222-333-1000"
	otherSID := "S-1-12-1-11-22-33-44"
	tests := []struct {
		name    string
		facts   CallerFacts
		sid     string
		list    []string
		trusted bool
	}{
		{name: "empty list permits first trusted account", facts: facts, sid: allowedSID, trusted: true},
		{name: "listed account", facts: facts, sid: allowedSID, list: []string{allowedSID}, trusted: true},
		{name: "unlisted account", facts: facts, sid: otherSID, list: []string{allowedSID}},
		{name: "unreadable account SID", facts: facts, list: []string{allowedSID}},
		{name: "bad path facts", facts: with(facts, func(f *CallerFacts) {
			f.ServiceSigned = false
			f.CallerPath = `C:\Other\Mistgate.exe`
		}), sid: allowedSID, list: []string{allowedSID}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsCallerTrustedForSID(test.facts, test.sid, test.list); got != test.trusted {
				t.Fatalf("IsCallerTrustedForSID() = %v, want %v", got, test.trusted)
			}
		})
	}
}

func TestCallerAccessRecordsOneFirstUseSIDUnderConcurrency(t *testing.T) {
	facts := CallerFacts{
		ServiceSigned:           true,
		ServiceSignatureValid:   true,
		ServiceSignerThumbprint: "aabbcc",
		CallerSigned:            true,
		CallerSignatureValid:    true,
		CallerSignerThumbprint:  "AABBCC",
	}
	sids := []string{
		"S-1-5-21-1-2-3-1000",
		"S-1-12-1-11-22-33-44",
	}
	var writes atomic.Int32
	access := NewCallerAccess(nil, func(got []string) error {
		writes.Add(1)
		if len(got) != 1 {
			t.Errorf("first-use write got %v, want one SID", got)
		}
		return nil
	})

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	var trusted atomic.Int32
	for _, sid := range sids {
		done.Add(1)
		go func(sid string) {
			defer done.Done()
			start.Wait()
			allowed, err := access.IsTrusted(facts, sid)
			if err != nil {
				t.Errorf("IsTrusted() returned a write error: %v", err)
			}
			if allowed {
				trusted.Add(1)
			}
		}(sid)
	}
	start.Done()
	done.Wait()

	if got := writes.Load(); got != 1 {
		t.Fatalf("first-use writes = %d, want exactly one", got)
	}
	if got := trusted.Load(); got != 1 {
		t.Fatalf("concurrently trusted callers = %d, want exactly one", got)
	}
	if got := access.AllowedSIDs(); len(got) != 1 || got[0] != sids[0] && got[0] != sids[1] {
		t.Fatalf("in-memory users = %v, want exactly the winning caller", got)
	}
}

func TestCallerAccessKeepsFirstUseInMemoryWhenWriteFails(t *testing.T) {
	facts := CallerFacts{
		ServiceSigned:           true,
		ServiceSignatureValid:   true,
		ServiceSignerThumbprint: "AABBCC",
		CallerSigned:            true,
		CallerSignatureValid:    true,
		CallerSignerThumbprint:  "aabbcc",
	}
	firstSID := "S-1-5-21-1-2-3-1000"
	secondSID := "S-1-12-1-11-22-33-44"
	writes := 0
	access := NewCallerAccess(nil, func([]string) error {
		writes++
		return errors.New("write failed")
	})
	trusted, err := access.IsTrusted(facts, firstSID)
	if !trusted || err == nil {
		t.Fatalf("first caller = (%v, %v), want trusted with a reported write failure", trusted, err)
	}
	trusted, err = access.IsTrusted(facts, secondSID)
	if trusted || err != nil {
		t.Fatalf("second caller = (%v, %v), want denied without a second write", trusted, err)
	}
	if writes != 1 {
		t.Fatalf("list writes = %d, want one", writes)
	}
}

func TestPipeSDDLForUsers(t *testing.T) {
	first := "S-1-5-21-1-2-3-1000"
	second := "S-1-12-1-11-22-33-44"
	tests := []struct {
		name string
		list []string
		want string
	}{
		{name: "empty", want: PipeSDDL},
		{name: "one SID", list: []string{first}, want: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + first + ")"},
		{name: "two SIDs", list: []string{first, second}, want: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + first + ")(A;;GRGW;;;" + second + ")"},
		{name: "invalid ignored", list: []string{"S-1-5-32-544"}, want: PipeSDDL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := PipeSDDLForUsers(test.list); got != test.want {
				t.Fatalf("PipeSDDLForUsers() = %q, want %q", got, test.want)
			}
		})
	}
}

func with(facts CallerFacts, update func(*CallerFacts)) CallerFacts {
	update(&facts)
	return facts
}
