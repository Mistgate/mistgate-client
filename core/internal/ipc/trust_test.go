package ipc

import "testing"

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

func with(facts CallerFacts, update func(*CallerFacts)) CallerFacts {
	update(&facts)
	return facts
}
