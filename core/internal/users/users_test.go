package users

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidateSID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{name: "domain user", input: "S-1-5-21-111-222-333-1000", want: "S-1-5-21-111-222-333-1000", valid: true},
		{name: "local user", input: "S-1-5-21-1-2-3-1001", want: "S-1-5-21-1-2-3-1001", valid: true},
		{name: "Entra user", input: "S-1-12-1-123-456-789-1011", want: "S-1-12-1-123-456-789-1011", valid: true},
		{name: "canonicalizes numbers", input: "s-01-05-021-001-002-003-01000", want: "S-1-5-21-1-2-3-1000", valid: true},
		{name: "system", input: "S-1-5-18"},
		{name: "builtin group", input: "S-1-5-32-544"},
		{name: "other authority", input: "S-1-5-19"},
		{name: "missing RID", input: "S-1-5-21-1-2-3-0"},
		{name: "domain shape incomplete", input: "S-1-5-21-1-2-1000"},
		{name: "Entra shape incomplete", input: "S-1-12-1-123"},
		{name: "numeric overflow", input: "S-1-5-21-1-2-4294967296-1000"},
		{name: "non-numeric", input: "S-1-5-21-1-2-name-1000"},
		{name: "whitespace", input: " S-1-5-21-1-2-3-1000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := ValidateSID(test.input)
			if valid != test.valid || got != test.want {
				t.Fatalf("ValidateSID(%q) = (%q, %v), want (%q, %v)", test.input, got, valid, test.want, test.valid)
			}
		})
	}
}

func TestReadWriteUsers(t *testing.T) {
	directory := t.TempDir()
	if got, err := Read(directory); err != nil || len(got) != 0 {
		t.Fatalf("Read missing users file = (%v, %v), want empty list and no error", got, err)
	}

	want := []string{"S-1-5-21-1-2-3-1000", "S-1-12-1-11-22-33-44"}
	if err := Write(directory, want); err != nil {
		t.Fatal("Write users file failed")
	}
	got, err := Read(directory)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Read after Write = (%v, %v), want (%v, nil)", got, err, want)
	}

	if err := os.WriteFile(filepath.Join(directory, fileName), []byte("garbage\nS-1-5-32-544\nS-1-5-21-1-2-3-1000\n"), 0600); err != nil {
		t.Fatal("write malformed users fixture failed")
	}
	got, err = Read(directory)
	if err != nil || !reflect.DeepEqual(got, want[:1]) {
		t.Fatalf("Read with invalid lines = (%v, %v), want one valid SID and no error", got, err)
	}
}
