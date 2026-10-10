package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	keepassadapter "github.com/vaultcore/secrets-broker/internal/adapters/keepass"
)

const (
	fixtureMasterPW = "fixture-master-pw"  // testdata/fixture.kdbx (public test constant)
	fixtureSecret   = "kpxcSecretToken456" // its GitHub/password value
)

func TestProbeReportsExistenceNeverValues(t *testing.T) {
	db, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "fixture.kdbx"))
	if _, err := os.Stat(db); err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	a := &keepassadapter.Adapter{DBPath: db, PasswordFn: func() (string, error) { return fixtureMasterPW, nil }}

	var out bytes.Buffer
	if err := probe(a.Resolve, "password", []string{"GitHub", "NoSuchEntry"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := probe(a.Resolve, "otp", []string{"GitHub"}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"FOUND     sec://keepass/GitHub/password",
		"NO_ENTRY  NoSuchEntry",
		"NO_FIELD  GitHub",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, fixtureSecret) {
		t.Fatal("probe printed a secret value")
	}
}

// An unlock failure must stop the probe, not be reported as NO_ENTRY.
func TestProbeFailsOnUnlockError(t *testing.T) {
	db, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "fixture.kdbx"))
	if _, err := os.Stat(db); err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	a := &keepassadapter.Adapter{DBPath: db, PasswordFn: func() (string, error) { return "wrong", nil }}
	var out bytes.Buffer
	if err := probe(a.Resolve, "password", []string{"GitHub"}, &out); err == nil {
		t.Fatalf("expected an unlock error, got output %q", out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("printed an answer despite failing to unlock: %q", out.String())
	}
}
