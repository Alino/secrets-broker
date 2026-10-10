package keepass

import (
	"os"
	"path/filepath"
	"testing"
)

const kdbxPassword = "fixture-master-pw"

func newAdapter(t *testing.T) *Adapter {
	t.Helper()
	db, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "fixture.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db); err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	return &Adapter{
		DBPath:     db,
		PasswordFn: func() (string, error) { return kdbxPassword, nil },
	}
}

func TestResolvePassword(t *testing.T) {
	a := newAdapter(t)
	got, err := a.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if got != "kpxcSecretToken456" {
		t.Fatalf("wrong secret: %q", got)
	}
}

func TestResolveUserName(t *testing.T) {
	a := newAdapter(t)
	got, err := a.Resolve("sec://keepass/GitHub/UserName")
	if err != nil {
		t.Fatal(err)
	}
	if got != "alex@example.com" {
		t.Fatalf("wrong username: %q", got)
	}
}

func TestWrongPasswordStickyFail(t *testing.T) {
	db, _ := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "fixture.kdbx"))
	a := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return "nope", nil }}
	if _, err := a.Resolve("sec://keepass/GitHub/password"); err == nil {
		t.Fatal("expected unlock failure")
	}
	a.PasswordFn = func() (string, error) { return kdbxPassword, nil }
	if _, err := a.Resolve("sec://keepass/GitHub/password"); err == nil {
		t.Fatal("expected sticky failure")
	}
}

func TestUnknownEntry(t *testing.T) {
	a := newAdapter(t)
	if _, err := a.Resolve("sec://keepass/Nope/password"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestParseRef(t *testing.T) {
	if _, _, err := parseRef("sec://opvault/x/y"); err == nil {
		t.Fatal("wrong adapter prefix must fail")
	}
	// field = last segment, entry may contain '/'
	e, f, err := parseRef("sec://keepass/Work/Sub/API/key")
	if err != nil || e != "Work/Sub/API" || f != "key" {
		t.Fatalf("parse wrong: %q %q %v", e, f, err)
	}
}
