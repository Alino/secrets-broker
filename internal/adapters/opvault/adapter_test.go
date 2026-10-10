package opvaultadapter

import (
	"os"
	"path/filepath"
	"testing"
)

const fixturePassword = "correct horse battery staple"
const fixtureSecret = "ghp_SuperSecretFixtureToken123"

func newAdapter(t *testing.T) *Adapter {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "fixture_vault"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "default", "profile.js")); err != nil {
		t.Skipf("fixture vault not present: %v", err)
	}
	return &Adapter{
		Dir:        dir,
		PasswordFn: func() (string, error) { return fixturePassword, nil },
	}
}

func TestResolvePasswordField(t *testing.T) {
	a := newAdapter(t)
	got, err := a.Resolve("sec://opvault/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureSecret {
		t.Fatalf("wrong secret: %q", got)
	}
}

func TestResolveByUsernameDesignation(t *testing.T) {
	a := newAdapter(t)
	got, err := a.Resolve("sec://opvault/github/username") // case-insensitive title
	if err != nil {
		t.Fatal(err)
	}
	if got != "alex@example.com" {
		t.Fatalf("wrong username: %q", got)
	}
}

func TestResolveByNameField(t *testing.T) {
	a := newAdapter(t)
	got, err := a.Resolve("sec://opvault/GitHub/password") // name == 'password' matches directly
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureSecret {
		t.Fatalf("wrong secret: %q", got)
	}
}

func TestWrongPasswordFailsClosedAndSticky(t *testing.T) {
	dir, _ := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "fixture_vault"))
	a := &Adapter{
		Dir:        dir,
		PasswordFn: func() (string, error) { return "wrong-password", nil },
	}
	if _, err := a.Resolve("sec://opvault/GitHub/password"); err == nil {
		t.Fatal("expected unlock failure")
	}
	// sticky: even with corrected password source, adapter stays locked
	a.PasswordFn = func() (string, error) { return fixturePassword, nil }
	if _, err := a.Resolve("sec://opvault/GitHub/password"); err == nil {
		t.Fatal("expected sticky failure after bad unlock")
	}
}

func TestListItems(t *testing.T) {
	a := newAdapter(t)
	items, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0] != "GitHub" {
		t.Fatalf("unexpected items: %v", items)
	}
}

func TestParseRef(t *testing.T) {
	bad := []string{"op://x/y", "sec://opvault/onlyitem", "sec://keepass/x/y"}
	for _, b := range bad {
		if _, _, err := parseRef(b); err == nil {
			t.Fatalf("expected error for %q", b)
		}
	}
	i, f, err := parseRef("sec://opvault/GitHub/password")
	if err != nil || i != "GitHub" || f != "password" {
		t.Fatalf("parse wrong: %v %v %v", i, f, err)
	}
}
