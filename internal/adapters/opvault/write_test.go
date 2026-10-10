package opvaultadapter

import (
	"os"
	"path/filepath"
	"testing"
)

func copyVault(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "fixture_vault")
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture vault not present: %v", err)
	}
	dst := t.TempDir()
	// copy directory tree (profile.js + band_0.js)
	for _, name := range []string{"default/profile.js", "default/band_0.js"} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Skipf("fixture file missing: %v", err)
		}
		os.MkdirAll(filepath.Join(dst, filepath.Dir(name)), 0700)
		if err := os.WriteFile(filepath.Join(dst, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestCreateEntryOpvault(t *testing.T) {
	dir := copyVault(t)
	a := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	ref, err := a.CreateEntry("", "NewSaaS", map[string]string{
		"UserName": "agent@xenask.dev",
		"Password": "opGenSecret1",
		"URL":      "https://new.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "sec://opvault/NewSaaS/password" {
		t.Fatalf("bad ref %q", ref)
	}
	// fresh adapter (fresh reader) resolves it from disk — round-trip proof
	a2 := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	got, err := a2.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != "opGenSecret1" {
		t.Fatalf("round-trip mismatch: %q", got)
	}
	// original fixture item still resolvable (band rewrite kept it)
	old, err := a2.Resolve("sec://opvault/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if old == "" {
		t.Fatal("original GitHub item lost")
	}
}

func TestCreateEntryWrongPwFails(t *testing.T) {
	dir := copyVault(t)
	a := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "wrong-password", nil }}
	if _, err := a.CreateEntry("", "X", map[string]string{"Password": "p"}); err == nil {
		t.Fatal("write with wrong master password must fail")
	}
}

// A vault with no band_0.js (items sharded into other bands, like a real
// 1Password export) must still accept a new item — CreateEntry creates the
// band file. Regression for a live failure: opening band_0.js that isn't there.
func TestCreateEntryNoBand0(t *testing.T) {
	dir := copyVault(t)
	// simulate a vault whose items live in a different band: rename band_0.
	def := filepath.Join(dir, "default")
	if err := os.Rename(filepath.Join(def, "band_0.js"), filepath.Join(def, "band_5.js")); err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	ref, err := a.CreateEntry("", "Fresh", map[string]string{"Password": "brandNew1"})
	if err != nil {
		t.Fatalf("create into a vault without band_0 must succeed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(def, "band_0.js")); err != nil {
		t.Fatalf("band_0.js should have been created: %v", err)
	}
	a2 := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	if got, err := a2.Resolve(ref); err != nil || got != "brandNew1" {
		t.Fatalf("new item not resolvable: got %q err %v", got, err)
	}
	// the item that was in the renamed band is still resolvable
	if _, err := a2.Resolve("sec://opvault/GitHub/password"); err != nil {
		t.Fatalf("item in band_5 lost: %v", err)
	}
}

// A new band inherits the mode of the vault's existing files, so a co-reader
// sharing the group (e.g. 1Password on the same synced .opvault) can read what
// the broker writes — the broker must not force 0600 onto a shared vault.
func TestCreateEntryMatchesVaultMode(t *testing.T) {
	dir := copyVault(t)
	def := filepath.Join(dir, "default")
	// mark the vault group-readable, as a shared vault would be
	for _, f := range []string{"profile.js", "band_0.js"} {
		if err := os.Chmod(filepath.Join(def, f), 0640); err != nil {
			t.Fatal(err)
		}
	}
	a := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	if _, err := a.CreateEntry("", "Shared", map[string]string{"Password": "x1"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(def, "band_0.js"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("new band mode = %o, want 0640 (must match the vault's sharing)", fi.Mode().Perm())
	}
}
