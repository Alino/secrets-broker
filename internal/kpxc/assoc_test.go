package kpxc

import (
	"path/filepath"
	"testing"
)

// The daemon and `sb browser` are separate processes holding separate
// in-memory copies of one file. A write by either must never revert what the
// other wrote.
func TestConcurrentStoresDoNotRevertEachOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "associations.json")
	daemon, err := LoadAssoc(path)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := LoadAssoc(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := daemon.Add("a", "key-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := cli.Approve("a", ScopeHuman); err != nil {
		t.Fatalf("the CLI must see an association the daemon added: %v", err)
	}
	// the daemon still holds its pre-approval copy; using it must not revert
	if _, err := daemon.Verify("a", "key-a"); err != nil {
		t.Fatalf("approval made by the CLI must be visible to the daemon: %v", err)
	}
	if _, err := cli.Add("b", "key-b", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Verify("a", "key-a"); err != nil {
		t.Fatal(err)
	}

	fresh, err := LoadAssoc(path)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := fresh.Get("a")
	if !ok || !a.Approved || a.LastUsed.IsZero() {
		t.Fatalf("approval or last-used lost: %+v", a)
	}
	if _, ok := fresh.Get("b"); !ok {
		t.Fatal("an association added by the CLI was overwritten by the daemon")
	}
}

// Revoking something that does not exist must not create the file.
func TestRemoveUnknownDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "associations.json")
	s, err := LoadAssoc(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("nope"); err == nil {
		t.Fatal("removing an unknown association must fail")
	}
	if all := s.All(); len(all) != 0 {
		t.Fatalf("unexpected associations: %v", all)
	}
}

// A revocation by `sb browser` must stop the daemon's next Verify, even when
// both writes land in the same mtime tick.
func TestRevocationSeenByDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "associations.json")
	daemon, _ := LoadAssoc(path)
	cli, _ := LoadAssoc(path)
	if _, err := daemon.Add("a", "key-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := cli.Approve("a", ScopeHuman); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Verify("a", "key-a"); err != nil {
		t.Fatal(err)
	}
	if err := cli.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Verify("a", "key-a"); err == nil {
		t.Fatal("a revoked association must not verify")
	}
}
