package keepass

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func copyFixture(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "fixture.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "test.kdbx")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestCreateEntryAndResolve(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}

	pw := "generated-PW-" + base64.RawURLEncoding.EncodeToString(mustRand(9))
	ref, err := a.CreateEntry("Agents", "NewService", map[string]string{
		"UserName": "agent@example.com",
		"Password": pw,
		"URL":      "https://newservice.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "sec://keepass/Agents/NewService/Password" {
		t.Fatalf("unexpected ref %q", ref)
	}
	// fresh adapter resolves it back from disk (round-trip proof)
	a2 := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	got, err := a2.Resolve("sec://keepass/Agents/NewService/Password")
	if err != nil {
		t.Fatal(err)
	}
	if got != pw {
		t.Fatalf("round-trip mismatch: %q != %q", got, pw)
	}
	user, err := a2.Resolve("sec://keepass/Agents/NewService/UserName")
	if err != nil || user != "agent@example.com" {
		t.Fatalf("username: %q %v", user, err)
	}
}

func TestCreateEntryUpdatesExisting(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, AllowUpdates: true, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	if _, err := a.CreateEntry("", "GitHub", map[string]string{"Password": "rotated-PW-123"}); err != nil {
		t.Fatal(err)
	}
	a2 := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	got, err := a2.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if got != "rotated-PW-123" {
		t.Fatalf("update failed: %q", got)
	}
	// and the fixture still lists exactly one GitHub (any group depth)
	items, _ := a2.List()
	count := 0
	for _, it := range items {
		if strings.HasSuffix(it, "/GitHub") || it == "GitHub" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 GitHub entry, got %d in %v", count, items)
	}
}

func TestKeepassxcCanReadOurWrite(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	if _, err := a.CreateEntry("Agents", "Interop", map[string]string{"Password": "interop-PW"}); err != nil {
		t.Fatal(err)
	}
	// keepassxc-cli (if present) must be able to read what we wrote
	bin := "keepassxc-cli"
	if _, err := execLookPath(bin); err != nil {
		t.Skip("keepassxc-cli not available")
	}
	out, err := runKeepassxcShow(db, "Agents/Interop")
	if err != nil {
		t.Fatalf("keepassxc-cli cannot read our file: %v\n%s", err, out)
	}
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func execLookPath(bin string) (string, error) { return exec.LookPath(bin) }

func runKeepassxcShow(db, entry string) (string, error) {
	cmd := exec.Command("keepassxc-cli", "show", "-sa", "Password", db, entry)
	cmd.Stdin = strings.NewReader(kdbxPassword + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A write preserves the database's existing mode, so a co-reader sharing the
// group (KeePassXC on the same .kdbx) can read what the broker writes — the
// adapter must not force 0600 onto a shared vault.
func TestWritePreservesMode(t *testing.T) {
	db := copyFixture(t)
	if err := os.Chmod(db, 0660); err != nil {
		t.Fatal(err)
	}
	a := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }, AllowUpdates: true}
	if _, err := a.CreateEntry("Agents", "PermCheck", map[string]string{"Password": "z1"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(db)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0660 {
		t.Fatalf("kdbx mode after write = %o, want 0660 (must match the vault's sharing)", fi.Mode().Perm())
	}
}
