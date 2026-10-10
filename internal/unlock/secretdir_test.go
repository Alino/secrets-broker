package unlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSecretRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SB_SECRET_DIR", dir)
	acct := "opvault:/vaults/agent.opvault"

	if _, found, err := fileSecret(acct); found || err != nil {
		t.Fatalf("missing file should be not-found: found=%v err=%v", found, err)
	}
	path, err := WriteSecretFile(dir, acct, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	pw, found, err := fileSecret(acct)
	if err != nil || !found || pw != "s3cret" {
		t.Fatalf("read back: pw=%q found=%v err=%v", pw, found, err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("secret escaped its directory: %s", path)
	}
	// vault paths must not be guessable from a listing
	if name := filepath.Base(path); name == "opvault:/vaults/agent.opvault.pw" {
		t.Fatal("file name leaks the vault path")
	}
}

// A password file other local accounts can read is worse than no file: every
// macOS account is in group staff.
func TestFileSecretRefusesLooseMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SB_SECRET_DIR", dir)
	acct := "keepass:/vaults/agent.kdbx"
	path, err := WriteSecretFile(dir, acct, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, found, err := fileSecret(acct); !found || err == nil {
		t.Fatalf("0644 password file must be refused: found=%v err=%v", found, err)
	}
}

// Without SB_SECRET_DIR the file source is inert and callers fall through to
// the OS keychain (single-uid mode).
func TestFileSecretDisabledWithoutDir(t *testing.T) {
	t.Setenv("SB_SECRET_DIR", "")
	if _, found, err := fileSecret("opvault:/x"); found || err != nil {
		t.Fatalf("unconfigured secret dir must be inert: found=%v err=%v", found, err)
	}
}

// A permission problem on the secret file must surface, not fall through to a
// keychain the daemon has no session for.
func TestFileSecretErrorIsNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SB_SECRET_DIR", dir)
	acct := "opvault:/vaults/agent.opvault"
	if _, err := WriteSecretFile(dir, acct, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	_, err := OpvaultPassword("/vaults/agent.opvault")
	if err == nil {
		t.Fatal("an unreadable secret dir must produce an error, not a keychain fallback")
	}
	if strings.Contains(err.Error(), "keychain item") {
		t.Fatalf("error should name the real problem, got: %v", err)
	}
}
