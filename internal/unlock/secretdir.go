package unlock

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecretDir is where an isolated-mode daemon keeps master passwords: a
// directory owned by the broker's service account, mode 0700, unreadable by
// the agent's user. It is checked before the OS keychain, because in isolated
// mode the daemon has no login session and therefore no usable keychain.
//
// Empty (the default) means "not configured" and the keychain path is used.
func SecretDir() string { return os.Getenv("SB_SECRET_DIR") }

// SecretFile returns the path holding the master password for one vault.
// The name is a digest so that vault paths never appear in a directory
// listing and cannot escape the directory.
func SecretFile(dir, account string) string {
	sum := sha256.Sum256([]byte(account))
	return filepath.Join(dir, hex.EncodeToString(sum[:8])+".pw")
}

// fileSecret reads a master password from the secret directory. A file that
// is group- or world-readable is refused: on macOS every local account is in
// group staff, so a 0644 password file is readable by every user on the box.
func fileSecret(account string) (string, bool, error) {
	dir := SecretDir()
	if dir == "" {
		return "", false, nil
	}
	path := SecretFile(dir, account)
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		return "", true, fmt.Errorf("%s is readable by other users (%04o); fix with: chmod 600 %s", path, perm, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", true, err
	}
	pw := strings.TrimRight(string(b), "\n")
	if pw == "" {
		return "", true, fmt.Errorf("%s is empty", path)
	}
	return pw, true, nil
}

// WriteSecretFile stores a master password for the daemon (sb set-password).
func WriteSecretFile(dir, account, password string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := SecretFile(dir, account)
	if err := os.WriteFile(path, []byte(password), 0600); err != nil {
		return "", err
	}
	return path, nil
}
