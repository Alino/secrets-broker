package unlock

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// systemSecret reads a master password from the OS secret store:
//   - macOS: login keychain via /usr/bin/security (service "secrets-broker")
//   - Linux: libsecret via secret-tool (GNOME Keyring/KWallet backend)
//
// account identifies the vault (e.g. "keepass:/path/db.kdbx").
// Falls back with a "not available" error when neither exists — never prompts.
func systemSecret(service, account string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("/usr/bin/security",
			"find-generic-password", "-s", service, "-a", account, "-w").Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 44 {
				return "", fmt.Errorf("keychain item %s/%s not found — create it with: security add-generic-password -s %s -a %s -w", service, account, service, account)
			}
			return "", fmt.Errorf("keychain read: %w", err)
		}
		pw := strings.TrimRight(string(out), "\n")
		if pw == "" {
			return "", fmt.Errorf("keychain item %s/%s is empty", service, account)
		}
		return pw, nil
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err != nil {
			return "", fmt.Errorf("secret-tool not installed (apt install libsecret-tools / dnf install libsecret)")
		}
		out, err := exec.Command("secret-tool", "lookup", "service", service, "account", account).Output()
		if err != nil {
			return "", fmt.Errorf("libsecret read: %w", err)
		}
		pw := strings.TrimRight(string(out), "\n")
		if pw == "" {
			return "", fmt.Errorf("libsecret item %s/%s is empty — store it with: secret-tool store --label='secrets-broker %s' service %s account %s", service, account, account, service, account)
		}
		return pw, nil
	}
	return "", fmt.Errorf("no system secret store on %s", runtime.GOOS)
}

// storeHint returns the platform-appropriate command to store a secret.
func storeHint(account string) string {
	if runtime.GOOS == "linux" {
		return fmt.Sprintf("secret-tool store --label='secrets-broker %s' service secrets-broker account %s", account, account)
	}
	return fmt.Sprintf("security add-generic-password -s secrets-broker -a %s -w", account)
}

// systemStoreAvailable reports whether an OS secret store exists here.
func systemStoreAvailable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat("/usr/bin/security")
		return err == nil
	case "linux":
		_, err := exec.LookPath("secret-tool")
		return err == nil
	}
	return false
}
