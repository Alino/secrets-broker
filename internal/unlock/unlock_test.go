package unlock

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEnvWinsOverKeychain(t *testing.T) {
	t.Setenv("SB_OPVAULT_PASSWORD", "from-env")
	got, err := OpvaultPassword("/some/vault")
	if err != nil || got != "from-env" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestKeychainMissingItemActionableError(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/security"); err != nil {
		t.Skip("not macOS")
	}
	t.Setenv("SB_OPVAULT_PASSWORD", "")
	_, err := OpvaultPassword("/nonexistent/vault/for-sure")
	if err == nil {
		t.Fatal("expected error for missing keychain item")
	}
	// The error must tell the user how to fix it.
	msg := err.Error()
	for _, want := range []string{"add-generic-password", "secrets-broker", "opvault:/nonexistent/vault/for-sure"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error lacks %q: %v", want, msg)
		}
	}
}
