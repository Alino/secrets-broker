// Package unlock resolves the master-password source for vault adapters.
// Order (first wins):
//  1. SB_OPVAULT_PASSWORD / SB_KEEPASS_PASSWORD / SB_ENPASS_PASSWORD /
//     SB_BW_PASSWORD env (tests only)
//  2. SB_SECRET_DIR file (isolated mode: owned by the broker's service
//     account, unreadable by the agent's user)
//  3. OS secret store: macOS Keychain (/usr/bin/security) or Linux
//     libsecret (secret-tool) — service "secrets-broker",
//     account = "<adapter>:<vault id>"
//  3. failure with an actionable message (never a prompt on the MCP path —
//     the agent must never be able to phish the password)
package unlock

import (
	"fmt"
	"os"
)

// OpvaultPassword resolves the opvault master password: env, then OS store.
func OpvaultPassword(vaultDir string) (string, error) {
	if pw := os.Getenv("SB_OPVAULT_PASSWORD"); pw != "" {
		return pw, nil
	}
	if pw, found, err := fileSecret("opvault:" + vaultDir); found || err != nil {
		return pw, err
	}
	if systemStoreAvailable() {
		return systemSecret("secrets-broker", "opvault:"+vaultDir)
	}
	return "", fmt.Errorf("no unlock source: set SB_OPVAULT_PASSWORD (tests) or store the password with: %s", storeHint("opvault:"+vaultDir))
}

// KeepassPassword resolves the KeePass master password: env, then OS store.
func KeepassPassword(dbPath string) (string, error) {
	if pw := os.Getenv("SB_KEEPASS_PASSWORD"); pw != "" {
		return pw, nil
	}
	if pw, found, err := fileSecret("keepass:" + dbPath); found || err != nil {
		return pw, err
	}
	if systemStoreAvailable() {
		return systemSecret("secrets-broker", "keepass:"+dbPath)
	}
	return "", fmt.Errorf("no unlock source: set SB_KEEPASS_PASSWORD (tests) or store the password with: %s", storeHint("keepass:"+dbPath))
}

// BwPassword resolves the Bitwarden master password: env, then OS store.
func BwPassword(email string) (string, error) {
	if pw := os.Getenv("SB_BW_PASSWORD"); pw != "" {
		return pw, nil
	}
	if pw, found, err := fileSecret("bw:" + email); found || err != nil {
		return pw, err
	}
	if systemStoreAvailable() {
		return systemSecret("secrets-broker", "bw:"+email)
	}
	return "", fmt.Errorf("no unlock source: set SB_BW_PASSWORD (tests) or store the password with: %s", storeHint("bw:"+email))
}

// Keychain is kept (macOS path) for compatibility with older callers/tests.
func Keychain(service, account string) (string, error) {
	return systemSecret(service, account)
}
