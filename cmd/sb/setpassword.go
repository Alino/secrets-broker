package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vaultcore/secrets-broker/internal/unlock"
)

// setPasswordCmd stores a vault master password where an isolated-mode daemon
// can read it and the agent's user cannot. Run by a human, as root.
//
// This is deliberately not a keychain item: a LaunchDaemon has no login
// session, so it has no unlocked keychain to read from.
func setPasswordCmd(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: sudo sb set-password <adapter> <vault-path-or-email>\n" +
			"  e.g. sudo sb set-password opvault /usr/local/var/secrets-broker/agent.opvault")
	}
	adapter, id := args[0], args[1]
	switch adapter {
	case "opvault", "keepass", "bw":
	default:
		return fmt.Errorf("adapter must be one of: opvault, keepass, bw")
	}

	dir := unlock.SecretDir()
	if dir == "" {
		dir = filepath.Join(brokerVar, "secrets")
	}

	pw, err := readPassword("master password for " + adapter + ":" + id + ": ")
	if err != nil {
		return err
	}
	if pw == "" {
		return fmt.Errorf("empty password, nothing written")
	}
	path, err := unlock.WriteSecretFile(dir, adapter+":"+id, pw)
	if err != nil {
		return err
	}
	// The daemon's account must own it; root-owned would work too but the
	// daemon never needs to be root to read its own secrets.
	if os.Geteuid() == 0 {
		if err := run("chown", brokerUser+":daemon", path); err != nil {
			return err
		}
	}
	fmt.Printf("stored (0600, owner %s)\n", brokerUser)
	return nil
}

// readPassword reads from the terminal with echo off. stty keeps this
// dependency-free; if there is no tty we refuse rather than echo the password.
func readPassword(prompt string) (string, error) {
	if _, err := os.Stat("/dev/tty"); err != nil {
		return "", fmt.Errorf("no terminal available — run this from a shell, not from an agent")
	}
	fmt.Print(prompt)
	restore := exec.Command("/bin/stty", "-f", "/dev/tty", "echo")
	off := exec.Command("/bin/stty", "-f", "/dev/tty", "-echo")
	if err := off.Run(); err != nil {
		// /dev/tty exists but there is no controlling terminal — e.g. an agent
		// or a pipeline. Refuse rather than read the password with echo on.
		return "", fmt.Errorf("no controlling terminal — run this yourself from a shell " +
			"(an agent cannot enter the master password)")
	}
	defer func() { _ = restore.Run(); fmt.Println() }()

	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", err
	}
	defer tty.Close()
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
