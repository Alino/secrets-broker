package main

import (
	"fmt"
	"os"
)

// uninstallCmd reverses `sb install`. It is best-effort: a step that finds its
// target already gone is not an error, so a partial install still tears down
// cleanly. By default it leaves user data in place — the policy, the audit log,
// stored master passwords, and any vault placed under brokerVar — and only
// removes the daemon, binaries, sockets and service account. --purge also
// deletes brokerVar and brokerEtc (everything).
func uninstallCmd(args []string) error {
	dry, purge := false, false
	for _, a := range args {
		switch a {
		case "--dry-run", "-n":
			dry = true
		case "--purge":
			purge = true
		default:
			return fmt.Errorf("unknown flag %q (usage: sb uninstall [--purge] [--dry-run])", a)
		}
	}
	if !dry && os.Geteuid() != 0 {
		return fmt.Errorf("sb uninstall must run as root:\n  sudo sb uninstall\n" +
			"(run `sb uninstall --dry-run` first to see exactly what it will do)")
	}

	steps := platformUninstallSteps(purge)

	if dry {
		fmt.Print("sb uninstall --dry-run — this is what `sudo sb uninstall` would do:\n\n")
		for i, s := range steps {
			fmt.Printf("  %d. %s\n", i+1, s.desc)
		}
		fmt.Print("\n" + uninstallKeepNote(purge))
		return nil
	}

	var warns int
	for i, s := range steps {
		fmt.Printf("[%d/%d] %s\n", i+1, len(steps), s.desc)
		if err := s.fn(); err != nil {
			fmt.Printf("      warning: %v\n", err)
			warns++
		}
	}
	fmt.Print("\n" + uninstallKeepNote(purge))
	if warns > 0 {
		return fmt.Errorf("uninstall finished with %d warning(s) — see above", warns)
	}
	fmt.Println("done.")
	return nil
}

// uninstallKeepNote tells the user what was intentionally kept (or, with
// --purge, that nothing was).
func uninstallKeepNote(purge bool) string {
	if purge {
		return fmt.Sprintf("purged: %s and %s removed (policy, audit log, stored master passwords\n"+
			"and any vault placed there are gone).\n", brokerVar, brokerEtc)
	}
	return fmt.Sprintf("kept (remove by hand, or re-run with --purge):\n"+
		"  %s   policy you configured with `sb allow`\n"+
		"  %s   audit log and stored master passwords (secrets/), plus any vault you moved here\n",
		brokerEtc, brokerVar)
}

// removeIfPresent deletes a file, treating "already gone" as success — the
// point of a best-effort uninstall.
func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
