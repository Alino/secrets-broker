package main

import (
	"strings"
	"testing"
)

func TestPlatformUninstallSteps(t *testing.T) {
	base := platformUninstallSteps(false)
	purged := platformUninstallSteps(true)
	if len(base) == 0 {
		t.Fatal("no uninstall steps")
	}
	if len(purged) != len(base)+2 {
		t.Fatalf("--purge should add exactly 2 steps: base=%d purge=%d", len(base), len(purged))
	}
	// Non-purge must NOT touch the data dirs; purge must.
	for _, s := range base {
		if strings.Contains(s.desc, "purge") {
			t.Errorf("non-purge step should not purge data: %q", s.desc)
		}
	}
	joined := ""
	for _, s := range purged {
		joined += s.desc + "\n"
	}
	for _, want := range []string{brokerLibexec, brokerUser, clientGroup, brokerVar, brokerEtc} {
		if !strings.Contains(joined, want) {
			t.Errorf("purge steps missing reference to %q", want)
		}
	}
}

func TestUninstallKeepNote(t *testing.T) {
	keep := uninstallKeepNote(false)
	if !strings.Contains(keep, brokerVar) || !strings.Contains(keep, brokerEtc) {
		t.Errorf("keep note should name the retained dirs: %q", keep)
	}
	if strings.Contains(keep, "purged:") {
		t.Errorf("non-purge note should not claim a purge: %q", keep)
	}
	if !strings.Contains(uninstallKeepNote(true), "purged:") {
		t.Error("purge note should say purged")
	}
}
