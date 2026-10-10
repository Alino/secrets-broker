package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestWriteAllowSetsExactlyTheListedModes(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy.json")
	t.Setenv("SB_POLICY_FILE", pf)

	steps := []struct {
		mode string
		want policy.WritePolicy
	}{
		{"create", policy.WritePolicy{AllowCreate: true}},
		{"create,add-fields", policy.WritePolicy{AllowCreate: true, AllowAddFields: true}},
		{"add-fields", policy.WritePolicy{AllowAddFields: true}}, // exact set: create is dropped
		{"both", policy.WritePolicy{AllowCreate: true, AllowUpdate: true}},
		{"none", policy.WritePolicy{}},
	}
	for _, s := range steps {
		out := captureStdout(t, func() {
			if err := writeAllowCmd("keepass", s.mode); err != nil {
				t.Fatalf("%s: %v", s.mode, err)
			}
		})
		st, err := policy.Load(pf)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.WriteAllow("keepass"); got != s.want {
			t.Fatalf("after %q: %+v, want %+v", s.mode, got, s.want)
		}
		if !strings.Contains(out, "vault writes for keepass: "+s.want.String()) {
			t.Fatalf("after %q printed %q", s.mode, out)
		}
	}

	// A typo is an error and changes nothing.
	if err := writeAllowCmd("keepass", "create"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(pf)
	if err := writeAllowCmd("keepass", "create,add_fields"); err == nil {
		t.Fatal("a misspelled mode must be refused")
	}
	if after, _ := os.ReadFile(pf); string(after) != string(before) {
		t.Fatal("a refused write-allow changed the policy file")
	}
}

// `sb list` shows write grants next to the read bindings, including when no
// secret is bound yet.
func TestListShowsWriteGrants(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy.json")
	t.Setenv("SB_POLICY_FILE", pf)
	out := captureStdout(t, func() { _ = listCmd() })
	if !strings.Contains(out, "(none — every adapter is read-only)") {
		t.Fatalf("empty policy: %q", out)
	}
	captureStdout(t, func() { _ = writeAllowCmd("keepass", "create,add-fields") })
	out = captureStdout(t, func() { _ = listCmd() })
	if !strings.Contains(out, "keepass") || !strings.Contains(out, "create,add-fields") {
		t.Fatalf("grant not listed: %q", out)
	}
}
