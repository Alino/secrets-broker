package keepass

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestUpdateDeniedWithoutPolicy: security regression — an agent with create
// rights must NOT be able to overwrite an existing credential (credential
// substitution). Update requires explicit AllowUpdate.
func TestUpdateDeniedWithoutPolicy(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, AllowUpdates: false, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	_, err := a.CreateEntry("", "GitHub", map[string]string{"Password": "attacker-pw"})
	if err == nil {
		t.Fatal("update WITHOUT AllowUpdate must be DENIED (credential substitution guard)")
	}
	if !strings.Contains(err.Error(), "update policy required") {
		t.Fatalf("unexpected error: %v", err)
	}
	// original password intact
	a2 := &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
	got, err := a2.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if got == "attacker-pw" || got == "" {
		t.Fatalf("original credential damaged: %q", got)
	}
	_ = filepath.Join
}
