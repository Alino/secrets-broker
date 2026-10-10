package opvaultadapter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// opvault items carry only a username, password and URL. A field it cannot
// store (a TOTP seed) must be refused with nothing written — before, it was
// dropped and the caller still got a ref back as if it were stored.
func TestCreateEntryRefusesFieldsItCannotStore(t *testing.T) {
	dir := copyVault(t)
	band := filepath.Join(dir, "default", "band_0.js")
	orig, err := os.ReadFile(band)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Dir: dir, PasswordFn: func() (string, error) { return "correct horse battery staple", nil }}
	_, err = a.CreateEntry("", "WithSeed", map[string]string{"Password": "p", "otp": "GEZDGNBVGY3TQOJQ"})
	if err == nil || !strings.Contains(err.Error(), "otp") {
		t.Fatalf("want a refusal naming otp, got %v", err)
	}
	now, err := os.ReadFile(band)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, now) {
		t.Fatal("a refused write changed the vault")
	}
}
