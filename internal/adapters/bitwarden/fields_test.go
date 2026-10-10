package bitwarden

import (
	"strings"
	"testing"
)

// The bw adapter writes only username, password and URL into a login item;
// any other field is refused before bw is even started (no session needed),
// instead of being dropped while the caller gets a ref back.
func TestCreateEntryRefusesFieldsItCannotStore(t *testing.T) {
	a := &Adapter{BwBin: "/nonexistent/bw-must-not-run"}
	_, err := a.CreateEntry("", "WithSeed", map[string]string{"Password": "p", "otp": "GEZDGNBVGY3TQOJQ"})
	if err == nil || !strings.Contains(err.Error(), "otp") || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a refusal naming otp, got %v", err)
	}
}
