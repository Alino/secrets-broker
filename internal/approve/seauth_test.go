package approve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// A signature over the exact request nonce, made with the key whose public
// half is registered, must verify — and nothing else must.
func TestVerifyApprovalSignature(t *testing.T) {
	// stand in for the Secure Enclave key: a P-256 key, X9.63 public half
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubX963 := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) // 04||X||Y, matches SecKeyCopyExternalRepresentation
	pub, err := ParseApprovalKey(base64.StdEncoding.EncodeToString(pubX963))
	if err != nil {
		t.Fatal(err)
	}

	nonce, desc := "a1b2c3d4e5f60718", `/usr/bin/gh "api" "/user"  with  sec://v/GH/pw`
	sign := func(n, d string) string {
		sum := sha256.Sum256(ApprovalMessage(n, d))
		der, _ := ecdsa.SignASN1(rand.Reader, priv, sum[:])
		return base64.StdEncoding.EncodeToString(der)
	}

	if !VerifyApproval(pub, nonce, desc, sign(nonce, desc)) {
		t.Fatal("a valid signature over (nonce, description) must verify")
	}
	if VerifyApproval(pub, nonce, desc, sign("b0b0b0b0b0b0b0b0", desc)) {
		t.Fatal("a signature over another nonce must not verify")
	}
	if VerifyApproval(pub, nonce, desc, sign(nonce, "a benign-looking description")) {
		t.Fatal("a signature over a DIFFERENT description must not verify — this is what stops a misleading prompt")
	}
	if VerifyApproval(pub, nonce, desc, "not base64!!") || VerifyApproval(pub, nonce, desc, "") {
		t.Fatal("malformed signatures must be rejected")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sumN := sha256.Sum256(ApprovalMessage(nonce, desc))
	otherDER, _ := ecdsa.SignASN1(rand.Reader, other, sumN[:])
	if VerifyApproval(pub, nonce, desc, base64.StdEncoding.EncodeToString(otherDER)) {
		t.Fatal("only the registered key may approve")
	}
}

func TestParseApprovalKeyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not base64", base64.StdEncoding.EncodeToString([]byte("too short"))} {
		if _, err := ParseApprovalKey(bad); err == nil {
			t.Errorf("ParseApprovalKey(%q) should fail", bad)
		}
	}
}

// The daemon loads the registered public key from a file written at install.
func TestLoadApprovalKeyFile(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubX963 := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	dir := t.TempDir()
	path := filepath.Join(dir, "approval.pub")
	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pubX963)+"\n"), 0644)

	pub, err := LoadApprovalKey(path)
	if err != nil {
		t.Fatal(err)
	}
	nonce, desc := "0011223344556677", "cmd desc"
	sum := sha256.Sum256(ApprovalMessage(nonce, desc))
	der, _ := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if !VerifyApproval(pub, nonce, desc, base64.StdEncoding.EncodeToString(der)) {
		t.Fatal("key loaded from file should verify its own signatures")
	}

	if _, err := LoadApprovalKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing key file must be an error, so approval fails closed")
	}
}
