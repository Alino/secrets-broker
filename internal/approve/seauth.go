package approve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// The Secure Enclave approval path. A key created in the console user's Secure
// Enclave (by sb-seauth at install) requires a fresh biometric on every use
// and cannot be exported. Its public half is registered with the daemon here.
// Approving a request means signing that request's nonce with the key; the
// daemon verifies the signature with the registered public key — pure crypto,
// no root, and a signature for one nonce cannot approve another.
//
// This is the property Authorization Services could not provide: the proof is
// bound to the request (it IS a signature over the nonce) and is not reusable
// (each signing is a fresh biometric over different bytes).

// ParseApprovalKey decodes a base64 X9.63 point (04||X||Y), the form
// SecKeyCopyExternalRepresentation emits for a P-256 public key.
func ParseApprovalKey(b64 string) (*ecdsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("approval key is not valid base64: %w", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return nil, fmt.Errorf("approval key is not a P-256 point (%d bytes)", len(raw))
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// LoadApprovalKey reads the registered public key from a file (written
// root-owned at install). A missing or unreadable file is an error, so
// approval fails closed rather than silently accepting nothing.
func LoadApprovalKey(path string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseApprovalKey(string(b))
}

// ApprovalMessage is the exact byte string signed for a request: the nonce
// and the human-readable description, together. Binding the description means
// a valid signature proves the human saw THIS command — not just this nonce.
// An agent that shows a misleading prompt signs a different description, and
// the daemon, which recomputes the description from its own record, rejects it.
func ApprovalMessage(nonce, describe string) []byte {
	return []byte(nonce + "\n" + describe)
}

// VerifyApproval reports whether sigB64 signs ApprovalMessage(nonce, describe)
// under pub. The signature is DER (X9.62) ECDSA over SHA-256, matching
// kSecKeyAlgorithmECDSASignatureMessageX962SHA256.
func VerifyApproval(pub *ecdsa.PublicKey, nonce, describe, sigB64 string) bool {
	if pub == nil {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(der) == 0 {
		return false
	}
	sum := sha256.Sum256(ApprovalMessage(nonce, describe))
	return ecdsa.VerifyASN1(pub, sum[:], der)
}
