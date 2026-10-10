package approve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// counter writes one line per invocation so tests can count prompts.
func counter(t *testing.T, exitCode int) (helper, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	helper = filepath.Join(dir, "helper.sh")
	// always writes a line, even when the helper is called with no arguments
	// (the verifier takes its token on stdin)
	script := "#!/bin/sh\necho \"call:$@\" >> " + log + "\nexit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return helper, log
}

func calls(t *testing.T, log string) int {
	t.Helper()
	b, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
}

func TestAskApproved(t *testing.T) {
	helper, log := counter(t, 0)
	g := &Gate{Helper: helper, TTL: time.Minute}
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh"); err != nil {
		t.Fatalf("approved helper must pass: %v", err)
	}
	if n := calls(t, log); n != 1 {
		t.Fatalf("expected 1 prompt, got %d", n)
	}
}

func TestAskDeniedFailsClosed(t *testing.T) {
	helper, _ := counter(t, 1)
	g := &Gate{Helper: helper, TTL: time.Minute}
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh"); err == nil {
		t.Fatal("a declined prompt must deny the secret")
	}
}

// A missing helper must deny, not silently allow: the whole point is that the
// gate cannot be removed by deleting a file.
func TestMissingHelperFailsClosed(t *testing.T) {
	g := &Gate{Helper: "/nonexistent/sb-approve", TTL: time.Minute}
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh"); err == nil {
		t.Fatal("missing helper must deny")
	}
	g2 := &Gate{TTL: time.Minute}
	if err := g2.Ask("sec://x/y/pw", "/usr/bin/gh"); err == nil {
		t.Fatal("unconfigured helper must deny")
	}
}

func TestApprovalCachedWithinTTL(t *testing.T) {
	helper, log := counter(t, 0)
	now := time.Unix(1000, 0)
	g := &Gate{Helper: helper, TTL: 30 * time.Second, Now: func() time.Time { return now }}

	for i := 0; i < 3; i++ {
		if err := g.Ask("sec://x/y/pw", "/usr/bin/gh"); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls(t, log); n != 1 {
		t.Fatalf("approval should be cached: %d prompts", n)
	}
	// a different destination is a different decision
	if err := g.Ask("sec://x/y/pw", "/usr/bin/aws"); err != nil {
		t.Fatal(err)
	}
	if n := calls(t, log); n != 2 {
		t.Fatalf("different exec must re-prompt: %d prompts", n)
	}
	// and so is the same binary with different arguments
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh", "api", "/user"); err != nil {
		t.Fatal(err)
	}
	if n := calls(t, log); n != 3 {
		t.Fatalf("different argv must re-prompt: %d prompts", n)
	}
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh", "api", "/user"); err != nil {
		t.Fatal(err)
	}
	if n := calls(t, log); n != 3 {
		t.Fatalf("identical argv should reuse the approval: %d prompts", n)
	}
	// past the TTL the human is asked again
	now = now.Add(31 * time.Second)
	if err := g.Ask("sec://x/y/pw", "/usr/bin/gh"); err != nil {
		t.Fatal(err)
	}
	if n := calls(t, log); n != 4 {
		t.Fatalf("expired approval must re-prompt: %d prompts", n)
	}
}

func TestDenialIsNotCached(t *testing.T) {
	helper, log := counter(t, 1)
	g := &Gate{Helper: helper, TTL: time.Minute}
	_ = g.Ask("sec://x/y/pw", "/usr/bin/gh")
	_ = g.Ask("sec://x/y/pw", "/usr/bin/gh")
	if n := calls(t, log); n != 2 {
		t.Fatalf("denials must not be cached: %d prompts", n)
	}
}

// With no approval key registered, isolated mode cannot verify anything and
// fails closed.
func TestIsolatedNoKeyFailsClosed(t *testing.T) {
	g := &Gate{Pending: NewPendingStore(time.Minute)} // no PubKey, no Helper
	err := g.Require("", []string{"sec://v/A/pw"}, "/usr/bin/gh", nil)
	var un *ErrApprovalUnavailable
	if !errors.As(err, &un) {
		t.Fatalf("no registered key must fail closed, got %v", err)
	}
	if err := g.SubmitApproval("x", "y"); err == nil {
		t.Fatal("SubmitApproval must refuse when no key is configured")
	}
}

// The full isolated flow with a stand-in Secure Enclave key: mint a request,
// sign its nonce, submit, then the retry runs — once, for that command only.
func TestIsolatedSignAndSubmit(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	g := &Gate{Pending: NewPendingStore(time.Minute), PubKey: pub}
	refs := []string{"sec://v/B/pw", "sec://v/A/pw"}

	err := g.Require("", refs, "/usr/bin/gh", []string{"api", "/user"})
	var req *ErrApprovalRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected a minted request, got %v", err)
	}
	// sign the request's own description, as sb-seauth will
	pend, _ := g.Pending.Get(req.Nonce)
	sign := func(nonce, desc string) string {
		sum := sha256.Sum256(ApprovalMessage(nonce, desc))
		der, _ := ecdsa.SignASN1(rand.Reader, priv, sum[:])
		return base64.StdEncoding.EncodeToString(der)
	}

	// before submission the request is not approved
	if err := g.Require(req.Nonce, refs, "/usr/bin/gh", []string{"api", "/user"}); err == nil {
		t.Fatal("must not run before the signature is submitted")
	}
	if err := g.SubmitApproval(req.Nonce, sign(req.Nonce, pend.Describe())); err != nil {
		t.Fatalf("a valid signature over the nonce must be accepted: %v", err)
	}
	// ref order in the retry does not matter
	if err := g.Require(req.Nonce, []string{"sec://v/A/pw", "sec://v/B/pw"}, "/usr/bin/gh", []string{"api", "/user"}); err != nil {
		t.Fatalf("the approved command should run: %v", err)
	}
	if err := g.Require(req.Nonce, refs, "/usr/bin/gh", []string{"api", "/user"}); err == nil {
		t.Fatal("approval must be one-shot")
	}
}

// A signature made for one request cannot approve another.
func TestSignatureCannotBeMoved(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g := &Gate{Pending: NewPendingStore(time.Minute), PubKey: &priv.PublicKey}
	var a, b *ErrApprovalRequired
	errors.As(g.Require("", []string{"sec://v/Staging/pw"}, "/bin/echo", []string{"hi"}), &a)
	errors.As(g.Require("", []string{"sec://v/Prod/key"}, "/bin/echo", []string{"hi"}), &b)
	pa, _ := g.Pending.Get(a.Nonce)
	sumA := sha256.Sum256(ApprovalMessage(a.Nonce, pa.Describe()))
	derA, _ := ecdsa.SignASN1(rand.Reader, priv, sumA[:])
	// present A's signature for B
	if err := g.SubmitApproval(b.Nonce, base64.StdEncoding.EncodeToString(derA)); err == nil {
		t.Fatal("a signature over A's nonce must not approve B")
	}
}

// A signature from an unregistered key is rejected.
func TestForeignKeyRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g := &Gate{Pending: NewPendingStore(time.Minute), PubKey: &priv.PublicKey}
	var req *ErrApprovalRequired
	errors.As(g.Require("", []string{"r"}, "/usr/bin/gh", nil), &req)
	pr, _ := g.Pending.Get(req.Nonce)
	sum := sha256.Sum256(ApprovalMessage(req.Nonce, pr.Describe()))
	der, _ := ecdsa.SignASN1(rand.Reader, attacker, sum[:])
	if err := g.SubmitApproval(req.Nonce, base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("only the registered key may approve")
	}
}

// Refs with no approval requirement are unaffected.
func TestRequireNoGatedRefsPasses(t *testing.T) {
	g := &Gate{Pending: NewPendingStore(time.Minute)}
	if err := g.Require("", nil, "/usr/bin/gh", nil); err != nil {
		t.Fatalf("no gated refs must pass: %v", err)
	}
}
