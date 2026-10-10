// Package approve puts a human in front of each use of a secret.
//
// Every other control in this broker is enforced by code the agent shares a
// machine with: policy files it may be able to edit, binaries it may be able
// to replace, masking it can transform its way around. A biometric prompt is
// different in kind — an agent can read files, spawn processes and even drive
// the UI with osascript, but it cannot produce a fingerprint, and the system
// SecurityAgent draws its prompt in a session the agent cannot reach.
//
// Approvals are cached briefly per (ref, destination) so that a task running
// a dozen commands doesn't ask a dozen times. Denials are never cached.
package approve

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ErrApprovalRequired means a human must authorize this exact exec. It carries
// the nonce the daemon minted for it.
type ErrApprovalRequired struct {
	Refs  []string
	Exec  string
	Nonce string
}

// ErrApprovalUnavailable means a ref requires human approval but this broker
// has no sound way to obtain it in its current mode. It fails closed.
type ErrApprovalUnavailable struct{ Refs []string }

func (e *ErrApprovalUnavailable) Error() string {
	which := ""
	if len(e.Refs) > 0 {
		which = " for " + strings.Join(e.Refs, ", ")
	}
	return "DENIED: approval required" + which + " but no approval key is registered " +
		"(run `sudo sb install` as the console user to register one); " +
		"or mark the ref without --approve, or use single-uid mode"
}

func (e *ErrApprovalUnavailable) asError() error { return e }

func (e *ErrApprovalRequired) Error() string {
	return "APPROVAL REQUIRED for " + strings.Join(e.Refs, ", ") + " -> " + e.Exec +
		": a human must run `sb approve --request " + e.Nonce +
		"`, then retry with approval_request=" + e.Nonce
}

// Gate puts a human in front of secrets that require approval.
//
// Two modes, because a daemon cannot draw a prompt:
//
//   - Helper set (single-uid): prompt directly in the user's session.
//   - otherwise (daemon/isolated): fail closed — see Require.
type Gate struct {
	Helper  string           // sb-approve for direct prompting (single-uid mode)
	TTL     time.Duration    // single-uid approval cache
	Pending *PendingStore    // isolated-mode requests awaiting a signed approval
	PubKey  *ecdsa.PublicKey // registered Secure Enclave public key (isolated mode)
	Now     func() time.Time

	mu       sync.Mutex
	approved map[string]time.Time
}

// Require checks approval for every gated ref of one exec at once. It must be
// called after every other policy check has passed: in isolated mode a
// supplied nonce is consumed here, and nothing may fail after that.
func (g *Gate) Require(nonce string, refs []string, execPath string, argv []string) error {
	if len(refs) == 0 {
		return nil
	}
	if g.Helper != "" {
		for _, ref := range refs {
			if err := g.Ask(ref, execPath, argv...); err != nil {
				return err
			}
		}
		return nil
	}
	// Isolated mode (daemon, no session to prompt in). Approval is a Secure
	// Enclave signature over the request nonce, verified against the public
	// key registered at install. With no key registered there is no way to
	// approve, so it fails closed.
	if g.Pending == nil || g.PubKey == nil {
		return &ErrApprovalUnavailable{Refs: refs}
	}
	if nonce != "" {
		// The retry: release only if this request was approved (its nonce was
		// signed) and matches exactly what was minted.
		if err := g.Pending.Consume(nonce, refs, execPath, argv); err != nil {
			return fmt.Errorf("DENIED: %w", err)
		}
		return nil
	}
	// First encounter: mint one request covering every gated ref and tell the
	// caller which nonce a human must sign.
	p := g.Pending.Create(refs, execPath, argv)
	return &ErrApprovalRequired{Refs: p.Refs, Exec: execPath, Nonce: p.Nonce}
}

// SubmitApproval records that a human signed this request's nonce with the
// registered Secure Enclave key. The signature binds to the nonce, so it
// cannot approve any other request, and a fresh biometric was required to
// produce it. Verification is a public-key check — no root, nothing to reuse.
func (g *Gate) SubmitApproval(nonce, signatureB64 string) error {
	if g.Pending == nil || g.PubKey == nil {
		return fmt.Errorf("approval is not configured on this broker")
	}
	p, err := g.Pending.Get(nonce)
	if err != nil {
		return err
	}
	// The description is recomputed here from the daemon's own record, so a
	// signature only verifies if the human was shown exactly this command.
	if !VerifyApproval(g.PubKey, nonce, p.Describe(), signatureB64) {
		return fmt.Errorf("signature does not verify for request %q", nonce)
	}
	return g.Pending.MarkApproved(nonce)
}

// ApproveRequest has root verify that a human granted THIS request's right,
// then records the approval. The right is removed once the approval is
// recorded; on failure it is kept so the human can try again.

func (g *Gate) Ask(ref, execPath string, argv ...string) error {
	key := strings.Join(append([]string{ref, execPath}, argv...), "\x00")
	now := g.now()

	g.mu.Lock()
	if until, ok := g.approved[key]; ok && now.Before(until) {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	if g.Helper == "" {
		return fmt.Errorf("approval required for %s but no approval helper is configured "+
			"(in isolated mode approval goes through Require)", ref)
	}
	if _, err := os.Stat(g.Helper); err != nil {
		return fmt.Errorf("approval required for %s but the helper is unusable: %w", ref, err)
	}

	cmd := exec.Command(g.Helper, append([]string{ref, execPath}, argv...)...)
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout = nil, nil
	cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	if err := cmd.Run(); err != nil {
		// The helper's own diagnosis is the useful part: "cancelled by the
		// user" and "no GUI session to prompt in" are very different problems.
		if why := strings.TrimSpace(stderr.String()); why != "" {
			return fmt.Errorf("DENIED: %s for %s — %s", ref, execPath, why)
		}
		return fmt.Errorf("DENIED: %s for %s was not approved", ref, execPath)
	}

	if g.TTL > 0 {
		g.mu.Lock()
		if g.approved == nil {
			g.approved = map[string]time.Time{}
		}
		g.approved[key] = now.Add(g.TTL)
		g.mu.Unlock()
	}
	return nil
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}
