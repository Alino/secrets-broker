package approve

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pending is one exec awaiting a human decision.
//
// It covers EVERY gated ref the exec uses, not one ref: a command that needs
// two gated secrets must be approvable with one fingerprint, and approving
// half of it is meaningless. This is scaffolding for the Secure Enclave
// approval design (docs/approval.md): the nonce is what a biometric-gated
// signature will attest to. It is not wired into a live approval path today —
// isolated-mode approval fails closed (see approve.go).
type Pending struct {
	Nonce   string
	Refs    []string // sorted
	Exec    string
	Argv    []string
	Created time.Time
	Expires time.Time

	approved bool
}

// Describe is what root registers as the right's prompt. It comes from the
// daemon's record, never from the caller. Arguments are quoted so that
// ["api","/user -H x"] and ["api","/user","-H","x"] cannot read identically,
// and control characters cannot hide a flag.
func (p *Pending) Describe() string {
	parts := []string{p.Exec}
	for _, a := range p.Argv {
		parts = append(parts, strconv.Quote(a))
	}
	return strings.Join(parts, " ") + "  with  " + strings.Join(p.Refs, ", ")
}

// PendingStore holds requests awaiting approval. Entries are one-shot and
// short-lived. OnExpire, if set, is called (outside the lock) with each nonce
// that expires, so the matching authorization right can be removed.
type PendingStore struct {
	TTL      time.Duration
	Now      func() time.Time
	OnExpire func(nonce string)

	mu   sync.Mutex
	list map[string]*Pending
}

func NewPendingStore(ttl time.Duration) *PendingStore {
	return &PendingStore{TTL: ttl, list: map[string]*Pending{}}
}

func (s *PendingStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func sortedCopy(refs []string) []string {
	out := append([]string(nil), refs...)
	sort.Strings(out)
	return out
}

// Create records a request covering refs and returns it.
func (s *PendingStore) Create(refs []string, execPath string, argv []string) *Pending {
	s.mu.Lock()
	expired := s.sweep()
	now := s.now()
	p := &Pending{
		Nonce:   randomNonce(),
		Refs:    sortedCopy(refs),
		Exec:    execPath,
		Argv:    append([]string(nil), argv...),
		Created: now,
		Expires: now.Add(s.TTL),
	}
	s.list[p.Nonce] = p
	s.mu.Unlock()
	s.expire(expired)
	return p
}

// Drop discards a request, e.g. when registering its right failed.
func (s *PendingStore) Drop(nonce string) {
	s.mu.Lock()
	delete(s.list, nonce)
	s.mu.Unlock()
}

// Get returns a live request.
func (s *PendingStore) Get(nonce string) (*Pending, error) {
	s.mu.Lock()
	expired := s.sweep()
	p, ok := s.list[nonce]
	s.mu.Unlock()
	s.expire(expired)
	if !ok {
		return nil, fmt.Errorf("no pending request %q (it may have expired)", nonce)
	}
	return p, nil
}

// MarkApproved records that a human authorized this request.
func (s *PendingStore) MarkApproved(nonce string) error {
	s.mu.Lock()
	expired := s.sweep()
	p, ok := s.list[nonce]
	if ok {
		p.approved = true
	}
	s.mu.Unlock()
	s.expire(expired)
	if !ok {
		return fmt.Errorf("no pending request %q (it may have expired)", nonce)
	}
	return nil
}

// Consume releases an approved request, only for exactly the refs, exec and
// argv it was minted for, and only once. The caller must have finished every
// other check first: consuming is the last step before the secrets resolve,
// so a later failure cannot waste the human's approval. A mismatch is the
// attack this store exists to stop, so it burns the approval.
func (s *PendingStore) Consume(nonce string, refs []string, execPath string, argv []string) error {
	s.mu.Lock()
	expired := s.sweep()
	p, ok := s.list[nonce]
	var err error
	switch {
	case !ok:
		err = fmt.Errorf("no pending request %q (it may have expired)", nonce)
	case !p.approved:
		err = fmt.Errorf("request %q has not been approved yet", nonce)
	case !sameRequest(p, refs, execPath, argv):
		delete(s.list, nonce)
		err = fmt.Errorf("approval %q was granted for a different command (%s) — refusing",
			nonce, p.Describe())
	default:
		delete(s.list, nonce)
	}
	s.mu.Unlock()
	s.expire(expired)
	return err
}

func sameRequest(p *Pending, refs []string, execPath string, argv []string) bool {
	got := sortedCopy(refs)
	if p.Exec != execPath || len(p.Refs) != len(got) || len(p.Argv) != len(argv) {
		return false
	}
	for i := range got {
		if p.Refs[i] != got[i] {
			return false
		}
	}
	for i := range argv {
		if p.Argv[i] != argv[i] {
			return false
		}
	}
	return true
}

// sweep drops expired requests and returns their nonces. Callers hold the lock.
func (s *PendingStore) sweep() []string {
	now := s.now()
	var gone []string
	for k, p := range s.list {
		if now.After(p.Expires) {
			delete(s.list, k)
			gone = append(gone, k)
		}
	}
	return gone
}

func (s *PendingStore) expire(nonces []string) {
	if s.OnExpire == nil {
		return
	}
	for _, n := range nonces {
		s.OnExpire(n)
	}
}

func randomNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the machine is not usable
	}
	return hex.EncodeToString(b)
}
