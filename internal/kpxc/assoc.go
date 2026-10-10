// Package kpxc speaks the KeePassXC-Browser native messaging protocol, so the
// existing (published, reviewed, already-installed) browser extension can fill
// credentials from any adapter this broker supports — opvault and
// Bitwarden included, none of which have a browser filler of their own since
// 1Password 7 went end of life.
//
// The protocol is documented at
// github.com/keepassxreboot/keepassxc-browser/blob/master/keepassxc-protocol.md
// and reimplemented here; no code from that project is used.
package kpxc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Scope is what an associated browser is allowed to ask for. An association
// is a principal: "my everyday browser" and "the browser an agent drives" are
// not the same caller and must not have the same rights.
type Scope string

const (
	// ScopeHuman: every credential whose policy binds it to the requested
	// origin. The human is already able to open their own vault.
	ScopeHuman Scope = "human"
	// ScopeAgent: the same, minus anything the policy has not explicitly
	// bound to an origin — and the daemon still applies its own checks.
	ScopeAgent Scope = "agent"
)

// Assoc is one associated browser.
type Assoc struct {
	ID       string    `json:"id"`
	IDKey    string    `json:"id_key"` // base64 public key the browser identifies with
	Scope    Scope     `json:"scope"`
	Approved bool      `json:"approved"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitempty"`
	Note     string    `json:"note,omitempty"` // browser/user agent hint, for the human approving
}

// AssocStore persists associations next to the daemon's other state. New
// associations arrive UNAPPROVED: the daemon has no GUI to prompt with, so a
// human approves them out of band with `sb browser approve`. Auto-approving
// would let anything that can reach the socket enrol itself as a filler.
type AssocStore struct {
	path  string
	mu    sync.Mutex
	list  map[string]*Assoc
	mtime time.Time
}

// reloadIfChanged re-reads the file when it has moved on disk. The daemon
// holds this store in memory while `sb browser approve` edits the file from
// another process — without this, approving does nothing until a restart.
// Callers hold the lock.
func (s *AssocStore) reloadIfChanged() {
	if s.path == "" {
		return
	}
	fi, err := os.Stat(s.path)
	if err != nil || fi.ModTime().Equal(s.mtime) {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return // keep what we have; a half-written file must not drop grants
	}
	var items []*Assoc
	if err := json.Unmarshal(b, &items); err != nil {
		return
	}
	s.list = map[string]*Assoc{}
	for _, a := range items {
		s.list[a.ID] = a
	}
	s.mtime = fi.ModTime()
}

func LoadAssoc(path string) (*AssocStore, error) {
	s := &AssocStore{path: path, list: map[string]*Assoc{}}
	if fi, err := os.Stat(path); err == nil {
		s.mtime = fi.ModTime()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var items []*Assoc
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	for _, a := range items {
		s.list[a.ID] = a
	}
	return s, nil
}

func (s *AssocStore) save() error {
	if s.path == "" {
		return nil
	}
	items := make([]*Assoc, 0, len(s.list))
	for _, a := range s.list {
		items = append(items, a)
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(s.path, b, 0600); err != nil {
		return err
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime = fi.ModTime()
	}
	return nil
}

// locked runs fn while holding an exclusive lock shared by every process that
// uses this file — the daemon and `sb browser` both do. Inside the lock the
// file is re-read unconditionally, so a mutation always applies to what is on
// disk rather than to a stale in-memory copy. Without this, the daemon could
// reload, then `sudo sb browser approve` could write, then the daemon's save
// would write its old copy back and silently revert the approval.
//
// The lock file is opened read-only and created 0644: if root creates it
// first, the daemon's account can still open and flock it (flock works on a
// read-only descriptor). A 0600 root-owned lock would lock the daemon out.
func (s *AssocStore) locked(fn func() error) error {
	if s.path == "" {
		return fn()
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path+".lock", os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err := s.forceReload(); err != nil {
		return err
	}
	return fn()
}

// forceReload replaces the in-memory list with the file's contents, ignoring
// mtime (whose granularity is not something a lock should depend on). A
// missing file means no associations.
func (s *AssocStore) forceReload() error {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.list = map[string]*Assoc{}
		return nil
	}
	if err != nil {
		return err
	}
	var items []*Assoc
	if err := json.Unmarshal(b, &items); err != nil {
		return err
	}
	s.list = map[string]*Assoc{}
	for _, a := range items {
		s.list[a.ID] = a
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime = fi.ModTime()
	}
	return nil
}

// Add records a new association request. It is not usable until approved.
func (s *AssocStore) Add(id, idKey, note string) (*Assoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &Assoc{ID: id, IDKey: idKey, Scope: ScopeAgent, Created: time.Now().UTC(), Note: note}
	err := s.locked(func() error {
		s.list[id] = a
		return s.save()
	})
	return a, err
}

// Get returns an association by id.
func (s *AssocStore) Get(id string) (*Assoc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadIfChanged()
	a, ok := s.list[id]
	return a, ok
}

// Verify reports whether id is known, approved, and identified by idKey.
// A mismatched key is a different browser claiming someone else's id.
func (s *AssocStore) Verify(id, idKey string) (*Assoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Decide against the file as it is now, under the lock: an mtime check can
	// miss a write landing in the same timestamp tick, and a missed revocation
	// would keep a revoked browser filling.
	var a *Assoc
	err := s.locked(func() error {
		cur, ok := s.list[id]
		if !ok {
			return fmt.Errorf("unknown association %q", id)
		}
		if cur.IDKey != idKey {
			return fmt.Errorf("association %q presented the wrong identity key", id)
		}
		if !cur.Approved {
			return fmt.Errorf("association %q is not approved — run: sb browser approve %s", id, id)
		}
		cur.LastUsed = time.Now().UTC()
		a = cur
		_ = s.save() // last-used is bookkeeping; failing to record it must not deny
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Approve marks an association usable, with a scope.
func (s *AssocStore) Approve(id string, scope Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked(func() error {
		a, ok := s.list[id]
		if !ok {
			return fmt.Errorf("unknown association %q", id)
		}
		a.Approved, a.Scope = true, scope
		return s.save()
	})
}

// Remove revokes an association.
func (s *AssocStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked(func() error {
		if _, ok := s.list[id]; !ok {
			// Do not create the file as a side effect of revoking nothing: run
			// as root it would land root-owned and lock the daemon out of it.
			return fmt.Errorf("unknown association %q", id)
		}
		delete(s.list, id)
		return s.save()
	})
}

// All returns every association, for `sb browser list`.
func (s *AssocStore) All() []Assoc {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadIfChanged()
	out := make([]Assoc, 0, len(s.list))
	for _, a := range s.list {
		out = append(out, *a)
	}
	return out
}
