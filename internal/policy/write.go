package policy

import (
	"fmt"
	"sort"
	"strings"
)

// WritePolicy gates vault WRITES (save_secret / create_secret). Writes are
// denied by default; the user opts in per adapter via the policy file.
// Rationale: a prompt-injected agent must not be able to overwrite the
// user's vault (e.g. replacing the GitHub password to hijack future logins).
type WritePolicy struct {
	AllowCreate bool `json:"allow_create"` // allow NEW entries
	AllowUpdate bool `json:"allow_update"` // allow overwriting existing values
	// AllowAddFields allows adding a field an existing entry does not have
	// (or has empty) — e.g. a TOTP seed to a login — and never overwriting
	// one, nor setting the fields that decide which sites a login is offered
	// on (URL and the like). Credential substitution needs an overwrite or a
	// re-pointed URL, so this is safe to grant where AllowUpdate is not.
	AllowAddFields bool `json:"allow_add_fields,omitempty"`
}

// WriteMode is what ONE vault write may do. The MCP server derives it from the
// policy as reloaded for that call — never from adapter state set at startup —
// so a grant the user revokes stops working on the next call, not the next
// restart.
type WriteMode struct {
	Create    bool // make a new entry
	AddFields bool // add fields an existing entry lacks or has empty
	Update    bool // overwrite existing values (implies AddFields)
}

// Mode is the per-call write mode this policy grants.
func (p WritePolicy) Mode() WriteMode {
	return WriteMode{Create: p.AllowCreate, AddFields: p.AllowAddFields || p.AllowUpdate, Update: p.AllowUpdate}
}

// Any reports whether the mode permits any write at all.
func (m WriteMode) Any() bool { return m.Create || m.AddFields || m.Update }

// Write-mode names as `sb write-allow` takes and prints them.
const (
	ModeCreate    = "create"
	ModeAddFields = "add-fields"
	ModeUpdate    = "update"
)

// ParseWriteModes parses `sb write-allow` modes: a comma-separated list of
// create, add-fields and update; "both" (create,update, kept for existing
// scripts); or "none" to revoke every write. The result is exactly the listed
// set — it replaces the adapter's policy rather than adding to it.
func ParseWriteModes(s string) (WritePolicy, error) {
	var p WritePolicy
	s = strings.TrimSpace(s)
	switch s {
	case "none":
		return p, nil
	case "both":
		return WritePolicy{AllowCreate: true, AllowUpdate: true}, nil
	}
	for _, m := range strings.Split(s, ",") {
		switch strings.TrimSpace(m) {
		case ModeCreate:
			p.AllowCreate = true
		case ModeAddFields:
			p.AllowAddFields = true
		case ModeUpdate:
			p.AllowUpdate = true
		default:
			return WritePolicy{}, fmt.Errorf("unknown write mode %q (use create, add-fields, update — comma-separated — or both, none)", m)
		}
	}
	return p, nil
}

// Modes lists the granted modes in a stable order, for display and for
// rebuilding a mode string; empty when every write is denied.
func (p WritePolicy) Modes() []string {
	var out []string
	if p.AllowCreate {
		out = append(out, ModeCreate)
	}
	if p.AllowAddFields {
		out = append(out, ModeAddFields)
	}
	if p.AllowUpdate {
		out = append(out, ModeUpdate)
	}
	return out
}

// String renders the policy as `sb write-allow` would take it.
func (p WritePolicy) String() string {
	if m := p.Modes(); len(m) > 0 {
		return strings.Join(m, ",")
	}
	return "none"
}

// writePolicies maps adapter prefix -> policy, embedded in the store file.
type WriteConfig struct {
	Writes map[string]WritePolicy `json:"writes"`
}

// writeAllow returns the effective write policy for an adapter prefix.
func (s *Store) WriteAllow(adapter string) WritePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writes == nil {
		return WritePolicy{} // deny both
	}
	return s.writes[adapter]
}

// SetWritePolicy installs a write policy (used by the sb CLI).
func (s *Store) SetWritePolicy(adapter string, p WritePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writes == nil {
		s.writes = map[string]WritePolicy{}
	}
	s.writes[adapter] = p
}

// WritesRange iterates write policies (for serialization).
func (s *Store) WritesRange(fn func(adapter string, p WritePolicy)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for a, p := range s.writes {
		fn(a, p)
	}
}

// WriteAdapters lists adapters with a write policy entry, sorted.
func (s *Store) WriteAdapters() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.writes))
	for a := range s.writes {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
