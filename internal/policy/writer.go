package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Writer is the optional write capability of an adapter. Implemented by
// keepass, bitwarden, opvault; enforced by Store.WriteAllow.
type Writer interface {
	// CreateEntry stores fields under groupPath/title and returns the ref.
	// Adapters decide field naming (UserName/Password for login items), and
	// must refuse a field they cannot store rather than silently drop it.
	CreateEntry(groupPath, title string, fields map[string]string) (string, error)
}

// EntryWriter is a Writer that can also change an EXISTING entry, within what
// mode allows for this one call. Adapters that only ever create new items
// (bitwarden, opvault) do not implement it.
type EntryWriter interface {
	Writer
	// WriteEntry stores fields in the entry groupPath/title and returns the
	// ref of refField in it — the field the caller is going to spend, so the
	// ref names what was actually written.
	WriteEntry(groupPath, title string, fields map[string]string, refField string, mode WriteMode) (WriteResult, error)
}

// RefuseUnknownFields returns an error naming every field an adapter cannot
// store. Adapters call it before writing anything: silently dropping a field
// the caller believes is stored — a TOTP seed, recovery codes — and returning
// a ref as if it were, is worse than refusing. Field names only, never values.
func RefuseUnknownFields(adapter string, fields map[string]string, supported ...string) error {
	var bad []string
	for k := range fields {
		ok := false
		for _, s := range supported {
			if k == s { // exact: the adapters look these names up exactly
				ok = true
				break
			}
		}
		if !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%s adapter cannot store field(s) %s (it stores only %s); nothing was written",
		adapter, strings.Join(bad, ", "), strings.Join(supported, ", "))
}

// WriteResult describes a completed vault write.
type WriteResult struct {
	Ref     string
	Created bool // a new entry, as opposed to fields added to an existing one
}
