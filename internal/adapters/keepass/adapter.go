// Package keepass resolves sec://keepass/<entry>/<field> from a .kdbx vault
// via gokeepasslib (kdbx4: AES/ChaCha20 + Argon2).
package keepass

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	keepasslib "github.com/tobischo/gokeepasslib/v3"
)

// Adapter resolves refs against one keepass database.
type Adapter struct {
	DBPath     string
	PasswordFn func() (string, error)
	// AllowUpdates lets CreateEntry change an existing entry. The MCP server
	// does not use it: it calls WriteEntry with a mode taken from the policy
	// as reloaded for each call, so a revoked grant cannot outlive a restart.
	AllowUpdates bool
	KeyFile      string // optional .keyx/.key path

	mu        sync.Mutex
	db        *keepasslib.Database // never mutated once published; replaced whole
	loaded    os.FileInfo          // the file version db was decoded from
	creds     *keepasslib.DBCredentials
	unlockErr error
}

// Resolve implements the broker Resolver for sec://keepass/<entry>/<field>.
// Entry matched by title (case-insensitive); "Group/Entry" paths supported.
// Field matched by KeePass KV name, falling back to UserName/Password.
func (a *Adapter) Resolve(ref string) (string, error) {
	entry, field, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	db, err := a.current()
	if err != nil {
		return "", err
	}
	root := db.Content.Root
	if root == nil {
		return "", fmt.Errorf("keepass: empty database")
	}
	e := findEntry(root.Groups, entry)
	if e == nil {
		return "", &lookupError{fmt.Sprintf("keepass: entry %q not found", entry), ErrEntryNotFound}
	}
	for i := range e.Values {
		kv := &e.Values[i]
		if strings.EqualFold(kv.Key, field) && kv.Value.Content != "" {
			return kv.Value.Content, nil
		}
	}
	switch strings.ToLower(field) {
	case "password":
		if v := e.GetContent("Password"); v != "" {
			return v, nil
		}
	case "username":
		if v := e.GetContent("UserName"); v != "" {
			return v, nil
		}
	}
	return "", &lookupError{fmt.Sprintf("keepass: field %q not found in entry %q", field, entry), ErrFieldNotFound}
}

// ErrEntryNotFound and ErrFieldNotFound classify Resolve failures (errors.Is)
// for callers such as `sb probe`, without parsing messages. The messages are
// unchanged: docs tell agents that `entry "…" not found` proves an unlock.
var (
	ErrEntryNotFound = errors.New("keepass: entry not found")
	ErrFieldNotFound = errors.New("keepass: field not found")
)

type lookupError struct {
	msg  string
	kind error
}

func (e *lookupError) Error() string { return e.msg }
func (e *lookupError) Unwrap() error { return e.kind }

// List returns "Group/Entry" titles (metadata only).
func (a *Adapter) List() ([]string, error) {
	db, err := a.current()
	if err != nil {
		return nil, err
	}
	if db.Content.Root == nil {
		return nil, nil
	}
	var out []string
	var walk func(groups []keepasslib.Group, prefix string)
	walk = func(groups []keepasslib.Group, prefix string) {
		for _, g := range groups {
			p := g.Name
			if prefix != "" {
				p = prefix + "/" + g.Name
			}
			for _, e := range g.Entries {
				title := e.GetTitle()
				if title == "" {
					continue
				}
				if p != "" {
					out = append(out, p+"/"+title)
				} else {
					out = append(out, title)
				}
			}
			walk(g.Groups, p)
		}
	}
	walk(db.Content.Root.Groups, "")
	return out, nil
}

// current returns the database as it is on disk now. The vault is shared with
// other writers — the user's KeePassXC, Syncthing delivering an edit from
// another device, a second broker — so the copy decoded at first unlock is
// re-read whenever the file changes. Answering from a stale copy hides the
// user's new entries; writing one back deletes them.
func (a *Adapter) current() (*keepasslib.Database, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.loadLocked(); err != nil {
		return nil, err
	}
	return a.db, nil
}

// loadLocked unlocks on first use and re-reads the vault when the file on disk
// is no longer the version last decoded. a.mu must be held.
//
// The FIRST unlock is sticky fail-closed: a bad password locks the adapter for
// its lifetime and is never retried. A failed RE-read is not sticky — it reuses
// the password that already opened this vault, so retrying guesses nothing —
// but it fails closed: it never falls back to the old copy.
func (a *Adapter) loadLocked() error {
	if a.unlockErr != nil {
		return a.unlockErr
	}
	if a.db == nil {
		return a.firstUnlockLocked()
	}
	fi, err := os.Stat(a.DBPath)
	if err != nil {
		return fmt.Errorf("keepass: vault unreadable: %w", err)
	}
	if sameVersion(a.loaded, fi) {
		return nil
	}
	db, fi, err := decodeFile(a.DBPath, a.creds)
	if err != nil {
		return fmt.Errorf("keepass: the vault changed on disk and cannot be re-read; refusing to answer "+
			"from the old copy (if the master password changed, store the new one with `sb set-password` "+
			"and restart the broker): %w", err)
	}
	a.db, a.loaded = db, fi
	return nil
}

func (a *Adapter) firstUnlockLocked() error {
	if _, err := os.Stat(a.DBPath); err != nil {
		a.unlockErr = err
		return err
	}
	pw, err := a.PasswordFn()
	if err != nil {
		a.unlockErr = err
		return err
	}
	creds := keepasslib.NewPasswordCredentials(pw)
	db, fi, err := decodeFile(a.DBPath, creds)
	if err != nil {
		a.unlockErr = fmt.Errorf("keepass unlock failed: %w", err)
		return a.unlockErr
	}
	a.db, a.loaded, a.creds = db, fi, creds
	return nil
}

// decodeFile decodes the vault at path with protected values in plaintext. The
// returned FileInfo is taken from the open descriptor, so it describes exactly
// the bytes that were decoded even if the path is replaced meanwhile.
func decodeFile(path string, creds *keepasslib.DBCredentials) (*keepasslib.Database, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	db := keepasslib.NewDatabase()
	db.Credentials = creds
	if err := keepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, nil, err
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, nil, fmt.Errorf("decrypt entries: %w", err)
	}
	return db, fi, nil
}

// sameVersion reports whether two stats describe the same version of the vault
// file. A writer that replaces the file atomically (KeePassXC's safe save,
// Syncthing, this adapter) changes the inode; one that rewrites it in place
// changes the size or the modification time.
func sameVersion(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) &&
		a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// findEntry walks groups; title may contain '/' to address "Group/Entry".
// Group segments match ANY group at ANY depth (depth-first), so refs are
// independent of the root group's name (keepassxc calls it "Passwords",
// KeePass uses "NewDatabase" etc.).
func findEntry(groups []keepasslib.Group, title string) *keepasslib.Entry {
	if i := strings.Index(title, "/"); i >= 0 {
		groupName, rest := title[:i], title[i+1:]
		var found *keepasslib.Entry
		var search func(gs []keepasslib.Group)
		search = func(gs []keepasslib.Group) {
			for gi := range gs {
				if found != nil {
					return
				}
				g := &gs[gi]
				if strings.EqualFold(g.Name, groupName) {
					if sub := findEntry(g.Groups, rest); sub != nil {
						found = sub
						return
					}
					for ei := range g.Entries {
						if strings.EqualFold(g.Entries[ei].GetTitle(), rest) {
							found = &g.Entries[ei]
							return
						}
					}
					// name matched but entry not here — keep looking
					// (another same-named group deeper/elsewhere may hold it)
				}
				search(g.Groups)
			}
		}
		search(groups)
		return found
	}
	var found *keepasslib.Entry
	var scan func(groups []keepasslib.Group)
	scan = func(groups []keepasslib.Group) {
		for _, g := range groups {
			for i := range g.Entries {
				if found == nil && strings.EqualFold(g.Entries[i].GetTitle(), title) {
					found = &g.Entries[i]
				}
			}
			scan(g.Groups)
		}
	}
	scan(groups)
	return found
}

// parseRef splits sec://keepass/<entry>/<field>; field is the LAST segment.
func parseRef(ref string) (entry, field string, err error) {
	const prefix = "sec://keepass/"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", fmt.Errorf("keepass adapter: unsupported ref %q", ref)
	}
	rest := strings.TrimPrefix(ref, prefix)
	i := strings.LastIndex(rest, "/")
	if i <= 0 || i == len(rest)-1 {
		return "", "", fmt.Errorf("keepass adapter: ref must be sec://keepass/<entry>/<field>, got %q", ref)
	}
	return rest[:i], rest[i+1:], nil
}
