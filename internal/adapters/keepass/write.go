package keepass

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	keepasslib "github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

// maxWriteAttempts bounds how often a write is redone because another writer
// replaced the vault while it was being encoded.
const maxWriteAttempts = 3

// testHookBeforeReplace, when set, runs after a write is encoded and verified
// and before the vault is checked for concurrent changes (tests only).
var testHookBeforeReplace func()

// CreateEntry adds a new entry (or, with AllowUpdates, overwrites the named
// fields of the existing one) and returns the ref of its Password. It is
// WriteEntry with the mode fixed by the adapter's own AllowUpdates; the MCP
// server calls WriteEntry with a mode derived from the live policy instead.
func (a *Adapter) CreateEntry(groupPath, title string, fields map[string]string) (string, error) {
	res, err := a.WriteEntry(groupPath, title, fields, "Password",
		policy.WriteMode{Create: true, AddFields: a.AllowUpdates, Update: a.AllowUpdates})
	return res.Ref, err
}

// WriteEntry stores fields in the entry groupPath/title, as far as mode allows,
// and returns the ref of refField in it:
//
//   - no such entry: needs mode.Create; it is made in groupPath
//   - the entry lacks the field, or has it empty: needs mode.AddFields
//   - the entry has a value in the field: needs mode.Update; it is overwritten
//
// An existing entry is found the way Resolve finds one — title match at any
// group depth, "Group/Title" paths — so the returned ref resolves to the entry
// that was written. Changing an existing entry keeps every field the caller
// did not name and moves the previous version into the entry's history, where
// KeePassXC can restore it. refField is always stored protected: it is the
// value the caller is going to spend.
//
// Password fields are stored protected (inner-stream encrypted), per the
// library's writing pattern: set values -> db.LockProtectedEntries() -> Encode.
// The vault is shared with other writers, so the write is applied to the file
// as it is on disk NOW — decoded under the write lock — never to the copy read
// at unlock: writing that copy back would delete everything added since. If the
// file is replaced again while this write is being encoded, the write is redone
// against the new version rather than overwriting it.
func (a *Adapter) WriteEntry(groupPath, title string, fields map[string]string, refField string, mode policy.WriteMode) (policy.WriteResult, error) {
	if refField == "" {
		refField = "Password"
	}
	groupPath = strings.Trim(groupPath, "/")
	if strings.TrimSpace(title) == "" {
		return policy.WriteResult{}, fmt.Errorf("keepass: an entry title is required")
	}
	for k := range fields {
		if strings.TrimSpace(k) == "" {
			return policy.WriteResult{}, fmt.Errorf("keepass: empty field name")
		}
		if strings.EqualFold(k, "Title") {
			return policy.WriteResult{}, fmt.Errorf("keepass: the title is set by the title parameter, not as a field")
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.loadLocked(); err != nil {
		return policy.WriteResult{}, err
	}

	// serialize broker writers (KeePassXC does not know this lock; the
	// re-check before rename below covers it)
	lock := a.DBPath + ".sblock"
	lockF, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return policy.WriteResult{}, fmt.Errorf("keepass: another writer holds the lock (%s)", lock)
	}
	defer func() { lockF.Close(); os.Remove(lock) }()

	tmp := a.DBPath + ".sbtmp"
	for attempt := 0; attempt < maxWriteAttempts; attempt++ {
		work, base, err := decodeFile(a.DBPath, a.creds)
		if err != nil {
			return policy.WriteResult{}, fmt.Errorf("keepass: re-reading the vault before writing failed (vault NOT modified): %w", err)
		}
		created, err := applyWrite(work, groupPath, title, fields, refField, mode)
		if err != nil {
			return policy.WriteResult{}, err
		}
		written, writtenFI, err := a.encodeVerified(work, base, tmp)
		if err != nil {
			os.Remove(tmp)
			return policy.WriteResult{}, err
		}
		if testHookBeforeReplace != nil {
			testHookBeforeReplace()
		}
		// Last check before replacing: if another writer saved after we
		// decoded, our copy lacks its change — start over from its version.
		now, err := os.Stat(a.DBPath)
		if err != nil {
			os.Remove(tmp)
			return policy.WriteResult{}, err
		}
		if !sameVersion(base, now) {
			os.Remove(tmp)
			continue
		}
		if err := os.Rename(tmp, a.DBPath); err != nil {
			os.Remove(tmp)
			return policy.WriteResult{}, err
		}
		// Publish the verified re-decode of what is now on disk: plaintext
		// values, and the stamp of the file it came from (rename keeps the
		// inode, so the next read sees it as current).
		a.db, a.loaded = written, writtenFI
		return policy.WriteResult{Ref: entryRef(groupPath, title, refField), Created: created}, nil
	}
	return policy.WriteResult{}, fmt.Errorf("keepass: the vault kept changing during the write; gave up after %d attempts (vault NOT modified)", maxWriteAttempts)
}

func entryRef(groupPath, title, field string) string {
	if groupPath != "" {
		return "sec://keepass/" + groupPath + "/" + title + "/" + field
	}
	return "sec://keepass/" + title + "/" + field
}

// applyWrite applies one write to db in memory and reports whether it made a
// new entry. On error db is discarded as is: nothing in it is published.
func applyWrite(db *keepasslib.Database, groupPath, title string, fields map[string]string, refField string, mode policy.WriteMode) (bool, error) {
	root := db.Content.Root
	if root == nil {
		return false, fmt.Errorf("keepass: empty database")
	}

	// KDBX spec: Root has EXACTLY ONE Group (the root group); sub-groups nest
	// inside it. (Appending a sibling root group makes keepassxc report
	// "No root group" — verified empirically.)
	if len(root.Groups) == 0 {
		return false, fmt.Errorf("keepass: database has no root group")
	}

	// Look the entry up exactly as Resolve will. Searching only groupPath
	// would make a second entry with the same title beside one that lives in
	// another group, and the ref would keep resolving to the old one — which
	// lacks the field just written.
	path := title
	if groupPath != "" {
		path = groupPath + "/" + title
	}
	if e := findEntry(root.Groups, path); e != nil {
		return false, changeEntry(e, path, fields, refField, mode)
	}
	if !mode.Create {
		return false, fmt.Errorf("keepass: no entry %q, and creating entries is not allowed — needs: sb write-allow keepass create", path)
	}

	target := &root.Groups[0]
	for _, p := range splitPath(groupPath) {
		var next *keepasslib.Group
		for i := range target.Groups {
			if target.Groups[i].Name == p {
				next = &target.Groups[i]
				break
			}
		}
		if next == nil {
			g := keepasslib.NewGroup()
			g.Name = p
			g.Times = keepasslib.NewTimeData()
			target.Groups = append(target.Groups, g)
			next = &target.Groups[len(target.Groups)-1]
		}
		target = next
	}

	target.Entries = append(target.Entries, keepasslib.NewEntry())
	entry := &target.Entries[len(target.Entries)-1]
	now := w.Now()
	entry.Times = keepasslib.TimeData{
		CreationTime:         &now,
		LastModificationTime: &now,
		LastAccessTime:       &now,
		LocationChanged:      &now,
		Expires:              w.NewBoolWrapper(false),
	}
	vals := []keepasslib.ValueData{{Key: "Title", Value: keepasslib.V{Content: title}}}
	for _, k := range sortedKeys(fields) {
		vals = append(vals, keepasslib.ValueData{
			Key:   k,
			Value: keepasslib.V{Content: fields[k], Protected: w.NewBoolWrapper(isProtectedField(k) || strings.EqualFold(k, refField))},
		})
	}
	entry.Values = vals
	return true, nil
}

// changeEntry adds and/or overwrites fields of an existing entry, as mode
// allows. Every field is checked before anything changes, so a refused write
// leaves the entry as it was. Error messages name fields, never values.
func changeEntry(e *keepasslib.Entry, path string, fields map[string]string, refField string, mode policy.WriteMode) error {
	var overwrites, routing []string
	for k := range fields {
		i := valueIndex(e, k)
		switch {
		case i >= 0 && e.Values[i].Value.Content != "":
			overwrites = append(overwrites, e.Values[i].Key)
		case routesAutofill(k):
			routing = append(routing, k)
		}
	}
	sort.Strings(overwrites)
	sort.Strings(routing)
	switch {
	case len(overwrites) > 0 && !mode.Update:
		if mode.AddFields {
			return fmt.Errorf("keepass: entry %q already has a value in %s; adding fields never overwrites one — "+
				"changing a stored value needs: sb write-allow keepass update", path, strings.Join(overwrites, ", "))
		}
		return fmt.Errorf("keepass: entry %q already exists — update policy required (AllowUpdate): sb write-allow keepass update", path)
	case len(routing) > 0 && !mode.Update:
		return fmt.Errorf("keepass: %s decides which sites entry %q is offered on, so setting it on an existing "+
			"entry needs: sb write-allow keepass update", strings.Join(routing, ", "), path)
	case !mode.AddFields && !mode.Update:
		return fmt.Errorf("keepass: entry %q already exists — adding fields to it needs: sb write-allow keepass add-fields", path)
	}

	// History first: KeePassXC shows it under the entry's History tab and can
	// restore it, so nothing the agent writes is unrecoverable. A history item
	// carries its entry's UUID and has no history of its own.
	snap := e.Clone()
	snap.UUID = e.UUID
	snap.Histories = nil
	if len(e.Histories) == 0 {
		e.Histories = []keepasslib.History{{}}
	}
	last := &e.Histories[len(e.Histories)-1]
	last.Entries = append(last.Entries, snap)

	for _, k := range sortedKeys(fields) {
		protect := isProtectedField(k) || strings.EqualFold(k, refField)
		if i := valueIndex(e, k); i >= 0 {
			e.Values[i].Value.Content = fields[k]
			e.Values[i].Value.Protected = w.NewBoolWrapper(protect || e.Values[i].Value.Protected.Bool)
			continue
		}
		e.Values = append(e.Values, keepasslib.ValueData{
			Key: k, Value: keepasslib.V{Content: fields[k], Protected: w.NewBoolWrapper(protect)},
		})
	}
	now := w.Now()
	e.Times.LastModificationTime = &now
	e.Times.LastAccessTime = &now
	return nil
}

// valueIndex finds a field by name the way Resolve matches one
// (case-insensitively), so a write and a later read agree on which it is.
func valueIndex(e *keepasslib.Entry, key string) int {
	for i := range e.Values {
		if strings.EqualFold(e.Values[i].Key, key) {
			return i
		}
	}
	return -1
}

// routesAutofill reports fields that decide which sites a login is offered
// on: the URL, KeePassXC-Browser's additional URLs (KP2A_URL, KP2A_URL_1, …)
// and its legacy "KPH: …" settings. add-fields may not set them on an existing
// entry even when empty: pointing the GitHub entry's empty URL at a phishing
// origin would make the user's own browser extension offer the GitHub
// password there. That is a substitution of where, not what, and needs update.
func routesAutofill(k string) bool {
	l := strings.ToLower(strings.TrimSpace(k))
	return l == "url" || strings.HasPrefix(l, "kp2a_url") || strings.HasPrefix(l, "kph:")
}

// isProtectedField reports fields stored inner-stream encrypted and shown
// masked by KeePassXC: the password, and every field that holds a secret the
// broker writes — TOTP seeds (KeePassXC's "otp", its older "TOTP Seed", and
// KeePass 2.47+'s TimeOtp-/HmacOtp-Secret* family) and generic token names.
func isProtectedField(k string) bool {
	l := strings.ToLower(strings.TrimSpace(k))
	switch l {
	case "password", "otp", "totp seed", "secret", "api key", "token":
		return true
	}
	return strings.HasPrefix(l, "timeotp-secret") || strings.HasPrefix(l, "hmacotp-secret")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// encodeVerified encodes db to tmp with the vault's current mode and group,
// then re-decodes tmp with the same credentials. It returns that re-decode —
// plaintext, and exactly what will be on disk — with tmp's FileInfo. Encoding
// leaves db's protected values as ciphertext, so db itself is never published.
func (a *Adapter) encodeVerified(db *keepasslib.Database, base os.FileInfo, tmp string) (*keepasslib.Database, os.FileInfo, error) {
	f, err := os.Create(tmp)
	if err != nil {
		return nil, nil, err
	}
	if err := db.LockProtectedEntries(); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("keepass: protect entries: %w", err)
	}
	if err := keepasslib.NewEncoder(f).Encode(db); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("keepass: encode: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	// Match the existing database's mode and group so a co-reader that shares
	// the group — e.g. KeePassXC running as the user on the same .kdbx — can
	// read what the broker writes. (Same rule as the opvault adapter.)
	os.Chmod(tmp, base.Mode().Perm())
	if st, ok := base.Sys().(*syscall.Stat_t); ok {
		os.Chown(tmp, -1, int(st.Gid)) // group only; keep our uid
	}
	written, fi, err := decodeFile(tmp, a.creds)
	if err != nil {
		return nil, nil, fmt.Errorf("keepass: verify failed (vault NOT modified): %w", err)
	}
	return written, fi, nil
}

func splitPath(p string) []string {
	var out []string
	cur := ""
	for _, r := range p {
		if r == '/' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
