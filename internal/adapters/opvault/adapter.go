// Package opvaultadapter resolves sec://opvault/<item>/<field> references
// from a local 1Password 7 standalone vault (.opvault directory), using the
// MIT-licensed reader vendored in third_party/opvault.
//
// The master password comes from (in order): SB_OPVAULT_PASSWORD env (tests),
// or a keychain-backed secret file path given at construction (production).
// The vault stays locked until first Resolve; unlock failures fail closed.
package opvaultadapter

import (
	"fmt"
	"strings"
	"sync"

	"github.com/vaultcore/secrets-broker/third_party/opvault"
)

// Adapter resolves refs against one opvault profile.
type Adapter struct {
	Dir        string // path to .opvault
	Profile    string // profile name, "" = default
	PasswordFn func() (string, error)

	mu        sync.Mutex
	profile   *opvault.Profile
	unlockErr error
}

// Resolve implements broker Resolver for sec://opvault/<item>/<field>.
// Item is matched by title (case-insensitive); field by label, falling back
// to common field kinds (password, username).
func (a *Adapter) Resolve(ref string) (string, error) {
	item, field, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	if err := a.ensureUnlocked(); err != nil {
		return "", err
	}
	items, err := a.profile.Items()
	if err != nil {
		return "", err
	}
	for _, it := range items {
		if !strings.EqualFold(it.Title(), item) {
			continue
		}
		detail, err := it.Detail()
		if err != nil {
			return "", err
		}
		for _, f := range detail.Fields() {
			if strings.EqualFold(f.Name(), field) {
				return f.Value(), nil
			}
		}
		// designation fallbacks: password / username by FieldDesignation
		switch strings.ToLower(field) {
		case "password":
			for _, f := range detail.Fields() {
				if f.Designation() == opvault.PasswordDesignation || f.Type() == opvault.PasswordFieldType {
					return f.Value(), nil
				}
			}
		case "username":
			for _, f := range detail.Fields() {
				if f.Designation() == opvault.UsernameDesignation {
					return f.Value(), nil
				}
			}
		}
		return "", fmt.Errorf("field %q not found in item %q", field, item)
	}
	return "", fmt.Errorf("item %q not found", item)
}

// List returns item titles (metadata only — for list_secrets).
func (a *Adapter) List() ([]string, error) {
	if err := a.ensureUnlocked(); err != nil {
		return nil, err
	}
	items, err := a.profile.Items()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !it.Trashed() {
			out = append(out, it.Title())
		}
	}
	return out, nil
}

func (a *Adapter) ensureUnlocked() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.profile != nil {
		return nil
	}
	if a.unlockErr != nil {
		return a.unlockErr // sticky: don't retry-brute a bad password
	}
	v, err := opvault.Open(a.Dir)
	if err != nil {
		a.unlockErr = err
		return err
	}
	profileName := a.Profile
	if profileName == "" {
		names, err := v.ProfileNames()
		if err != nil || len(names) == 0 {
			a.unlockErr = fmt.Errorf("no profiles in vault: %v", err)
			return a.unlockErr
		}
		profileName = names[0]
	}
	p, err := v.Profile(profileName)
	if err != nil {
		a.unlockErr = err
		return err
	}
	pw, err := a.PasswordFn()
	if err != nil {
		a.unlockErr = err
		return err
	}
	if err := p.Unlock(pw); err != nil {
		a.unlockErr = fmt.Errorf("opvault unlock failed (wrong password?)")
		return a.unlockErr
	}
	a.profile = p
	return nil
}

// parseRef splits sec://opvault/Item/Field with validation.
func parseRef(ref string) (item, field string, err error) {
	const prefix = "sec://opvault/"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", fmt.Errorf("opvault adapter: unsupported ref %q", ref)
	}
	rest := strings.TrimPrefix(ref, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("opvault adapter: ref must be sec://opvault/<item>/<field>, got %q", ref)
	}
	return parts[0], parts[1], nil
}
