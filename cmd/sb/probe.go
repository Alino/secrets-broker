package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	keepassadapter "github.com/vaultcore/secrets-broker/internal/adapters/keepass"
	"github.com/vaultcore/secrets-broker/internal/unlock"
)

// probeCmd answers, for entry titles the caller NAMES, whether the vault holds
// that entry and whether the entry carries a non-empty field — so an agent can
// find the ref to bind (`Steam`, not `store.steampowered.com`) and learn
// whether a login can finish unattended (an `otp` field) without anyone
// reading a value.
//
// Why this is not the inventory `sb items` withholds: it never lists, it only
// confirms names it is given; it prints no values; and it unlocks through the
// same sources as the broker (env → SB_SECRET_DIR → OS store), never a prompt.
// In single-uid mode that grants nothing the agent's uid could not already
// read. In isolated mode the agent's uid cannot read the stored master
// password, so the probe fails to unlock — only a human (sudo) can run it,
// which is the boundary working.
//
// Pass the vault path exactly as SB_KEEPASS_DB has it: the stored password is
// looked up by that string.
func probeCmd(args []string) error {
	if len(args) < 4 || args[0] != "keepass" {
		return fmt.Errorf("usage: sb probe keepass <vault-path> <field> <title> [<title>...]\n" +
			"  e.g. sb probe keepass \"$SB_KEEPASS_DB\" otp GitHub Steam\n" +
			"  reports FOUND / NO_ENTRY / NO_FIELD per title; prints no values")
	}
	path, field, titles := args[1], args[2], args[3:]
	a := &keepassadapter.Adapter{DBPath: path, PasswordFn: func() (string, error) {
		return unlock.KeepassPassword(path)
	}}
	return probe(a.Resolve, field, titles, os.Stdout)
}

// probe resolves each title's field and reports only the outcome; the value
// is dropped on the spot.
func probe(resolve func(string) (string, error), field string, titles []string, w io.Writer) error {
	for _, t := range titles {
		ref := "sec://keepass/" + t + "/" + field
		_, err := resolve(ref)
		switch {
		case err == nil:
			fmt.Fprintf(w, "FOUND     %s\n", ref)
		case errors.Is(err, keepassadapter.ErrEntryNotFound):
			fmt.Fprintf(w, "NO_ENTRY  %s\n", t)
		case errors.Is(err, keepassadapter.ErrFieldNotFound):
			fmt.Fprintf(w, "NO_FIELD  %s (entry exists; %q is absent or empty)\n", t, field)
		default:
			return err // unlock failure etc.: no answer is better than a wrong one
		}
	}
	return nil
}
