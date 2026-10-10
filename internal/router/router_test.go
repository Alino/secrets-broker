// Package router dispatches sec:// refs to the right adapter by prefix.
package router

import (
	"strings"
	"testing"
)

func TestDispatch(t *testing.T) {
	r := New()
	r.Register("opvault", func(ref string) (string, error) { return "OP", nil })
	r.Register("keepass", func(ref string) (string, error) { return "KP", nil })
	if v, err := r.Resolve("sec://keepass/GitHub/password"); err != nil || v != "KP" {
		t.Fatalf("keepass: %q %v", v, err)
	}
	if v, err := r.Resolve("sec://opvault/GitHub/password"); err != nil || v != "OP" {
		t.Fatalf("opvault: %q %v", v, err)
	}
}

func TestUnknownAdapterNamesKnown(t *testing.T) {
	r := New()
	r.Register("opvault", func(ref string) (string, error) { return "", nil })
	_, err := r.Resolve("sec://enpass/x/y")
	if err == nil || !strings.Contains(err.Error(), "opvault") {
		t.Fatalf("expected helpful error, got %v", err)
	}
}

func TestMalformedRefs(t *testing.T) {
	r := New()
	for _, bad := range []string{"op://x", "sec://onlyprefix", "sec:///", "sec://a"} {
		if _, err := r.Resolve(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
