package gen

import (
	"regexp"
	"testing"
)

func TestPasswordShape(t *testing.T) {
	pw, err := Password(20, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 20 {
		t.Fatalf("length %d", len(pw))
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(pw) ||
		!regexp.MustCompile(`[A-Z]`).MatchString(pw) ||
		!regexp.MustCompile(`[0-9]`).MatchString(pw) {
		t.Fatalf("missing class: %q", pw)
	}
}

func TestPasswordNoAmbiguous(t *testing.T) {
	for i := 0; i < 50; i++ {
		pw, _ := Password(16, false)
		for _, bad := range "0O1lIio" {
			for _, c := range pw {
				if c == bad {
					t.Fatalf("ambiguous char %q in %q", bad, pw)
				}
			}
		}
	}
}

func TestTokenShape(t *testing.T) {
	tok, err := Token(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("length %d", len(tok))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(tok) {
		t.Fatalf("not url-safe: %q", tok)
	}
}

func TestUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		pw, _ := Password(12, false)
		if seen[pw] {
			t.Fatal("collision")
		}
		seen[pw] = true
	}
}
