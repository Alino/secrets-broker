package masking

import (
	"bytes"
	"strings"
	"testing"
)

func run(t *testing.T, minPartial int, secrets []string, chunks []string) string {
	t.Helper()
	m := New(minPartial)
	for _, s := range secrets {
		m.Register(s)
	}
	var buf bytes.Buffer
	w := m.Writer(&buf)
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestFullSecretMasked(t *testing.T) {
	got := run(t, 6, []string{"s3cr3t-value-xyz"}, []string{"prefix s3cr3t-value-xyz suffix"})
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret leaked: %q", got)
	}
	want := "prefix <concealed> suffix"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestPartialSecretMasked(t *testing.T) {
	// child prints only an interior slice of the secret (>= minPartial)
	got := run(t, 6, []string{"abcdefgh"}, []string{"x bcdefg y"})
	if strings.Contains(got, "bcdefg") {
		t.Fatalf("partial leaked: %q", got)
	}
	if !strings.Contains(got, "<concealed>") {
		t.Fatalf("expected placeholder: %q", got)
	}
}

func TestBoundarySpanning(t *testing.T) {
	secret := "SUPERSECRET123"
	chunks := []string{"out: SUPERSEC", "RET123 end"}
	got := run(t, 6, []string{secret}, chunks)
	if strings.Contains(got, "SUPERSEC") || strings.Contains(got, "RET123") {
		t.Fatalf("spanning secret leaked: %q", got)
	}
	if !strings.Contains(got, "<concealed>") {
		t.Fatalf("expected placeholder: %q", got)
	}
}

func TestShortSecretFullMatchOnly(t *testing.T) {
	// 5-char secret with minPartial 6: only the exact value is masked
	got := run(t, 6, []string{"abcde"}, []string{"abcd no, abcde yes"})
	if strings.Contains(got, "abcde") {
		t.Fatalf("short secret leaked: %q", got)
	}
	if !strings.Contains(got, "abcd no") {
		t.Fatalf("overshort fragment should pass: %q", got)
	}
}

func TestNoSecretsPassthrough(t *testing.T) {
	got := run(t, 6, nil, []string{"hello world"})
	if got != "hello world" {
		t.Fatalf("got %q", got)
	}
}

func TestUndecidedCarryFlush(t *testing.T) {
	// ends mid-secret with fewer than minPartial matching bytes: passes on flush
	got := run(t, 8, []string{"SECRETSECRET"}, []string{"tail SEC"})
	if !strings.HasSuffix(got, "SEC") {
		t.Fatalf("carry should flush verbatim when undecided: %q", got)
	}
}
