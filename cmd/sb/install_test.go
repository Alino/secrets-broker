package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultEnvVar(t *testing.T) {
	cases := []struct {
		spec    string
		wantKey string // substring expected, or "" for empty result
		wantErr bool
	}{
		{"", "", false},
		{"opvault:/vaults/a.opvault", "SB_VAULT_DIR", false},
		{"keepass:/vaults/a.kdbx", "SB_KEEPASS_DB", false},
		{"enpass:/vaults/a.enpassdb", "", true}, // adapter removed in v0.3
		{"bogus:/x", "", true},
		{"opvault", "", true},  // no ":"
		{"opvault:", "", true}, // empty path
	}
	for _, c := range cases {
		got, err := vaultEnvVar(c.spec)
		if (err != nil) != c.wantErr {
			t.Fatalf("vaultEnvVar(%q) err=%v want err=%v", c.spec, err, c.wantErr)
		}
		if c.wantErr {
			continue
		}
		if c.wantKey == "" {
			if got != "" {
				t.Fatalf("vaultEnvVar(%q)=%q want empty", c.spec, got)
			}
			continue
		}
		if !strings.Contains(got, c.wantKey) {
			t.Fatalf("vaultEnvVar(%q)=%q want key %q", c.spec, got, c.wantKey)
		}
	}
}

func TestVaultKeyValue(t *testing.T) {
	got, err := vaultKeyValue("keepass:/v/a.kdbx")
	if err != nil || got != "SB_KEEPASS_DB=/v/a.kdbx" {
		t.Fatalf("vaultKeyValue = %q, %v", got, err)
	}
	if got, _ := vaultKeyValue(""); got != "" {
		t.Fatalf("empty spec => %q, want empty", got)
	}
	if _, err := vaultKeyValue("bogus:/x"); err == nil {
		t.Fatal("expected error for unknown adapter")
	}
}

func TestXMLEscape(t *testing.T) {
	got := xmlEscape("/vaults/a & b <c>.opvault")
	if strings.Contains(got, "<c>") { // raw angle brackets would break plist parsing
		t.Fatalf("xmlEscape left raw markup in %q", got)
	}
	for _, enc := range []string{"&amp;", "&lt;", "&gt;"} {
		if !strings.Contains(got, enc) {
			t.Fatalf("xmlEscape did not produce %q: %q", enc, got)
		}
	}
}

// A vault path with XML-special characters must not break plist parsing.
func TestPlistBodyIsValidXML(t *testing.T) {
	env, err := vaultEnvVar("opvault:/vaults/a & b.opvault")
	if err != nil {
		t.Fatal(err)
	}
	body := plistBody(env)
	if err := xml.Unmarshal([]byte(body), new(any)); err != nil {
		t.Fatalf("plist is not valid XML: %v\n%s", err, body)
	}
	// The daemon reads these; a template edit that drops one is a silent break.
	for _, want := range []string{"SB_POLICY_FILE", "SB_SECRET_DIR", "SB_VAULT_DIR", "-socket", socketPath} {
		if !strings.Contains(body, want) {
			t.Fatalf("plist missing %q", want)
		}
	}
	// No vault => no vault env key, but still valid XML.
	if err := xml.Unmarshal([]byte(plistBody("")), new(any)); err != nil {
		t.Fatalf("no-vault plist invalid XML: %v", err)
	}
}

func TestUnitBody(t *testing.T) {
	kv, err := vaultKeyValue("keepass:/v/a.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	body := unitBody(kv)
	for _, want := range []string{
		"User=" + brokerUser,
		"Group=" + clientGroup,
		"Environment=SB_KEEPASS_DB=/v/a.kdbx",
		"WantedBy=multi-user.target",
		"-socket " + socketPath,
		"ReadWritePaths=" + brokerVar,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unit missing %q:\n%s", want, body)
		}
	}
	// No vault => no SB_KEEPASS_DB/SB_VAULT_DIR line.
	if strings.Contains(unitBody(""), "SB_KEEPASS_DB") {
		t.Fatal("no-vault unit unexpectedly set a vault env")
	}
}

func TestFindBinary(t *testing.T) {
	dir := t.TempDir()
	// exact name wins
	touch(t, filepath.Join(dir, "sb"))
	if got, err := findBinary(dir, "sb"); err != nil || got != filepath.Join(dir, "sb") {
		t.Fatalf("findBinary exact = %q, %v", got, err)
	}
	// platform-suffixed name is accepted
	touch(t, filepath.Join(dir, "secrets-broker-mcp-darwin"))
	if _, err := findBinary(dir, "secrets-broker-mcp"); err != nil {
		t.Fatalf("suffixed lookup: %v", err)
	}
	// missing, non-swift binary => actionable error
	if _, err := findBinary(dir, "nope"); err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestEnsureTraversable(t *testing.T) {
	// ensureTraversable walks up to "/", so the tree must sit under a
	// world-traversable base — the macOS per-user temp dir (/var/folders/...)
	// is not, and chmod on its ancestors we don't own fails. /tmp (sticky
	// 1777) is world-traversable, which is exactly the property under test.
	root, err := os.MkdirTemp("/tmp", "sbtrav")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	mid := filepath.Join(root, "mid")
	leaf := filepath.Join(mid, "leaf")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0700); err != nil { // strip traversal for others
		t.Fatal(err)
	}
	if err := ensureTraversable(leaf); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(mid)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0001 == 0 {
		t.Fatalf("ensureTraversable did not add +x to %s (mode %04o)", mid, fi.Mode().Perm())
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
}
