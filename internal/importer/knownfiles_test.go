package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLooksSecret(t *testing.T) {
	secret := []string{"token", "oauth_token", "api_key", "apiKey", "secret_access_key",
		"password", "client_secret", "AccessKey", "personal_access_token", "PAT"}
	notSecret := []string{"user", "username", "url", "region", "host", "email", "account_id"}
	for _, k := range secret {
		if !looksSecret(k) {
			t.Errorf("looksSecret(%q)=false, want true", k)
		}
	}
	for _, k := range notSecret {
		if looksSecret(k) {
			t.Errorf("looksSecret(%q)=true, want false", k)
		}
	}
}

// One fixture per known credential-file format, dropped at its real home-relative
// path; ScanKnownFiles must discover the secret and never the plaintext value
// in the redacted view.
func TestScanKnownFiles(t *testing.T) {
	home := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// TOML (stripe), YAML nested (gh), JSON nested (docker), INI/rc (npm).
	write(".config/stripe/config.toml", "[default]\ntest_mode_api_key = \"sk_test_STRIPEVAL\"\ndevice_name = \"laptop\"\n")
	write(".config/gh/hosts.yml", "github.com:\n    user: me\n    oauth_token: gho_GITHUBVAL\n")
	write(".docker/config.json", `{"auths":{"registry.io":{"auth":"DOCKERVAL","email":"a@b.c"}}}`)
	write(".npmrc", "//registry.npmjs.org/:_authToken=npm_NPMVAL\nregistry=https://registry.npmjs.org/\n")

	got := ScanKnownFiles(home)
	if len(got) == 0 {
		t.Fatal("ScanKnownFiles found nothing")
	}
	values := map[string]bool{"sk_test_STRIPEVAL": true, "gho_GITHUBVAL": true, "DOCKERVAL": true, "npm_NPMVAL": true}
	found := map[string]bool{}
	for _, c := range got {
		if !c.Secret() {
			t.Errorf("candidate %q not marked secret", c.Suggest)
		}
		// The value must be present for the real import...
		for _, v := range c.Fields {
			if values[v] {
				found[v] = true
			}
		}
		// ...but never in the redacted display.
		red := c.Redacted()
		for v := range values {
			if strings.Contains(red, v) {
				t.Errorf("Redacted() leaked value %q: %s", v, red)
			}
		}
	}
	for v := range values {
		if !found[v] {
			t.Errorf("did not discover secret value from a fixture (%q)", v)
		}
	}
	// Suggested titles must be clean (no URL noise from npmrc scoped keys).
	for _, c := range got {
		if strings.ContainsAny(c.Suggest, "/: ") {
			t.Errorf("unclean suggest name %q", c.Suggest)
		}
	}
}

func TestCleanSeg(t *testing.T) {
	cases := map[string]string{
		"//registry.npmjs.org/:_authToken": "authToken",
		"_authToken":                       "authToken",
		"oauth_token":                      "oauth_token",
		"api-key":                          "api-key",
	}
	for in, want := range cases {
		if got := cleanSeg(in); got != want {
			t.Errorf("cleanSeg(%q)=%q want %q", in, got, want)
		}
	}
}

// Non-secret keys (user, url, region) must not become candidates.
func TestScanKnownFilesSkipsNonSecrets(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".config/glab-cli/config.yml")
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("hosts:\n  gitlab.com:\n    username: me\n    token: glpat-SECRET\n"), 0600)
	got := ScanKnownFiles(home)
	for _, c := range got {
		if _, ok := c.Fields["username"]; ok {
			t.Errorf("username should not be a candidate field: %v", c.Fields)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 candidate (the token), got %d: %+v", len(got), got)
	}
}
