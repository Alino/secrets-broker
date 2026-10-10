package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	os.MkdirAll(filepath.Dir(p), 0700)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func find(cs []Candidate, suggest string) *Candidate {
	for i := range cs {
		if cs[i].Suggest == suggest {
			return &cs[i]
		}
	}
	return nil
}

func TestScanAWS(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".aws/credentials", `[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = defaultsecret

[work]
aws_access_key_id = AKIAWORK
aws_secret_access_key = worksecret
aws_session_token = worktoken
`)
	cs := ScanAWS(home)
	if len(cs) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(cs))
	}
	w := find(cs, "aws-work")
	if w == nil {
		t.Fatal("work profile not found")
	}
	if w.Fields["AccessKeyId"] != "AKIAWORK" || w.Fields["SecretKey"] != "worksecret" || w.Fields["SessionToken"] != "worktoken" {
		t.Fatalf("work fields wrong: %v", w.Fields)
	}
	if w.Secret() == false {
		t.Fatal("aws candidate should be marked secret")
	}
}

func TestScanNetrc(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".netrc", "machine api.example.com login me password s3cret\ndefault login guest password g\n")
	cs := ScanNetrc(home)
	c := find(cs, "netrc-api.example.com")
	if c == nil {
		t.Fatalf("machine entry not found in %v", cs)
	}
	if c.Fields["UserName"] != "me" || c.Fields["password"] != "s3cret" {
		t.Fatalf("netrc fields wrong: %v", c.Fields)
	}
}

func TestScanEnvFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	os.WriteFile(p, []byte("# comment\nAPI_KEY=abc123\nexport TOKEN=\"quoted val\"\nPLAIN=x\nNOTSECRET_readme=hi\n"), 0600)
	cs := ScanEnvFile(p)
	if find(cs, "API_KEY") == nil || find(cs, "TOKEN") == nil {
		t.Fatalf("expected API_KEY and TOKEN, got %v", cs)
	}
	if find(cs, "TOKEN").Fields["value"] != "quoted val" {
		t.Fatalf("quoted value not unquoted: %q", find(cs, "TOKEN").Fields["value"])
	}
}

// Redacted output must never contain a value — only source, suggestion, fields.
func TestRedactedHasNoValues(t *testing.T) {
	c := Candidate{Source: "~/.aws/credentials [work]", Suggest: "aws-work",
		Fields: map[string]string{"AccessKeyId": "AKIAWORK", "SecretKey": "worksecret"}}
	r := c.Redacted()
	if contains(r, "AKIAWORK") || contains(r, "worksecret") {
		t.Fatalf("redacted leaked a value: %q", r)
	}
	if !contains(r, "aws-work") || !contains(r, "AccessKeyId") {
		t.Fatalf("redacted should name the ref and fields: %q", r)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
