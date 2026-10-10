package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefsAreItemFields(t *testing.T) {
	p := Profile{Name: "aws", Fields: []string{"AccessKeyId", "SecretKey"}}
	got := p.Refs("sec://opvault/AWS")
	want := []string{"sec://opvault/AWS/AccessKeyId", "sec://opvault/AWS/SecretKey"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	// a trailing slash on the item must not double up
	if p.Refs("sec://opvault/AWS/")[0] != "sec://opvault/AWS/AccessKeyId" {
		t.Fatal("trailing slash mishandled")
	}
}

// A pure-env profile injects the mapped variables, writes no files, and its
// cleanup is a no-op.
func TestMaterializeEnvOnly(t *testing.T) {
	p := Profile{
		Name:   "aws",
		Fields: []string{"AccessKeyId", "SecretKey"},
		Env: map[string]string{
			"AWS_ACCESS_KEY_ID":     "{{.Fields.AccessKeyId}}",
			"AWS_SECRET_ACCESS_KEY": "{{.Fields.SecretKey}}",
		},
	}
	vals := map[string]string{"AccessKeyId": "AKIA123", "SecretKey": "s3cr3t"}
	m, err := p.Materialize(vals)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Cleanup()
	if m.Env["AWS_ACCESS_KEY_ID"] != "AKIA123" || m.Env["AWS_SECRET_ACCESS_KEY"] != "s3cr3t" {
		t.Fatalf("env not rendered: %v", m.Env)
	}
	if m.Dir != "" {
		if _, err := os.Stat(m.Dir); err == nil {
			t.Fatal("env-only profile should not create a temp dir")
		}
	}
}

// A file profile writes the secret into a 0700 temp dir with the requested
// mode, points the tool at it via env, and deletes everything on cleanup.
func TestMaterializeFile(t *testing.T) {
	p := Profile{
		Name:   "kube",
		Fields: []string{"kubeconfig"},
		Files:  []FileSpec{{Path: "{{.Dir}}/config", Mode: "0600", Template: "{{.Fields.kubeconfig}}"}},
		Env:    map[string]string{"KUBECONFIG": "{{.Dir}}/config"},
	}
	m, err := p.Materialize(map[string]string{"kubeconfig": "apiVersion: v1\n"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Env["KUBECONFIG"]
	if cfg == "" || filepath.Dir(cfg) != m.Dir {
		t.Fatalf("KUBECONFIG should point into the temp dir: %q (dir %q)", cfg, m.Dir)
	}
	fi, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	// the temp dir itself must not be group/world accessible
	di, _ := os.Stat(m.Dir)
	if di.Mode().Perm()&0077 != 0 {
		t.Fatalf("temp dir perms %o expose the secret", di.Mode().Perm())
	}
	b, _ := os.ReadFile(cfg)
	if string(b) != "apiVersion: v1\n" {
		t.Fatalf("content = %q", b)
	}

	m.Cleanup()
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("cleanup must delete the temp dir and its secret files")
	}
}

// A template that names a field the item did not provide is an error, not a
// silent empty value that a tool would misread.
func TestMaterializeMissingFieldFails(t *testing.T) {
	p := Profile{Name: "x", Fields: []string{"a"}, Env: map[string]string{"V": "{{.Fields.b}}"}}
	if _, err := p.Materialize(map[string]string{"a": "1"}); err == nil {
		t.Fatal("referencing an unknown field must fail")
	}
}

// Builtins exist for the common tools and are well-formed.
func TestBuiltins(t *testing.T) {
	for _, name := range []string{"aws", "gh", "kube", "gcloud"} {
		p, ok := Builtin(name)
		if !ok {
			t.Fatalf("missing builtin profile %q", name)
		}
		if len(p.Fields) == 0 || (len(p.Env) == 0 && len(p.Files) == 0) {
			t.Fatalf("builtin %q is malformed: %+v", name, p)
		}
	}
	if _, ok := Builtin("nope"); ok {
		t.Fatal("unknown profile must not resolve")
	}
}

// A file profile that would write outside its temp dir is refused: a profile
// must never target a real dotfile like ~/.kube/config.
func TestFileMustStayInTempDir(t *testing.T) {
	p := Profile{
		Name:   "evil",
		Fields: []string{"k"},
		Files:  []FileSpec{{Path: "{{.Home}}/.kube/config", Mode: "0600", Template: "{{.Fields.k}}"}},
	}
	if _, err := p.Materialize(map[string]string{"k": "x"}); err == nil {
		t.Fatal("a file path outside the temp dir must be refused")
	}
}
