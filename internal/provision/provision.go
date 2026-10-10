// Package provision shapes a resolved credential the way a specific tool
// expects it — env vars with the right names, or a secret file the tool is
// pointed at — so an agent can say "give this item to kubectl" without knowing
// kubectl reads ~/.kube/config. It is scoped to what an agent broker needs.
//
// Files are written only into a per-exec 0700 temp dir and deleted when the
// child exits; the tool is pointed at them by env (KUBECONFIG, etc.), never by
// overwriting the user's real dotfiles. Provisioning changes only HOW a
// resolved secret reaches the allow-listed child — destination binding,
// masking and audit are unchanged and still apply to every field ref.
package provision

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// FileSpec is one secret file to materialize in the exec's temp dir.
type FileSpec struct {
	Path     string `json:"path"`     // template; must resolve under {{.Dir}}
	Mode     string `json:"mode"`     // octal, e.g. "0600"
	Template string `json:"template"` // content template over item fields
}

// Profile maps an item's fields to how a tool receives them.
type Profile struct {
	Name   string            `json:"name"`
	Fields []string          `json:"fields"`          // item field names this profile consumes
	Env    map[string]string `json:"env,omitempty"`   // ENV_NAME -> template
	Files  []FileSpec        `json:"files,omitempty"` // secret files, written under the temp dir
}

// Refs returns the sec:// refs this profile needs from an item — one per
// field. These are what the exec must be policy-allowed for, exactly like the
// refs of a plain env injection.
func (p Profile) Refs(item string) []string {
	item = strings.TrimRight(item, "/")
	out := make([]string, 0, len(p.Fields))
	for _, f := range p.Fields {
		out = append(out, item+"/"+f)
	}
	return out
}

// Materialized is the result of provisioning: env additions for the child, the
// temp dir (empty if none), and a Cleanup that removes it.
type Materialized struct {
	Env     map[string]string
	Dir     string
	Cleanup func()
}

type tmplData struct {
	Dir    string
	Home   string
	Fields map[string]string
}

// Materialize renders the profile against resolved field values. Templates
// that reference a missing field fail rather than silently emit empty, and any
// file that would land outside the temp dir is refused.
func (p Profile) Materialize(values map[string]string) (*Materialized, error) {
	home, _ := os.UserHomeDir()
	m := &Materialized{Env: map[string]string{}, Cleanup: func() {}}

	// A temp dir is created only if the profile writes files.
	if len(p.Files) > 0 {
		// MkdirTemp already creates the dir 0700.
		dir, err := os.MkdirTemp("", "sb-provision-")
		if err != nil {
			return nil, err
		}
		m.Dir = dir
		m.Cleanup = func() { os.RemoveAll(dir) }
	}

	data := tmplData{Dir: m.Dir, Home: home, Fields: values}

	for _, f := range p.Files {
		path, err := render("path", f.Path, data)
		if err != nil {
			m.Cleanup()
			return nil, err
		}
		// Refuse anything that escapes the temp dir — a profile must never
		// target a real dotfile.
		if rel, err := filepath.Rel(m.Dir, path); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			m.Cleanup()
			return nil, fmt.Errorf("profile %q: file %q is outside the temp dir", p.Name, path)
		}
		content, err := render("content", f.Template, data)
		if err != nil {
			m.Cleanup()
			return nil, err
		}
		mode := os.FileMode(0600)
		if f.Mode != "" {
			n, err := strconv.ParseUint(f.Mode, 8, 32)
			if err != nil {
				m.Cleanup()
				return nil, fmt.Errorf("profile %q: bad mode %q", p.Name, f.Mode)
			}
			mode = os.FileMode(n)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			m.Cleanup()
			return nil, err
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			m.Cleanup()
			return nil, err
		}
	}

	for name, tmpl := range p.Env {
		v, err := render("env "+name, tmpl, data)
		if err != nil {
			m.Cleanup()
			return nil, err
		}
		m.Env[name] = v
	}
	return m, nil
}

// render fails on a missing field rather than emitting empty, so a tool never
// silently receives a blank credential.
func render(what, tmpl string, data tmplData) (string, error) {
	t, err := template.New(what).Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return b.String(), nil
}
