package provision

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
)

// builtins are the profiles shipped with the broker: the common tools whose
// credential shape is stable. A JSON file (loaded by LoadProfiles) can add or
// override these. Kept small on purpose — a few that cover most agent work,
// not a plugin for every tool.
var builtins = map[string]Profile{
	// env-only
	"aws": {
		Name:   "aws",
		Fields: []string{"AccessKeyId", "SecretKey"},
		Env: map[string]string{
			"AWS_ACCESS_KEY_ID":     "{{.Fields.AccessKeyId}}",
			"AWS_SECRET_ACCESS_KEY": "{{.Fields.SecretKey}}",
		},
	},
	"gh": {
		Name:   "gh",
		Fields: []string{"token"},
		Env:    map[string]string{"GH_TOKEN": "{{.Fields.token}}"},
	},
	// file-based: written into the temp dir, tool pointed at it by env
	"kube": {
		Name:   "kube",
		Fields: []string{"kubeconfig"},
		Files:  []FileSpec{{Path: "{{.Dir}}/config", Mode: "0600", Template: "{{.Fields.kubeconfig}}"}},
		Env:    map[string]string{"KUBECONFIG": "{{.Dir}}/config"},
	},
	"gcloud": {
		Name:   "gcloud",
		Fields: []string{"credentials_json"},
		Files:  []FileSpec{{Path: "{{.Dir}}/gcp.json", Mode: "0600", Template: "{{.Fields.credentials_json}}"}},
		Env:    map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "{{.Dir}}/gcp.json"},
	},
}

// Builtin returns a shipped profile by name.
func Builtin(name string) (Profile, bool) {
	p, ok := builtins[name]
	return p, ok
}

// Registry is the set of profiles the broker offers: builtins, plus any from a
// JSON file that add new ones or override builtins by name.
type Registry struct{ m map[string]Profile }

// LoadRegistry starts from the builtins and merges a JSON array of profiles
// from path (if it exists). A missing file is fine — you get the builtins.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{m: map[string]Profile{}}
	for k, v := range builtins {
		r.m[k] = v
	}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	var custom []Profile
	if err := json.Unmarshal(b, &custom); err != nil {
		return nil, err
	}
	for _, p := range custom {
		if p.Name == "" {
			return nil, errors.New("profile in file has no name")
		}
		r.m[p.Name] = p
	}
	return r, nil
}

// Get returns a profile by name.
func (r *Registry) Get(name string) (Profile, bool) { p, ok := r.m[name]; return p, ok }

// Names lists the registered profile names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
