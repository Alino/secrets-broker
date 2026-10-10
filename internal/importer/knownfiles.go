package importer

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// This is the "support every common file-based secret" scanner. Rather than a
// plugin per vendor, we scan the well-known credential files that common CLIs
// write and pull out any value under a secret-looking key. The formats
// collapse to two parsers: JSON, and a generic key/value+section scanner that
// covers TOML, INI, .npmrc/.pypirc-style rc files, and shallow YAML. One
// heuristic (looksSecret) decides what counts.

// knownFile is a CLI's credential file, relative to $HOME, tagged
// with the tool it belongs to (used to name the suggested vault item).
type knownFile struct {
	rel  string
	tool string
}

// knownFiles lists the credential files scanned by the generic parsers.
// .aws/credentials and .netrc are handled by their own structured scanners.
var knownFiles = []knownFile{
	{".npmrc", "npm"},
	{".pypirc", "pypi"},
	{".docker/config.json", "docker"},
	{".cargo/credentials.toml", "cargo"},
	{".config/gh/hosts.yml", "github"},
	{".config/glab-cli/config.yml", "gitlab"},
	{".config/stripe/config.toml", "stripe"},
	{".config/fastly/config.toml", "fastly"},
	{".config/hcloud/cli.toml", "hcloud"},
	{".config/ngrok/ngrok.yml", "ngrok"},
	{".config/scw/config.yaml", "scaleway"},
	{".config/doctl/config.yaml", "digitalocean"},
	{".config/argocd/config", "argocd"},
	{".config/octopus/cli_config.json", "octopus"},
	{".config/todoist/config.json", "todoist"},
	{".config/exercism/user.json", "exercism"},
	{".config/tea/config.yml", "gitea"},
	{".config/configstore/snyk.json", "snyk"},
	{".config/com.vercel.cli/auth.json", "vercel"},
	{".doppler/.doppler.yaml", "doppler"},
	{".fly/config.yml", "flyctl"},
	{".kaggle/kaggle.json", "kaggle"},
	{".lacework.toml", "lacework"},
	{".okta/okta.yaml", "okta"},
	{".pulumi/credentials.json", "pulumi"},
	{".td/td.conf", "treasuredata"},
	{".twilio-cli/config.json", "twilio"},
	{".upstash.json", "upstash"},
	{".vultr-cli.yaml", "vultr"},
	{".civo.json", "civo"},
	{".tugboat.yml", "tugboat"},
	{".databrickscfg", "databricks"},
}

// secretKeyRe matches key NAMES that hold a credential. Kept deliberately
// broad on the secret side (missing a secret is worse than offering an extra
// candidate the user can decline) and excludes the common *_id / public_* /
// username / url keys that sit next to them.
var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|api[_-]?key|apikey|auth|credential|access[_-]?key|private[_-]?key|\bpat\b|clientsecret)`)

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	// An access-KEY-ID is an identifier, not the secret beside it.
	if strings.HasSuffix(k, "_id") || strings.HasSuffix(k, "id") && strings.Contains(k, "key") {
		if !strings.Contains(k, "secret") {
			return false
		}
	}
	if strings.Contains(k, "public") {
		return false
	}
	return secretKeyRe.MatchString(key)
}

// ScanKnownFiles walks the known credential files under home and returns one
// candidate per secret-looking value found. Read-only.
func ScanKnownFiles(home string) []Candidate {
	var out []Candidate
	for _, kf := range knownFiles {
		path := filepath.Join(home, kf.rel)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var pairs []kv
		if strings.HasSuffix(kf.rel, ".json") {
			pairs = scanJSON(b)
		} else {
			pairs = scanKVText(b)
		}
		display := "~/" + kf.rel
		for _, p := range pairs {
			if !looksSecret(p.key) {
				continue
			}
			leaf := cleanSeg(lastSeg(p.path))
			suggest := kf.tool
			if leaf != "" {
				suggest = kf.tool + "-" + leaf
			}
			out = append(out, Candidate{
				Source:  display + " [" + p.path + "]",
				Suggest: suggest,
				Fields:  map[string]string{p.key: p.val},
			})
		}
	}
	return out
}

// kv is one discovered key/value with a dotted path for context (e.g.
// "github.com.oauth_token" or "auths.registry.io.auth").
type kv struct {
	path string // dotted location, for the display/suggest name
	key  string // the leaf key name (what looksSecret judges)
	val  string
}

func lastSeg(dotted string) string {
	if i := strings.LastIndex(dotted, "."); i >= 0 {
		return dotted[i+1:]
	}
	return dotted
}

// cleanSeg reduces a key name to a tidy vault-title segment: it keeps only the
// part after the last '/' or ':' (npmrc scoped keys look like
// "//registry/:_authToken"), then keeps letters, digits, '-' and '_'.
func cleanSeg(s string) string {
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		s = s[i+1:]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == '_':
			if b.Len() > 0 { // drop leading underscores (e.g. _authToken)
				b.WriteRune(r)
			}
		}
	}
	return strings.Trim(b.String(), "-_")
}

// scanJSON walks arbitrary JSON and yields every string leaf with its dotted
// path. Non-string leaves (numbers/bools) are never credentials.
func scanJSON(b []byte) []kv {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	var out []kv
	var walk func(prefix string, node any)
	walk = func(prefix string, node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, child := range n {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if s, ok := child.(string); ok {
					out = append(out, kv{path: p, key: k, val: s})
				} else {
					walk(p, child)
				}
			}
		case []any:
			for _, child := range n {
				walk(prefix, child)
			}
		}
	}
	walk("", v)
	return out
}

// scanKVText handles TOML, INI, rc and shallow YAML with one line scanner:
// `key = value` or `key: value`, `[section]` headers, and one level of YAML
// nesting (an indented `key:` with no value opens a section). Quotes and inline
// comments are stripped. Good enough for credential files, which are shallow.
func scanKVText(b []byte) []kv {
	var out []kv
	section := ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		raw := sc.Text()
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// [section] (TOML/INI)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		sep := sepIndex(line)
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(line[:sep])
		val := cleanValue(line[sep+1:])
		// YAML: a `key:` with no value opens a nested section.
		if val == "" && strings.HasSuffix(strings.TrimSpace(line), ":") {
			if indented {
				// nested-in-nested: keep the top section, append
				section = topSection(section) + "." + key
			} else {
				section = key
			}
			continue
		}
		p := key
		if section != "" {
			p = section + "." + key
		}
		out = append(out, kv{path: p, key: key, val: val})
	}
	return out
}

// sepIndex returns the index of the key/value separator (= or :), preferring
// whichever comes first. `:` handles YAML and npmrc scoped keys
// (//host/:_authToken=...) still split on the last `=`.
func sepIndex(line string) int {
	eq := strings.Index(line, "=")
	// npmrc: //registry/:_authToken=TOKEN — split on `=`, not the `:` in the URL.
	if eq >= 0 && strings.Contains(line[:eq], "_authToken") {
		return eq
	}
	colon := strings.Index(line, ":")
	switch {
	case eq < 0:
		return colon
	case colon < 0:
		return eq
	case colon < eq:
		return colon
	default:
		return eq
	}
}

func topSection(s string) string {
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i]
	}
	return s
}

// cleanValue strips surrounding quotes and trailing inline comments.
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	// trailing inline comment on unquoted values (TOML/INI)
	for _, c := range []string{" #", " ;"} {
		if i := strings.Index(v, c); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
	}
	return v
}
