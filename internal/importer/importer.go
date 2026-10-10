// Package importer discovers credentials already sitting in dotfiles and shapes
// them for the vault — the migration on-ramp: move an existing project onto the
// broker without hand-entering secrets. Scanning is read-only; the values are
// read so they can be vaulted, but Candidate.Redacted() (what `sb import scan`
// prints) never includes a value, only the source, the suggested ref name, and
// the field names.
package importer

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Candidate is one importable credential: where it came from, a suggested vault
// item name, and its fields (values included, for the actual import).
type Candidate struct {
	Source  string            // human-readable origin, e.g. "~/.aws/credentials [work]"
	Suggest string            // suggested item title / ref segment
	Fields  map[string]string // field label -> value
}

// secretFields are treated as sensitive for display and marking.
var secretFields = map[string]bool{
	"SecretKey": true, "SessionToken": true, "password": true,
	"token": true, "value": true, "oauth_token": true,
}

// fieldSecret reports whether a field name is sensitive — by the fixed labels
// the structured scanners emit, or by the looksSecret heuristic the known-file
// scanner relies on.
func fieldSecret(k string) bool { return secretFields[k] || looksSecret(k) }

// Secret reports whether the candidate holds at least one sensitive field.
func (c Candidate) Secret() bool {
	for k := range c.Fields {
		if fieldSecret(k) {
			return true
		}
	}
	return false
}

// Redacted renders the candidate for display: source, suggested ref, and field
// NAMES with a marker for the sensitive ones — never a value.
func (c Candidate) Redacted() string {
	var names []string
	for k := range c.Fields {
		if fieldSecret(k) {
			names = append(names, k+"(secret)")
		} else {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return c.Source + "  ->  suggest '" + c.Suggest + "'  fields: " + strings.Join(names, ", ")
}

// ScanAll runs the home-directory scanners: the structured ones for the two
// formats worth shaping precisely (AWS, netrc) plus the broad known-file
// scanner covering the well-known credential files of common CLIs.
func ScanAll(home string) []Candidate {
	var out []Candidate
	out = append(out, ScanAWS(home)...)
	out = append(out, ScanNetrc(home)...)
	out = append(out, ScanKnownFiles(home)...)
	return out
}

// ScanAWS parses ~/.aws/credentials (INI): one candidate per profile.
func ScanAWS(home string) []Candidate {
	f, err := os.Open(filepath.Join(home, ".aws", "credentials"))
	if err != nil {
		return nil
	}
	defer f.Close()
	label := map[string]string{
		"aws_access_key_id":     "AccessKeyId",
		"aws_secret_access_key": "SecretKey",
		"aws_session_token":     "SessionToken",
	}
	var out []Candidate
	var cur *Candidate
	flush := func() {
		if cur != nil && len(cur.Fields) > 0 {
			out = append(out, *cur)
		}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			prof := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			cur = &Candidate{Source: "~/.aws/credentials [" + prof + "]",
				Suggest: "aws-" + prof, Fields: map[string]string{}}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := splitKV(line, "=")
		if ok {
			if lab, known := label[strings.ToLower(k)]; known {
				cur.Fields[lab] = v
			}
		}
	}
	flush()
	return out
}

// ScanNetrc parses ~/.netrc into one candidate per machine entry.
func ScanNetrc(home string) []Candidate {
	b, err := os.ReadFile(filepath.Join(home, ".netrc"))
	if err != nil {
		return nil
	}
	toks := strings.Fields(string(b))
	var out []Candidate
	var cur *Candidate
	flush := func() {
		if cur != nil && cur.Fields["password"] != "" {
			out = append(out, *cur)
		}
	}
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "machine":
			flush()
			if i+1 < len(toks) {
				i++
				cur = &Candidate{Source: "~/.netrc " + toks[i],
					Suggest: "netrc-" + toks[i], Fields: map[string]string{}}
			}
		case "default":
			flush()
			cur = &Candidate{Source: "~/.netrc default", Suggest: "netrc-default", Fields: map[string]string{}}
		case "login":
			if cur != nil && i+1 < len(toks) {
				i++
				cur.Fields["UserName"] = toks[i]
			}
		case "password":
			if cur != nil && i+1 < len(toks) {
				i++
				cur.Fields["password"] = toks[i]
			}
		case "account":
			if i+1 < len(toks) {
				i++
			}
		}
	}
	flush()
	return out
}

// ScanEnvFile parses a .env file: one candidate per KEY=VALUE.
func ScanEnvFile(path string) []Candidate {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Candidate
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := splitKV(line, "=")
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out = append(out, Candidate{Source: path + " (" + k + ")", Suggest: k,
			Fields: map[string]string{"value": v}})
	}
	return out
}

func splitKV(line, sep string) (string, string, bool) {
	i := strings.Index(line, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}
