package policy

import (
	"net/url"
	"sort"
	"strings"
)

// CheckHost reports whether ref may be filled into a page at rawURL. It is
// the browser counterpart of the exec allow-list, and it is deny-by-default
// in the same way: a ref with no Host entries is fillable nowhere.
//
// Matching is on the ORIGIN — scheme, host and port — never the path, and
// never a suffix: "mail.proton.me.evil.example" must not match
// "mail.proton.me". The URL compared here has to be the browser's actual
// current URL; a URL supplied by the agent proves nothing.
func (s *Store) CheckHost(ref, rawURL string) bool {
	s.mu.RLock()
	p, ok := s.items[ref]
	s.mu.RUnlock()
	if !ok || len(p.Host) == 0 {
		return false
	}
	got, err := origin(rawURL)
	if err != nil {
		return false
	}
	for _, allowed := range p.Host {
		if originMatches(allowed, got) {
			return true
		}
	}
	return false
}

// originMatches compares one policy entry against a concrete origin.
// "https://*.example.com" matches any subdomain of example.com — but never
// example.com itself, never a lookalike like evilexample.com, and never a
// different scheme or port. Everything else is an exact origin comparison.
//
// Strict is the default because a wildcard hands the credential to whoever
// controls any subdomain, which is not always the same party.
func originMatches(pattern, got string) bool {
	scheme, host, ok := splitOrigin(pattern)
	if !ok {
		return false
	}
	if !strings.HasPrefix(host, "*.") {
		want, err := origin(pattern)
		return err == nil && want == got
	}
	gotScheme, gotHost, ok := splitOrigin(got)
	if !ok || gotScheme != scheme {
		return false
	}
	suffix := host[1:] // ".example.com" — keeps the label boundary
	return strings.HasSuffix(gotHost, suffix) && len(gotHost) > len(suffix)
}

// splitOrigin breaks "scheme://host[:port]" into its parts, lowercased.
func splitOrigin(s string) (scheme, host string, ok bool) {
	i := strings.Index(s, "://")
	if i < 0 {
		return "", "", false
	}
	scheme = strings.ToLower(s[:i])
	host = strings.ToLower(s[i+3:])
	if host == "" || strings.ContainsAny(host, "/?#") {
		host = strings.SplitN(host, "/", 2)[0]
	}
	return scheme, host, host != ""
}

// RefsForSite lists the refs bound to the origin of rawURL. This is the only
// discovery the broker offers: scoped to one site, refs only, never values
// and never an inventory of the whole vault.
func (s *Store) RefsForSite(rawURL string) []string {
	got, err := origin(rawURL)
	if err != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for ref, p := range s.items {
		for _, allowed := range p.Host {
			if originMatches(allowed, got) {
				out = append(out, ref)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// origin reduces a URL to scheme://host[:port], lowercased. A bare host with
// no scheme is rejected: "evil.example" and "https://evil.example" must not
// be conflated when the difference decides who receives a password.
func origin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errNoOrigin
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

type originErr string

func (e originErr) Error() string { return string(e) }

const errNoOrigin = originErr("not an absolute URL with scheme and host")
