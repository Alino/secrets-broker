package execrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/internal/provision"
)

const testSecret = "hunter2-super-secret-value"

// fakeResolver returns a known secret for any ref.
func fakeResolver(ref string) (string, error) { return testSecret, nil }

func writePolicy(t *testing.T, dir string, execs []string) *policy.Store {
	t.Helper()
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/item/pw", Exec: execs})
	return st
}

func TestRunInjectsAndMasks(t *testing.T) {
	dir := t.TempDir()
	// /bin/sh is the "allowed tool" for this test
	st := writePolicy(t, dir, []string{"/bin/sh"})
	audit := filepath.Join(dir, "audit.jsonl")

	res, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", `echo "pw=$SECRET"; echo err-pw=$SECRET >&2`},
		EnvRefs:  map[string]string{"SECRET": "sec://test/item/pw"},
		Resolver: fakeResolver,
		Policy:   st,
		AuditLog: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	if strings.Contains(res.Stdout, testSecret) || strings.Contains(res.Stderr, testSecret) {
		t.Fatalf("SECRET LEAKED: out=%q err=%q", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "pw=") || !strings.Contains(res.Stdout, "<concealed>") {
		t.Fatalf("expected masked placeholder: %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "<concealed>") {
		t.Fatalf("stderr should be masked too: %q", res.Stderr)
	}
	// audit trail exists and never contains the value
	b, _ := os.ReadFile(audit)
	if strings.Contains(string(b), testSecret) {
		t.Fatal("audit log contains secret value")
	}
	var first map[string]any
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		t.Fatalf("audit empty: %s", b)
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("audit line not json: %v (%s)", err, lines[0])
	}
	if first["allowed"] != true {
		t.Fatalf("audit entry wrong: %s", lines[0])
	}
}

func TestRunDeniesUnlistedExec(t *testing.T) {
	dir := t.TempDir()
	st := writePolicy(t, dir, []string{"/usr/bin/authorized-tool"}) // not what we run
	_, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "echo $SECRET"},
		EnvRefs:  map[string]string{"SECRET": "sec://test/item/pw"},
		Resolver: fakeResolver,
		Policy:   st,
	})
	if err == nil {
		t.Fatal("expected denial for unlisted executable")
	}
	if !strings.Contains(err.Error(), "DENIED") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestRunDeniesUnknownRef(t *testing.T) {
	st := policy.NewEmpty()
	_, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "echo $SECRET"},
		EnvRefs:  map[string]string{"SECRET": "sec://other/item"},
		Resolver: fakeResolver,
		Policy:   st,
	})
	if err == nil || !strings.Contains(err.Error(), "DENIED") {
		t.Fatalf("expected denial: %v", err)
	}
}

func TestSymlinkBypassDenied(t *testing.T) {
	dir := t.TempDir()
	st := writePolicy(t, dir, []string{"/bin/echo"})
	// attacker tries to reach the secret via a symlink named like an allowed tool
	link := filepath.Join(dir, "echo")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Skip("symlink unavailable")
	}
	_, err := Run(Request{
		Argv:     []string{link, "-c", "echo $SECRET"},
		EnvRefs:  map[string]string{"SECRET": "sec://test/item/pw"},
		Resolver: fakeResolver,
		Policy:   st,
	})
	if err == nil || !strings.Contains(err.Error(), "DENIED") {
		t.Fatalf("symlink must resolve to real exec and be denied: %v", err)
	}
}

// An allow-listed binary invoked with arguments the policy did not permit is
// denied before the child spawns — the gap that let `gh api ... evil.example`
// through when only argv[0] was checked.
func TestRunEnforcesArgsConstraint(t *testing.T) {
	dir := t.TempDir()
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{
		Ref:  "sec://test/item/pw",
		Exec: []string{"/bin/sh"},
		Args: []string{"-c", "echo fixed"},
	})
	audit := filepath.Join(dir, "audit.jsonl")

	req := func(argv []string) Request {
		return Request{
			Argv:     argv,
			EnvRefs:  map[string]string{"SECRET": "sec://test/item/pw"},
			Resolver: fakeResolver,
			Policy:   st,
			AuditLog: audit,
		}
	}

	if _, err := Run(req([]string{"/bin/sh", "-c", `printf %s "$SECRET" | base64`})); err == nil {
		t.Fatal("argv outside the policy prefix must be denied")
	}
	res, err := Run(req([]string{"/bin/sh", "-c", "echo fixed"}))
	if err != nil {
		t.Fatalf("permitted argv must run: %v", err)
	}
	if !strings.Contains(res.Stdout, "fixed") {
		t.Fatalf("unexpected output %q", res.Stdout)
	}

	b, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "arguments not in allow-list") {
		t.Fatalf("denial reason not audited: %s", b)
	}
	if strings.Contains(string(b), testSecret) {
		t.Fatal("audit log must never contain secret values")
	}
}

// A ref marked approve:true must not resolve without a human decision, and
// must fail closed when no gate is wired up at all.
func TestRunRequiresApproval(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/item/pw", Exec: []string{"/bin/echo"}, Approve: true})

	base := func() Request {
		return Request{
			Argv:     []string{"/bin/echo", "hi"},
			EnvRefs:  map[string]string{"SECRET": "sec://test/item/pw"},
			Resolver: fakeResolver,
			Policy:   st,
		}
	}

	if _, err := Run(base()); err == nil {
		t.Fatal("approval-required ref must fail closed when no gate is configured")
	}

	asked := 0
	r := base()
	r.Approve = func(refs []string, exec string, argv []string) error { asked++; return nil }
	if _, err := Run(r); err != nil {
		t.Fatalf("approved run should proceed: %v", err)
	}
	if asked != 1 {
		t.Fatalf("gate called %d times, want 1", asked)
	}

	r = base()
	r.Approve = func(refs []string, exec string, argv []string) error { return errRefused }
	if _, err := Run(r); err == nil {
		t.Fatal("declined approval must deny the secret")
	}

	// refs without approve:true are not gated
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/item/pw", Exec: []string{"/bin/echo"}})
	asked = 0
	r = base()
	r.Approve = func(refs []string, exec string, argv []string) error { asked++; return nil }
	if _, err := Run(r); err != nil {
		t.Fatal(err)
	}
	if asked != 0 {
		t.Fatalf("ungated ref must not prompt, got %d prompts", asked)
	}
}

var errRefused = simpleErr("refused")

// Two gated refs in one exec reach the gate together, exactly once, and only
// after every policy check has passed.
func TestRunApprovesAllGatedRefsOnce(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/a/pw", Exec: []string{"/bin/echo"}, Approve: true})
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/b/pw", Exec: []string{"/bin/echo"}, Approve: true})
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/c/pw", Exec: []string{"/bin/echo"}})

	var calls [][]string
	req := Request{
		Argv:     []string{"/bin/echo", "hi"},
		EnvRefs:  map[string]string{"A": "sec://test/a/pw", "B": "sec://test/b/pw", "C": "sec://test/c/pw"},
		Resolver: fakeResolver,
		Policy:   st,
		Approve: func(refs []string, exec string, argv []string) error {
			calls = append(calls, refs)
			return nil
		},
	}
	if _, err := Run(req); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("gate should be called once for the whole exec, got %d calls", len(calls))
	}
	if len(calls[0]) != 2 || calls[0][0] != "sec://test/a/pw" || calls[0][1] != "sec://test/b/pw" {
		t.Fatalf("gate should receive exactly the gated refs, sorted: %v", calls[0])
	}
}

// If any ref fails policy, the gate is never consulted — so an approval can
// never be consumed by an exec that was going to be refused anyway.
func TestRunDoesNotConsultGateWhenPolicyRefuses(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/a/pw", Exec: []string{"/bin/echo"}, Approve: true})
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/b/pw", Exec: []string{"/bin/cat"}})
	consulted := false
	_, err := Run(Request{
		Argv:     []string{"/bin/echo", "hi"},
		EnvRefs:  map[string]string{"A": "sec://test/a/pw", "B": "sec://test/b/pw"},
		Resolver: fakeResolver,
		Policy:   st,
		Approve: func(refs []string, exec string, argv []string) error {
			consulted = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("a ref outside its allow-list must deny the exec")
	}
	if consulted {
		t.Fatal("the gate must not be consulted when policy already refuses")
	}
}

// A profile resolves an item's fields and injects them as the tool expects —
// here a file the tool is pointed at by env — with the field refs subject to
// the same policy check, and the temp file removed after the child exits.
func TestRunWithFileProfile(t *testing.T) {
	st := policy.NewEmpty()
	// the profile's field ref must be allow-listed for the exec, like any ref
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/Kube/kubeconfig", Exec: []string{"/bin/sh"}})

	prof := &provision.Profile{
		Name:   "kube",
		Fields: []string{"kubeconfig"},
		Files:  []provision.FileSpec{{Path: "{{.Dir}}/config", Mode: "0600", Template: "{{.Fields.kubeconfig}}"}},
		Env:    map[string]string{"KUBECONFIG": "{{.Dir}}/config"},
	}
	res, err := Run(Request{
		// the child proves it received a readable config file at $KUBECONFIG
		Argv:        []string{"/bin/sh", "-c", `test -r "$KUBECONFIG" && echo HAVE_CONFIG && cat "$KUBECONFIG"`},
		Profile:     prof,
		ProfileItem: "sec://test/Kube",
		Resolver:    fakeResolver, // returns testSecret for any ref
		Policy:      st,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "HAVE_CONFIG") {
		t.Fatalf("tool did not receive its config file: exit=%d out=%q", res.ExitCode, res.Stdout)
	}
	// the secret's value must be masked in the child's echoed file content
	if strings.Contains(res.Stdout, testSecret) {
		t.Fatalf("profile-provisioned secret leaked into output: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "<concealed>") {
		t.Fatalf("expected masked content: %q", res.Stdout)
	}
}

// A profile whose field ref is not allow-listed for the exec is denied before
// anything is written.
func TestRunProfileRespectsPolicy(t *testing.T) {
	st := policy.NewEmpty() // nothing allowed
	prof, _ := provisionBuiltin("kube")
	_, err := Run(Request{
		Argv:        []string{"/bin/sh", "-c", "true"},
		Profile:     prof,
		ProfileItem: "sec://test/Kube",
		Resolver:    fakeResolver,
		Policy:      st,
	})
	if err == nil {
		t.Fatal("a profile field ref outside the allow-list must be denied")
	}
}

func provisionBuiltin(name string) (*provision.Profile, bool) {
	p, ok := provision.Builtin(name)
	return &p, ok
}

// A child that hangs must be killed at the timeout, and the profile temp dir
// must be cleaned up — the review found WaitDelay alone never kills it.
func TestRunTimeoutKillsChildAndCleansUp(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/Kube/kubeconfig", Exec: []string{"/bin/sh"}})
	prof := &provision.Profile{
		Name:   "kube",
		Fields: []string{"kubeconfig"},
		Files:  []provision.FileSpec{{Path: "{{.Dir}}/config", Mode: "0600", Template: "{{.Fields.kubeconfig}}"}},
		Env:    map[string]string{"KUBECONFIG": "{{.Dir}}/config"},
	}
	// capture the temp dir the child sees, to assert it is gone afterward
	before := tempDirsMatching(t)
	start := time.Now()
	res, err := Run(Request{
		Argv:        []string{"/bin/sh", "-c", "sleep 30"},
		Profile:     prof,
		ProfileItem: "sec://test/Kube",
		Resolver:    fakeResolver,
		Policy:      st,
		Timeout:     500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("timeout did not kill the hung child")
	}
	if res.ExitCode == 0 {
		t.Fatal("a killed child must not report success")
	}
	// no sb-provision-* temp dir should survive
	after := tempDirsMatching(t)
	if len(after) > len(before) {
		t.Fatalf("profile temp dir leaked after timeout: before=%d after=%d", len(before), len(after))
	}
}

func tempDirsMatching(t *testing.T) []string {
	t.Helper()
	entries, _ := filepath.Glob(filepath.Join(os.TempDir(), "sb-provision-*"))
	return entries
}

// A profile that tries to set a dangerous env name is refused, like env_refs.
func TestRunProfileEnvNameGuarded(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/x/tok", Exec: []string{"/bin/sh"}})
	prof := &provision.Profile{
		Name:   "evil",
		Fields: []string{"tok"},
		Env:    map[string]string{"DYLD_INSERT_LIBRARIES": "{{.Fields.tok}}"},
	}
	_, err := Run(Request{
		Argv: []string{"/bin/sh", "-c", "true"}, Profile: prof,
		ProfileItem: "sec://test/x", Resolver: fakeResolver, Policy: st,
	})
	if err == nil {
		t.Fatal("a profile setting DYLD_INSERT_LIBRARIES must be refused")
	}
}

// An empty resolved field must be refused, not passed as a blank credential.
func TestRunProfileEmptyFieldRefused(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/x/tok", Exec: []string{"/bin/sh"}})
	prof := &provision.Profile{Name: "gh", Fields: []string{"tok"}, Env: map[string]string{"GH_TOKEN": "{{.Fields.tok}}"}}
	_, err := Run(Request{
		Argv: []string{"/bin/sh", "-c", "true"}, Profile: prof,
		ProfileItem: "sec://test/x",
		Resolver:    func(string) (string, error) { return "", nil }, // empty value
		Policy:      st,
	})
	if err == nil {
		t.Fatal("an empty resolved field must be refused")
	}
}

// env_refs must reject loader/shell names as well, not only profiles.
func TestRunEnvRefRejectsLoaderName(t *testing.T) {
	st := policy.NewEmpty()
	st.Upsert(policy.ItemPolicy{Ref: "sec://test/x/pw", Exec: []string{"/bin/sh"}})
	_, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "true"},
		EnvRefs:  map[string]string{"PATH": "sec://test/x/pw"},
		Resolver: fakeResolver, Policy: st,
	})
	if err == nil {
		t.Fatal("env_refs setting PATH must be refused")
	}
}
