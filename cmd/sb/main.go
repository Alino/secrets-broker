// sb — secrets-broker management CLI.
//
//	sb init                        create ~/.secrets-broker/policy.json
//	sb list                        list refs + allowed execs
//	sb allow <ref> <exec...>        allow executable(s) to receive a secret
//	sb deny <ref>                  remove a ref's policy (deny all)
//	sb test <ref> <exec> [args...] check whether an exec+argv would be allowed
//	sb doctor                      report the security posture of this install
//	sb audit [N]                   show last N audit entries (default 20)
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

// policyPath resolves the policy file: explicit env first, then the
// isolated-mode location (root-owned, world-readable, root-writable) if this
// machine has been installed, then the per-user file for single-uid mode.
func policyPath() string {
	if p := os.Getenv("SB_POLICY_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat(installedPolicy); err == nil {
		return installedPolicy
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secrets-broker", "policy.json")
}

func auditPath() string {
	if p := os.Getenv("SB_AUDIT_LOG"); p != "" {
		return p
	}
	// In isolated mode the daemon owns the audit log, whether or not it has
	// written to it yet; pointing at the user's home would be a lie.
	if isolatedMode() {
		return installedAudit
	}
	if _, err := os.Stat(installedAudit); err == nil {
		return installedAudit
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secrets-broker", "audit.jsonl")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		must(initCmd())
	case "list":
		must(listCmd())
	case "allow":
		if len(args) < 2 {
			die("usage: sb allow <ref> <exec...>")
		}
		must(allowCmd(args[0], args[1:]))
	case "deny":
		if len(args) != 1 {
			die("usage: sb deny <ref>")
		}
		must(denyCmd(args[0]))
	case "test":
		if len(args) < 2 {
			die("usage: sb test <ref> <exec> [args...]")
		}
		must(testCmd(args[0], args[1], args[2:]))
	case "write-allow":
		if len(args) < 2 {
			die("usage: sb write-allow <adapter> <create|add-fields|update>[,...] | both | none")
		}
		must(writeAllowCmd(args[0], args[1]))
	case "install":
		must(installCmd(args))
	case "uninstall":
		must(uninstallCmd(args))
	case "set-password":
		must(setPasswordCmd(args))
	case "items":
		must(itemsCmd(args))
	case "probe":
		must(probeCmd(args))
	case "approve":
		must(approveCmd(args))
	case "import":
		must(importCmd(args))
	case "profiles":
		must(profilesCmd(args))
	case "browser":
		must(browserCmd(args))
	case "doctor":
		must(doctorCmd())
	case "audit":
		n := 20
		if len(args) == 1 {
			if i, err := strconv.Atoi(args[0]); err == nil {
				n = i
			}
		}
		must(auditCmd(n))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `sb — secrets-broker management CLI

commands:
  init                  create an empty policy file
  list                  list secret refs and their allowed executables
  allow <ref> [<exec...>] [--host=<url>] [-- <args...>] [--approve] [--force]
                       allow executable path(s), optionally pinning the argv prefix;
                       --approve requires Touch ID for each use (--no-approve removes it)
                       --no-network denies the child (and its descendants) all network
                       access, so a local tool cannot exfiltrate the secret it receives
                       (--allow-network removes it; macOS + Linux, refused where unenforceable)
                       --agent-browser lets agent-scoped browsers fill it
  deny <ref>            remove all allowances for a ref
  test <ref> <exec> [args...]
                       check if an exec+argv would be allowed
  items <adapter> <vault>
                       list item titles in a vault (prompts for the master
                       password on the terminal; prints no values)
  probe keepass <vault> <field> <title...>
                       for the titles you NAME, report FOUND / NO_ENTRY / NO_FIELD
                       (no listing, no values; unlocks like the broker, no prompt)
  approve --request <nonce>
                       authorize one pending request (Touch ID)
  import scan|apply     discover credentials in dotfiles and vault them
  profiles              list provisioning profiles (tool credential shapes)
  browser list|approve <id> [--agent]|revoke <id>
                       manage browsers associated for autofill
  doctor                report the security posture of this install
  install [--dry-run]   switch to isolated mode (service account + daemon); run as root
  uninstall [--purge] [--dry-run]
                       remove the daemon, binaries and service account (run as root);
                       --purge also deletes the policy, audit log and stored passwords
  set-password <adapter> <vault>
                       store a vault master password for the daemon (root)
  write-allow <adapter> <modes>
                       set vault WRITES for an adapter (default: none). modes is a
                       comma list: create (new entries), add-fields (fields an
                       existing entry lacks, e.g. a TOTP seed; never overwrites),
                       update (overwrite stored values) — or both, none
  audit [N]             show last N audit entries (default 20)

policy file: %s (override with SB_POLICY_FILE)
audit log:   %s (override with SB_AUDIT_LOG)
`, policyPath(), auditPath())
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "sb:", msg)
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "sb:", err)
		os.Exit(1)
	}
}

func initCmd() error {
	p := policyPath()
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("policy file already exists: %s", p)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	st := policy.NewEmpty()
	if err := save(st); err != nil {
		return err
	}
	fmt.Println("created", p)
	return nil
}

func save(st *policy.Store) error {
	list := []policy.ItemPolicy{}
	for _, ref := range st.Refs() {
		if p, ok := st.Get(ref); ok {
			list = append(list, p)
		}
	}
	file := struct {
		Items  []policy.ItemPolicy           `json:"items"`
		Writes map[string]policy.WritePolicy `json:"writes"`
	}{Items: list, Writes: map[string]policy.WritePolicy{}}
	st.WritesRange(func(adapter string, p policy.WritePolicy) {
		file.Writes[adapter] = p
	})
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	p := policyPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0600)
}

func listCmd() error {
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	refs := st.Refs()
	if len(refs) == 0 {
		fmt.Println("(no policies — everything is denied by default)")
		printWrites(st)
		return nil
	}
	defer printWrites(st)
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	for _, ref := range refs {
		p, _ := st.Get(ref)
		constraint := "(any args)"
		switch {
		case p.NoArgs:
			constraint = "(no args)"
		case len(p.Args) > 0:
			constraint = strings.Join(p.Args, " ")
		case len(p.Exec) == 0:
			constraint = "-" // browser-only credential: no argv to constrain
		}
		dest := strings.Join(p.Exec, ", ")
		if len(p.Host) > 0 {
			if dest != "" {
				dest += " | "
			}
			dest += strings.Join(p.Host, ", ")
		}
		if p.Network == policy.NetworkNone {
			constraint += "  [no-network]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", ref, dest, constraint)
	}
	return w.Flush()
}

// printWrites shows the vault-write grants next to the read bindings: a write
// permission the operator cannot see is one nobody remembers to revoke.
func printWrites(st *policy.Store) {
	adapters := st.WriteAdapters()
	fmt.Println("\nvault writes (sb write-allow):")
	if len(adapters) == 0 {
		fmt.Println("  (none — every adapter is read-only)")
		return
	}
	for _, a := range adapters {
		fmt.Printf("  %-10s %s\n", a, st.WriteAllow(a))
	}
}

// allowCmd grants executables access to a secret. Everything after "--" is
// the required argv prefix: sb allow <ref> /usr/bin/gh -- api --hostname github.com
func allowCmd(ref string, rest []string) error {
	if !strings.HasPrefix(ref, "sec://") {
		return fmt.Errorf("ref must start with sec:// (e.g. sec://keepass/GitHub/password)")
	}
	force := false
	var hosts []string
	var requireApproval, agentBrowser *bool
	var network *string
	execs, args := []string{}, []string(nil)
	seenSep := false
	for _, a := range rest {
		switch {
		case seenSep: // everything after -- belongs to the child command
			args = append(args, a)
		case a == "--force":
			force = true
		case a == "--approve":
			p2 := true
			requireApproval = &p2
		case a == "--no-approve":
			p2 := false
			requireApproval = &p2
		case a == "--agent-browser":
			t := true
			agentBrowser = &t
		case a == "--no-agent-browser":
			f := false
			agentBrowser = &f
		case a == "--no-network":
			n := policy.NetworkNone
			network = &n
		case a == "--allow-network":
			n := policy.NetworkUnrestricted
			network = &n
		case strings.HasPrefix(a, "--host="):
			hosts = append(hosts, strings.TrimPrefix(a, "--host="))
		case a == "--":
			seenSep = true
			args = []string{}
		default:
			execs = append(execs, a)
		}
	}
	if len(execs) == 0 && len(hosts) == 0 {
		return fmt.Errorf("give an executable, or --host=<url> for a browser credential")
	}
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	p, _ := st.Get(ref)
	p.Ref = ref
	if seenSep {
		p.Args = args
		p.NoArgs = len(args) == 0 // bare `--` means exactly no arguments
	}
	if requireApproval != nil {
		p.Approve = *requireApproval
	}
	if agentBrowser != nil {
		p.AgentBrowser = *agentBrowser
	}
	if network != nil {
		p.Network = *network
	}
	for _, h := range hosts {
		if _, err := url.Parse(strings.Replace(h, "*.", "wildcard.", 1)); err != nil || !strings.HasPrefix(h, "https://") {
			return fmt.Errorf("--host must be an absolute https URL (got %q); "+
				"http would let a network attacker receive the secret", h)
		}
		if strings.Contains(h, "*") {
			if !strings.HasPrefix(strings.TrimPrefix(h, "https://"), "*.") {
				return fmt.Errorf("a wildcard host must look like https://*.example.com (got %q)", h)
			}
			fmt.Fprintf(os.Stderr, "warning: %s matches every subdomain — the credential goes to "+
				"whoever controls any of them, which may not be the same party\n", h)
		}
		if !containsStr(p.Host, h) {
			p.Host = append(p.Host, h)
		}
	}
	for _, e := range execs {
		abs, err := absExec(e)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", e, err)
		}
		if err := vetExec(abs, force); err != nil {
			return err
		}
		if !containsStr(p.Exec, abs) {
			p.Exec = append(p.Exec, abs)
		}
	}
	// Only meaningful for exec destinations; a host-only (browser) credential
	// has no argv to constrain.
	if len(p.Args) == 0 && !p.NoArgs && len(execs) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %s may be run with ANY arguments; constrain it with:\n"+
			"  sb allow %s %s -- <required args>\n", filepath.Base(execs[0]), ref, execs[0])
	}
	st.Upsert(p)
	if err := save(st); err != nil {
		return err
	}
	dests := append(append([]string{}, p.Exec...), p.Host...)
	fmt.Printf("allowed %s for %s\n", strings.Join(dests, ", "), ref)
	return nil
}

// writeAllowCmd sets an adapter's vault-write grants to exactly the listed
// modes (see policy.ParseWriteModes): create, add-fields, update, comma-
// separated, or both / none.
func writeAllowCmd(adapter, mode string) error {
	p, err := policy.ParseWriteModes(mode)
	if err != nil {
		return err
	}
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	st.SetWritePolicy(adapter, p)
	if err := save(st); err != nil {
		return err
	}
	fmt.Printf("vault writes for %s: %s\n", adapter, p)
	return nil
}

func denyCmd(ref string) error {
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	st.Remove(ref)
	return save(st)
}

func testCmd(ref, exec string, argv []string) error {
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	abs, err := absExec(exec)
	if err != nil {
		return err
	}
	if st.Check(ref, abs, argv) {
		if p, ok := st.Get(ref); ok && p.Approve {
			fmt.Println("ALLOWED (requires human approval at run time)")
			return nil
		}
		fmt.Println("ALLOWED")
		return nil
	}
	fmt.Println("DENIED")
	os.Exit(1)
	return nil
}

func auditCmd(n int) error {
	b, err := os.ReadFile(auditPath())
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("(no audit log yet)")
			return nil
		}
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		fmt.Println("(no audit entries)")
		return nil
	}
	start := len(lines) - n
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:] {
		var e map[string]any
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			fmt.Println("?", l)
			continue
		}
		status := "ALLOW"
		if allowed, _ := e["allowed"].(bool); !allowed {
			status = "DENY  "
		}
		fmt.Printf("%s  %s  %s  %s\n", e["ts"], status, e["ref"], e["exec"])
	}
	return nil
}

// vetExec refuses allow-list entries that cannot hold: binaries the agent's
// own user can replace, and interpreters that will run whatever the agent
// asks. --force records the decision anyway.
func vetExec(abs string, force bool) error {
	if policy.IsInterpreter(abs) {
		if !force {
			return fmt.Errorf("%s is a shell/interpreter/network client: an agent can use it to "+
				"print or transform the secret, and output masking will not catch it.\n"+
				"  allow-list the specific tool instead, or re-run with --force", abs)
		}
		fmt.Fprintf(os.Stderr, "warning: %s is an interpreter — the secret is readable by the agent\n", abs)
	}
	if ok, why := policy.PathSafe(abs); !ok {
		if !force {
			return fmt.Errorf("%s is replaceable by the agent's user, so allow-listing it is not a boundary:\n"+
				"  %s\n  use a root-owned path (e.g. /usr/bin/...), or re-run with --force", abs, why)
		}
		fmt.Fprintf(os.Stderr, "warning: %s is replaceable by the agent's user (%s)\n", abs, why)
	}
	return nil
}

func absExec(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("exec path must be absolute (got %q)", p)
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s does not exist", p)
	}
	return filepath.EvalSymlinks(p)
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
