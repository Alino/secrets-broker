package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vaultcore/secrets-broker/internal/kpxc"
	"github.com/vaultcore/secrets-broker/internal/policy"
)

// socketPath is where an isolated-mode daemon listens. Its existence (owned
// by another uid) is what distinguishes the two deployment modes.
const socketPath = "/usr/local/var/secrets-broker/run/sb.sock"

type report struct{ fails, warns int }

func (r *report) pass(format string, a ...any) { fmt.Printf("  PASS  "+format+"\n", a...) }
func (r *report) warn(format string, a ...any) {
	r.warns++
	fmt.Printf("  WARN  "+format+"\n", a...)
}
func (r *report) fail(format string, a ...any) {
	r.fails++
	fmt.Printf("  FAIL  "+format+"\n", a...)
}

// doctorCmd reports the real security posture of this machine. It is
// read-only and safe for an agent to run; it never reads secret values.
func doctorCmd() error {
	r := &report{}
	isolated := isolatedMode()

	fmt.Println("mode")
	if isolated {
		r.pass("isolated — broker runs as another uid; this user cannot reach the vault directly")
	} else {
		r.warn("single-uid — the broker runs as you (%s).", currentUser())
		fmt.Println("        Policy, masking and audit still apply, but anything running as")
		fmt.Println("        this user can bypass the broker and read the vault directly.")
		fmt.Println("        This is a convenience and traceability layer, not a boundary.")
		fmt.Println("        Run `sudo sb install` for isolated mode.")
	}

	fmt.Println("\nbroker state files")
	checkPolicyFile(r, policyPath())
	checkOwn(r, "audit log", auditPath(), isolated)

	fmt.Println("\nvaults")
	vaults := map[string]string{
		"SB_VAULT_DIR":  vaultPath("SB_VAULT_DIR"),
		"SB_KEEPASS_DB": vaultPath("SB_KEEPASS_DB"),
		"SB_ENPASS_DB":  vaultPath("SB_ENPASS_DB"),
	}
	any := false
	for env, path := range vaults {
		if path == "" {
			continue
		}
		any = true
		checkVault(r, env, path)
	}
	if !any {
		fmt.Println("  ----  no vault configured in this environment (SB_VAULT_DIR / SB_KEEPASS_DB / SB_ENPASS_DB)")
	}

	fmt.Println("\npolicy")
	st, err := policy.Load(policyPath())
	if err != nil {
		return err
	}
	refs := st.Refs()
	if len(refs) == 0 {
		fmt.Println("  ----  no policy entries — everything is denied by default")
	}
	for _, ref := range refs {
		p, _ := st.Get(ref)
		fmt.Printf("  %s\n", ref)
		if len(p.Exec) == 0 {
			r.warn("%s: no executables allowed (this ref is unusable)", ref)
		}
		for _, e := range p.Exec {
			switch {
			case policy.IsInterpreter(e):
				r.fail("%s is an interpreter — the agent can print or transform the secret", e)
			default:
				if ok, why := policy.PathSafe(e); !ok {
					r.fail("%s: %s", e, why)
				} else {
					r.pass("%s is root-owned and not replaceable", e)
				}
			}
		}
		if p.Approve {
			r.pass("%s requires human approval (Touch ID) for each use", ref)
		}
		if len(p.Args) == 0 && !p.NoArgs && len(p.Exec) > 0 {
			r.warn("%s: any arguments permitted — pin them with `sb allow %s <exec> -- <args>`", ref, ref)
		}
	}

	fmt.Println("\napproval")
	checkApprovalRight(r, st)
	checkApprovalUsable(r, st, isolated)

	fmt.Println("\nbrowser integration")
	checkBrowser(r, isolated)

	fmt.Println("\nmasking")
	fmt.Println("  ----  output masking conceals exact values only; base64/tr/rev defeat it.")
	fmt.Println("        It prevents accidental echo, not a hostile child process.")

	fmt.Printf("\n%d failing, %d warning\n", r.fails, r.warns)
	if r.fails > 0 {
		os.Exit(1)
	}
	return nil
}

// checkOwn reports whether a path is reachable by the current user. In
// isolated mode the broker's files should NOT be owned by the caller.
func checkOwn(r *report, label, path string, isolated bool) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  ----  %s: %v\n", label, err)
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		r.warn("%s: cannot read ownership", label)
		return
	}
	mine := int(st.Uid) == os.Getuid()
	switch {
	case isolated && mine:
		r.fail("%s (%s) is owned by this user — isolated mode is not in effect for it", label, path)
	case isolated:
		r.pass("%s (%s) is owned by uid %d, out of this user's reach", label, path, st.Uid)
	case mine:
		r.warn("%s (%s) is owned and writable by this user", label, path)
	default:
		r.pass("%s (%s) is owned by uid %d", label, path, st.Uid)
	}
	// Only read/write bits matter here: a directory may need o+x so client
	// users can traverse to the socket without being able to list it.
	if fi.Mode().Perm()&0066 != 0 {
		r.fail("%s (%s) is readable or writable by other local users (%04o) — every account is in group staff",
			label, path, fi.Mode().Perm())
	}
}

// checkApprovalRight verifies the custom authorization right exists and does
// not reuse credentials. An unregistered right silently falls back to the
// system default rule, which can approve without prompting.
func checkApprovalRight(r *report, st *policy.Store) {
	gated := false
	for _, ref := range st.Refs() {
		if p, ok := st.Get(ref); ok && p.Approve {
			gated = true
		}
	}
	out, err := exec.Command("security", "authorizationdb", "read", ApprovalRight).Output()
	if err != nil || len(out) == 0 {
		if gated {
			r.fail("approval right %s is not registered — gated refs will refuse to run "+
				"(fix: sudo sb install)", ApprovalRight)
		} else {
			fmt.Printf("  ----  approval right %s not registered (no refs require approval)\n", ApprovalRight)
		}
		return
	}
	// Substring matching is wrong here: a rule contains other integer keys
	// (version, for one), so "<integer>0</integer>" can appear while timeout
	// is 300. Ask plutil for the value of the timeout key specifically.
	val, err := plistValue(ApprovalRight, "timeout")
	switch {
	case err != nil:
		r.warn("approval right %s has no timeout set — credentials may be cached for the session", ApprovalRight)
	case val != "0":
		r.warn("approval right %s caches credentials for %ss — one authentication authorizes later uses",
			ApprovalRight, val)
	default:
		r.pass("approval right %s is registered and does not reuse credentials", ApprovalRight)
	}
}

// checkPolicyFile: the installed policy is root-owned and world-READABLE by
// design — the daemon and this command both read it. Only write access by
// anyone other than root is a finding.
func checkPolicyFile(r *report, path string) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  ----  policy file: %v\n", err)
		return
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	perm := fi.Mode().Perm()
	switch {
	case st != nil && st.Uid == 0 && perm&0022 == 0:
		r.pass("policy file (%s) is root-owned, %04o — readable by all, writable only by root", path, perm)
	case perm&0022 != 0:
		r.fail("policy file (%s) is writable by non-root (%04o) — an agent could add its own allow-list entry", path, perm)
	default:
		r.warn("policy file (%s) is owned by uid %d — in isolated mode it should be root", path, st.Uid)
	}
}

// checkVault reports who can read the vault. Group sharing is legitimate (a
// synced vault must stay writable by the syncing user), so what matters is
// whether the sharing group is a broad one and whether this user is in it.
func checkVault(r *report, label, path string) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  ----  %s: %v\n", label, err)
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		r.warn("%s: cannot read ownership", label)
		return
	}
	perm := fi.Mode().Perm()
	if perm&0007 != 0 {
		r.fail("%s (%s) is accessible to every local account (%04o)", label, path, perm)
	}
	if int(st.Uid) == os.Getuid() {
		r.fail("%s (%s) is owned by THIS user — if the agent runs as %s it can read the "+
			"ciphertext directly and attack the password offline. Run the agent as a "+
			"separate standard user.", label, path, currentUser())
	}
	if perm&0070 != 0 {
		g := groupName(st.Gid)
		switch g {
		case "staff", "admin", "wheel", "everyone":
			r.fail("%s (%s) is group-readable by %q — every local account is in it", label, path, g)
		default:
			r.pass("%s (%s) is shared with group %q only: %s", label, path, g, groupMembers(g))
		}
	}
}

// checkApprovalUsable: a system LaunchDaemon has no GUI session, so the
// SecurityAgent prompt cannot be drawn from there (errAuthorizationInternal
// -60007). Gated refs therefore fail closed in isolated mode until the
// prompt is moved into the user's session.
func checkApprovalUsable(r *report, st *policy.Store, isolated bool) {
	var gated []string
	for _, ref := range st.Refs() {
		if p, ok := st.Get(ref); ok && p.Approve {
			gated = append(gated, ref)
		}
	}
	if len(gated) == 0 {
		return
	}
	if isolated {
		seauth := brokerLibexec + "/sb-seauth"
		if ok, why := policy.PathSafe(seauth); !ok {
			r.fail("%d ref(s) require approval but the signer %s is unusable or replaceable: %s",
				len(gated), seauth, why)
			return
		}
		if _, err := os.Stat(approvalPubKey); err != nil {
			r.fail("%d ref(s) require approval but no key is registered at %s — they will be DENIED. "+
				"Registering one needs a code-signed sb-seauth (Apple Developer identity); without it, "+
				"use single-uid mode. See docs/approval.md. Refs: %s", len(gated), approvalPubKey, strings.Join(gated, ", "))
			return
		}
		r.pass("%d ref(s) require approval: a human signs the request nonce with the Secure Enclave "+
			"key registered at %s (fresh biometric, bound to that one request)", len(gated), approvalPubKey)
		return
	}
	r.pass("%d ref(s) require approval and this process can prompt", len(gated))
}

func groupName(gid uint32) string {
	if g, err := user.LookupGroupId(fmt.Sprint(gid)); err == nil {
		return g.Name
	}
	return fmt.Sprint(gid)
}

func groupMembers(g string) string {
	out, err := exec.Command("dscl", ".", "-read", "/Groups/"+g, "GroupMembership").Output()
	if err != nil {
		return "(members unknown)"
	}
	f := strings.Fields(string(out))
	if len(f) > 1 {
		return strings.Join(f[1:], ", ")
	}
	return "(no members)"
}

// vaultPath prefers the environment, then what the installed daemon is
// actually configured with, so `sb doctor` needs no env vars to be truthful.
func vaultPath(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	out, err := exec.Command("plutil", "-extract", "EnvironmentVariables."+key, "raw", "-o", "-",
		"/Library/LaunchDaemons/dev.secretsbroker.plist").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// checkBrowser reports on the KeePassXC-Browser path: the socket the proxy
// connects to, the native-messaging manifests (which decide WHICH extension
// may talk to us), and the associations that gate credential release.
func checkBrowser(r *report, isolated bool) {
	// 1. socket
	if fi, err := os.Stat(browserSocket); err != nil {
		fmt.Printf("  ----  browser socket: %v (browser autofill is off)\n", err)
	} else {
		st, _ := fi.Sys().(*syscall.Stat_t)
		perm := fi.Mode().Perm()
		switch {
		case perm&0007 != 0:
			r.fail("browser socket is connectable by every local account (%04o)", perm)
		case st != nil && isolated && int(st.Uid) == os.Getuid():
			r.fail("browser socket is owned by this user — the daemon should own it")
		default:
			r.pass("browser socket %04o owned by uid %d, group-restricted", perm, st.Uid)
		}
	}

	// 2. native-messaging manifests: they name the ONLY extension that may
	// reach the proxy, so a writable manifest is a repointable one.
	found := 0
	for _, dir := range nmHostDirs {
		path := filepath.Join(dir, nmHostName+".json")
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		found++
		st, _ := fi.Sys().(*syscall.Stat_t)
		if st != nil && st.Uid != 0 {
			r.fail("%s is owned by uid %d, not root — an agent could repoint the extension", path, st.Uid)
			continue
		}
		if fi.Mode().Perm()&0022 != 0 {
			r.fail("%s is writable by non-root (%04o)", path, fi.Mode().Perm())
			continue
		}
		var m struct {
			Path           string   `json:"path"`
			AllowedOrigins []string `json:"allowed_origins"`
			AllowedExts    []string `json:"allowed_extensions"`
		}
		b, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(b, &m) == nil {
			if len(m.AllowedOrigins)+len(m.AllowedExts) == 0 {
				r.fail("%s pins no extension — any extension could use it", path)
				continue
			}
			if ok, why := policy.PathSafe(m.Path); !ok {
				r.fail("%s points at a replaceable binary: %s", path, why)
				continue
			}
		}
		r.pass("%s manifest is root-owned and pins %d extension(s)", browserLabel(dir), len(m.AllowedOrigins)+len(m.AllowedExts))
	}
	if found == 0 {
		fmt.Println("  ----  no native-messaging manifest installed (run: sudo sb install)")
	}

	// 3. associations
	store, err := kpxc.LoadAssoc(assocPath())
	if err != nil {
		fmt.Printf("  ----  associations: %v (run doctor with sudo to inspect them)\n", err)
		return
	}
	all := store.All()
	if len(all) == 0 {
		fmt.Println("  ----  no browsers associated")
		return
	}
	for _, a := range all {
		switch {
		case !a.Approved:
			r.warn("association %s is PENDING — it gets nothing until approved (sb browser approve %s)", a.ID, a.ID)
		case a.LastUsed.IsZero():
			r.warn("association %s is approved but has never been used — revoke it if you did not expect it", a.ID)
		case time.Since(a.LastUsed) > 90*24*time.Hour:
			r.warn("association %s last used %s — revoke it if that browser is gone",
				a.ID, a.LastUsed.Format("2006-01-02"))
		default:
			r.pass("association %s (%s) last used %s", a.ID, a.Scope, a.LastUsed.Format("2006-01-02"))
		}
	}
}

// browserLabel names the browser a native-messaging directory belongs to, so
// five identical "NativeMessagingHosts" lines are distinguishable.
// plistValue extracts one key from an authorization rule.
func plistValue(right, key string) (string, error) {
	rule, err := exec.Command("security", "authorizationdb", "read", right).Output()
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "sb-right-*.plist")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(rule); err != nil {
		return "", err
	}
	tmp.Close()
	out, err := exec.Command("plutil", "-extract", key, "raw", "-o", "-", tmp.Name()).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func browserLabel(dir string) string {
	return filepath.Base(filepath.Dir(dir))
}

func isolatedMode() bool {
	fi, err := os.Stat(socketPath)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) != os.Getuid()
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return fmt.Sprintf("uid %d", os.Getuid())
}
