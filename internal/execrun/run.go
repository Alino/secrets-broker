// Package execrun implements the broker's core tool: run a child process with
// secret references resolved into its environment ONLY after destination
// binding checks pass. The agent receives masked stdout/stderr + exit code,
// never the values.
package execrun

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vaultcore/secrets-broker/internal/masking"
	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/internal/provision"
)

// Resolver maps a secret reference (sec://adapter/item/field) to its value.
// Adapters implement this; the broker core never stores values longer than
// the lifetime of one Run call.
type Resolver func(ref string) (string, error)

// Request is one exec_with_secret invocation.
type Request struct {
	Argv    []string          // child command; argv[0] must be policy-allowed
	EnvRefs map[string]string // ENV_VAR_NAME -> sec:// ref
	// Profile + ProfileItem shape one item's fields for a specific tool
	// (env vars and/or secret files). Optional; composes with EnvRefs.
	Profile     *provision.Profile
	ProfileItem string
	Resolver    Resolver
	Policy      *policy.Store
	// Approve is called ONCE per exec with every ref whose policy sets
	// approve:true, after all other checks have passed and before any secret
	// resolves. Consuming an approval is the last step that can fail, so a
	// later error cannot waste the human's fingerprint. A nil Approve denies
	// gated refs: the gate must not be removable by leaving a field unset.
	Approve  func(refs []string, execPath string, argv []string) error
	AuditLog string // path to append-only JSONL audit log ("" = no audit)
	Timeout  time.Duration
}

// Result is everything the agent is allowed to see.
type Result struct {
	ExitCode int
	Stdout   string // masked
	Stderr   string // masked
	Duration time.Duration
}

type auditEntry struct {
	TS       string `json:"ts"`
	Ref      string `json:"ref"`
	Exec     string `json:"exec"`
	Allowed  bool   `json:"allowed"`
	ExitCode int    `json:"exit_code,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Run executes the request. Denials return an error before any child spawns.
func Run(req Request) (*Result, error) {
	if len(req.Argv) == 0 {
		return nil, errEmpty("argv")
	}
	execPath, err := exec.LookPath(req.Argv[0])
	if err != nil {
		return nil, err
	}
	execPath, _ = filepath.Abs(execPath)

	// 1. destination binding: every referenced secret must allow this
	// executable and argv. All refs are checked before anything else happens.
	masker := masking.New(6)
	env := scrubEnv(os.Environ())
	var gated []string
	var noNetRefs []string
	needsNoNetwork := false
	for name, ref := range req.EnvRefs {
		if !safeInjectName(name) {
			return nil, errEmpty("env_refs key " + name + " (must be [A-Z_][A-Z0-9_]* and not a loader/shell var)")
		}
		if err := req.bindRef(ref, execPath, &gated, &noNetRefs); err != nil {
			return nil, err
		}
	}
	// Profile field refs are checked exactly like env refs: destination
	// binding and approval apply to each field the profile will resolve.
	var profileRefs []string
	if req.Profile != nil {
		if req.ProfileItem == "" {
			return nil, errEmpty("profile_item")
		}
		profileRefs = req.Profile.Refs(req.ProfileItem)
		for _, ref := range profileRefs {
			if err := req.bindRef(ref, execPath, &gated, &noNetRefs); err != nil {
				return nil, err
			}
		}
	}
	needsNoNetwork = len(noNetRefs) > 0

	// 2. one approval for every gated ref, only now that nothing else can refuse
	if len(gated) > 0 {
		sort.Strings(gated)
		if req.Approve == nil {
			for _, ref := range gated {
				req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: false,
					Reason: "approval required but no approval gate configured"})
			}
			return nil, deniedErr(strings.Join(gated, ", "), execPath, "approval required but no gate is configured")
		}
		if err := req.Approve(gated, execPath, req.Argv[1:]); err != nil {
			for _, ref := range gated {
				req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: false,
					Reason: "not approved by the user"})
			}
			return nil, err
		}
	}

	// 3. resolve
	for name, ref := range req.EnvRefs {
		val, err := req.Resolver(ref)
		if err != nil {
			return nil, err
		}
		masker.Register(val)
		env = append(env, name+"="+val)
		req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: true})
	}

	// 3b. resolve the profile's fields and materialize env vars / secret files
	if req.Profile != nil {
		values := map[string]string{}
		for i, ref := range profileRefs {
			val, err := req.Resolver(ref)
			if err != nil {
				return nil, err
			}
			if val == "" {
				return nil, errEmpty("profile field " + req.Profile.Fields[i] + " resolved from " + ref +
					" is empty; a tool must not receive a blank credential")
			}
			masker.Register(val)
			values[req.Profile.Fields[i]] = val
			req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: true})
		}
		mat, err := req.Profile.Materialize(values)
		if err != nil {
			return nil, err
		}
		defer mat.Cleanup() // temp secret files removed when the child exits
		for name, val := range mat.Env {
			// Same guard as env_refs: a profile must not set names like PATH
			// or DYLD_INSERT_LIBRARIES that redirect the child.
			if !safeInjectName(name) {
				return nil, errEmpty("profile env var " + name + " (must be [A-Z_][A-Z0-9_]* and not a loader/shell var)")
			}
			env = append(env, name+"="+val)
		}
	}

	// 4. spawn with masked pipes. A Context bounds the run: WaitDelay alone
	// never kills a child that simply hangs, which would also strand the
	// deferred temp-file cleanup above. The context kills the process on
	// timeout; WaitDelay is only the grace for draining its pipes afterward.
	ctx := context.Background()
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, execPath, req.Argv[1:]...)
	// Network jail, if any ref demands it. Applied AFTER the command is built
	// but BEFORE it starts. The strictest requirement among the refs wins: a
	// secret that must not touch the network cannot be laundered by pairing it
	// with an unrestricted one in the same call.
	if needsNoNetwork {
		if err := jailNoNetwork(cmd); err != nil {
			for _, ref := range noNetRefs {
				req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: false,
					Reason: "network:none unenforceable on this platform"})
			}
			return nil, err
		}
	}
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	outW := masker.Writer(&outBuf)
	errW := masker.Writer(&errBuf)
	cmd.Stdout = outW
	cmd.Stderr = errW
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	// A jailed child can only fail to be confined at spawn time on Linux
	// (CLONE_NEWUSER is refused by the seccomp profile or a sysctl). Start
	// separately so that failure is reported as a REFUSAL rather than being
	// indistinguishable from the command itself failing — and so the secret
	// is never handed to an unconfined process.
	if err := cmd.Start(); err != nil {
		if needsNoNetwork {
			for _, ref := range noNetRefs {
				req.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: false,
					Reason: "network:none could not be enforced at spawn"})
			}
			return nil, errNoJail(jailUnavailableHint + ": " + err.Error())
		}
		return nil, err
	}
	runErr := cmd.Wait()
	_ = outW.Flush()
	_ = errW.Flush()
	res := &Result{
		ExitCode: cmd.ProcessState.ExitCode(),
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		Duration: time.Since(start),
	}
	if runErr != nil {
		if res.ExitCode == 0 {
			res.ExitCode = -1
		}
	}
	return res, nil
}

// bindRef enforces destination binding for one ref against this exec+argv and
// collects it if its policy requires approval. Shared by the env-ref and
// profile-ref paths so the denial reason and gating rule cannot drift apart.
func (r Request) bindRef(ref, execPath string, gated, noNet *[]string) error {
	if !r.Policy.Check(ref, execPath, r.Argv[1:]) {
		reason := "destination not in allow-list"
		if p, ok := r.Policy.Get(ref); ok && len(p.Exec) > 0 && r.Policy.Check(ref, execPath, p.Args) {
			reason = "arguments not in allow-list"
		}
		r.audit(auditEntry{TS: now(), Ref: ref, Exec: execPath, Allowed: false, Reason: reason})
		return deniedErr(ref, execPath, reason)
	}
	if p, ok := r.Policy.Get(ref); ok {
		if p.Approve {
			*gated = append(*gated, ref)
		}
		if p.Network == policy.NetworkNone {
			*noNet = append(*noNet, ref)
		}
	}
	return nil
}

func (r Request) audit(e auditEntry) {
	if r.AuditLog == "" {
		return
	}
	f, err := os.OpenFile(r.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	f.Write(append(b, '\n'))
}

// validEnvName rejects env var names that could override broker-internal
// behavior in the child (e.g. LD_PRELOAD, PATH-style injection via weird keys).
// unsafeEnvNames redirect the dynamic linker or the shell and must never be
// set from a ref or a profile, whatever the value: a vault field that happens
// to hold a path could otherwise load code into the allow-listed tool.
var unsafeEnvNames = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
	"PATH": true, "IFS": true, "BASH_ENV": true, "ENV": true, "SHELL": true,
}

// safeInjectName reports whether name is a well-formed env var that is also not
// one of the loader/shell names an attacker could use to redirect the child.
func safeInjectName(name string) bool {
	return validEnvName(name) && !unsafeEnvNames[name]
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		ok := c == '_' || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// scrubEnv removes broker-internal secrets from the environment before the
// child is spawned. A policy-allowed child must not inherit e.g.
// SB_*_PASSWORD (set for adapter unlock) or BW_BROKER_PW — the agent could
// otherwise read them by running `env` through an allowed executable.
var scrubbedEnvPrefixes = []string{
	"SB_OPVAULT_PASSWORD=", "SB_KEEPASS_PASSWORD=", "SB_ENPASS_PASSWORD=",
	"SB_BW_PASSWORD=", "BW_BROKER_PW=", "BW_SESSION=",
}

func scrubEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		drop := false
		for _, p := range scrubbedEnvPrefixes {
			if strings.HasPrefix(e, p) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }

func errEmpty(what string) error { return simpleErr(what + " must not be empty") }
func deniedErr(ref, exe, reason string) error {
	return simpleErr("DENIED: secret " + ref + " for executable " + exe + " (" + reason + ")")
}
