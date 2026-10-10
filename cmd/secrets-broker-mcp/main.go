// secrets-broker MCP server: exposes list_secrets + exec_with_secret to agents.
// Secrets NEVER travel back over MCP — exec_with_secret returns only masked
// stdout/stderr + exit code (see internal/execrun).
//
// Config via env:
//
//	SB_VAULT_DIR     path to .opvault directory (opvault adapter)
//	SB_POLICY_FILE   policy JSON (destination binding allow-lists)
//	SB_AUDIT_LOG     audit JSONL path (default ~/.secrets-broker/audit.jsonl)
//	SB_OPVAULT_PASSWORD  master password (TESTS ONLY; production: keychain)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	bitwardenadapter "github.com/vaultcore/secrets-broker/internal/adapters/bitwarden"
	keepassadapter "github.com/vaultcore/secrets-broker/internal/adapters/keepass"
	opvaultadapter "github.com/vaultcore/secrets-broker/internal/adapters/opvault"
	"github.com/vaultcore/secrets-broker/internal/approve"
	"github.com/vaultcore/secrets-broker/internal/execrun"
	"github.com/vaultcore/secrets-broker/internal/gen"
	"github.com/vaultcore/secrets-broker/internal/kpxc"
	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/internal/provision"
	"github.com/vaultcore/secrets-broker/internal/router"
	"github.com/vaultcore/secrets-broker/internal/totp"
	"github.com/vaultcore/secrets-broker/internal/unlock"
)

var (
	socketFlag        = flag.String("socket", "", "serve MCP over this unix socket (isolated mode daemon)")
	connectFlag       = flag.String("connect", "", "pipe stdio to an isolated-mode daemon socket")
	browserSocketFlag = flag.String("browser-socket", "",
		"also serve the KeePassXC-Browser protocol on this unix socket")
)

// assocPath is where browser associations live: beside the daemon's other
// state, readable only by the daemon's own account.
func assocPath() string {
	if p := os.Getenv("SB_ASSOC_FILE"); p != "" {
		return p
	}
	return "/usr/local/var/secrets-broker/associations.json"
}

// umask wraps syscall.Umask so browser.go can keep the socket from ever
// existing world-connectable.
func umask(m int) int { return syscall.Umask(m) }

func main() {
	flag.Parse()
	ctx := context.Background()

	if *connectFlag != "" {
		if err := connectSocket(*connectFlag); err != nil {
			log.Fatalf("connect: %v", err)
		}
		return
	}

	policyFile := os.Getenv("SB_POLICY_FILE")
	auditLog := os.Getenv("SB_AUDIT_LOG")
	if auditLog == "" {
		home, _ := os.UserHomeDir()
		auditLog = filepath.Join(home, ".secrets-broker", "audit.jsonl")
		_ = os.MkdirAll(filepath.Dir(auditLog), 0700)
	}

	// Approval helper: installed by `sudo sb install`, overridable for tests.
	helper := os.Getenv("SB_APPROVE_HELPER")
	if helper == "" {
		helper = "/usr/local/libexec/secrets-broker/sb-approve"
	}
	// Single-uid mode prompts directly via sb-approve. Isolated mode verifies a
	// Secure Enclave signature over the request nonce against the public key
	// registered at install (SB_APPROVAL_PUBKEY); with no key it fails closed.
	gate := &approve.Gate{TTL: approvalTTL(), Pending: approve.NewPendingStore(approvalTTL())}
	if kp := os.Getenv("SB_APPROVAL_PUBKEY"); kp != "" {
		if pub, err := approve.LoadApprovalKey(kp); err != nil {
			log.Printf("approval key %s: %v (approval will fail closed)", kp, err)
		} else {
			gate.PubKey = pub
		}
	}
	if *socketFlag == "" {
		gate.Helper = helper
	}

	store, err := policy.Load(policyFile)
	if err != nil {
		log.Fatalf("policy load: %v", err)
	}
	profiles, err := provision.LoadRegistry(os.Getenv("SB_PROFILES_FILE"))
	if err != nil {
		log.Fatalf("profiles load: %v", err)
	}

	var resolver execrun.Resolver
	rtr := router.New()
	var kpWriter *keepassadapter.Adapter
	// write-capable adapters (create_secret / save_secret), keyed by prefix
	writers := map[string]policy.Writer{}
	if vaultDir := os.Getenv("SB_VAULT_DIR"); vaultDir != "" {
		ova := &opvaultadapter.Adapter{Dir: vaultDir, PasswordFn: func() (string, error) {
			return unlock.OpvaultPassword(vaultDir)
		}}
		rtr.Register("opvault", ova.Resolve)
		writers["opvault"] = ova
	}
	if kdbx := os.Getenv("SB_KEEPASS_DB"); kdbx != "" {
		kpWriter = &keepassadapter.Adapter{DBPath: kdbx, PasswordFn: func() (string, error) {
			return unlock.KeepassPassword(kdbx)
		}} // write modes come from the live policy per call (WriteEntry), not from here
		rtr.Register("keepass", kpWriter.Resolve)
		writers["keepass"] = kpWriter
	}
	// SB_ENPASS_DB is intentionally unsupported: the Enpass adapter was
	// removed because it cannot open Enpass 6.8+ vaults (the current format
	// is not supported). Failing loudly beats silently ignoring a
	// vault the user believes is configured.
	if os.Getenv("SB_ENPASS_DB") != "" {
		log.Fatal("SB_ENPASS_DB is set but the enpass adapter was removed in v0.3 " +
			"(it cannot open Enpass 6.8+ vaults). Use keepass, bitwarden or opvault.")
	}
	if bwServer := os.Getenv("SB_BW_SERVER"); bwServer != "" || os.Getenv("SB_BW_EMAIL") != "" {
		bwa := &bitwardenadapter.Adapter{
			Server: os.Getenv("SB_BW_SERVER"),
			Email:  os.Getenv("SB_BW_EMAIL"),
			CACert: os.Getenv("SB_BW_CACERT"),
			PasswordFn: func() (string, error) {
				return unlock.BwPassword(os.Getenv("SB_BW_EMAIL"))
			},
		}
		rtr.Register("bw", bwa.Resolve)
		writers["bw"] = bwa
	}
	resolver = rtr.Resolve
	_ = resolver

	server := mcp.NewServer(&mcp.Implementation{Name: "secrets-broker", Version: "0.1.0"}, nil)

	type secretMeta struct {
		Ref  string   `json:"ref"`
		Exec []string `json:"allowed_exec"`
	}
	// Typed tool outputs: returned as MCP structured content so a
	// structured-output client (e.g. Claude Code) actually sees results,
	// instead of an empty {} while the payload hides in text content.
	type listOut struct {
		Secrets []secretMeta `json:"secrets"`
	}
	type writeOut struct {
		Ref           string `json:"ref"`
		Field         string `json:"field"`
		Created       bool   `json:"created"` // false: fields were added to an existing entry
		Stored        bool   `json:"stored"`
		ValueReturned bool   `json:"value_returned"`
	}
	type approvalReqOut struct {
		Nonce    string   `json:"nonce"`
		Refs     []string `json:"refs"`
		Exec     string   `json:"exec"`
		Argv     []string `json:"argv"`
		Describe string   `json:"describe"`
		Expires  string   `json:"expires"`
	}
	type approveOut struct {
		Approved bool `json:"approved"`
	}

	// writeSecret performs one vault write within mode and describes it. TOTP
	// seeds are validated and normalized first, so a seed that cannot produce
	// codes is refused now rather than failing at a login weeks later. Errors
	// name fields, never values.
	writeSecret := func(w policy.Writer, adapter, group, title string, fields map[string]string, field string, mode policy.WriteMode) (writeOut, error) {
		for k, v := range fields {
			if totp.IsField(k) {
				nv, err := totp.Normalize(v, title)
				if err != nil {
					return writeOut{}, fmt.Errorf("field %s: %v — nothing was written", k, err)
				}
				fields[k] = nv
			}
		}
		if ew, ok := w.(policy.EntryWriter); ok {
			res, err := ew.WriteEntry(group, title, fields, field, mode)
			if err != nil {
				return writeOut{}, err
			}
			return writeOut{Ref: res.Ref, Field: field, Created: res.Created, Stored: true}, nil
		}
		// The other adapters only ever make a new item, and return its password's ref.
		if !mode.Create {
			return writeOut{}, fmt.Errorf("vault writes DENIED for %s: it can only create new items — run: sb write-allow %s create", adapter, adapter)
		}
		if !strings.EqualFold(field, "Password") {
			return writeOut{}, fmt.Errorf("%s stores a secret only in an item's Password, not in %q — nothing was written", adapter, field)
		}
		ref, err := w.CreateEntry(group, title, fields)
		if err != nil {
			return writeOut{}, err
		}
		return writeOut{Ref: ref, Field: field, Created: true, Stored: true}, nil
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List secret references available to this broker. Returns metadata only (ref, allowed executables). Values are never returned.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, listOut, error) {
		reloadPolicy(store)
		out := []secretMeta{}
		for _, ref := range store.Refs() {
			if p, ok := store.Get(ref); ok {
				out = append(out, secretMeta{Ref: ref, Exec: p.Exec})
			}
		}
		return textResult(listOut{Secrets: out}), listOut{Secrets: out}, nil
	})

	// find_secrets_for_site is the only discovery the broker offers: scoped to
	// one origin, refs only. There is deliberately no "list everything in the
	// vault" tool — an agent needs a ref to USE a credential, never an
	// inventory of what exists.
	mcp.AddTool(server, &mcp.Tool{
		Name: "find_secrets_for_site",
		Description: "List secret references bound to a website's origin (scheme+host+port). " +
			"Returns refs only — never values, and never secrets bound to other sites. " +
			"Use the ref with a fill/exec tool; the broker re-checks the origin against the " +
			"browser's real URL before releasing anything.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		URL string `json:"url"`
	}) (*mcp.CallToolResult, listOut, error) {
		reloadPolicy(store)
		refs := store.RefsForSite(in.URL)
		out := []secretMeta{}
		for _, ref := range refs {
			if p, ok := store.Get(ref); ok {
				out = append(out, secretMeta{Ref: ref, Exec: p.Exec})
			}
		}
		return textResult(listOut{Secrets: out}), listOut{Secrets: out}, nil
	})

	type execIn struct {
		Argv    []string          `json:"argv"`
		EnvRefs map[string]string `json:"env_refs,omitempty"`
		// ApprovalRequest is the nonce of a request a human approved with
		// `sb approve --request <nonce>`. Required for approve:true refs when
		// the broker runs as a daemon, which has no session to prompt in.
		// The nonce is bound to this exact ref, executable and argv.
		ApprovalRequest string `json:"approval_request,omitempty"`
		// Profile shapes one item's fields for a specific tool (e.g. "kube"
		// writes a kubeconfig and sets KUBECONFIG). ProfileItem is the item.
		Profile     string `json:"profile,omitempty"`
		ProfileItem string `json:"profile_item,omitempty"`
	}

	mcp.AddTool(server, &mcp.Tool{
		Name: "create_secret",
		Description: "Generate a NEW random secret and store it in the vault (keepass). " +
			"PREFER THIS over asking the user to invent a password or over generating one yourself " +
			"in the shell — the value never enters your context. The VALUE IS NEVER RETURNED, only the ref. " +
			"Use exec_with_secret with the ref to spend it (e.g. register an account: generate here, " +
			"submit via curl with the ref). Requires write policy: sb write-allow keepass create|both.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Adapter string            `json:"adapter,omitempty"` // keepass (default) | bw
		Title   string            `json:"title"`
		Group   string            `json:"group,omitempty"`
		Fields  map[string]string `json:"fields,omitempty"` // extra non-secret fields (URL, UserName, notes)
		Kind    string            `json:"kind,omitempty"`   // "password" (default) | "token"
		Length  int               `json:"length,omitempty"` // default 20 pw / 32 token
		Symbols bool              `json:"symbols,omitempty"`
	}) (*mcp.CallToolResult, writeOut, error) {
		adapter := in.Adapter
		if adapter == "" {
			adapter = "keepass"
		}
		w, ok := writers[adapter]
		if !ok {
			return errText("adapter " + adapter + " not configured or not write-capable"), writeOut{}, nil
		}
		reloadPolicy(store)
		mode := store.WriteAllow(adapter).Mode()
		if !mode.Create {
			return errText("vault writes DENIED for " + adapter + " — run: sb write-allow " + adapter + " create"), writeOut{}, nil
		}
		var value string
		var err error
		if in.Kind == "token" {
			n := in.Length
			if n == 0 {
				n = 32
			}
			value, err = gen.Token(n)
		} else {
			n := in.Length
			if n == 0 {
				n = 20
			}
			value, err = gen.Password(n, in.Symbols)
		}
		if err != nil {
			return errText(err.Error()), writeOut{}, nil
		}
		fields := map[string]string{}
		for k, v := range in.Fields {
			fields[k] = v
		}
		fields["Password"] = value
		out, err := writeSecret(w, adapter, in.Group, in.Title, fields, "Password", mode)
		if err != nil {
			return errText(err.Error()), writeOut{}, nil
		}
		return textResult(out), out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "save_secret",
		Description: "Store a secret VALUE you already hold (e.g. an API key from a signup response) " +
			"into the vault, and then USE IT ONLY BY ITS REF — do not keep it in your context, write it " +
			"to a file/.env, or echo it. The response contains only the ref of `field` (default Password). " +
			"TOTP: field \"otp\" takes an otpauth://totp URI or a base32 key; it is validated and stored the " +
			"way KeePassXC keeps TOTP, so sb-cdpfill FILL_TOTP and KeePassXC both compute codes from it. " +
			"If an entry with this title exists, the fields are ADDED to it — never overwriting a stored " +
			"value without update policy. Requires write policy: sb write-allow keepass create (new " +
			"entries) and/or add-fields (fields an existing entry lacks).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Adapter string            `json:"adapter,omitempty"` // keepass (default) | bw
		Title   string            `json:"title"`
		Group   string            `json:"group,omitempty"`
		Field   string            `json:"field,omitempty"` // default "Password"; "otp" for a TOTP seed
		Value   string            `json:"value"`
		Fields  map[string]string `json:"fields,omitempty"`
	}) (*mcp.CallToolResult, writeOut, error) {
		adapter := in.Adapter
		if adapter == "" {
			adapter = "keepass"
		}
		w, ok := writers[adapter]
		if !ok {
			return errText("adapter " + adapter + " not configured or not write-capable"), writeOut{}, nil
		}
		reloadPolicy(store)
		mode := store.WriteAllow(adapter).Mode()
		if !mode.Any() {
			return errText("vault writes DENIED for " + adapter + " — run: sb write-allow " + adapter +
				" create (new entries) or add-fields (fields an existing entry lacks)"), writeOut{}, nil
		}
		field := in.Field
		if field == "" {
			field = "Password"
		}
		fields := map[string]string{}
		for k, v := range in.Fields {
			if !strings.EqualFold(k, field) { // `value` wins over a same-named extra field
				fields[k] = v
			}
		}
		fields[field] = in.Value
		out, err := writeSecret(w, adapter, in.Group, in.Title, fields, field, mode)
		if err != nil {
			return errText(err.Error()), writeOut{}, nil
		}
		return textResult(out), out, nil
	})

	// Approval pair for isolated mode. get_approval_request lets `sb approve`
	// show the human what the BROKER recorded (not what any caller claims);
	// submit_approval takes a Secure Enclave signature over the nonce. Both are
	// safe to expose: describing a request reveals only what the caller already
	// asked, and approving requires a signature only the enrolled human can make.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_approval_request",
		Description: "Return a pending approval request by nonce: the exact command and refs the broker recorded, for `sb approve` to display and sign.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Nonce string `json:"nonce"`
	}) (*mcp.CallToolResult, approvalReqOut, error) {
		p, err := gate.Pending.Get(in.Nonce)
		if err != nil {
			return errText(err.Error()), approvalReqOut{}, nil
		}
		out := approvalReqOut{
			Nonce: p.Nonce, Refs: p.Refs, Exec: p.Exec, Argv: p.Argv,
			Describe: p.Describe(), Expires: p.Expires.UTC().Format(time.RFC3339),
		}
		return textResult(out), out, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "submit_approval",
		Description: "Approve a pending request with a Secure Enclave signature over its nonce (from `sb approve`). The signature binds to that one request and required a fresh biometric.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}) (*mcp.CallToolResult, approveOut, error) {
		if err := gate.SubmitApproval(in.Nonce, in.Signature); err != nil {
			return errText(err.Error()), approveOut{}, nil
		}
		return textResult(approveOut{Approved: true}), approveOut{Approved: true}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "exec_with_secret",
		Description: "Run a command with secrets resolved into its environment (destination-binding enforced). " +
			"USE THIS whenever a command needs a credential — never ask the user to paste a secret and never " +
			"inline a value into argv. env_refs maps env vars to sec:// refs; or set profile + profile_item to " +
			"shape an item for a tool (e.g. profile \"kube\", profile_item \"sec://opvault/Kube\" writes a " +
			"kubeconfig and sets KUBECONFIG). Returns ONLY masked stdout/stderr and the exit code — secret " +
			"values never appear in the response. If denied, the error names the exact `sb allow` command to fix it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, execrun.Result, error) {
		if resolver == nil {
			return errText("no vault adapter configured (SB_VAULT_DIR)"), execrun.Result{}, nil
		}
		reloadPolicy(store)
		var prof *provision.Profile
		if in.Profile != "" {
			p, ok := profiles.Get(in.Profile)
			if !ok {
				return errText("unknown profile " + in.Profile + " (see `sb profiles`)"), execrun.Result{}, nil
			}
			prof = &p
		}
		res, err := execrun.Run(execrun.Request{
			Argv:        in.Argv,
			EnvRefs:     in.EnvRefs,
			Profile:     prof,
			ProfileItem: in.ProfileItem,
			Resolver:    resolver,
			Policy:      store,
			Approve: func(refs []string, execPath string, argv []string) error {
				return gate.Require(in.ApprovalRequest, refs, execPath, argv)
			},
			AuditLog: auditLog,
		})
		if err != nil {
			return errText(err.Error()), execrun.Result{}, nil
		}
		return textResult(res), *res, nil
	})

	// Two deployment shapes over the same handlers:
	//   default        stdio — broker runs as the calling user (single-uid mode)
	//   -socket PATH   unix socket — broker runs as its own uid (isolated mode)
	//   -connect PATH  thin client: pipes stdio to an isolated-mode daemon
	// Browser protocol: served alongside MCP so the same policy, the same
	// audit log and the same uid isolation cover both callers.
	// Both sockets are created here, sequentially, before any accept loop:
	// see listenRestricted on why they must not race.
	var browserLn net.Listener
	if *browserSocketFlag != "" {
		var err error
		if browserLn, err = listenRestricted(*browserSocketFlag); err != nil {
			log.Fatalf("browser socket: %v", err)
		}
	}
	var mcpLn net.Listener
	if *socketFlag != "" {
		var err error
		if mcpLn, err = listenRestricted(*socketFlag); err != nil {
			log.Fatalf("socket: %v", err)
		}
	}

	if browserLn != nil {
		assocs, err := kpxc.LoadAssoc(assocPath())
		if err != nil {
			log.Fatalf("associations: %v", err)
		}
		v := &brokerVault{store: store, resolver: resolver, auditLog: auditLog,
			vaultID: os.Getenv("SB_VAULT_DIR") + os.Getenv("SB_KEEPASS_DB") + os.Getenv("SB_ENPASS_DB")}
		go func() {
			if err := serveBrowserSocket(browserLn, v, assocs); err != nil {
				log.Printf("browser socket: %v", err)
			}
		}()
	}

	if mcpLn != nil {
		log.Printf("secrets-broker: isolated mode, listening on %s", mcpLn.Addr())
		if err := serveSocket(ctx, server, mcpLn); err != nil {
			log.Fatalf("socket server: %v", err)
		}
		return
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("mcp server: %v", err)
	}
}

// serveSocket accepts MCP sessions over a unix socket. The socket is the only
// thing the agent's uid can reach in isolated mode; everything behind it
// (vault, master password, policy, audit log) belongs to the broker's user.
func serveSocket(ctx context.Context, server *mcp.Server, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			err := server.Run(ctx, &mcp.IOTransport{Reader: conn, Writer: conn})
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("session: %v", err)
			}
		}()
	}
}

// connectSocket is the client half: stdio in, socket out. The agent's MCP
// config points at this, so the agent never holds anything but a pipe.
func connectSocket(path string) error {
	// First dial must succeed so we can report a clear error; after that the
	// proxy reconnects across daemon restarts (see proxyReconnecting).
	first, err := net.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("dial %s: %w (is the daemon running? sudo sb install)", path, err)
	}
	first.Close()
	return proxyReconnecting(os.Stdin, os.Stdout, func() (net.Conn, error) {
		return net.Dial("unix", path)
	})
}

// approvalTTL is how long one Touch ID approval stands for the same
// secret+destination pair. Short enough that a task cannot ride an old
// approval, long enough that a multi-step task asks once.
func approvalTTL() time.Duration {
	if v := os.Getenv("SB_APPROVAL_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 5 * time.Minute
}

// reloadPolicy picks up `sb allow` edits without a daemon restart. A failure
// leaves the last good policy in force and is logged rather than surfaced to
// the agent: it must not be able to tell whether its own probing changed the
// policy file.
func reloadPolicy(store *policy.Store) {
	if err := store.ReloadIfChanged(); err != nil {
		log.Printf("policy reload: %v (keeping last good policy)", err)
	}
}

// textResult mirrors a structured output as pretty JSON in text content, so
// text-only MCP clients see the same payload structured-output clients get.
func textResult(v any) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func errText(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}
