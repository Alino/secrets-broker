package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/vaultcore/secrets-broker/internal/kpxc"
)

// browserCmd manages the browsers associated with this broker.
//
// An association is a principal, not a convenience: "my everyday browser" and
// "a browser an agent drives" get different scopes. New associations arrive
// unapproved because the daemon has no GUI to prompt in — approving is a
// human act, done here.
func browserCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sb browser list | approve <id> [--agent] | revoke <id> | install-host [--dir <profile>]")
	}
	if args[0] == "install-host" {
		return browserInstallHost(args[1:])
	}
	store, err := kpxc.LoadAssoc(assocPath())
	if err != nil {
		return fmt.Errorf("%s: %w (in isolated mode: sudo sb browser ...)", assocPath(), err)
	}

	switch args[0] {
	case "list":
		all := store.All()
		if len(all) == 0 {
			fmt.Println("(no browsers have asked to associate)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATE\tSCOPE\tCREATED\tLAST USED")
		for _, a := range all {
			state := "PENDING"
			if a.Approved {
				state = "approved"
			}
			last := "never"
			if !a.LastUsed.IsZero() {
				last = a.LastUsed.Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, state, a.Scope, a.Created.Format(time.RFC3339), last)
		}
		return w.Flush()

	case "approve":
		if len(args) < 2 {
			return fmt.Errorf("usage: sb browser approve <id> [--agent]")
		}
		scope := kpxc.ScopeHuman
		for _, a := range args[2:] {
			if a == "--agent" {
				scope = kpxc.ScopeAgent
			}
		}
		if err := store.Approve(args[1], scope); err != nil {
			return err
		}
		fmt.Printf("approved %s with scope %s\n", args[1], scope)
		return nil

	case "revoke":
		if len(args) != 2 {
			return fmt.Errorf("usage: sb browser revoke <id>")
		}
		if err := store.Remove(args[1]); err != nil {
			return err
		}
		fmt.Println("revoked", args[1])
		return nil
	}
	return fmt.Errorf("unknown subcommand %q", args[0])
}

// assocPath mirrors the daemon's location for the association file.
func assocPath() string {
	if p := os.Getenv("SB_ASSOC_FILE"); p != "" {
		return p
	}
	return brokerVar + "/associations.json"
}

// browserInstallHost writes the native-messaging manifest into ONE Chrome
// profile directory, for single-uid mode where there is no root-owned
// system-wide install.
//
// Isolated mode installs the manifest system-wide and root-owned, precisely so
// an agent cannot repoint the extension at a host it controls. This
// per-profile variant deliberately does NOT have that property: the profile
// dir is writable by the same uid as the agent. It exists because single-uid
// mode has already accepted that trade-off (`sb doctor` says so), and because
// an agent-driven browser profile — where the agent is the only user — is
// exactly the case the system-wide install cannot serve without sudo.
//
// Refuses to run as root: a root-installed manifest in a user profile dir
// would be a confusing half-measure. Use `sudo sb install` for the real thing.
func browserInstallHost(args []string) error {
	dir := ""
	for i, a := range args {
		switch {
		case a == "--dir" && i+1 < len(args):
			dir = args[i+1]
		case strings.HasPrefix(a, "--dir="):
			dir = strings.TrimPrefix(a, "--dir=")
		}
	}
	if dir == "" {
		return fmt.Errorf("usage: sb browser install-host --dir <chrome-profile-dir>\n" +
			"  e.g. --dir ~/.config/assistant/chrome-profile   (the agent's browser-harness profile)\n" +
			"  for your everyday browser, prefer: sudo sb install  (root-owned, system-wide)")
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("don't run this as root — it installs into a user profile dir.\n" +
			"  for the root-owned system-wide manifest, use: sudo sb install")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	proxy := filepath.Join(filepath.Dir(self), "sb-browser-proxy")
	if _, err := os.Stat(proxy); err != nil {
		return fmt.Errorf("sb-browser-proxy not found next to sb (%s): %w", proxy, err)
	}
	proxy, _ = filepath.Abs(proxy)

	nmDir := filepath.Join(dir, "NativeMessagingHosts")
	if err := os.MkdirAll(nmDir, 0700); err != nil {
		return err
	}
	// Must match sb-browser-proxy's fallback: Chrome launches the host with
	// no args and no useful env, so both sides agree on this per-user path.
	sock := os.Getenv("SB_BROWSER_SOCKET")
	if sock == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		sock = filepath.Join(home, ".secrets-broker", "browser.sock")
	}
	manifest := map[string]any{
		"name":        nmHostName,
		"description": "secrets-broker browser integration (single-uid, per-profile)",
		// The proxy holds no keys and makes no decisions; it pipes the
		// extension's stdio to the broker socket, which enforces policy.
		"path":            proxy,
		"type":            "stdio",
		"allowed_origins": keepassxcExtensionIDs,
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	out := filepath.Join(nmDir, nmHostName+".json")
	if err := os.WriteFile(out, append(body, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", out)
	fmt.Printf("  proxy:  %s\n", proxy)
	fmt.Printf("  socket: %s\n", sock)
	fmt.Println()
	fmt.Println("next:")
	fmt.Println("  1. run the broker with -browser-socket " + sock)
	fmt.Println("  2. install the KeePassXC-Browser extension in that profile")
	fmt.Println("  3. click Connect in the extension, then approve it:")
	fmt.Println("       sb browser list        # shows it as PENDING")
	fmt.Println("       sb browser approve <id> --agent")
	fmt.Println()
	fmt.Println("note: this manifest is writable by your own user, so it is a")
	fmt.Println("convenience, not a boundary. `sudo sb install` is the root-owned form.")
	return nil
}

