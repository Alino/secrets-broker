package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/internal/unlock"
)

// Isolated mode layout. Everything the agent must not reach lives under
// brokerVar, owned by the service account; everything the agent executes
// lives under brokerLibexec, owned by root so it cannot be swapped out.
// These paths are shared across platforms; how the service account, the
// service manager and the approval helper are wired up is platform-specific
// (see install_darwin.go / install_linux.go).
const (
	brokerUser    = "_secretsbroker"
	clientGroup   = "secrets-broker-clients"
	brokerLibexec = "/usr/local/libexec/secrets-broker"
	brokerVar     = "/usr/local/var/secrets-broker"
	brokerEtc     = "/usr/local/etc/secrets-broker"
	// installedPolicy is root-owned and world-readable: the daemon must read
	// it, `sb list`/`sb doctor` must read it, and only root may change it.
	installedPolicy = brokerEtc + "/policy.json"
	// approvalPubKey is the registered Secure Enclave public key: root-owned,
	// world-readable (it is a public key), read by the daemon to verify
	// approval signatures.
	approvalPubKey = brokerEtc + "/approval.pub"
	// brokerRun holds the socket. It cannot live in /var/run: that is
	// root:wheel 0755 and the daemon runs unprivileged. The directory is
	// 0750 _secretsbroker:secrets-broker-clients so client users can traverse
	// it to reach the socket but cannot list or write the parent.
	brokerRun = brokerVar + "/run"
	brokerLog = brokerVar + "/broker.log"
	// installedAudit is the daemon's audit log; the agent's user can neither
	// read nor rewrite it.
	installedAudit = brokerVar + "/audit.jsonl"
	// ApprovalRight is the custom authorization right the approval helper
	// requests (macOS only). Registered with timeout=0 so no approval is ever
	// reused, and allow-root=false so a root caller is still challenged.
	ApprovalRight = "dev.secretsbroker.approve"
	// browserSocket carries the KeePassXC-Browser protocol.
	browserSocket = brokerRun + "/browser.sock"
	// nmHostName is the host the KeePassXC-Browser extension looks for. We
	// answer to it so the published, already-reviewed extension works against
	// this broker — no new extension for anyone to install or trust.
	nmHostName = "org.keepassxc.keepassxc_browser"
	// daemonPlist / daemonLabel are the macOS launchd job (used by install and
	// doctor); harmless as shared constants on other platforms.
	daemonPlist = "/Library/LaunchDaemons/dev.secretsbroker.plist"
	daemonLabel = "dev.secretsbroker"
)

// keepassxcExtensionIDs are the published KeePassXC-Browser extension IDs.
// Chrome enforces this list: it will not start the host for any other
// extension.
var keepassxcExtensionIDs = []string{
	"chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", // Chrome/Chromium/Brave
	"chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/", // Edge
}

const keepassxcFirefoxID = "keepassxc-browser@keepassxc.org"

// nmHostDirs are the SYSTEM-WIDE native messaging directories (macOS paths).
// The per-user ones are writable by the agent's own account: an agent could
// drop a manifest there pointing the extension at a host it controls.
// Installing root-owned is the whole point. `sb doctor` reads this list.
var nmHostDirs = []string{
	"/Library/Google/Chrome/NativeMessagingHosts",
	"/Library/Application Support/Chromium/NativeMessagingHosts",
	"/Library/Application Support/Microsoft Edge/NativeMessagingHosts",
	"/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
	"/Library/Application Support/Mozilla/NativeMessagingHosts",
}

// writeNativeMessagingHosts writes the root-owned NM manifest into each dir.
// Shared by both platforms — the manifest body and root ownership are
// identical; only the directory paths and root group (rootGroup) differ.
func writeNativeMessagingHosts(dirs []string) error {
	proxy := brokerLibexec + "/sb-browser-proxy"
	chrome := map[string]any{
		"name": nmHostName, "description": "secrets-broker browser integration",
		"path": proxy, "type": "stdio", "allowed_origins": keepassxcExtensionIDs,
	}
	firefox := map[string]any{
		"name": nmHostName, "description": "secrets-broker browser integration",
		"path": proxy, "type": "stdio", "allowed_extensions": []string{keepassxcFirefoxID},
	}
	for _, dir := range dirs {
		body := chrome
		if strings.Contains(strings.ToLower(dir), "mozilla") || strings.Contains(dir, "firefox") {
			body = firefox
		}
		if err := mkdirOwned(dir, "root", rootGroup, 0755); err != nil {
			return err
		}
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return err
		}
		path := filepath.Join(dir, nmHostName+".json")
		if err := os.WriteFile(path, b, 0644); err != nil {
			return err
		}
		if err := run("chown", "root:"+rootGroup, path); err != nil {
			return err
		}
	}
	return nil
}

// installCmd switches this machine from single-uid mode to isolated mode.
//
// A human must run this. If an agent can run `sudo sb install`, it can create
// its own service account and rewrite the daemon, and the isolation it sets
// up is meaningless. The platform-specific steps live in platformSteps().
func installCmd(args []string) error {
	dry := false
	vault := "" // <adapter>:<path>, e.g. opvault:/usr/local/var/secrets-broker/agent.opvault
	for i, a := range args {
		switch {
		case a == "--dry-run" || a == "-n":
			dry = true
		case a == "--vault" && i+1 < len(args):
			vault = args[i+1]
		case strings.HasPrefix(a, "--vault="):
			vault = strings.TrimPrefix(a, "--vault=")
		}
	}
	if !dry && os.Geteuid() != 0 {
		return fmt.Errorf("sb install must run as root:\n  sudo sb install\n" +
			"(run `sb install --dry-run` first to see exactly what it will do)")
	}

	owner := os.Getenv("SUDO_USER")
	if owner == "" && !dry {
		return fmt.Errorf("cannot determine the user that will run the agent (SUDO_USER unset); " +
			"run via sudo from that user's account")
	}
	if owner == "" {
		owner = currentUser()
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	srcDir := filepath.Dir(self)

	steps, err := platformSteps(owner, srcDir, vault)
	if err != nil {
		return err
	}

	if dry {
		fmt.Print("sb install --dry-run — this is what `sudo sb install` would do:\n\n")
		for i, s := range steps {
			fmt.Printf("  %d. %s\n", i+1, s.desc)
		}
		if vault != "" {
			fmt.Printf("  %d. prompt you for the vault master password and store it\n", len(steps)+1)
			fmt.Printf("  %d. ask whether the agent may CREATE new vault entries (default: no)\n", len(steps)+2)
		}
		if vault == "" {
			fmt.Println("\n  note: no --vault given, so the daemon will start with no vault configured.")
			fmt.Printf("        re-run with e.g. --vault opvault:%s/agent.opvault\n", brokerVar)
		}
		fmt.Print("\n" + platformNextSteps(owner))
		return nil
	}

	for i, s := range steps {
		fmt.Printf("[%d/%d] %s\n", i+1, len(steps), s.desc)
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.desc, err)
		}
	}

	// Finish the job: prompt for the master password here rather than making
	// the human run a second privileged command. Isolated mode is the mode
	// with the real guarantee, so every extra step is a reason not to use it.
	// Skipped when there is no vault, no tty, or a password is already stored.
	if vault != "" {
		if err := setPasswordDuringInstall(vault); err != nil {
			fmt.Printf("\n  could not store the master password now: %v\n", err)
			fmt.Printf("  run it yourself when convenient:\n    sudo sb set-password %s\n",
				strings.Replace(vault, ":", " ", 1))
		}
		// Writes stay denied unless the user says otherwise. Asking here is
		// the difference between a capability they know they have and one
		// they discover from a denial message weeks later — but the default
		// on a bare Enter is still NO, because a prompt-injected agent
		// overwriting vault entries is the thing this gate exists to stop.
		offerWriteAllow(vault)
	}
	offerBrowserHost()

	fmt.Printf("\ndone. verify with:\n"+
		"  sb doctor   (expect: mode isolated)\n"+
		"point your MCP client at:\n"+
		"  %s/secrets-broker-mcp -connect %s\n"+
		"note: group membership only applies to NEW shells — open one before connecting.\n",
		brokerLibexec, socketPath)
	return nil
}

// setPasswordDuringInstall stores the vault master password as the last step of
// `sb install`, so isolated mode is one command instead of two. It is a no-op
// when a password is already stored, and returns an error (rather than failing
// the install) when there is no terminal to prompt on — the install itself has
// already succeeded by this point.
func setPasswordDuringInstall(vault string) error {
	adapter, path, ok := strings.Cut(vault, ":")
	if !ok || path == "" {
		return fmt.Errorf("vault spec %q is not <adapter>:<path>", vault)
	}
	dir := unlock.SecretDir()
	if dir == "" {
		dir = filepath.Join(brokerVar, "secrets")
	}
	if _, err := os.Stat(unlock.SecretFile(dir, adapter+":"+path)); err == nil {
		fmt.Println("\n  master password already stored — leaving it as is.")
		return nil
	}
	fmt.Println()
	return setPasswordCmd([]string{adapter, path})
}

// offerWriteAllow asks whether the agent may CREATE new vault entries.
//
// Writes are denied by default and that default is deliberate: a
// prompt-injected agent must not be able to overwrite the GitHub password and
// hijack future logins. But "denied by default and never mentioned" means the
// user meets the gate as a cryptic denial later, so ask once, here.
//
// Only `create` is on offer. `update` (overwriting existing entries) stays a
// separate, explicit decision — it is the dangerous half, and nothing about
// finishing an install implies consent to it.
func offerWriteAllow(vault string) {
	adapter, _, ok := strings.Cut(vault, ":")
	if !ok || adapter == "" {
		return
	}
	st, err := policy.Load(policyPath())
	if err != nil {
		return
	}
	if wp := st.WriteAllow(adapter); wp.AllowCreate {
		return // already opted in
	}
	fmt.Printf("\nAllow the agent to CREATE new entries in this vault?\n"+
		"  This lets it generate a strong credential and store it without the\n"+
		"  value ever entering its context (create_secret). It can NOT change\n"+
		"  existing entries — adding a field such as a TOTP seed to one, or\n"+
		"  overwriting a value, stays denied until you run:\n"+
		"      sb write-allow %s create,add-fields   (or ...,update)\n", adapter)
	if !askYesNo("  Allow creating new entries? [y/N]: ") {
		fmt.Printf("  left denied. Enable later with: sudo sb write-allow %s create\n", adapter)
		return
	}
	// Reuse the CLI path so there is exactly one place that writes this, and
	// keep whatever else was already granted (add-fields, say): the question
	// was only about create.
	wp := st.WriteAllow(adapter)
	wp.AllowCreate = true
	if err := writeAllowCmd(adapter, wp.String()); err != nil {
		fmt.Printf("  could not save: %v\n  run: sudo sb write-allow %s create\n", err, adapter)
		return
	}
	if !wp.AllowUpdate {
		fmt.Println("  (overwriting stored values stays denied)")
	}
}

// offerBrowserHost points out browser autofill after a system-wide install.
// The manifest is already written by platformSteps; what the user still needs
// is the extension and an approval, and neither is discoverable from here.
func offerBrowserHost() {
	fmt.Print("\nBrowser autofill is installed (native-messaging host, root-owned).\n" +
		"  To use it: install KeePassXC-Browser, click Connect, then approve:\n" +
		"      sudo sb browser list\n" +
		"      sudo sb browser approve <id>          # --agent for an agent's browser\n" +
		"  Credentials only fill on origins you bind:\n" +
		"      sb allow <ref> --host=https://example.com\n")
}

// askYesNo reads a yes/no answer from the terminal. Anything other than an
// explicit yes — including no tty at all — is NO: a security default must
// never be flipped by absence of input.
func askYesNo(prompt string) bool {
	if _, err := os.Stat("/dev/tty"); err != nil {
		return false
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Print(prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		fmt.Println()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

type step struct {
	desc string
	fn   func() error
}

func mkdirOwned(path, user, group string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := run("chown", user+":"+group, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// vaultEnvVar turns --vault <adapter>:<path> into the service-manager
// environment entry the daemon reads. Without it the daemon starts with no
// vault configured. The returned string is a plist <key>/<string> fragment on
// macOS; install_linux.go rewrites it into KEY=value for systemd.
func vaultEnvVar(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	adapter, path, ok := strings.Cut(spec, ":")
	if !ok || path == "" {
		return "", fmt.Errorf("--vault must look like <adapter>:<path>, e.g. opvault:%s/agent.opvault", brokerVar)
	}
	var key string
	switch adapter {
	case "opvault":
		key = "SB_VAULT_DIR"
	case "keepass":
		key = "SB_KEEPASS_DB"
	default:
		return "", fmt.Errorf("--vault adapter must be opvault or keepass (bw is configured with SB_BW_EMAIL)")
	}
	return fmt.Sprintf("    <key>%s</key><string>%s</string>\n", key, xmlEscape(path)), nil
}

// vaultKeyValue is vaultEnvVar's systemd form: KEY=value, or "" for no vault.
func vaultKeyValue(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	adapter, path, ok := strings.Cut(spec, ":")
	if !ok || path == "" {
		return "", fmt.Errorf("--vault must look like <adapter>:<path>")
	}
	key := map[string]string{"opvault": "SB_VAULT_DIR", "keepass": "SB_KEEPASS_DB"}[adapter]
	if key == "" {
		return "", fmt.Errorf("--vault adapter must be opvault or keepass")
	}
	return key + "=" + path, nil
}

// xmlEscape keeps a vault path with &, < or > (all legal in filenames) from
// producing a plist launchctl cannot parse.
func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

// findBinary locates a built artifact next to sb. The repo builds
// platform-suffixed names (secrets-broker-mcp-darwin), so accept both; and
// build the Swift approval helper on demand, since it has no Go build.
func findBinary(dir, name string) (string, error) {
	for _, candidate := range []string{name, name + "-darwin", name + "-linux"} {
		p := filepath.Join(dir, candidate)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if strings.HasPrefix(name, "sb-") && hasSwiftHelper(name) {
		src := filepath.Join("cmd", name, "main.swift")
		if _, err := os.Stat(src); err == nil {
			out := filepath.Join(dir, name)
			if err := run("swiftc", "-O", "-o", out, src); err != nil {
				return "", fmt.Errorf("building the approval helper: %w", err)
			}
			return out, nil
		}
	}
	return "", fmt.Errorf("%s not found next to sb — build it first:\n"+
		"  go build -o bin/secrets-broker-mcp ./cmd/secrets-broker-mcp\n"+
		"  go build -o bin/sb ./cmd/sb\n"+
		"  go build -o bin/sb-browser-proxy ./cmd/sb-browser-proxy\n"+
		"  go build -o bin/sb-cdpfill ./cmd/sb-cdpfill\n"+
		"  (or just: make build)", name)
}

// ensureTraversable adds the execute bit to each parent directory so the
// daemon (running as its own account) and client users can reach the socket.
// /usr/local/var ships as 0700 root on some machines, which silently breaks
// both: the daemon cannot create its socket and the log it would complain in.
// Only +x is added — never read or write.
func ensureTraversable(dir string) error {
	var missing []string
	for p := filepath.Clean(dir); p != "/" && p != "."; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if fi.Mode().Perm()&0001 == 0 {
			missing = append(missing, p)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		fi, err := os.Stat(missing[i])
		if err != nil {
			return err
		}
		if err := os.Chmod(missing[i], fi.Mode().Perm()|0001); err != nil {
			return err
		}
		fmt.Printf("      +x on %s (was %04o)\n", missing[i], fi.Mode().Perm())
	}
	return nil
}

// waitForSocket blocks until the daemon accepts connections. The service
// manager returns as soon as the job is loaded, not when it is listening, so
// without this `sb install` reports done while the first client still gets
// "connection refused".
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not start listening on %s within %s — see %s", path, timeout, brokerLog)
}

// plistBody builds the macOS launchd job. vaultEnv is a plist <key>/<string>
// fragment from vaultEnvVar, or "" for no vault. Kept here (not in the darwin
// file) so it can be unit-tested for XML validity on any platform.
func plistBody(vaultEnv string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>UserName</key><string>%s</string>
  <key>GroupName</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s/secrets-broker-mcp</string>
    <string>-socket</string>
    <string>%s</string>
    <string>-browser-socket</string>
    <string>%s</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SB_POLICY_FILE</key><string>%s</string>
    <key>SB_AUDIT_LOG</key><string>%s/audit.jsonl</string>
    <key>SB_SECRET_DIR</key><string>%s/secrets</string>
    <key>SB_APPROVE_HELPER</key><string>%s/sb-approve</string>
    <key>SB_APPROVAL_PUBKEY</key><string>%s</string>
%s  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, daemonLabel, brokerUser, clientGroup, brokerLibexec, socketPath, browserSocket, installedPolicy, brokerVar, brokerVar, brokerLibexec, approvalPubKey, vaultEnv, brokerLog)
}

// unitBody builds the Linux systemd unit. vaultKV is one "KEY=value" line from
// vaultKeyValue, or "" for no vault. Kept here so it is unit-testable on any
// platform (the linux-only writeUnit just writes it to disk).
func unitBody(vaultKV string) string {
	var vaultLine string
	if vaultKV != "" {
		vaultLine = "Environment=" + vaultKV + "\n"
	}
	return fmt.Sprintf(`[Unit]
Description=secrets-broker isolated daemon
After=network.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s/secrets-broker-mcp -socket %s -browser-socket %s
Environment=SB_POLICY_FILE=%s
Environment=SB_AUDIT_LOG=%s/audit.jsonl
Environment=SB_SECRET_DIR=%s/secrets
%sRestart=always
RestartSec=1
# The daemon must create its socket group-readable for client users.
UMask=0007
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=%s
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, brokerUser, clientGroup, brokerLibexec, socketPath, browserSocket,
		installedPolicy, brokerVar, brokerVar, vaultLine, brokerVar)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
