package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// rootGroup owns root-owned files on this platform (wheel on macOS).
const rootGroup = "wheel"

// hasSwiftHelper: macOS builds the Swift approval helpers on demand.
func hasSwiftHelper(name string) bool { return true }

// platformSteps is the macOS (launchd + Directory Services + Secure Enclave)
// install sequence.
func platformSteps(owner, srcDir, vaultSpec string) ([]step, error) {
	vaultEnv, err := vaultEnvVar(vaultSpec)
	if err != nil {
		return nil, err
	}
	return []step{
		{"create service account " + brokerUser, func() error { return createUser(brokerUser) }},
		{"create client group " + clientGroup + " and add " + owner, func() error { return createGroup(clientGroup, owner) }},
		{"install binaries into " + brokerLibexec + " (root-owned, not agent-writable)", func() error {
			if err := mkdirOwned(brokerLibexec, "root", "wheel", 0755); err != nil {
				return err
			}
			for _, b := range []string{"secrets-broker-mcp", "sb", "sb-approve", "sb-seauth", "sb-browser-proxy", "sb-cdpfill"} {
				src, err := findBinary(srcDir, b)
				if err != nil {
					return err
				}
				if err := run("install", "-o", "root", "-g", "wheel", "-m", "0755", src, filepath.Join(brokerLibexec, b)); err != nil {
					return err
				}
			}
			return nil
		}},
		{"create " + brokerEtc + " (policy, root-owned 0644 — agent can read, not write)", func() error {
			if err := mkdirOwned(brokerEtc, "root", "wheel", 0755); err != nil {
				return err
			}
			if _, err := os.Stat(installedPolicy); os.IsNotExist(err) {
				if err := os.WriteFile(installedPolicy, []byte("{\"items\":[],\"writes\":{}}\n"), 0644); err != nil {
					return err
				}
			}
			return run("chown", "root:wheel", installedPolicy)
		}},
		{"make " + filepath.Dir(brokerVar) + " traversable (parents must allow reaching the socket)",
			func() error { return ensureTraversable(filepath.Dir(brokerVar)) }},
		{"register the Secure Enclave approval key (as " + owner + "; optional)",
			func() error {
				if err := registerApprovalKey(owner); err != nil {
					// Non-fatal: everything else installs, and isolated-mode
					// approval simply fails closed until a signed sb-seauth can
					// register a key. Persistent Secure Enclave keys need a
					// code-signed helper (see docs/approval.md).
					fmt.Printf("      skipped: %v\n", err)
					fmt.Println("      isolated-mode --approve will be unavailable (fails closed);")
					fmt.Println("      single-uid mode approval still works. See docs/approval.md.")
				}
				return nil
			}},
		{"create " + brokerVar + " (0711 owned by " + brokerUser + ": traversable, not listable)", func() error {
			if err := mkdirOwned(brokerVar, brokerUser, "daemon", 0711); err != nil {
				return err
			}
			if err := mkdirOwned(filepath.Join(brokerVar, "secrets"), brokerUser, "daemon", 0700); err != nil {
				return err
			}
			return mkdirOwned(brokerRun, brokerUser, clientGroup, 0750)
		}},
		{"install the browser native-messaging host (root-owned, so an agent cannot repoint it)",
			installNativeMessagingHosts},
		{"register the approval right " + ApprovalRight + " (timeout 0, no credential reuse)",
			registerApprovalRight},
		{"write " + daemonPlist, func() error { return writePlist(vaultEnv) }},
		{"(re)load the daemon", func() error {
			_ = run("launchctl", "bootout", "system", daemonPlist)
			if err := run("launchctl", "bootstrap", "system", daemonPlist); err != nil {
				return err
			}
			return waitForSocket(socketPath, 15*time.Second)
		}},
	}, nil
}

// platformUninstallSteps reverses platformSteps on macOS. Best-effort: each
// step tolerates its target being absent.
func platformUninstallSteps(purge bool) []step {
	steps := []step{
		{"stop and remove the launchd daemon", func() error {
			_ = run("launchctl", "bootout", "system", daemonPlist) // ignore: may not be loaded
			return removeIfPresent(daemonPlist)
		}},
		{"remove the browser native-messaging hosts", func() error {
			for _, dir := range nmHostDirs {
				if err := removeIfPresent(filepath.Join(dir, nmHostName+".json")); err != nil {
					return err
				}
			}
			return nil
		}},
		{"remove the approval right " + ApprovalRight, func() error {
			return run("security", "authorizationdb", "remove", ApprovalRight)
		}},
		{"remove binaries in " + brokerLibexec, func() error { return os.RemoveAll(brokerLibexec) }},
		{"remove the socket directory " + brokerRun, func() error { return os.RemoveAll(brokerRun) }},
		{"remove the client group " + clientGroup, func() error {
			return run("dseditgroup", "-o", "delete", clientGroup)
		}},
		{"remove the service account " + brokerUser, func() error {
			return run("dscl", ".", "-delete", "/Users/"+brokerUser)
		}},
	}
	if purge {
		steps = append(steps,
			step{"purge " + brokerVar, func() error { return os.RemoveAll(brokerVar) }},
			step{"purge " + brokerEtc, func() error { return os.RemoveAll(brokerEtc) }},
		)
	}
	return steps
}

func platformNextSteps(owner string) string {
	return fmt.Sprintf("install also prompts for the vault master password at the end,\n"+
		"so this is normally the only command you need to run.\n\n"+
		"afterwards:\n"+
		"  1. move the agent's vault into %s and chown it to %s\n"+
		"     (or point --vault at where it already lives)\n"+
		"  2. point the agent's MCP config at:\n"+
		"       %s/secrets-broker-mcp -connect %s\n"+
		"  3. sb doctor   (should report: mode isolated)\n", brokerVar, brokerUser, brokerLibexec, socketPath)
}

// createUser makes a hidden service account with no login shell. Idempotent.
func createUser(name string) error {
	if err := run("dscl", ".", "-read", "/Users/"+name); err == nil {
		fmt.Println("      (already exists)")
		return nil
	}
	uid, err := freeSystemUID()
	if err != nil {
		return err
	}
	for _, kv := range [][]string{
		{"UniqueID", uid},
		{"PrimaryGroupID", "1"}, // daemon
		{"UserShell", "/usr/bin/false"},
		{"RealName", "secrets-broker service account"},
		{"NFSHomeDirectory", brokerVar},
		{"IsHidden", "1"},
	} {
		if err := run("dscl", ".", "-create", "/Users/"+name, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// freeSystemUID picks an unused uid below 500 so the account stays hidden and
// outside the normal user range.
func freeSystemUID() (string, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return "", err
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if id, err := strconv.Atoi(f[1]); err == nil {
				used[id] = true
			}
		}
	}
	for id := 400; id < 500; id++ {
		if !used[id] {
			return strconv.Itoa(id), nil
		}
	}
	return "", fmt.Errorf("no free system uid in 400-499")
}

func createGroup(name, member string) error {
	if err := run("dseditgroup", "-o", "read", name); err != nil {
		if err := run("dseditgroup", "-o", "create", name); err != nil {
			return err
		}
	}
	return run("dseditgroup", "-o", "edit", "-a", member, "-t", "user", name)
}

func writePlist(vaultEnv string) error {
	if err := os.WriteFile(daemonPlist, []byte(plistBody(vaultEnv)), 0644); err != nil {
		return err
	}
	return run("chown", "root:wheel", daemonPlist)
}

func installNativeMessagingHosts() error {
	return writeNativeMessagingHosts(nmHostDirs)
}

// registerApprovalRight installs the authorization rule used by sb-approve.
// Without it Authorization Services falls back to the system default rule,
// which can approve from a credential cached by some unrelated admin action —
// the helper refuses to run in that case, so this step is mandatory.
func registerApprovalRight() error {
	rule := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>class</key><string>user</string>
  <key>group</key><string>admin</string>
  <key>shared</key><false/>
  <key>timeout</key><integer>0</integer>
  <key>allow-root</key><false/>
  <key>session-owner</key><true/>
  <key>comment</key><string>secrets-broker: authorize one use of one secret</string>
</dict>
</plist>
`
	cmd := exec.Command("security", "authorizationdb", "write", ApprovalRight)
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("security authorizationdb write: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// registerApprovalKey creates (idempotently) the Secure Enclave approval key
// as the console user — the only identity with biometric enrollment — and
// records its public half root-owned for the daemon. Key creation needs no
// biometric and no root; only USING the key later does.
func registerApprovalKey(owner string) error {
	seauth := brokerLibexec + "/sb-seauth"
	cmd := exec.Command("sudo", "-u", owner, seauth, "keygen")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if strings.Contains(msg, "-34018") || strings.Contains(msg, "MissingEntitlement") {
			msg = "sb-seauth is not code-signed with a keychain entitlement (needs an Apple Developer identity)"
		}
		return fmt.Errorf("%s", msg)
	}
	pub := strings.TrimSpace(out.String())
	if pub == "" {
		return fmt.Errorf("sb-seauth produced no public key")
	}
	if err := os.WriteFile(approvalPubKey, []byte(pub+"\n"), 0644); err != nil {
		return err
	}
	return run("chown", "root:wheel", approvalPubKey)
}
