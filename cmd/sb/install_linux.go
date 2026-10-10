package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// unitPath is the systemd unit for the isolated daemon.
	unitPath = "/etc/systemd/system/secrets-broker.service"
	// rootGroup owns root-owned files on this platform.
	rootGroup = "root"
)

// hasSwiftHelper: Linux has no Secure Enclave / Swift approval helper.
func hasSwiftHelper(name string) bool { return false }

// nmHostDirsLinux are the SYSTEM-WIDE native-messaging directories on Linux.
// Same reasoning as macOS: the per-user (~/.config/...) dirs are agent-writable,
// so the manifest goes in the system dirs, root-owned.
var nmHostDirsLinux = []string{
	"/etc/opt/chrome/native-messaging-hosts",
	"/etc/chromium/native-messaging-hosts",
	"/etc/opt/edge/native-messaging-hosts",
	"/etc/opt/brave/native-messaging-hosts",
	"/usr/lib/mozilla/native-messaging-hosts",
}

// platformSteps is the Linux (systemd + useradd) install sequence. There is no
// Secure Enclave, so isolated-mode approval is unavailable and fails closed
// (same documented behaviour as macOS without a signed sb-seauth).
func platformSteps(owner, srcDir, vaultSpec string) ([]step, error) {
	vaultKV, err := vaultKeyValue(vaultSpec)
	if err != nil {
		return nil, err
	}
	return []step{
		{"create service account " + brokerUser, func() error { return createUser(brokerUser) }},
		{"create client group " + clientGroup + " and add " + owner, func() error { return createGroup(clientGroup, owner) }},
		{"install binaries into " + brokerLibexec + " (root-owned, not agent-writable)", func() error {
			if err := mkdirOwned(brokerLibexec, "root", rootGroup, 0755); err != nil {
				return err
			}
			for _, b := range []string{"secrets-broker-mcp", "sb", "sb-browser-proxy", "sb-cdpfill"} {
				src, err := findBinary(srcDir, b)
				if err != nil {
					return err
				}
				if err := run("install", "-o", "root", "-g", rootGroup, "-m", "0755", src, filepath.Join(brokerLibexec, b)); err != nil {
					return err
				}
			}
			return nil
		}},
		{"create " + brokerEtc + " (policy, root-owned 0644 — agent can read, not write)", func() error {
			if err := mkdirOwned(brokerEtc, "root", rootGroup, 0755); err != nil {
				return err
			}
			if _, err := os.Stat(installedPolicy); os.IsNotExist(err) {
				if err := os.WriteFile(installedPolicy, []byte("{\"items\":[],\"writes\":{}}\n"), 0644); err != nil {
					return err
				}
			}
			return run("chown", "root:"+rootGroup, installedPolicy)
		}},
		{"make " + filepath.Dir(brokerVar) + " traversable (parents must allow reaching the socket)",
			func() error { return ensureTraversable(filepath.Dir(brokerVar)) }},
		{"create " + brokerVar + " (0711 owned by " + brokerUser + ": traversable, not listable)", func() error {
			if err := mkdirOwned(brokerVar, brokerUser, brokerUser, 0711); err != nil {
				return err
			}
			if err := mkdirOwned(filepath.Join(brokerVar, "secrets"), brokerUser, brokerUser, 0700); err != nil {
				return err
			}
			return mkdirOwned(brokerRun, brokerUser, clientGroup, 0750)
		}},
		{"install the browser native-messaging host (root-owned, so an agent cannot repoint it)",
			func() error { return writeNativeMessagingHosts(nmHostDirsLinux) }},
		{"write " + unitPath, func() error { return writeUnit(vaultKV) }},
		{"(re)load the daemon", func() error {
			if err := run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			if err := run("systemctl", "enable", "--now", "secrets-broker.service"); err != nil {
				return err
			}
			return waitForSocket(socketPath, 15*time.Second)
		}},
	}, nil
}

// platformUninstallSteps reverses platformSteps on Linux. Best-effort: each
// step tolerates its target being absent.
func platformUninstallSteps(purge bool) []step {
	steps := []step{
		{"stop and remove the systemd unit", func() error {
			_ = run("systemctl", "disable", "--now", "secrets-broker.service") // ignore: may not be loaded
			if err := removeIfPresent(unitPath); err != nil {
				return err
			}
			return run("systemctl", "daemon-reload")
		}},
		{"remove the browser native-messaging hosts", func() error {
			for _, dir := range nmHostDirsLinux {
				if err := removeIfPresent(filepath.Join(dir, nmHostName+".json")); err != nil {
					return err
				}
			}
			return nil
		}},
		{"remove binaries in " + brokerLibexec, func() error { return os.RemoveAll(brokerLibexec) }},
		{"remove the socket directory " + brokerRun, func() error { return os.RemoveAll(brokerRun) }},
		{"remove the client group " + clientGroup, func() error { return run("groupdel", clientGroup) }},
		{"remove the service account " + brokerUser, func() error { return run("userdel", brokerUser) }},
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
	return fmt.Sprintf("after that, as a human at this machine:\n"+
		"  1. move the agent's vault into %s and chown it to %s\n"+
		"  2. sudo sb set-password <adapter> <vault-path>\n"+
		"  3. point the agent's MCP config at:\n"+
		"       %s/secrets-broker-mcp -connect %s\n"+
		"  4. sb doctor   (should report: mode isolated)\n"+
		"note: isolated-mode --approve is unavailable on Linux (no Secure Enclave);\n"+
		"      approval-gated refs fail closed. Use single-uid mode if you need approval.\n",
		brokerVar, brokerUser, brokerLibexec, socketPath)
}

// createUser makes a hidden system service account with no login shell.
// Idempotent. useradd --system also creates a same-named primary group.
func createUser(name string) error {
	if err := run("id", name); err == nil {
		fmt.Println("      (already exists)")
		return nil
	}
	nologin := "/usr/sbin/nologin"
	if _, err := os.Stat(nologin); err != nil {
		nologin = "/bin/false"
	}
	return run("useradd", "--system", "--no-create-home",
		"--home-dir", brokerVar, "--shell", nologin,
		"--comment", "secrets-broker service account", name)
}

func createGroup(name, member string) error {
	// groupadd -f is idempotent (no error if the group exists).
	if err := run("groupadd", "-f", name); err != nil {
		return err
	}
	return run("usermod", "-aG", name, member)
}

// writeUnit writes the systemd unit (body from unitBody, so the template is
// shared and unit-tested). vaultKV is one "KEY=value" line or "" (no vault).
func writeUnit(vaultKV string) error {
	if err := os.WriteFile(unitPath, []byte(unitBody(vaultKV)), 0644); err != nil {
		return err
	}
	return run("chown", "root:"+rootGroup, unitPath)
}
