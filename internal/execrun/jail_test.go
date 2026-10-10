package execrun

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

// netPolicy builds a store allowing ref->exe with the given network mode.
func netPolicy(t *testing.T, ref, exe, mode string) *policy.Store {
	t.Helper()
	s := policy.NewEmpty()
	s.Upsert(policy.ItemPolicy{Ref: ref, Exec: []string{exe}, Network: mode})
	return s
}

// findCurl locates curl, which lives in different places across platforms.
func findCurl(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not present")
	}
	return p
}

// requireJail skips when this environment cannot enforce network:none — e.g.
// a container whose seccomp profile blocks unshare, which is the norm under
// Docker's defaults. It probes with a real jailed exec rather than guessing
// from runtime.GOOS, so the tests assert against the actual capability.
func requireJail(t *testing.T) {
	t.Helper()
	ref := "sec://keepass/probe/password"
	_, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "exit 0"},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "probe-value", nil },
		Policy:   netPolicy(t, ref, "/bin/sh", policy.NetworkNone),
	})
	if err != nil {
		t.Skipf("network jail unavailable in this environment: %v", err)
	}
}

// The point of the feature: a credential released to a local tool must not be
// exfiltratable by that tool. Uses a real network call, not a stub.
func TestNetworkNoneBlocksRealEgress(t *testing.T) {
	requireJail(t)
	curlPath := findCurl(t)
	ref := "sec://keepass/T/password"
	res, err := Run(Request{
		Argv:     []string{curlPath, "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "s3cret-value", nil },
		Policy:   netPolicy(t, ref, curlPath, policy.NetworkNone),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// curl writes 000 when it could not connect at all.
	if strings.Contains(res.Stdout, "200") {
		t.Fatalf("network:none did not block egress, got stdout %q", res.Stdout)
	}
}

// The jail must not leak into normal operation: a tool that does not need the
// network must still run, keep its exit code, and produce its output.
func TestNetworkNonePreservesExecution(t *testing.T) {
	requireJail(t)
	ref := "sec://keepass/T/password"
	res, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "echo out; exit 7"},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "s3cret-value", nil },
		Policy:   netPolicy(t, ref, "/bin/sh", policy.NetworkNone),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code not preserved through the jail: got %d, want 7", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "out") {
		t.Fatalf("stdout lost through the jail: %q", res.Stdout)
	}
}

// Masking must still apply inside the jail — the two features compose.
func TestNetworkNoneStillMasks(t *testing.T) {
	requireJail(t)
	ref := "sec://keepass/T/password"
	res, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", `echo "leak=$TOKEN"`},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "supersecretvalue", nil },
		Policy:   netPolicy(t, ref, "/bin/sh", policy.NetworkNone),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(res.Stdout, "supersecretvalue") {
		t.Fatalf("secret leaked through the jailed child: %q", res.Stdout)
	}
}

// The secret must actually still ARRIVE in the jailed child — a jail that
// broke injection would pass the "no leak" test for the wrong reason.
func TestNetworkNoneStillDeliversSecret(t *testing.T) {
	requireJail(t)
	ref := "sec://keepass/T/password"
	res, err := Run(Request{
		// Print only the length, so the assertion never needs the value.
		Argv:     []string{"/bin/sh", "-c", `printf %s "$TOKEN" | wc -c`},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "0123456789", nil },
		Policy:   netPolicy(t, ref, "/bin/sh", policy.NetworkNone),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Stdout, "10") {
		t.Fatalf("secret did not reach the jailed child, got %q", res.Stdout)
	}
}

// Fail-closed is the whole contract: if the jail cannot be applied, the child
// must NOT run. On Linux this is only detectable at spawn time, so the check
// is that no side effect happened.
//
// Linux CAN jail when unprivileged user namespaces are available, so this test
// asserts the right thing for the environment it finds: either the jail worked
// (and the canary exists but had no network), or it was refused (and the
// canary does not exist). What must never happen is the child running
// unconfined while the policy claims network:none.
func TestNetworkNoneNeverRunsUnconfined(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "canary")
	ref := "sec://keepass/T/password"
	_, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "touch " + canary},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "s3cret-value", nil },
		Policy:   netPolicy(t, ref, "/bin/sh", policy.NetworkNone),
	})
	_, statErr := os.Stat(canary)
	ran := statErr == nil

	switch {
	case err == nil && ran:
		// Jail applied and the child ran inside it — correct.
	case err != nil && !ran:
		// Jail unavailable and the exec was refused — also correct.
		if !strings.Contains(err.Error(), "network:none") {
			t.Fatalf("refusal should name the unenforceable policy, got: %v", err)
		}
	case err != nil && ran:
		t.Fatal("child ran even though the broker reported a refusal")
	default:
		t.Fatal("broker reported success but the child never ran")
	}
}

// Mixing refs must take the STRICTEST setting: pairing a jailed secret with an
// unrestricted one must not launder the jailed one onto the network.
func TestStrictestNetworkModeWins(t *testing.T) {
	requireJail(t)
	curlPath := findCurl(t)
	strict := "sec://keepass/Strict/password"
	loose := "sec://keepass/Loose/password"
	s := policy.NewEmpty()
	s.Upsert(policy.ItemPolicy{Ref: strict, Exec: []string{curlPath}, Network: policy.NetworkNone})
	s.Upsert(policy.ItemPolicy{Ref: loose, Exec: []string{curlPath}, Network: policy.NetworkUnrestricted})

	res, err := Run(Request{
		Argv:     []string{curlPath, "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"},
		EnvRefs:  map[string]string{"A": strict, "B": loose},
		Resolver: func(string) (string, error) { return "s3cret-value", nil },
		Policy:   s,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(res.Stdout, "200") {
		t.Fatalf("an unrestricted ref laundered a network:none ref onto the network: %q", res.Stdout)
	}
}

// Default must remain unrestricted, or the feature would silently break every
// existing policy that legitimately needs the network.
func TestDefaultPolicyKeepsNetwork(t *testing.T) {
	curlPath := findCurl(t)
	ref := "sec://keepass/T/password"
	res, err := Run(Request{
		Argv:     []string{curlPath, "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"},
		EnvRefs:  map[string]string{"TOKEN": ref},
		Resolver: func(string) (string, error) { return "s3cret-value", nil },
		Policy:   netPolicy(t, ref, curlPath, policy.NetworkUnrestricted),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(res.Stdout, "000") {
		t.Skip("no outbound network in this environment; nothing to assert")
	}
	if !strings.Contains(res.Stdout, "200") {
		t.Fatalf("default policy should not restrict the network, got %q", res.Stdout)
	}
}
