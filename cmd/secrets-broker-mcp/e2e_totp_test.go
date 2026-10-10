package main

// End-to-end: storing a TOTP seed on an EXISTING login through the real
// daemon, with the write gates read from the policy file on every call.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	keepassadapter "github.com/vaultcore/secrets-broker/internal/adapters/keepass"
)

func TestEndToEndTOTPOnExistingLogin(t *testing.T) {
	if _, err := os.Stat("/usr/bin/printenv"); err != nil {
		t.Skip("no /usr/bin/printenv")
	}
	dir := t.TempDir()
	kdbx := filepath.Join(dir, "vault.kdbx")
	src, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "fixture.kdbx"))
	fx, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	if err := os.WriteFile(kdbx, fx, 0600); err != nil {
		t.Fatal(err)
	}

	const otpRef = "sec://keepass/GitHub/otp"
	policyFile := filepath.Join(dir, "policy.json")
	bump := 0
	setPolicy := func(writes map[string]bool) {
		t.Helper()
		pj, _ := json.MarshalIndent(map[string]any{
			"writes": map[string]any{"keepass": writes},
			"items": []map[string]any{{
				"ref": otpRef, "exec": []string{"/usr/bin/printenv"}, "args": []string{"E2E_OTP"},
			}},
		}, "", "  ")
		if err := os.WriteFile(policyFile, pj, 0644); err != nil {
			t.Fatal(err)
		}
		// The daemon reloads on a changed mtime; make each version distinct
		// even on a filesystem with coarse timestamps.
		bump++
		ts := time.Now().Add(time.Duration(bump) * time.Second)
		if err := os.Chtimes(policyFile, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(map[string]bool{"allow_create": true}) // create only, to start

	bin := filepath.Join(dir, "daemon")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}
	sock := filepath.Join(dir, "sb.sock")
	audit := filepath.Join(dir, "audit.jsonl")
	daemon := exec.Command(bin, "-socket", sock)
	daemon.Env = append(os.Environ(),
		"SB_KEEPASS_DB="+kdbx, "SB_KEEPASS_PASSWORD="+e2eMasterPW,
		"SB_POLICY_FILE="+policyFile, "SB_AUDIT_LOG="+audit, "SB_APPROVE_HELPER=",
	)
	daemon.Stderr = os.Stderr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Process.Kill(); _, _ = daemon.Process.Wait() })
	waitSocket(t, sock)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-totp", Version: "0"}, nil).
		Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	defer sess.Close()

	// The seed as a user pastes it: lowercase, grouped. RFC 6238 test key.
	const pasted = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
	const canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	const wantStored = "otpauth://totp/GitHub?secret=" + canonical + "&period=30&digits=6&issuer=GitHub"
	saveOTP := map[string]any{"title": "GitHub", "field": "otp", "value": pasted}
	vaultBytes := func() []byte { b, _ := os.ReadFile(kdbx); return b }

	// 1. create-only: adding to an existing entry is refused, vault untouched.
	orig := vaultBytes()
	r := call(t, ctx, sess, "save_secret", saveOTP)
	if !isErr(r) || !strings.Contains(r, "add-fields") {
		t.Fatalf("create-only must refuse adding to GitHub, naming add-fields:\n%s", r)
	}
	if string(vaultBytes()) != string(orig) {
		t.Fatal("refused write modified the vault")
	}

	// 2. Grant add-fields in the FILE — no restart — and the same call works.
	setPolicy(map[string]bool{"allow_create": true, "allow_add_fields": true})
	r = call(t, ctx, sess, "save_secret", saveOTP)
	if isErr(r) {
		t.Fatalf("add-fields write failed:\n%s", r)
	}
	var out struct {
		Ref, Field             string
		Created, ValueReturned bool
	}
	if err := json.Unmarshal([]byte(r), &out); err != nil {
		t.Fatalf("unparseable result %q: %v", r, err)
	}
	if out.Ref != otpRef || out.Field != "otp" || out.Created || out.ValueReturned {
		t.Fatalf("got %+v, want ref %s for field otp on an existing entry", out, otpRef)
	}
	for _, v := range []string{pasted, canonical} {
		if strings.Contains(r, v) {
			t.Fatal("save_secret response contains the seed")
		}
	}

	// 3. What landed: the KeePassXC-style URI, the login itself untouched.
	disk := &keepassadapter.Adapter{DBPath: kdbx, PasswordFn: func() (string, error) { return e2eMasterPW, nil }}
	if got, err := disk.Resolve(otpRef); err != nil || got != wantStored {
		t.Fatalf("stored otp = %q (%v), want %q", got, err, wantStored)
	}
	if got, _ := disk.Resolve("sec://keepass/GitHub/Password"); got != "kpxcSecretToken456" {
		t.Fatal("adding the seed changed the password")
	}

	// 4. The ref is spendable, and the value comes back masked.
	er := call(t, ctx, sess, "exec_with_secret", map[string]any{
		"argv": []string{"/usr/bin/printenv", "E2E_OTP"}, "env_refs": map[string]string{"E2E_OTP": otpRef},
	})
	if strings.Contains(er, canonical) || !strings.Contains(er, "concealed") {
		t.Fatalf("exec output not masked:\n%s", er)
	}

	// 5. add-fields never overwrites — and does not echo the attempted value.
	const attacker = "attacker-PW-e2e-77"
	r = call(t, ctx, sess, "save_secret", map[string]any{"title": "GitHub", "value": attacker})
	if !isErr(r) || !strings.Contains(r, "never overwrites") || strings.Contains(r, attacker) {
		t.Fatalf("overwrite must be refused without echoing the value:\n%s", r)
	}

	// 6. A seed that cannot produce codes is refused before anything is written.
	r = call(t, ctx, sess, "save_secret", map[string]any{"title": "Truncated", "field": "otp", "value": "GEZDGNBVGY3TQ"})
	if !isErr(r) || !strings.Contains(r, "cut off") || strings.Contains(r, "GEZDGNBVGY3TQ") {
		t.Fatalf("truncated seed must be refused without echoing it:\n%s", r)
	}
	if items, _ := disk.List(); strings.Contains(strings.Join(items, ","), "Truncated") {
		t.Fatal("refused seed still created an entry")
	}

	// 7. Revoke in the file; the next call is denied without a restart.
	setPolicy(map[string]bool{})
	r = call(t, ctx, sess, "save_secret", map[string]any{"title": "AfterRevoke", "value": "x"})
	if !isErr(r) || !strings.Contains(r, "DENIED") {
		t.Fatalf("revoked writes must be denied at once:\n%s", r)
	}

	// 8. The audit log never holds the seed.
	if a, err := os.ReadFile(audit); err == nil {
		for _, v := range []string{canonical, pasted, attacker} {
			if strings.Contains(string(a), v) {
				t.Fatal("audit log contains a secret value")
			}
		}
	}
}
