package main

// End-to-end test of the assembled daemon: build the real binary, run it over a
// unix socket exactly as isolated mode does, and drive it with a real MCP
// client. This is the one test that exercises the whole pipeline the unit tests
// only cover in pieces — MCP handshake -> socket -> policy check -> vault
// resolve -> inject -> exec -> mask -> structured result. Every hand-found bug
// this project has hit (empty {} output, hung child, band_0) lived here.

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
)

const e2eMasterPW = "fixture-master-pw" // matches internal/adapters/keepass fixture

func TestEndToEnd(t *testing.T) {
	if _, err := os.Stat("/usr/bin/printenv"); err != nil {
		t.Skip("no /usr/bin/printenv")
	}
	dir := t.TempDir()

	// Writable copy of the keepass fixture (the daemon mutates it via save_secret).
	kdbx := filepath.Join(dir, "vault.kdbx")
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixture.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	fx, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("fixture kdbx not present: %v", err)
	}
	if err := os.WriteFile(kdbx, fx, 0600); err != nil {
		t.Fatal(err)
	}

	// Policy: allow creating keepass entries, and bind the secret we will create
	// to exactly `printenv E2E_TOK` — nothing else may receive it.
	const ref = "sec://keepass/E2E/Password"
	policy := map[string]any{
		"writes": map[string]any{"keepass": map[string]bool{"allow_create": true}},
		"items": []map[string]any{{
			"ref":  ref,
			"exec": []string{"/usr/bin/printenv"},
			"args": []string{"E2E_TOK"},
		}},
	}
	policyFile := filepath.Join(dir, "policy.json")
	pj, _ := json.MarshalIndent(policy, "", "  ")
	if err := os.WriteFile(policyFile, pj, 0644); err != nil {
		t.Fatal(err)
	}

	// Build and launch the real daemon over a unix socket.
	bin := filepath.Join(dir, "daemon")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}
	sock := filepath.Join(dir, "sb.sock")
	audit := filepath.Join(dir, "audit.jsonl")
	daemon := exec.Command(bin, "-socket", sock)
	daemon.Env = append(os.Environ(),
		"SB_KEEPASS_DB="+kdbx,
		"SB_KEEPASS_PASSWORD="+e2eMasterPW,
		"SB_POLICY_FILE="+policyFile,
		"SB_AUDIT_LOG="+audit,
		"SB_APPROVE_HELPER=", // no approval helper in this test
	)
	daemon.Stderr = os.Stderr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Process.Kill(); _, _ = daemon.Process.Wait() })
	waitSocket(t, sock)

	// Real MCP client over the socket.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	sess, err := client.Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		t.Fatalf("mcp connect (handshake): %v", err)
	}
	defer sess.Close()

	// 1. save_secret stores a value we know, so we can prove masking hides it.
	const plaintext = "SUPERSECRET-e2e-value-9f3a"
	call(t, ctx, sess, "save_secret", map[string]any{
		"adapter": "keepass", "title": "E2E", "value": plaintext,
	})

	// 2. list_secrets now reports the ref (structured output, not {}).
	lr := call(t, ctx, sess, "list_secrets", map[string]any{})
	if !strings.Contains(lr, ref) {
		t.Fatalf("list_secrets missing %q:\n%s", ref, lr)
	}

	// 3. exec_with_secret injects the value into `printenv E2E_TOK`; the child
	// prints it, and the broker must mask it before returning.
	er := call(t, ctx, sess, "exec_with_secret", map[string]any{
		"argv":     []string{"/usr/bin/printenv", "E2E_TOK"},
		"env_refs": map[string]string{"E2E_TOK": ref},
	})
	if strings.Contains(er, plaintext) {
		t.Fatalf("SECRET LEAKED in exec output:\n%s", er)
	}
	if !strings.Contains(er, "concealed") { // "<concealed>", JSON-escaped in text content
		t.Fatalf("expected masked marker in output:\n%s", er)
	}

	// 4. Policy denial: the same ref against a non-allow-listed argv is refused.
	dr := call(t, ctx, sess, "exec_with_secret", map[string]any{
		"argv":     []string{"/usr/bin/printenv", "OTHER"},
		"env_refs": map[string]string{"OTHER": ref},
	})
	if strings.Contains(dr, plaintext) {
		t.Fatalf("SECRET LEAKED past policy denial:\n%s", dr)
	}
	if !isErr(dr) && !strings.Contains(strings.ToLower(dr), "polic") && !strings.Contains(strings.ToLower(dr), "denied") {
		t.Fatalf("expected policy denial, got:\n%s", dr)
	}
}

// call invokes a tool and returns the text content, failing on transport error.
func call(t *testing.T, ctx context.Context, sess *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: transport error: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	out := b.String()
	if res.IsError {
		return "ERR:" + out
	}
	return out
}

func isErr(s string) bool { return strings.HasPrefix(s, "ERR:") }

func waitSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("daemon socket %s never appeared", path)
}
