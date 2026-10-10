package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// approveCmd authorizes ONE pending request by signing its nonce with the
// Secure Enclave approval key.
//
// The trust chain:
//   - What the human sees is the broker's own record of the request
//     (get_approval_request), not anything the caller claims.
//   - The signature is made by a Secure Enclave key that requires a fresh
//     biometric per use and cannot be exported, so it proves a human touch
//     bound to exactly this nonce.
//   - The daemon verifies the signature against the public key registered at
//     install. A signature for one request cannot approve another, and nothing
//     in this path runs as root.
func approveCmd(args []string) error {
	var nonce string
	for i, a := range args {
		switch {
		case a == "--request" && i+1 < len(args):
			nonce = args[i+1]
		case strings.HasPrefix(a, "--request="):
			nonce = strings.TrimPrefix(a, "--request=")
		}
	}
	if nonce == "" {
		return fmt.Errorf("usage: sb approve --request <nonce>\n" +
			"  the nonce comes from the APPROVAL REQUIRED error the broker returned")
	}
	seauth := brokerLibexec + "/sb-seauth"
	if _, err := os.Stat(seauth); err != nil {
		return fmt.Errorf("approval helper missing (%s) — run: sudo sb install", seauth)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("cannot reach the broker at %s: %w", socketPath, err)
	}
	defer conn.Close()
	rpc := &mcpConn{conn: conn, r: bufio.NewReader(conn)}
	if err := rpc.initialize(); err != nil {
		return err
	}

	// 1. what does the BROKER say this request is?
	info, err := rpc.call("get_approval_request", map[string]any{"nonce": nonce})
	if err != nil {
		return err
	}
	var desc struct{ Describe string }
	_ = json.Unmarshal([]byte(info), &desc)
	if desc.Describe == "" {
		return fmt.Errorf("broker did not recognise request %q: %s", nonce, strings.TrimSpace(info))
	}
	fmt.Fprintf(os.Stderr, "Request %s\n  %s\n\n", nonce, desc.Describe)

	// 2. sign the nonce — a fresh Touch ID showing that description
	// Pass the daemon's exact description: sb-seauth signs nonce+"\n"+describe,
	// and the daemon recomputes the same describe to verify. If they differ
	// (a misleading prompt), verification fails.
	cmd := exec.Command(seauth, "sign", nonce, desc.Describe)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("not approved")
	}
	sig := strings.TrimSpace(string(out))
	if sig == "" {
		return fmt.Errorf("no signature produced")
	}

	// 3. submit the signature; the daemon verifies it against the registered key
	res, err := rpc.call("submit_approval", map[string]any{"nonce": nonce, "signature": sig})
	if err != nil {
		return err
	}
	if !strings.Contains(res, `"approved":true`) {
		return fmt.Errorf("%s", strings.TrimSpace(res))
	}
	fmt.Printf("approved %s — the request may now run once\n", nonce)
	return nil
}

// mcpConn is the smallest JSON-RPC client that can call the approval tools.
type mcpConn struct {
	conn net.Conn
	r    *bufio.Reader
	id   int
}

func (m *mcpConn) send(method string, params any) error {
	m.id++
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.id, "method": method, "params": params})
	if err != nil {
		return err
	}
	_ = m.conn.SetDeadline(time.Now().Add(2 * time.Minute))
	_, err = m.conn.Write(append(b, '\n'))
	return err
}

func (m *mcpConn) recv() (map[string]any, error) {
	line, err := m.r.ReadBytes('\n')
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("broker closed the connection")
		}
		return nil, err
	}
	var res map[string]any
	return res, json.Unmarshal(line, &res)
}

func (m *mcpConn) initialize() error {
	if err := m.send("initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "sb approve", "version": "1"}}); err != nil {
		return err
	}
	if _, err := m.recv(); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	_, err := m.conn.Write(append(b, '\n'))
	return err
}

func (m *mcpConn) call(tool string, args map[string]any) (string, error) {
	if err := m.send("tools/call", map[string]any{"name": tool, "arguments": args}); err != nil {
		return "", err
	}
	res, err := m.recv()
	if err != nil {
		return "", err
	}
	result, _ := res["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return "", fmt.Errorf("empty response from %s", tool)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if isErr, _ := result["isError"].(bool); isErr {
		return "", fmt.Errorf("%s", text)
	}
	return text, nil
}
