// Package bitwarden resolves sec://bw/<item>/<field> via the official bw CLI
// (subprocess; works against Bitwarden cloud or self-hosted Vaultwarden).
// The master password comes from unlock.BwPassword (env/keychain) and is used
// ONCE to obtain BW_SESSION; afterwards only the session key lives in memory.
package bitwarden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

// Adapter talks to `bw` over subprocesses.
type Adapter struct {
	Server     string // custom server URL ("" = bitwarden cloud); Vaultwarden etc.
	Email      string
	PasswordFn func() (string, error)
	BwBin      string // default "bw"
	CACert     string // optional CA cert path for self-hosted TLS (NODE_EXTRA_CA_CERTS)

	mu        sync.Mutex
	session   string
	unlockErr error
}

type bwItem struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Login struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
		Uris     []struct {
			Uri string `json:"uri"`
		} `json:"uris"`
	} `json:"login"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields"`
}

func (a *Adapter) bw() string {
	if a.BwBin != "" {
		return a.BwBin
	}
	return "bw"
}

func (a *Adapter) run(args ...string) (string, error) {
	cmd := exec.Command(a.bw(), args...)
	cmd.Env = os.Environ()
	if a.CACert != "" {
		cmd.Env = append(cmd.Env, "NODE_EXTRA_CA_CERTS="+a.CACert)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", fmt.Errorf("bw %s: %s", args[0], msg)
	}
	return out.String(), nil
}

func (a *Adapter) runSession(args ...string) (string, error) {
	if err := a.ensureSession(); err != nil {
		return "", err
	}
	full := append([]string{"--session", a.session}, args...)
	return a.run(full...)
}

func (a *Adapter) ensureSession() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session != "" {
		return nil
	}
	if a.unlockErr != nil {
		return a.unlockErr
	}
	pw, err := a.PasswordFn()
	if err != nil {
		a.unlockErr = err
		return err
	}
	if a.Server != "" {
		if _, err := a.run("config", "server", a.Server); err != nil {
			// bw refuses config while logged in — logout first, then retry
			if strings.Contains(err.Error(), "Logout required") {
				a.run("logout")
				if _, err := a.run("config", "server", a.Server); err != nil {
					a.unlockErr = err
					return err
				}
			} else {
				a.unlockErr = err
				return err
			}
		}
	}
	// ensure logged in (fresh appdata dir has no account); bw login --raw
	// prints a session key directly — use it and skip the separate unlock.
	if true {
		cmd := exec.Command(a.bw(), "login", a.Email, "--passwordenv", "BW_BROKER_PW", "--raw")
		cmd.Env = append(os.Environ(), "BW_BROKER_PW="+pw)
		if a.CACert != "" {
			cmd.Env = append(cmd.Env, "NODE_EXTRA_CA_CERTS="+a.CACert)
		}
		var lOut, lErr bytes.Buffer
		cmd.Stdout = &lOut
		cmd.Stderr = &lErr
		if err := cmd.Run(); err != nil && !strings.Contains(lErr.String(), "already logged in") {
			// fall through: maybe already logged in — try unlock below
			a.run("logout")
			cmd2 := exec.Command(a.bw(), "login", a.Email, "--passwordenv", "BW_BROKER_PW", "--raw")
			cmd2.Env = cmd.Env
			var o2, e2 bytes.Buffer
			cmd2.Stdout = &o2
			cmd2.Stderr = &e2
			if err2 := cmd2.Run(); err2 != nil {
				a.unlockErr = fmt.Errorf("bw login failed: %s", strings.TrimSpace(e2.String()))
				return a.unlockErr
			}
			lOut = o2
		}
		if sess := strings.TrimSpace(lOut.String()); sess != "" {
			a.session = sess
			return nil
		}
	}
	cmd := exec.Command(a.bw(), "unlock", "--passwordenv", "BW_BROKER_PW", "--raw")
	cmd.Env = append(os.Environ(), "BW_BROKER_PW="+pw)
	if a.CACert != "" {
		cmd.Env = append(cmd.Env, "NODE_EXTRA_CA_CERTS="+a.CACert)
	}
	var uOut, uErr bytes.Buffer
	cmd.Stdout = &uOut
	cmd.Stderr = &uErr
	if err := cmd.Run(); err != nil {
		a.unlockErr = fmt.Errorf("bw unlock failed: %v: %s", err, strings.TrimSpace(uErr.String()))
		return a.unlockErr
	}
	sess := strings.TrimSpace(uOut.String())
	if sess == "" {
		a.unlockErr = fmt.Errorf("bw unlock returned empty session")
		return a.unlockErr
	}
	a.session = sess
	return nil
}

// items returns the decrypted vault (synced first).
func (a *Adapter) items() ([]bwItem, error) {
	if _, err := a.runSession("sync"); err != nil {
		return nil, err
	}
	out, err := a.runSession("list", "items")
	if err != nil {
		return nil, err
	}
	var items []bwItem
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		return nil, fmt.Errorf("bw list: bad json: %v", err)
	}
	return items, nil
}

// Resolve implements the broker Resolver for sec://bw/<item>/<field>.
func (a *Adapter) Resolve(ref string) (string, error) {
	item, field, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	items, err := a.items()
	if err != nil {
		return "", err
	}
	for _, it := range items {
		if !strings.EqualFold(it.Name, item) {
			continue
		}
		switch strings.ToLower(field) {
		case "password":
			return it.Login.Password, nil
		case "username":
			return it.Login.Username, nil
		case "totp":
			return it.Login.TOTP, nil
		case "uri":
			if len(it.Login.Uris) > 0 {
				return it.Login.Uris[0].Uri, nil
			}
			return "", fmt.Errorf("bw: no uri on item %q", item)
		}
		for _, f := range it.Fields {
			if strings.EqualFold(f.Name, field) {
				return f.Value, nil
			}
		}
		return "", fmt.Errorf("bw: field %q not found in item %q", field, item)
	}
	return "", fmt.Errorf("bw: item %q not found", item)
}

// List returns item names (metadata only).
func (a *Adapter) List() ([]string, error) {
	items, err := a.items()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it.Name != "" {
			out = append(out, it.Name)
		}
	}
	return out, nil
}

// CreateEntry creates a login item via `bw create` (template | encode | create).
// groupPath is ignored (folders not modeled yet). Returns the ref.
// Write policy is enforced by the caller (MCP layer).
func (a *Adapter) CreateEntry(groupPath, title string, fields map[string]string) (string, error) {
	// Only these three are written below; anything else would be dropped
	// while the caller got a ref back as if it were stored.
	if err := policy.RefuseUnknownFields("bw", fields, "UserName", "Password", "URL"); err != nil {
		return "", err
	}
	if err := a.ensureSession(); err != nil {
		return "", err
	}
	login := map[string]any{"uris": []any{}}
	if u, ok := fields["UserName"]; ok {
		login["username"] = u
	}
	if p, ok := fields["Password"]; ok {
		login["password"] = p
	} else {
		return "", fmt.Errorf("bw adapter: Password field required")
	}
	if uri, ok := fields["URL"]; ok {
		login["uris"] = []any{map[string]any{"uri": uri}}
	}
	item := map[string]any{
		"type":  1,
		"name":  title,
		"login": login,
		"notes": nil,
	}
	b, _ := json.Marshal(item)
	// bw create takes base64-encoded JSON on stdin (bw encode format)
	enc := base64Std(string(b))
	out, err := a.runWithStdin(append([]string{"create", "item"}, "--session", a.session), enc)
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(out), &created)
	if created.ID == "" {
		// bw prints the item JSON on success
		return "sec://bw/" + title + "/password", nil
	}
	return "sec://bw/" + title + "/password", nil
}

func (a *Adapter) runWithStdin(args []string, stdin string) (string, error) {
	cmd := exec.Command(a.bw(), args...)
	cmd.Env = os.Environ()
	if a.CACert != "" {
		cmd.Env = append(cmd.Env, "NODE_EXTRA_CA_CERTS="+a.CACert)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", fmt.Errorf("bw %s: %s", args[0], msg)
	}
	return out.String(), nil
}

func base64Std(s string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// small local encoder to avoid importing encoding/base64 just for clarity
	var sb strings.Builder
	for i := 0; i < len(s); i += 3 {
		var b [3]byte
		n := copy(b[:], s[i:])
		sb.WriteByte(chars[b[0]>>2])
		sb.WriteByte(chars[(b[0]&0x03)<<4|b[1]>>4])
		if n > 1 {
			sb.WriteByte(chars[(b[1]&0x0f)<<2|b[2]>>6])
		} else {
			sb.WriteByte('=')
		}
		if n > 2 {
			sb.WriteByte(chars[b[2]&0x3f])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// parseRef splits sec://bw/<item>/<field>.
func parseRef(ref string) (item, field string, err error) {
	const prefix = "sec://bw/"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", fmt.Errorf("bw adapter: unsupported ref %q", ref)
	}
	rest := strings.TrimPrefix(ref, prefix)
	i := strings.LastIndex(rest, "/")
	if i <= 0 || i == len(rest)-1 {
		return "", "", fmt.Errorf("bw adapter: ref must be sec://bw/<item>/<field>, got %q", ref)
	}
	return rest[:i], rest[i+1:], nil
}

var _ = time.Now
