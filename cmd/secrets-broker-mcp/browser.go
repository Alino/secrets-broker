package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vaultcore/secrets-broker/internal/execrun"
	"github.com/vaultcore/secrets-broker/internal/kpxc"
	"github.com/vaultcore/secrets-broker/internal/policy"
)

// brokerVault answers KeePassXC-Browser get-logins requests out of the same
// policy the exec path uses: only refs the policy binds to that exact origin.
// The browser never learns what else the vault holds.
type brokerVault struct {
	store    *policy.Store
	resolver execrun.Resolver
	auditLog string
	vaultID  string
}

func (b *brokerVault) Identity() string { return b.vaultID }

func (b *brokerVault) Logins(rawURL string, scope kpxc.Scope) ([]kpxc.Entry, error) {
	reloadPolicy(b.store)
	refs := b.store.RefsForSite(rawURL)
	out := make([]kpxc.Entry, 0, len(refs))
	for _, ref := range refs {
		// A browser fill cannot be approved: there is no prompt in that path,
		// and releasing a gated credential without one would make `--approve`
		// a lie for exactly the refs that asked for it.
		if p, ok := b.store.Get(ref); ok && p.Approve {
			b.audit(ref, rawURL, scope, false, "requires human approval; browser fill cannot prompt")
			continue
		}
		// Scope is a privilege boundary, not a label: a browser an agent
		// drives only receives refs explicitly marked for agent use.
		if p, ok := b.store.Get(ref); ok && scope == kpxc.ScopeAgent && !p.AgentBrowser {
			b.audit(ref, rawURL, scope, false, "not marked for agent browsers (sb allow --agent-browser)")
			continue
		}
		password, err := b.resolver(ref)
		if err != nil {
			b.audit(ref, rawURL, scope, false, err.Error())
			continue
		}
		e := kpxc.Entry{Name: itemName(ref), Password: password}
		// The username lives beside the password in every adapter's ref
		// scheme; a missing one is not fatal, the extension just fills less.
		if login, err := b.resolver(siblingRef(ref, "username")); err == nil {
			e.Login = login
		}
		out = append(out, e)
		b.audit(ref, rawURL, scope, true, "")
	}
	return out, nil
}

// audit records browser fills in the same log as exec decisions: a credential
// released to a browser is a release, and must leave the same trail.
func (b *brokerVault) audit(ref, url string, scope kpxc.Scope, allowed bool, reason string) {
	if b.auditLog == "" {
		return
	}
	entry := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "ref": ref,
		"exec": "browser:" + url, "allowed": allowed, "scope": string(scope),
	}
	if reason != "" {
		entry["reason"] = reason
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(b.auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// siblingRef swaps the field of a ref: sec://a/Item/password -> sec://a/Item/username
func siblingRef(ref, field string) string {
	i := strings.LastIndex(ref, "/")
	if i < 0 {
		return ref
	}
	return ref[:i+1] + field
}

// itemName is the item segment of a ref, used as the entry title the browser
// shows in its picker.
func itemName(ref string) string {
	parts := strings.Split(strings.TrimPrefix(ref, "sec://"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ref
}

// serveBrowserSocket speaks the KeePassXC-Browser protocol over a unix socket.
// The native-messaging proxy (sb-browser-proxy, launched by Chrome) forwards
// the extension's frames here; the same length-prefixed framing is used on
// both hops so the proxy stays a pipe with no parsing of its own.
func serveBrowserSocket(ln net.Listener, v kpxc.Vault, assocs *kpxc.AssocStore) error {
	defer ln.Close()
	log.Printf("secrets-broker: browser protocol on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			// One key pair per connection: transfer keys are per-session and
			// only the association's identity key persists.
			srv, err := kpxc.NewServer(v, assocs)
			if err != nil {
				log.Printf("browser session: %v", err)
				return
			}
			for {
				msg, err := readFrame(conn)
				if err != nil {
					return
				}
				res, err := srv.Handle(msg)
				if err != nil {
					log.Printf("browser session: %v", err)
					return
				}
				if err := writeFrame(conn, res); err != nil {
					return
				}
			}
		}()
	}
}

// listenRestricted creates a unix socket that is never more permissive than
// 0660, not even briefly. umask is process-global, so both listeners are
// created from one goroutine before any accept loop starts — two concurrent
// umask save/restore pairs can interleave and leave a socket world-connectable
// in the window before Chmod.
func listenRestricted(path string) (net.Listener, error) {
	if len(path) > 103 {
		return nil, fmt.Errorf("socket path is %d bytes, max 103: %s", len(path), path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	old := umask(0177)
	ln, err := net.Listen("unix", path)
	umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// readFrame/writeFrame implement Chrome's native messaging framing: a
// native-endian uint32 length followed by that many bytes of JSON.
func readFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n > 64*1024*1024 {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, body []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(body))); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}
