// sb-cdpfill types a login from secrets-broker into ONE page of a Chrome the
// agent drives over the DevTools protocol (CDP on 127.0.0.1), but only while
// that page's origin equals argv[1] exactly. It is meant to be the pinned exec
// destination of
//
//	sb allow <ref> /path/to/sb-cdpfill -- https://<origin> ...
//
// so a credential bound to one origin can never be typed into another site.
// exec_with_secret cannot do this on its own: it delivers a secret into a
// child process's environment, and a form filled over CDP has no child process.
//
// usage: sb-cdpfill <origin> [--port=N] <target-id-prefix> <user-selector|-> <pass-selector> [submit-selector]
//
// env (injected by the broker, never on argv):
//
//	FILL_USER  username, typed into user-selector (omit with user-selector "-")
//	FILL_PASS  password, typed into pass-selector
//	FILL_TOTP  instead of FILL_PASS: an otpauth:// URI (KeePassXC "otp" field),
//	           a KeePass2 "key=…" string or a bare base32 seed. The CURRENT
//	           RFC 6238 code is computed here and typed; the seed never is.
//
// It prints only lengths and status, never values. Exit codes: 0 filled,
// 1 error, 2 usage, 3 refused (origin mismatch).
//
// What this is not: a boundary against the agent itself. An agent that drives
// the same Chrome can read a filled field back over its own CDP connection.
// sb-cdpfill keeps the value out of the transcript for an agent that cooperates,
// and pins WHERE the value may be typed; it cannot stop the browser's owner
// from looking.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	os.Exit(run(os.Args, os.Getenv, os.Stdout, os.Stderr))
}

// exitError carries the process exit code for a failure.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, a...)}
}

func run(argv []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if err := fill(argv, getenv, stdout); err != nil {
		fmt.Fprintln(stderr, "sb-cdpfill:", err)
		var e *exitError
		if errors.As(err, &e) {
			return e.code
		}
		return 1
	}
	return 0
}

type request struct {
	origin, prefix, userSel, passSel, submitSel string
	port                                        int
	user, pass                                  string
}

// parseRequest validates argv and env. --port=N may appear anywhere after the
// origin (the policy pins argv[1] and lets the rest vary with a trailing "...").
func parseRequest(argv []string, getenv func(string) string) (*request, error) {
	r := &request{port: 9222}
	var args []string
	for i, a := range argv {
		if i > 1 && strings.HasPrefix(a, "--port=") {
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--port="))
			if err != nil || n < 1024 || n > 65535 {
				return nil, fail(2, "bad --port")
			}
			r.port = n
			continue
		}
		args = append(args, a)
	}
	if len(args) < 5 || len(args) > 6 {
		return nil, fail(2, "usage: sb-cdpfill <origin> [--port=N] <target-id-prefix> <user-selector|-> <pass-selector> [submit-selector]")
	}
	r.origin, r.prefix, r.userSel, r.passSel = args[1], args[2], args[3], args[4]
	if len(args) == 6 {
		r.submitSel = args[5]
	}
	if !strings.HasPrefix(r.origin, "https://") || strings.Count(r.origin, "/") != 2 {
		return nil, fail(2, "origin must be https://host[:port] with no path")
	}
	if r.prefix == "" {
		return nil, fail(2, "empty target id prefix")
	}
	r.pass, r.user = getenv("FILL_PASS"), getenv("FILL_USER")
	if spec := getenv("FILL_TOTP"); spec != "" {
		if r.pass != "" {
			return nil, fail(2, "give FILL_PASS or FILL_TOTP, not both")
		}
		code, err := totpCode(spec, time.Now)
		if err != nil {
			return nil, fail(2, "totp: %v", err)
		}
		r.pass = code
	}
	if r.pass == "" {
		return nil, fail(2, "FILL_PASS or FILL_TOTP not provided")
	}
	if r.userSel != "-" && r.user == "" {
		return nil, fail(2, "FILL_USER not provided")
	}
	return r, nil
}

func fill(argv []string, getenv func(string) string, stdout io.Writer) error {
	r, err := parseRequest(argv, getenv)
	if err != nil {
		return err
	}
	cl, err := connect(r.port, r.prefix)
	if err != nil {
		return err
	}
	defer cl.c.Close()

	ul := 0
	if r.userSel != "-" {
		if ul, err = cl.typeInto(r.origin, r.userSel, r.user); err != nil {
			return err
		}
	}
	pl, err := cl.typeInto(r.origin, r.passSel, r.pass)
	if err != nil {
		return err
	}
	submitted := false
	if r.submitSel != "" {
		v, err := cl.eval(guard(r.origin, `const b=pick(`+q(r.submitSel)+`);if(!b)return 'missing';b.click();return 'ok'`))
		if err != nil {
			return err
		}
		if err := refusal(v, r.origin); err != nil {
			return err
		}
		submitted = v == "ok"
	}
	fmt.Fprintf(stdout, "filled user_len=%d pass_len=%d submitted=%v\n", ul, pl, submitted)
	return nil
}

type target struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	WSURL string `json:"webSocketDebuggerUrl"`
}

type client struct {
	c  *websocket.Conn
	id int
}

// connect attaches to the first page target whose id starts with prefix, on
// the local DevTools port only.
func connect(port int, prefix string) (*client, error) {
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	var ts []target
	err = json.NewDecoder(resp.Body).Decode(&ts)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	for _, t := range ts {
		if t.Type == "page" && strings.HasPrefix(t.ID, prefix) {
			d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
			conn, _, err := d.Dial(t.WSURL, nil)
			if err != nil {
				return nil, fmt.Errorf("connect: %w", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			return &client{c: conn}, nil
		}
	}
	return nil, fmt.Errorf("no page target with id prefix %q", prefix)
}

func (cl *client) call(method string, params map[string]any) (map[string]any, error) {
	cl.id++
	id := cl.id
	if err := cl.c.WriteJSON(map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		var msg map[string]any
		if err := cl.c.ReadJSON(&msg); err != nil {
			return nil, err
		}
		if v, ok := msg["id"].(float64); ok && int(v) == id {
			if e, ok := msg["error"]; ok {
				return nil, fmt.Errorf("%s: %v", method, e)
			}
			r, _ := msg["result"].(map[string]any)
			return r, nil
		}
	}
}

func (cl *client) eval(expr string) (any, error) {
	r, err := cl.call("Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true})
	if err != nil {
		return nil, err
	}
	if _, bad := r["exceptionDetails"]; bad {
		return nil, fmt.Errorf("page script exception")
	}
	res, _ := r["result"].(map[string]any)
	return res["value"], nil
}

// guard wraps body so it runs only while the page is on origin, in the SAME
// evaluation as the origin check. pick(sel) prefers a visible match: login
// pages often render a hidden duplicate form first, and the first
// querySelector match is then an element that cannot take focus.
func guard(origin, body string) string {
	return `(()=>{if(location.origin!==` + q(origin) + `)return 'origin:'+location.origin;` +
		`const pick=s=>{const all=[...document.querySelectorAll(s)];return all.find(e=>e.getClientRects().length>0)||all[0]||null};` +
		body + `})()`
}

func refusal(v any, origin string) error {
	if s, _ := v.(string); strings.HasPrefix(s, "origin:") {
		return fail(3, "REFUSED: page origin %q != bound origin %q", strings.TrimPrefix(s, "origin:"), origin)
	}
	return nil
}

// typeInto focuses sel on the bound origin, types val with Input.insertText
// (real input events, so frameworks see the change) and returns the field's
// resulting length. It re-checks the origin afterwards, so a page that
// navigated mid-fill is reported rather than silently accepted.
func (cl *client) typeInto(origin, sel, val string) (int, error) {
	v, err := cl.eval(guard(origin, `const e=pick(`+q(sel)+`);if(!e)return 'missing';e.focus();if(e.select)e.select();return document.activeElement===e?'ok':'nofocus'`))
	if err != nil {
		return 0, err
	}
	if err := refusal(v, origin); err != nil {
		return 0, err
	}
	if v != "ok" {
		return 0, fmt.Errorf("cannot focus %s (%v)", sel, v)
	}
	if _, err := cl.call("Input.insertText", map[string]any{"text": val}); err != nil {
		return 0, fmt.Errorf("insertText: %w", err)
	}
	n, err := cl.eval(guard(origin, `const e=document.activeElement;return e&&typeof e.value==='string'?e.value.length:0`))
	if err != nil {
		return 0, err
	}
	if err := refusal(n, origin); err != nil {
		return 0, fmt.Errorf("page left the bound origin while filling: %w", err)
	}
	f, _ := n.(float64)
	return int(f), nil
}

func q(s string) string { b, _ := json.Marshal(s); return string(b) }
