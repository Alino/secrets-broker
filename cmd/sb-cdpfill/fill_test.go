package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func jsonDecode(resp *http.Response, v any) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func TestArgsAndEnvValidation(t *testing.T) {
	ok := map[string]string{"FILL_USER": "u", "FILL_PASS": "p"}
	cases := []struct {
		name string
		argv []string
		env  map[string]string
		code int
	}{
		{"http origin", []string{"x", "http://a.example", "T", "#u", "#p"}, ok, 2},
		{"origin with path", []string{"x", "https://a.example/login", "T", "#u", "#p"}, ok, 2},
		{"too few args", []string{"x", "https://a.example", "T", "#u"}, ok, 2},
		{"too many args", []string{"x", "https://a.example", "T", "#u", "#p", "#s", "extra"}, ok, 2},
		{"bad port", []string{"x", "https://a.example", "--port=80", "T", "#u", "#p"}, ok, 2},
		{"no secret", []string{"x", "https://a.example", "T", "#u", "#p"}, map[string]string{"FILL_USER": "u"}, 2},
		{"user selector without user", []string{"x", "https://a.example", "T", "#u", "#p"}, map[string]string{"FILL_PASS": "p"}, 2},
		{"pass and totp", []string{"x", "https://a.example", "T", "-", "#p"}, map[string]string{"FILL_PASS": "p", "FILL_TOTP": "GEZDGNBV"}, 2},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.argv, env(c.env), &out, &errb); got != c.code {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, got, c.code, errb.String())
		}
	}
}

// --- real-browser tests -----------------------------------------------------

func findChrome() string {
	if p := os.Getenv("SB_TEST_CHROME"); p != "" {
		return p
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	mac := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if _, err := os.Stat(mac); err == nil {
		return mac
	}
	return ""
}

// startChrome launches a throwaway headless Chrome and returns its DevTools
// port. It skips (rather than fails) only when no Chrome is installed.
func startChrome(t *testing.T) int {
	t.Helper()
	bin := findChrome()
	if bin == "" {
		t.Skip("no Chrome found (set SB_TEST_CHROME)")
	}
	dir := t.TempDir()
	args := []string{"--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + dir,
		"--no-first-run", "--no-default-browser-check", "--ignore-certificate-errors", "--disable-gpu"}
	if runtime.GOOS == "darwin" {
		args = append(args, "--use-mock-keychain")
	}
	if runtime.GOOS == "linux" {
		args = append(args, "--no-sandbox") // CI runners restrict user namespaces
	}
	cmd := exec.Command(bin, append(args, "about:blank")...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start chrome: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f, err := os.Open(filepath.Join(dir, "DevToolsActivePort")); err == nil {
			sc := bufio.NewScanner(f)
			sc.Scan()
			f.Close()
			var port int
			if _, err := fmt.Sscanf(sc.Text(), "%d", &port); err == nil && port > 0 {
				return port
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("chrome did not report a DevTools port")
	return 0
}

// openPage opens url in a new tab and returns the target id once loaded.
func openPage(t *testing.T, port int, url string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://127.0.0.1:%d/json/new?%s", port, url), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tg target
	if err := jsonDecode(resp, &tg); err != nil {
		t.Fatal(err)
	}
	cl, err := connect(port, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.c.Close()
	for i := 0; i < 100; i++ {
		if v, _ := cl.eval(`document.readyState==='complete'&&!!document.querySelector('#done')`); v == true {
			return tg.ID
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("page did not load")
	return ""
}

func pageEval(t *testing.T, port int, id, expr string) any {
	t.Helper()
	cl, err := connect(port, id)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.c.Close()
	v, err := cl.eval(expr)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The login page renders a HIDDEN duplicate form first, as real sites do.
const loginPage = `<!doctype html><title>login</title>
<form id=hidden style="display:none"><input name=user><input name=pass type=password></form>
<form id=real onsubmit="event.preventDefault();document.title='submitted'">
<input name=user><input name=pass type=password><button type=submit>Sign in</button></form>
<div id=done></div>`

func TestFillsOnlyTheBoundOrigin(t *testing.T) {
	port := startChrome(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, loginPage)
	}))
	defer srv.Close()
	const user, pass = "agent@example.com", "s3cret-Fill-Value"
	secrets := env(map[string]string{"FILL_USER": user, "FILL_PASS": pass})
	portArg := fmt.Sprintf("--port=%d", port)

	// 1. bound origin matches: both fields filled, form submitted, values not printed
	id := openPage(t, port, srv.URL+"/login")
	var out, errb bytes.Buffer
	code := run([]string{"sb-cdpfill", srv.URL, portArg, id[:8], "input[name=user]", "input[name=pass]", "button[type=submit]"},
		secrets, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := fmt.Sprintf("filled user_len=%d pass_len=%d submitted=true", len(user), len(pass))
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	if strings.Contains(out.String()+errb.String(), pass) || strings.Contains(out.String()+errb.String(), user) {
		t.Fatal("a value leaked into the output")
	}
	if got := pageEval(t, port, id, `document.querySelector('#real [name=pass]').value`); got != pass {
		t.Fatalf("visible form not filled: %v", got)
	}
	if got := pageEval(t, port, id, `document.querySelector('#hidden [name=pass]').value`); got != "" {
		t.Fatal("hidden duplicate form was filled instead of the visible one")
	}
	if got := pageEval(t, port, id, `document.title`); got != "submitted" {
		t.Fatalf("form not submitted: %v", got)
	}

	// 2. bound origin differs: refused with exit 3, nothing typed
	id2 := openPage(t, port, srv.URL+"/login")
	out.Reset()
	errb.Reset()
	code = run([]string{"sb-cdpfill", "https://github.com", portArg, id2[:8], "input[name=user]", "input[name=pass]"},
		secrets, &out, &errb)
	if code != 3 {
		t.Fatalf("mismatched origin: exit %d, want 3 (%s)", code, errb.String())
	}
	if got := pageEval(t, port, id2, `document.querySelector('#real [name=pass]').value+document.querySelector('#real [name=user]').value`); got != "" {
		t.Fatal("refused fill still typed into the page")
	}
}
