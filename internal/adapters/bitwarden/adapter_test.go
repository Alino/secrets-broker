package bitwarden

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLiveVaultwarden runs against the local Vaultwarden fixture (docker
// network sbnet, container vw) if available; skips otherwise.
// Preconditions set up by testdata scripts:
//   - Vaultwarden on https://vw:80 (inside docker network) with cert /tmp/vw-certs/cert.pem
//   - account agent11@xenask.dev / VWfixture-master-1
//   - item FromCLI with password cliSecretPW1
func TestLiveVaultwarden(t *testing.T) {
	if _, err := exec.LookPath("bw"); err != nil {
		t.Skip("bw CLI not installed")
	}
	if _, err := os.Stat("/certs/cert.pem"); err != nil {
		t.Skip("vw cert not mounted at /certs/cert.pem")
	}
	a := &Adapter{
		Server:     "https://vw:80",
		Email:      "agent11@xenask.dev",
		CACert:     "/certs/cert.pem",
		PasswordFn: func() (string, error) { return "VWfixture-master-1", nil },
	}
	got, err := a.Resolve("sec://bw/FromCLI/password")
	if err != nil {
		t.Fatal(err)
	}
	if got != "cliSecretPW1" {
		t.Fatalf("wrong secret: %q", got)
	}
	user, err := a.Resolve("sec://bw/FromCLI/username")
	if err != nil || user != "cli@x.dev" {
		t.Fatalf("username: %q %v", user, err)
	}
}

func TestCreateEntryLive(t *testing.T) {
	if _, err := exec.LookPath("bw"); err != nil {
		t.Skip("bw CLI not installed")
	}
	if _, err := os.Stat("/certs/cert.pem"); err != nil {
		t.Skip("vw cert not mounted")
	}
	a := &Adapter{
		Server:     "https://vw:80",
		Email:      "agent11@xenask.dev",
		CACert:     "/certs/cert.pem",
		PasswordFn: func() (string, error) { return "VWfixture-master-1", nil },
	}
	ref, err := a.CreateEntry("", "NewSaaS", map[string]string{
		"UserName": "agent@xenask.dev",
		"Password": "bwGeneratedSecret1",
		"URL":      "https://newsaas.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, "sec://bw/NewSaaS/") {
		t.Fatalf("bad ref %q", ref)
	}
	// round-trip: resolve it back
	got, err := a.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != "bwGeneratedSecret1" {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestParseRef(t *testing.T) {
	if _, _, err := parseRef("sec://keepass/x/y"); err == nil {
		t.Fatal("wrong prefix must fail")
	}
	i, f, err := parseRef("sec://bw/GitHub/password")
	if err != nil || i != "GitHub" || f != "password" {
		t.Fatalf("parse: %q %q %v", i, f, err)
	}
}
