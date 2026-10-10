package execrun

import (
	"testing"

	"github.com/vaultcore/secrets-broker/internal/policy"
)

func TestScrubEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"SB_KEEPASS_PASSWORD=supersecret",
		"SB_BW_PASSWORD=another",
		"BW_BROKER_PW=x",
		"BW_SESSION=y",
		"HOME=/root",
	}
	got := scrubEnv(env)
	want := []string{"PATH=/usr/bin", "HOME=/root"}
	if len(got) != len(want) {
		t.Fatalf("scrubEnv: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scrubEnv: got %v want %v", got, want)
		}
	}
}

func TestValidEnvName(t *testing.T) {
	for _, ok := range []string{"PW", "GITHUB_TOKEN", "_X", "A1"} {
		if !validEnvName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "lower", "with-dash", "with space", "PW=1", "LD_PRELOAD "} {
		if validEnvName(bad) {
			t.Errorf("%q should be INVALID", bad)
		}
	}
}

func TestEnvSecretsNotInherited(t *testing.T) {
	// integration: a policy-allowed child must NOT see SB_*_PASSWORD
	t.Setenv("SB_KEEPASS_PASSWORD", "env-leak-canary")
	store := policy.NewEmpty()
	store.Upsert(policy.ItemPolicy{Ref: "sec://keepass/X/password", Exec: []string{"/bin/sh"}})
	res, err := Run(Request{
		Argv:     []string{"/bin/sh", "-c", "if [ \"$SB_KEEPASS_PASSWORD\" != \"\" ]; then echo LEAKED; else echo CLEAN; fi"},
		Resolver: func(ref string) (string, error) { return "x", nil },
		Policy:   store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "CLEAN\n" {
		t.Fatalf("env leaked to child: %q", res.Stdout)
	}
}
