package approve

import (
	"strings"
	"testing"
	"time"
)

func TestPendingBindsToTheExactRequest(t *testing.T) {
	s := NewPendingStore(time.Minute)
	p := s.Create([]string{"sec://v/Staging/pw"}, "/bin/echo", []string{"hi"})
	if err := s.MarkApproved(p.Nonce); err != nil {
		t.Fatal(err)
	}
	err := s.Consume(p.Nonce, []string{"sec://v/Prod/api-key"}, "/bin/echo", []string{"hi"})
	if err == nil || !strings.Contains(err.Error(), "different command") {
		t.Fatalf("an approval must not transfer to a different ref: %v", err)
	}
	if err := s.Consume(p.Nonce, []string{"sec://v/Staging/pw"}, "/bin/echo", []string{"hi"}); err == nil {
		t.Fatal("a mismatched attempt must burn the approval")
	}
}

func TestPendingRejectsChangedRequest(t *testing.T) {
	for _, c := range []struct {
		name string
		refs []string
		exec string
		argv []string
	}{
		{"different argv", []string{"r"}, "/usr/bin/gh", []string{"api", "/admin"}},
		{"extra argv", []string{"r"}, "/usr/bin/gh", []string{"api", "/user", "--jq", "."}},
		{"different exec", []string{"r"}, "/bin/sh", []string{"api", "/user"}},
		{"subset of refs", []string{"r"}, "/usr/bin/gh", []string{"api", "/user"}},
		{"superset of refs", []string{"r", "s", "t"}, "/usr/bin/gh", []string{"api", "/user"}},
	} {
		s := NewPendingStore(time.Minute)
		p := s.Create([]string{"r", "s"}, "/usr/bin/gh", []string{"api", "/user"})
		s.MarkApproved(p.Nonce)
		if err := s.Consume(p.Nonce, c.refs, c.exec, c.argv); err == nil {
			t.Errorf("%s: must not be covered by the approval", c.name)
		}
	}
}

func TestPendingIsOneShotAndOrderIndependent(t *testing.T) {
	s := NewPendingStore(time.Minute)
	p := s.Create([]string{"b", "a"}, "/usr/bin/gh", []string{"api"})
	s.MarkApproved(p.Nonce)
	if err := s.Consume(p.Nonce, []string{"a", "b"}, "/usr/bin/gh", []string{"api"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(p.Nonce, []string{"a", "b"}, "/usr/bin/gh", []string{"api"}); err == nil {
		t.Fatal("an approval must be usable exactly once")
	}
}

func TestPendingRequiresApproval(t *testing.T) {
	s := NewPendingStore(time.Minute)
	p := s.Create([]string{"r"}, "/usr/bin/gh", nil)
	if err := s.Consume(p.Nonce, []string{"r"}, "/usr/bin/gh", nil); err == nil {
		t.Fatal("an unapproved request must not be consumable")
	}
}

// Expired requests are swept and their rights removed.
func TestPendingExpiresAndNotifies(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewPendingStore(60 * time.Second)
	s.Now = func() time.Time { return now }
	var expired []string
	s.OnExpire = func(n string) { expired = append(expired, n) }
	p := s.Create([]string{"r"}, "/usr/bin/gh", nil)
	s.MarkApproved(p.Nonce)

	now = now.Add(61 * time.Second)
	if err := s.Consume(p.Nonce, []string{"r"}, "/usr/bin/gh", nil); err == nil {
		t.Fatal("an expired approval must not be usable")
	}
	if len(expired) != 1 || expired[0] != p.Nonce {
		t.Fatalf("expiry should report the nonce so its right is removed: %v", expired)
	}
}

func TestDescribeQuotesArgumentsAndNamesAllRefs(t *testing.T) {
	s := NewPendingStore(time.Minute)
	got := s.Create([]string{"sec://v/B/pw", "sec://v/A/pw"}, "/usr/bin/gh", []string{"api", "/user"}).Describe()
	if !strings.Contains(got, `/usr/bin/gh "api" "/user"`) || !strings.Contains(got, "sec://v/A/pw, sec://v/B/pw") {
		t.Fatalf("description should name the exact command and every ref: %q", got)
	}
	joined := s.Create([]string{"r"}, "/usr/bin/gh", []string{"api", "/user -H evil"}).Describe()
	split := s.Create([]string{"r"}, "/usr/bin/gh", []string{"api", "/user", "-H", "evil"}).Describe()
	if joined == split {
		t.Fatalf("different argv rendered identically: %q", joined)
	}
	hidden := s.Create([]string{"r"}, "/usr/bin/gh", []string{"api\n\n-H Authorization: x"}).Describe()
	if strings.Contains(hidden, "\n") {
		t.Fatalf("control characters must be escaped, got %q", hidden)
	}
}

func TestUnknownNonce(t *testing.T) {
	s := NewPendingStore(time.Minute)
	if err := s.MarkApproved("deadbeefdeadbeef"); err == nil {
		t.Fatal("unknown nonce must not be approvable")
	}
	if err := s.Consume("deadbeefdeadbeef", []string{"r"}, "/bin/echo", nil); err == nil {
		t.Fatal("unknown nonce must not be consumable")
	}
}
