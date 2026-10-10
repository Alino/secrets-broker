package main

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors (8 digits). Seeds are the RFC's public ASCII test keys
// "1234567890" repeated to 20/32/64 bytes, base32-encoded.
func TestTOTPRFC6238(t *testing.T) {
	const (
		s1   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		s256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
		s512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
	)
	cases := []struct {
		unix int64
		spec string
		want string
	}{
		{59, "otpauth://totp/x?secret=" + s1 + "&digits=8", "94287082"},
		{1111111109, "otpauth://totp/x?secret=" + s1 + "&digits=8", "07081804"},
		{1234567890, "otpauth://totp/x?secret=" + s1 + "&digits=8&algorithm=SHA1", "89005924"},
		{20000000000, "otpauth://totp/x?secret=" + s1 + "&digits=8", "65353130"},
		{59, "otpauth://totp/x?secret=" + s256 + "&digits=8&algorithm=SHA256", "46119246"},
		{1111111109, "otpauth://totp/x?secret=" + s256 + "&digits=8&algorithm=SHA256", "68084774"},
		{59, "otpauth://totp/x?secret=" + s512 + "&digits=8&algorithm=SHA512", "90693936"},
		{1111111109, "otpauth://totp/x?secret=" + s512 + "&digits=8&algorithm=SHA512", "25091201"},
		// KeePass2 "key=…&size=…" form, and a bare base32 secret (6 digits = last 6 of the 8-digit value)
		{1111111109, "key=" + s1 + "&step=30&size=8", "07081804"},
		{1111111109, s1, "081804"},
		{1111111109, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "081804"},
	}
	for _, c := range cases {
		got, err := totpAt(c.spec, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("t=%d %q: %v", c.unix, c.spec, err)
		}
		if got != c.want {
			t.Errorf("t=%d spec=%q got %s want %s", c.unix, c.spec, got, c.want)
		}
	}
}

// Near a rollover totpCode must wait and return the NEXT period's code.
func TestTOTPWaitsBeforeRollover(t *testing.T) {
	spec := "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	calls := 0
	now := func() time.Time {
		calls++
		if calls == 1 {
			return time.Unix(1111111109, 0) // 1 s left in the period
		}
		return time.Unix(1111111110, 0) // next period
	}
	got, err := totpCode(spec, now)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := totpAt(spec, time.Unix(1111111110, 0))
	if got != want || calls != 2 {
		t.Errorf("got %s (calls=%d), want next-period code %s", got, calls, want)
	}
}

func TestTOTPRejectsGarbage(t *testing.T) {
	for _, s := range []string{"otpauth://hotp/x?secret=GEZDGNBV", "not!base32", "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5"} {
		if _, err := totpAt(s, time.Unix(1000, 0)); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
