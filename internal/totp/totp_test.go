package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B seeds: the ASCII "1234567890" repeated to 20/32/64
// bytes, base32-encoded. Public test constants, not secrets.
const (
	s1   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	s256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	s512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
)

func TestRFC6238Vectors(t *testing.T) {
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
		{1111111109, "key=" + s1, "081804"}, // empty step/size = defaults
		{1111111109, s1, "081804"},
		{1111111109, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "081804"},
	}
	for _, c := range cases {
		got, err := At(c.spec, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("t=%d %q: %v", c.unix, c.spec, err)
		}
		if got != c.want {
			t.Errorf("t=%d spec=%q got %s want %s", c.unix, c.spec, got, c.want)
		}
	}
}

// Near a rollover Code must wait and return the NEXT period's code.
func TestCodeWaitsBeforeRollover(t *testing.T) {
	spec := "otpauth://totp/x?secret=" + s1
	now := time.Unix(1111111109, 0) // 1 s left in the period
	slept := time.Duration(0)
	got, err := Code(spec, func() time.Time { return now }, func(d time.Duration) { slept = d; now = now.Add(d) })
	if err != nil {
		t.Fatal(err)
	}
	want, _ := At(spec, time.Unix(1111111110, 0))
	if got != want || slept == 0 {
		t.Errorf("got %s (slept %v), want next-period code %s", got, slept, want)
	}
}

// Parameters that are present but unusable must fail, not fall back to
// defaults: a 5-digit Steam code computed as 6 standard digits is wrong at
// every login, and that failure would surface far from its cause.
func TestParseRejectsUnusable(t *testing.T) {
	bad := map[string]string{
		"hotp":             "otpauth://hotp/x?secret=" + s1,
		"not base32":       "not!base32",
		"md5":              "otpauth://totp/x?secret=" + s1 + "&algorithm=MD5",
		"5 digits":         "otpauth://totp/x?secret=" + s1 + "&digits=5",
		"digits garbage":   "otpauth://totp/x?secret=" + s1 + "&digits=six",
		"zero period":      "otpauth://totp/x?secret=" + s1 + "&period=0",
		"steam encoder":    "otpauth://totp/Steam?secret=" + s1 + "&digits=5&encoder=steam",
		"empty secret":     "otpauth://totp/x?issuer=x",
		"ga export":        "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SEGFsaWNlQGdvb2dsZS5jb20aBkdvb2dsZSABKAEwAhABGAEgAA",
		"keepass size bad": "key=" + s1 + "&size=4",
	}
	for name, spec := range bad {
		if _, err := Parse(spec); err == nil {
			t.Errorf("%s: expected an error for %q", name, spec)
		}
	}
}

func TestNormalize(t *testing.T) {
	// A bare key becomes a KeePassXC-style URI (KeePassXC reads no bare key
	// from "otp"), labelled with the entry title and canonicalised.
	got, err := Normalize(" gezd gnbv gy3t-qojq gezd gnbv gy3t qojq ", "My Site")
	if err != nil {
		t.Fatal(err)
	}
	want := "otpauth://totp/My%20Site?secret=" + s1 + "&period=30&digits=6&issuer=My+Site"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// ...and computes the same codes as the key it came from.
	a, _ := At(got, time.Unix(1111111109, 0))
	b, _ := At(s1, time.Unix(1111111109, 0))
	if a != b {
		t.Fatalf("normalized URI computes %s, the bare key %s", a, b)
	}

	// A site's own URI and the KeePass2 form are kept exactly: label, issuer
	// and parameters belong to the site.
	for _, keep := range []string{
		"otpauth://totp/GitHub:alex?secret=" + s1 + "&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
		"key=" + s1 + "&step=30&size=6",
	} {
		got, err := Normalize("  "+keep+"\n", "ignored")
		if err != nil || got != keep {
			t.Errorf("Normalize(%q) = %q, %v; want it unchanged", keep, got, err)
		}
	}

	// No title: still a valid URI.
	if got, err := Normalize(s1, ""); err != nil || !strings.HasPrefix(got, "otpauth://totp/secrets-broker?") {
		t.Errorf("empty label: %q %v", got, err)
	}
}

func TestNormalizeRefusesShortAndUnusable(t *testing.T) {
	const short = "GEZDGNBVGY3TQOJQ" // 80 bits: the shortest accepted
	if _, err := Normalize(short, "x"); err != nil {
		t.Fatalf("80-bit key refused: %v", err)
	}
	if _, err := Normalize(short[:14], "x"); err == nil || !strings.Contains(err.Error(), "cut off") {
		t.Fatalf("a 70-bit key must be refused as truncated, got %v", err)
	}
	if _, err := Normalize("otpauth://totp/x?secret="+s1+"&encoder=steam", "x"); err == nil {
		t.Fatal("steam encoder must be refused")
	}
}

// Errors explain what is wrong without repeating the key: the error text goes
// back to the agent.
func TestErrorsNeverContainTheKey(t *testing.T) {
	const key = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ"
	for _, spec := range []string{
		key[:10], // too short
		"otpauth://totp/x?secret=" + key + "&digits=5",  // bad digits
		"otpauth://totp/x?secret=" + key + "&encoder=s", // bad encoder
		"otpauth://hotp/x?secret=" + key,                // hotp
		key + "!",                                       // not base32
	} {
		_, err := Normalize(spec, "x")
		if err == nil {
			t.Fatalf("expected an error for case %q", spec[:6])
		}
		if strings.Contains(err.Error(), key[:10]) {
			t.Fatalf("error repeats the key: %v", err)
		}
	}
}
