// Package totp parses RFC 6238 time-based one-time-password seeds in the forms
// password managers store them, computes codes from them, and normalizes a
// seed into the otpauth:// URI KeePassXC keeps in an entry's "otp" field.
//
// The broker validates a seed with the same parser sb-cdpfill later uses to
// mint codes, so a seed is refused when it is stored rather than failing at a
// login weeks later. No error message ever contains the seed.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FieldName is the KeePassXC attribute that holds a TOTP seed.
const FieldName = "otp"

// IsField reports whether an entry field holds a TOTP seed the broker
// validates and normalizes on write.
func IsField(name string) bool { return strings.EqualFold(name, FieldName) }

// MinKeyBytes is the shortest seed accepted on write. RFC 4226 asks for 128
// bits, but many sites still issue 80-bit (16-character) seeds, so those pass;
// anything shorter is almost always a key that was cut off when copied.
const MinKeyBytes = 10

// Spec is a parsed TOTP configuration.
type Spec struct {
	Key    []byte
	Digits int
	Period int
	Algo   string // SHA1 | SHA256 | SHA512
}

// Parse accepts an otpauth://totp URI, a KeePass2 "key=..&step=..&size=.."
// string, or a bare base32 secret (spaces, dashes, padding and lowercase are
// tolerated). Parameters that are present but unusable are errors, not
// silently replaced by defaults: a code computed with the wrong digit count or
// encoder is wrong at every login.
func Parse(spec string) (Spec, error) {
	spec = strings.TrimSpace(spec)
	s := Spec{Digits: 6, Period: 30, Algo: "SHA1"}
	secret := spec
	var q url.Values
	lower := strings.ToLower(spec)
	switch {
	case strings.HasPrefix(lower, "otpauth-migration://"):
		return Spec{}, fmt.Errorf("this is a Google Authenticator export (otpauth-migration://), " +
			"which can hold several accounts; store one account's otpauth://totp URI or base32 key")
	case strings.HasPrefix(lower, "otpauth://"):
		u, err := url.Parse(spec)
		if err != nil {
			return Spec{}, fmt.Errorf("bad otpauth uri")
		}
		if strings.ToLower(u.Host) != "totp" {
			return Spec{}, fmt.Errorf("only totp is supported (got otpauth://%s)", u.Host)
		}
		q = u.Query()
	case strings.Contains(spec, "key="):
		v, err := url.ParseQuery(spec)
		if err != nil {
			return Spec{}, fmt.Errorf("bad keepass otp string")
		}
		q = url.Values{"secret": {v.Get("key")}, "period": {v.Get("step")}, "digits": {v.Get("size")}}
	}
	if q != nil {
		secret = q.Get("secret")
		if d := q.Get("digits"); d != "" {
			n, err := strconv.Atoi(d)
			if err != nil || n < 6 || n > 10 {
				return Spec{}, fmt.Errorf("unsupported digit count %q (6-10)", d)
			}
			s.Digits = n
		}
		if p := q.Get("period"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 {
				return Spec{}, fmt.Errorf("unsupported period %q", p)
			}
			s.Period = n
		}
		if a := strings.ToUpper(q.Get("algorithm")); a != "" {
			s.Algo = a
		}
		if e := q.Get("encoder"); e != "" {
			return Spec{}, fmt.Errorf("unsupported encoder %q (e.g. Steam Guard codes are not standard TOTP)", e)
		}
	}
	switch s.Algo {
	case "SHA1", "SHA256", "SHA512":
	default:
		return Spec{}, fmt.Errorf("unsupported totp algorithm %q", s.Algo)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(canonicalSecret(secret))
	if err != nil || len(key) == 0 {
		return Spec{}, fmt.Errorf("totp secret is not valid base32")
	}
	s.Key = key
	return s, nil
}

// canonicalSecret strips the separators people paste and uppercases base32.
func canonicalSecret(s string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
}

func (s Spec) hash() func() hash.Hash {
	switch s.Algo {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	}
	return sha1.New
}

// At is the pure RFC 6238 computation for instant t.
func (s Spec) At(t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/int64(s.Period)))
	m := hmac.New(s.hash(), s.Key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < s.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", s.Digits, bin%mod)
}

// At parses spec and computes its code for instant t.
func At(spec string, t time.Time) (string, error) {
	s, err := Parse(spec)
	if err != nil {
		return "", err
	}
	return s.At(t), nil
}

// Code computes the current code. It waits for the next period when fewer
// than 4 s remain, so the code is still valid when the form is submitted.
func Code(spec string, now func() time.Time, sleep func(time.Duration)) (string, error) {
	s, err := Parse(spec)
	if err != nil {
		return "", err
	}
	t := now()
	if left := s.Period - int(t.Unix()%int64(s.Period)); left < 4 {
		sleep(time.Duration(left)*time.Second + 300*time.Millisecond)
		t = now()
	}
	return s.At(t), nil
}

// Normalize validates spec as a seed to store and returns the value to write
// into the "otp" field: an otpauth:// URI or KeePass2 key= string is kept as
// given (its label, issuer and parameters are the site's); a bare base32 key
// becomes a KeePassXC-style otpauth URI labelled with the entry title, because
// KeePassXC does not read a bare key from "otp" and would show no code.
func Normalize(spec, label string) (string, error) {
	spec = strings.TrimSpace(spec)
	s, err := Parse(spec)
	if err != nil {
		return "", fmt.Errorf("not a usable TOTP key: %w", err)
	}
	if len(s.Key) < MinKeyBytes {
		return "", fmt.Errorf("TOTP key is only %d bits; at least %d expected — it was probably cut off when copied",
			len(s.Key)*8, MinKeyBytes*8)
	}
	lower := strings.ToLower(spec)
	if strings.HasPrefix(lower, "otpauth://") || strings.Contains(spec, "key=") {
		return spec, nil
	}
	if label = strings.TrimSpace(label); label == "" {
		label = "secrets-broker"
	}
	return "otpauth://totp/" + url.PathEscape(label) +
		"?secret=" + canonicalSecret(spec) +
		"&period=30&digits=6&issuer=" + url.QueryEscape(label), nil
}
