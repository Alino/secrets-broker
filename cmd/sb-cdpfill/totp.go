package main

import (
	"time"

	"github.com/vaultcore/secrets-broker/internal/totp"
)

// The TOTP parser lives in internal/totp so the broker validates a seed with
// the same code that later mints its codes here.

// totpCode computes the current TOTP code from an otpauth:// URI, a KeePass2
// "key=..&step=..&size=.." string, or a bare base32 secret. It waits for the next
// period when fewer than 4 s remain, so the code is still valid when submitted.
func totpCode(spec string, now func() time.Time) (string, error) {
	return totp.Code(spec, now, time.Sleep)
}

// totpAt is the pure RFC 6238 computation for instant t.
func totpAt(spec string, t time.Time) (string, error) {
	return totp.At(spec, t)
}
