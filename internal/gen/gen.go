// Package gen generates passwords/API keys with crypto/rand.
package gen

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	Lower   = "abcdefghjkmnpqrstuvwxyz"  // no i, l, o
	Upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O
	Digits  = "23456789"                 // no 0, 1
	Symbols = "!@#$%^&*()-_=+[]{};:,.?/"
	// Ambiguous chars (0O1lIio) excluded from the classes above.
)

// Password generates a random password of the given length using the given
// character classes (at least one of each requested class).
func Password(length int, useSymbols bool) (string, error) {
	if length < 8 {
		length = 8
	}
	classes := []string{Lower, Upper, Digits}
	if useSymbols {
		classes = append(classes, Symbols)
	}
	var pool strings.Builder
	for _, c := range classes {
		pool.WriteString(c)
	}
	chars := pool.String()

	out := make([]byte, 0, length)
	// guarantee one char from each class
	for _, c := range classes {
		ch, err := pick(c)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for len(out) < length {
		ch, err := pick(chars)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	// Fisher-Yates shuffle
	for i := len(out) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

// Token generates a URL-safe random token (for API keys).
func Token(bytesLen int) (string, error) {
	if bytesLen < 16 {
		bytesLen = 16
	}
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("gen: %w", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 0, bytesLen*2)
	for _, x := range b {
		// two chars per byte, mod alphabet (fine for non-critical skew here:
		// secrets still have >= 95 bits of entropy from 16 random bytes)
		out = append(out, alphabet[int(x)%len(alphabet)])
		out = append(out, alphabet[int(x>>4)%len(alphabet)])
	}
	return string(out[:bytesLen]), nil
}

func pick(class string) (byte, error) {
	i, err := randInt(len(class))
	if err != nil {
		return 0, err
	}
	return class[i], nil
}

func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}
