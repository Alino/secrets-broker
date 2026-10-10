// Package masking implements streaming output masking for child processes
// that hold secrets.
//
// Guarantees:
//   - a registered secret value never appears verbatim in masked output
//   - any substring of a secret with length >= minPartial is also concealed
//     (partial-leak guard: a tool that prints half a token still leaks it)
//   - streaming-safe: secrets spanning Write boundaries are still masked
package masking

import (
	"bytes"
	"io"
	"strings"
	"sync"
)

const Placeholder = "<concealed>"

type Masker struct {
	mu         sync.Mutex
	secrets    []string
	minPartial int
}

func New(minPartial int) *Masker {
	if minPartial < 4 {
		minPartial = 4
	}
	return &Masker{minPartial: minPartial}
}

// Register adds a secret value to conceal. Values shorter than minPartial
// are still matched in full (exact value), but have no partial rule.
func (m *Masker) Register(secret string) {
	if secret == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.secrets {
		if s == secret {
			return
		}
	}
	m.secrets = append(m.secrets, secret)
}

// Writer returns an io.Writer that masks before forwarding to w.
// Call Flush (or Close) at end-of-stream to release the carry buffer.
func (m *Masker) Writer(w io.Writer) *Writer {
	return &Writer{m: m, w: w}
}

type Writer struct {
	m   *Masker
	w   io.Writer
	buf bytes.Buffer // pending input not yet decidable
}

func (mw *Writer) Write(p []byte) (int, error) {
	mw.m.mu.Lock()
	defer mw.m.mu.Unlock()
	mw.buf.Write(p)
	out, carry, err := mw.mask(mw.buf.Bytes(), false)
	if err != nil {
		return len(p), err
	}
	mw.buf.Reset()
	mw.buf.Write(carry)
	if len(out) > 0 {
		if _, err := mw.w.Write(out); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Flush emits the pending carry; at end-of-stream nothing can match anymore,
// so a carry that was an undecided short prefix passes through (possibly
// masked if it qualifies as a partial match on its own).
func (mw *Writer) Flush() error {
	mw.m.mu.Lock()
	defer mw.m.mu.Unlock()
	if mw.buf.Len() == 0 {
		return nil
	}
	out, _, err := mw.mask(mw.buf.Bytes(), true)
	mw.buf.Reset()
	if err != nil {
		return err
	}
	_, err = mw.w.Write(out)
	return err
}

// mask processes buf and returns (maskedOutput, carry, err).
// final=true means no more input arrives: undecided prefixes resolve now.
//
// Matching model: at each position we
// find the longest fragment that is a SUBSTRING of any registered secret.
// Fragments >= minPartial (or a full secret value) are concealed. A fragment
// that runs to the end of the buffer may grow on the next Write → carried.
func (mw *Writer) mask(buf []byte, final bool) ([]byte, []byte, error) {
	m := mw.m
	if len(m.secrets) == 0 {
		return buf, nil, nil
	}
	out := make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		l, isFull := longestFragmentAt(buf, i, m.secrets)
		switch {
		case isFull || l >= m.minPartial:
			out = append(out, Placeholder...)
			i += l
		case l > 0 && !final && i+l == len(buf):
			// undecided: fragment may extend to >= minPartial in next Write
			return out, buf[i:], nil
		default:
			out = append(out, buf[i])
			i++
		}
	}
	return out, nil, nil
}

// longestFragmentAt returns the length of the longest fragment starting at
// buf[i] that is a contiguous substring of some secret, and whether that
// fragment is an entire secret value.
func longestFragmentAt(buf []byte, i int, secrets []string) (int, bool) {
	best, bestFull := 0, false
	for _, s := range secrets {
		l := 0
		for i+l < len(buf) && l < len(s) && strings.Contains(s, string(buf[i:i+l+1])) {
			l++
		}
		full := l == len(s) && i+l <= len(buf) && string(buf[i:i+l]) == s
		if l > best || (l == best && full) {
			best, bestFull = l, full
		}
	}
	return best, bestFull
}
