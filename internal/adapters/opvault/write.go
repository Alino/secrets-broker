package opvaultadapter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/third_party/opvault"
)

// CreateEntry writes a login item into band_0.js (creating that band file if
// the vault does not have one — 1Password shards items across band_0..band_F
// and the reader scans them all, so a fresh band_0 is valid) and rewrites it
// atomically. groupPath is ignored (opvault has no groups). Returns the ref.
// Item format mirrors testdata/make_fixture.py (reader-verified).
func (a *Adapter) CreateEntry(groupPath, title string, fields map[string]string) (string, error) {
	// Only these three are written below; anything else would be dropped
	// while the caller got a ref back as if it were stored.
	if err := policy.RefuseUnknownFields("opvault", fields, "UserName", "Password", "URL"); err != nil {
		return "", err
	}
	if err := a.ensureUnlocked(); err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	mEnc, mMac, err := a.profile.ExportedMasterKeys()
	if err != nil {
		return "", fmt.Errorf("opvault write: %w", err)
	}
	oEnc, oMac, err := a.profile.ExportedOverviewKeys()
	if err != nil {
		return "", fmt.Errorf("opvault write: %w", err)
	}

	username := fields["UserName"]
	url := fields["URL"]
	var uuidBytes [16]byte
	if _, err := rand.Read(uuidBytes[:]); err != nil {
		return "", err
	}
	uuid := hexStr(uuidBytes[:])

	itemKeys := make([]byte, 64)
	if _, err := rand.Read(itemKeys); err != nil {
		return "", err
	}
	kBlob := aesCBCEncryptPad(itemKeys, mEnc)
	kMac := hmac.New(sha256.New, mMac)
	kMac.Write(kBlob)

	overview := map[string]any{"title": title, "ainfo": username, "url": url}
	detailFields := []map[string]any{}
	if username != "" {
		detailFields = append(detailFields, map[string]any{
			"name": "username", "value": username, "type": "T", "designation": "username"})
	}
	detailFields = append(detailFields, map[string]any{
		"name": "password", "value": fields["Password"], "type": "P", "designation": "password"})
	detail := map[string]any{"fields": detailFields, "notesPlain": ""}

	now := make([]byte, 8)
	binary.LittleEndian.PutUint64(now, uint64(time.Now().Unix()))
	hMAC := hmac.New(sha256.New, mMac)
	hMAC.Write([]byte(uuid))

	item := map[string]any{
		"uuid":     uuid,
		"category": "001",
		"created":  hexStr(now),
		"updated":  hexStr(now),
		"f":        nil,
		"h":        hexStr(hMAC.Sum(nil)),
		"trashed":  false,
		"o":        base64.StdEncoding.EncodeToString(opdata01Encrypt(mustJSON(overview), oEnc, oMac)),
		"k":        base64.StdEncoding.EncodeToString(append(kBlob, kMac.Sum(nil)...)),
		"d":        base64.StdEncoding.EncodeToString(opdata01Encrypt(mustJSON(detail), itemKeys[:32], itemKeys[32:])),
	}

	// Write into band_0.js, creating it if this vault has no band_0 (the reader
	// scans every band_*.js, so a new band_0 is picked up like any other).
	bandPath := filepath.Join(a.profile.Dir(), a.profile.ProfileDirName(), "band_0.js")
	bandMap := map[string]json.RawMessage{}
	if raw, err := os.ReadFile(bandPath); err == nil {
		if err := json.Unmarshal([]byte(trimBandWrapper(string(raw))), &bandMap); err != nil {
			return "", fmt.Errorf("opvault write: band_0.js parse: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	itemJSON, _ := json.Marshal(item)
	bandMap[uuid] = itemJSON
	newBody, err := json.Marshal(bandMap)
	if err != nil {
		return "", err
	}
	tmp := bandPath + ".sbtmp"
	content := append([]byte("ld("), newBody...)
	content = append(content, []byte(");")...)
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		return "", err
	}
	if err := verifyBandJSON(tmp); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("opvault write: verification failed (vault NOT modified): %w", err)
	}
	// Match the vault's existing sharing (group + mode) so a co-reader that
	// shares the group — e.g. 1Password running as the user on the same
	// synced .opvault — can read what we write. Without this the broker's
	// 0600 write is invisible to every other reader of the vault. If there is
	// no reference file, the write stays 0600 (broker-only vault).
	ref := bandPath
	if _, err := os.Stat(ref); err != nil {
		ref = filepath.Join(a.profile.Dir(), a.profile.ProfileDirName(), "profile.js")
	}
	if fi, err := os.Stat(ref); err == nil {
		_ = os.Chmod(tmp, fi.Mode().Perm())
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmp, -1, int(st.Gid)) // group only; keep our uid
		}
	}
	if err := os.Rename(tmp, bandPath); err != nil {
		os.Remove(tmp)
		return "", err
	}

	// reload the profile so the new item is resolvable immediately
	pw, err := a.PasswordFn()
	if err != nil {
		return "", err
	}
	v, err := opvault.Open(a.Dir)
	if err != nil {
		return "", err
	}
	profileName := a.Profile
	if profileName == "" {
		names, err := v.ProfileNames()
		if err != nil || len(names) == 0 {
			return "", fmt.Errorf("opvault write: no profiles: %v", err)
		}
		profileName = names[0]
	}
	p, err := v.Profile(profileName)
	if err != nil {
		return "", err
	}
	if err := p.Unlock(pw); err != nil {
		return "", err
	}
	a.profile = p
	return "sec://opvault/" + title + "/password", nil
}

func verifyBandJSON(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var band map[string]json.RawMessage
	return json.Unmarshal([]byte(trimBandWrapper(string(raw))), &band)
}

func trimBandWrapper(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "ld(")
	s = strings.TrimSuffix(s, ");")
	s = strings.TrimSuffix(s, ")")
	return strings.TrimSpace(s)
}

// opdata01Encrypt mirrors the fixture generator (and the reader's expectations):
// random front-pad, AES-CBC, HMAC-SHA256 over the whole body.
func opdata01Encrypt(plaintext, encKey, macKey []byte) []byte {
	iv := make([]byte, 16)
	rand.Read(iv)
	padLen := 16 - (len(plaintext) % 16)
	if padLen == 0 {
		padLen = 16
	}
	padded := make([]byte, padLen+len(plaintext))
	rand.Read(padded[:padLen])
	copy(padded[padLen:], plaintext)
	block, _ := aes.NewCipher(encKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	body := make([]byte, 0, 8+8+16+len(ct)+32)
	body = append(body, []byte("opdata01")...)
	var ln [8]byte
	binary.LittleEndian.PutUint64(ln[:], uint64(len(plaintext)))
	body = append(body, ln[:]...)
	body = append(body, iv...)
	body = append(body, ct...)
	h := hmac.New(sha256.New, macKey)
	h.Write(body)
	return append(body, h.Sum(nil)...)
}

// aesCBCEncryptPad: the reader takes the payload from the END of the
// decrypted buffer (keys[len-64:]), so the plaintext must sit at the END —
// random front-pad to a full block (same convention as opdata01).
func aesCBCEncryptPad(plaintext, key []byte) []byte {
	iv := make([]byte, 16)
	rand.Read(iv)
	padLen := 16 - (len(plaintext) % 16)
	if padLen == 0 {
		padLen = 16
	}
	padded := make([]byte, padLen+len(plaintext))
	rand.Read(padded[:padLen]) // random front-pad
	copy(padded[padLen:], plaintext)
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append(iv, ct...)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func hexStr(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexdigits[x>>4], hexdigits[x&0xf])
	}
	return string(out)
}
