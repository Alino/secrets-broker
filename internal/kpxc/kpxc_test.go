package kpxc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// fakeVault stands in for the adapters + policy: it only ever returns entries
// for an origin it was told about.
type fakeVault struct{ byOrigin map[string][]Entry }

func (f *fakeVault) Logins(url string, scope Scope) ([]Entry, error) {
	return f.byOrigin[url], nil
}
func (f *fakeVault) Identity() string { return "test-vault" }

// client is a minimal implementation of the browser side, so the test drives
// the real protocol rather than the server's own helpers.
type client struct {
	t          *testing.T
	s          *Server
	pub, priv  *[32]byte
	serverPub  *[32]byte
	clientID   string
	lastNonce  []byte
	associated string
	idKey      string
}

func newClient(t *testing.T, s *Server) *client {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, s: s, pub: pub, priv: priv,
		clientID: base64.StdEncoding.EncodeToString(randBytes(24)),
		idKey:    base64.StdEncoding.EncodeToString(idPub[:])}
	c.changeKeys()
	return c
}

func (c *client) changeKeys() {
	req, _ := json.Marshal(envelope{
		Action:    "change-public-keys",
		PublicKey: base64.StdEncoding.EncodeToString(c.pub[:]),
		Nonce:     base64.StdEncoding.EncodeToString(randBytes(24)),
		ClientID:  c.clientID,
	})
	raw, err := c.s.Handle(req)
	if err != nil {
		c.t.Fatal(err)
	}
	var res envelope
	if err := json.Unmarshal(raw, &res); err != nil {
		c.t.Fatal(err)
	}
	if res.Success != "true" {
		c.t.Fatalf("key exchange failed: %+v", res)
	}
	k, err := decodeKey(res.PublicKey)
	if err != nil {
		c.t.Fatal(err)
	}
	c.serverPub = k
}

// call sends one encrypted action and returns the decrypted response body.
func (c *client) call(action string, body map[string]any) (map[string]any, *envelope) {
	body["action"] = action
	plain, _ := json.Marshal(body)
	nonce := randBytes(24)
	var n [24]byte
	copy(n[:], nonce)
	ct := box.Seal(nil, plain, &n, c.serverPub, c.priv)
	req, _ := json.Marshal(envelope{
		Action:   action,
		Message:  base64.StdEncoding.EncodeToString(ct),
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
		ClientID: c.clientID,
	})
	c.lastNonce = nonce

	raw, err := c.s.Handle(req)
	if err != nil {
		c.t.Fatal(err)
	}
	var res envelope
	if err := json.Unmarshal(raw, &res); err != nil {
		c.t.Fatal(err)
	}
	if res.Message == "" {
		return nil, &res // error frame, unencrypted
	}
	ctIn, _ := base64.StdEncoding.DecodeString(res.Message)
	nIn, _ := base64.StdEncoding.DecodeString(res.Nonce)
	var n2 [24]byte
	copy(n2[:], nIn)
	out, ok := box.Open(nil, ctIn, &n2, c.serverPub, c.priv)
	if !ok {
		c.t.Fatal("could not decrypt response")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		c.t.Fatal(err)
	}
	return decoded, &res
}

func newServer(t *testing.T, v Vault) (*Server, *AssocStore) {
	t.Helper()
	assocs, err := LoadAssoc(filepath.Join(t.TempDir(), "assoc.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(v, assocs)
	if err != nil {
		t.Fatal(err)
	}
	return s, assocs
}

func TestHandshakeAndDatabaseHash(t *testing.T) {
	s, _ := newServer(t, &fakeVault{})
	c := newClient(t, s)
	body, _ := c.call("get-databasehash", map[string]any{})
	if body["success"] != "true" || body["hash"] == "" {
		t.Fatalf("unexpected hash response: %v", body)
	}
	// the reply nonce must be the request nonce + 1
	want := base64.StdEncoding.EncodeToString(incrementNonce(c.lastNonce))
	if body["nonce"] != want {
		t.Fatalf("nonce not incremented: got %v want %v", body["nonce"], want)
	}
}

// An association is a request, not a grant: until a human approves it, the
// browser gets nothing. The daemon has no GUI to prompt in, so auto-approving
// would let anything that reaches the socket enrol itself.
func TestAssociationRequiresHumanApproval(t *testing.T) {
	vault := &fakeVault{byOrigin: map[string][]Entry{
		"https://mail.proton.me": {{Login: "me@proton.me", Name: "Proton", Password: "pw"}},
	}}
	s, assocs := newServer(t, vault)
	c := newClient(t, s)

	body, _ := c.call("associate", map[string]any{"key": base64.StdEncoding.EncodeToString(c.pub[:]), "idKey": c.idKey})
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("no association id returned: %v", body)
	}
	c.associated = id

	if a, ok := assocs.Get(id); !ok || a.Approved {
		t.Fatal("a new association must start unapproved")
	}

	// unapproved: test-associate and get-logins both refuse
	if _, res := c.call("test-associate", map[string]any{"id": id, "key": c.idKey}); res.Success != "false" {
		t.Fatal("test-associate must fail while unapproved")
	}
	_, res := c.call("get-logins", map[string]any{
		"url":  "https://mail.proton.me",
		"keys": []map[string]string{{"id": id, "key": c.idKey}}})
	if res.Success != "false" || !strings.Contains(res.Error, "not approved") {
		t.Fatalf("unapproved association must not receive logins: %+v", res)
	}

	// after approval the same calls succeed
	if err := assocs.Approve(id, ScopeHuman); err != nil {
		t.Fatal(err)
	}
	if body, _ := c.call("test-associate", map[string]any{"id": id, "key": c.idKey}); body["success"] != "true" {
		t.Fatalf("test-associate should succeed once approved: %v", body)
	}
	body, _ = c.call("get-logins", map[string]any{
		"url":  "https://mail.proton.me",
		"keys": []map[string]string{{"id": id, "key": c.idKey}}})
	if body["count"].(float64) != 1 {
		t.Fatalf("expected one entry, got %v", body)
	}
}

// A browser that never associated, or that presents someone else's id with
// its own key, gets nothing.
func TestUnknownAndSpoofedAssociationsDenied(t *testing.T) {
	vault := &fakeVault{byOrigin: map[string][]Entry{"https://x.example": {{Login: "a", Password: "b"}}}}
	s, assocs := newServer(t, vault)
	c := newClient(t, s)

	if _, res := c.call("get-logins", map[string]any{"url": "https://x.example"}); res.Success != "false" {
		t.Fatal("get-logins without any association must fail")
	}

	body, _ := c.call("associate", map[string]any{"key": base64.StdEncoding.EncodeToString(c.pub[:]), "idKey": c.idKey})
	id := body["id"].(string)
	if err := assocs.Approve(id, ScopeHuman); err != nil {
		t.Fatal(err)
	}

	other, _, _ := box.GenerateKey(rand.Reader)
	_, res := c.call("get-logins", map[string]any{
		"url":  "https://x.example",
		"keys": []map[string]string{{"id": id, "key": base64.StdEncoding.EncodeToString(other[:])}}})
	if res.Success != "false" || !strings.Contains(res.Error, "wrong identity key") {
		t.Fatalf("an association id presented with the wrong key must be rejected: %+v", res)
	}
}

// Credentials are returned for the requested origin only — the same rule the
// exec allow-list applies, enforced for the browser.
func TestLoginsAreOriginScoped(t *testing.T) {
	vault := &fakeVault{byOrigin: map[string][]Entry{
		"https://mail.proton.me": {{Login: "me@proton.me", Password: "pw"}},
		"https://github.com":     {{Login: "octocat", Password: "gh"}},
	}}
	s, assocs := newServer(t, vault)
	c := newClient(t, s)
	body, _ := c.call("associate", map[string]any{"key": base64.StdEncoding.EncodeToString(c.pub[:]), "idKey": c.idKey})
	id := body["id"].(string)
	assocs.Approve(id, ScopeHuman)

	keys := []map[string]string{{"id": id, "key": c.idKey}}
	body, _ = c.call("get-logins", map[string]any{"url": "https://github.com", "keys": keys})
	entries := body["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["login"] != "octocat" {
		t.Fatalf("wrong entries for github: %v", body)
	}
	body, _ = c.call("get-logins", map[string]any{"url": "https://evil.example", "keys": keys})
	if body["count"].(float64) != 0 {
		t.Fatalf("an unbound origin must get nothing: %v", body)
	}
}

// Messages encrypted to a different key must not be accepted.
func TestForgedMessageRejected(t *testing.T) {
	s, _ := newServer(t, &fakeVault{})
	c := newClient(t, s)

	attackerPub, attackerPriv, _ := box.GenerateKey(rand.Reader)
	_ = attackerPub
	nonce := randBytes(24)
	var n [24]byte
	copy(n[:], nonce)
	ct := box.Seal(nil, []byte(`{"action":"get-databasehash"}`), &n, c.serverPub, attackerPriv)
	req, _ := json.Marshal(envelope{
		Action:   "get-databasehash",
		Message:  base64.StdEncoding.EncodeToString(ct),
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
		ClientID: c.clientID,
	})
	raw, err := s.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	var res envelope
	json.Unmarshal(raw, &res)
	if res.Success != "false" || !strings.Contains(res.Error, "decryption failed") {
		t.Fatalf("a message sealed with the wrong key must be rejected: %+v", res)
	}
}

// The extension correlates every reply by incrementedNonce(request.nonce) and
// verifyKeyResponse() compares it explicitly — including for the unencrypted
// key exchange. Echoing the request nonce breaks the handshake with
// "Corresponding request not found in the message buffer".
func TestChangePublicKeysIncrementsNonce(t *testing.T) {
	s, _ := newServer(t, &fakeVault{})
	pub, _, _ := box.GenerateKey(rand.Reader)
	nonce := randBytes(24)
	req, _ := json.Marshal(envelope{
		Action:    "change-public-keys",
		PublicKey: base64.StdEncoding.EncodeToString(pub[:]),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		ClientID:  base64.StdEncoding.EncodeToString(randBytes(24)),
	})
	raw, err := s.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	var res envelope
	json.Unmarshal(raw, &res)
	want := base64.StdEncoding.EncodeToString(incrementNonce(nonce))
	if res.Nonce != want {
		t.Fatalf("key exchange nonce not incremented: got %q want %q", res.Nonce, want)
	}
	if res.Success != "true" || res.PublicKey == "" {
		t.Fatalf("key exchange must report success and a public key: %+v", res)
	}
}
