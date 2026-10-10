package kpxc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"golang.org/x/crypto/nacl/box"
)

// Version reported to the extension. It checks this for feature support; the
// extension refuses to talk to anything it considers too old.
const Version = "2.7.9"

// Entry is one credential as the extension expects it.
type Entry struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Password string `json:"password"`
	UUID     string `json:"uuid,omitempty"`
}

// Vault supplies credentials for an origin. The implementation applies the
// broker's policy: only refs bound to that origin, nothing else, ever.
type Vault interface {
	Logins(url string, scope Scope) ([]Entry, error)
	Identity() string // stable id for this vault, reported as the database hash
}

// Server handles one native-messaging connection. Each connection gets its own
// key pair: the transfer keys are per-session by design, and only the
// association's identity key persists.
type Server struct {
	Vault  Vault
	Assocs *AssocStore

	mu        sync.Mutex
	pub, priv *[32]byte
	clientPub *[32]byte
}

func NewServer(v Vault, a *AssocStore) (*Server, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Server{Vault: v, Assocs: a, pub: pub, priv: priv}, nil
}

// envelope is the outer, unencrypted frame.
type envelope struct {
	Action    string `json:"action"`
	Message   string `json:"message,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	ClientID  string `json:"clientID,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Version   string `json:"version,omitempty"`
	Success   string `json:"success,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
}

// Handle processes one request frame and returns one response frame.
func (s *Server) Handle(raw []byte) ([]byte, error) {
	var req envelope
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if req.Action == "change-public-keys" {
		return s.changePublicKeys(req)
	}

	inner, nonce, err := s.open(req)
	if err != nil {
		return errorFrame(req.Action, err)
	}

	var body struct {
		Action    string `json:"action"`
		Key       string `json:"key"`
		IDKey     string `json:"idKey"`
		ID        string `json:"id"`
		URL       string `json:"url"`
		SubmitURL string `json:"submitUrl"`
		HTTPAuth  string `json:"httpAuth"`
	}
	if err := json.Unmarshal(inner, &body); err != nil {
		return errorFrame(req.Action, err)
	}

	switch req.Action {
	case "get-databasehash":
		return s.sealed(req, nonce, map[string]any{
			"action": "hash", "hash": s.hash(), "version": Version, "success": "true"})

	case "associate":
		// The browser proposes an identity key; we record it as a PENDING
		// association. There is no GUI here to prompt in, so a human approves
		// it with `sb browser approve`. Anything that can reach the socket can
		// ask; nothing gets credentials by asking.
		id := hex.EncodeToString(randBytes(8))
		if _, err := s.Assocs.Add(id, body.IDKey, "associate from clientID "+req.ClientID); err != nil {
			return errorFrame(req.Action, err)
		}
		return s.sealed(req, nonce, map[string]any{
			"hash": s.hash(), "version": Version, "success": "true", "id": id})

	case "test-associate":
		if _, err := s.Assocs.Verify(body.ID, body.Key); err != nil {
			return errorFrame(req.Action, err)
		}
		return s.sealed(req, nonce, map[string]any{
			"hash": s.hash(), "version": Version, "success": "true", "id": body.ID})

	case "get-logins":
		assoc, err := s.identify(inner)
		if err != nil {
			return errorFrame(req.Action, err)
		}
		entries, err := s.Vault.Logins(body.URL, assoc.Scope)
		if err != nil {
			return errorFrame(req.Action, err)
		}
		return s.sealed(req, nonce, map[string]any{
			"count": len(entries), "entries": entries,
			"hash": s.hash(), "version": Version, "success": "true"})

	case "lock-database":
		return errorFrame(req.Action, fmt.Errorf("the broker does not lock on request"))
	}
	return errorFrame(req.Action, fmt.Errorf("unsupported action %q", req.Action))
}

// identify finds which approved association is making a get-logins request.
// The extension sends the keys it holds; an unapproved or unknown key gets
// nothing, so a browser that never associated cannot read credentials.
func (s *Server) identify(inner []byte) (*Assoc, error) {
	var body struct {
		Keys []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(inner, &body); err != nil {
		return nil, err
	}
	if len(body.Keys) == 0 {
		return nil, fmt.Errorf("no association presented — associate first")
	}
	var lastErr error
	for _, k := range body.Keys {
		a, err := s.Assocs.Verify(k.ID, k.Key)
		if err == nil {
			return a, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *Server) changePublicKeys(req envelope) ([]byte, error) {
	pub, err := decodeKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.clientPub = pub
	s.mu.Unlock()
	// The reply nonce must be the request nonce PLUS ONE, like every other
	// response: the extension correlates replies by incrementedNonce(request)
	// and verifyKeyResponse() compares it explicitly. Echoing the nonce
	// unchanged makes the handshake fail with "Corresponding request not
	// found in the message buffer" and then "Message encryption failed".
	reqNonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(reqNonce) != 24 {
		return nil, fmt.Errorf("bad nonce in change-public-keys")
	}
	return json.Marshal(envelope{
		Action:    "change-public-keys",
		Version:   Version,
		PublicKey: base64.StdEncoding.EncodeToString(s.pub[:]),
		Success:   "true",
		Nonce:     base64.StdEncoding.EncodeToString(incrementNonce(reqNonce)),
	})
}

// open decrypts a request's message field and returns it with the nonce used.
func (s *Server) open(req envelope) ([]byte, []byte, error) {
	s.mu.Lock()
	clientPub, priv := s.clientPub, s.priv
	s.mu.Unlock()
	if clientPub == nil {
		return nil, nil, fmt.Errorf("no public key exchanged yet")
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != 24 {
		return nil, nil, fmt.Errorf("bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		return nil, nil, fmt.Errorf("bad message")
	}
	var n [24]byte
	copy(n[:], nonce)
	out, ok := box.Open(nil, ct, &n, clientPub, priv)
	if !ok {
		return nil, nil, fmt.Errorf("decryption failed")
	}
	return out, nonce, nil
}

// sealed encrypts a response under the incremented nonce, as the protocol
// requires: the reply nonce is the request nonce plus one.
func (s *Server) sealed(req envelope, reqNonce []byte, body map[string]any) ([]byte, error) {
	resNonce := incrementNonce(reqNonce)
	body["nonce"] = base64.StdEncoding.EncodeToString(resNonce)
	plain, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var n [24]byte
	copy(n[:], resNonce)
	s.mu.Lock()
	clientPub, priv := s.clientPub, s.priv
	s.mu.Unlock()
	ct := box.Seal(nil, plain, &n, clientPub, priv)
	return json.Marshal(envelope{
		Action:   req.Action,
		Message:  base64.StdEncoding.EncodeToString(ct),
		Nonce:    base64.StdEncoding.EncodeToString(resNonce),
		ClientID: req.ClientID,
	})
}

func (s *Server) hash() string {
	sum := sha256.Sum256([]byte(s.Vault.Identity()))
	return hex.EncodeToString(sum[:])
}

// incrementNonce adds one to the 24-byte nonce, little-endian, as the
// extension expects when it validates a reply.
func incrementNonce(n []byte) []byte {
	out := make([]byte, len(n))
	copy(out, n)
	carry := 1
	for i := 0; i < len(out); i++ {
		v := int(out[i]) + carry
		out[i] = byte(v)
		carry = v >> 8
		if carry == 0 {
			break
		}
	}
	return out
}

func errorFrame(action string, err error) ([]byte, error) {
	// Errors travel unencrypted: the extension shows them, and there is
	// nothing secret in "you are not associated".
	return json.Marshal(envelope{Action: action, Error: err.Error(), ErrorCode: "1", Success: "false"})
}

func decodeKey(b64 string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("bad public key")
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the machine is not usable
	}
	return b
}
