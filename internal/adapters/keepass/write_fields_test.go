package keepass

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	keepasslib "github.com/tobischo/gokeepasslib/v3"

	"github.com/vaultcore/secrets-broker/internal/policy"
	"github.com/vaultcore/secrets-broker/internal/totp"
)

// testSeed is the RFC 6238 test key as KeePassXC stores it. Public constant.
const testSeed = "otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6&issuer=GitHub"

// fixturePassword is testdata/fixture.kdbx's GitHub password (public test constant).
const fixturePassword = "kpxcSecretToken456"

var addFields = policy.WriteMode{AddFields: true}

func newFixtureAdapter(t *testing.T) (*Adapter, string) {
	t.Helper()
	db := copyFixture(t)
	return &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}, db
}

// fresh re-reads the vault from disk with a new adapter, so assertions see
// what was written, not what one instance holds in memory.
func fresh(t *testing.T, db string) *Adapter {
	t.Helper()
	return &Adapter{DBPath: db, PasswordFn: func() (string, error) { return kdbxPassword, nil }}
}

func entryOnDisk(t *testing.T, db, path string) *keepasslib.Entry {
	t.Helper()
	d, err := fresh(t, db).current()
	if err != nil {
		t.Fatal(err)
	}
	e := findEntry(d.Content.Root.Groups, path)
	if e == nil {
		t.Fatalf("entry %q not on disk", path)
	}
	return e
}

func mustResolve(t *testing.T, db, ref string) string {
	t.Helper()
	v, err := fresh(t, db).Resolve(ref)
	if err != nil {
		t.Fatalf("resolve %s: %v", ref, err)
	}
	return v
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func historyLen(e *keepasslib.Entry) int {
	n := 0
	for _, h := range e.Histories {
		n += len(h.Entries)
	}
	return n
}

// The motivating case: an existing login gets its TOTP seed, with only the
// add-fields grant. The ref names the field written, the seed is protected,
// nothing else in the entry changes, and the old version is in its history.
func TestAddFieldsAddsTOTPToExistingLogin(t *testing.T) {
	a, db := newFixtureAdapter(t)
	before := entryOnDisk(t, db, "GitHub")
	created := before.Times.CreationTime.Time
	user := before.GetContent("UserName")
	histBefore := historyLen(before)

	res, err := a.WriteEntry("", "GitHub", map[string]string{"otp": testSeed}, "otp", addFields)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "sec://keepass/GitHub/otp" || res.Created {
		t.Fatalf("got %+v, want ref sec://keepass/GitHub/otp and Created=false", res)
	}
	if got := mustResolve(t, db, res.Ref); got != testSeed {
		t.Fatalf("otp round-trip mismatch")
	}
	if got := mustResolve(t, db, "sec://keepass/GitHub/Password"); got != fixturePassword {
		t.Fatalf("adding a field changed the password")
	}

	e := entryOnDisk(t, db, "GitHub")
	if e.GetContent("UserName") != user {
		t.Fatalf("adding a field changed the username")
	}
	if !e.Times.CreationTime.Time.Equal(created) {
		t.Fatalf("creation time reset: %v -> %v", created, e.Times.CreationTime.Time)
	}
	i := valueIndex(e, "otp")
	if i < 0 || !e.Values[i].Value.Protected.Bool {
		t.Fatalf("otp missing or not protected")
	}
	if historyLen(e) != histBefore+1 {
		t.Fatalf("history items %d -> %d, want +1", histBefore, historyLen(e))
	}
	last := e.Histories[len(e.Histories)-1].Entries
	snap := last[len(last)-1]
	if snap.UUID != e.UUID || valueIndex(&snap, "otp") >= 0 || snap.GetContent("Password") != fixturePassword {
		t.Fatalf("history item is not the pre-change entry (same UUID, no otp, old password)")
	}
	if items, _ := fresh(t, db).List(); len(items) != 1 {
		t.Fatalf("expected the one GitHub entry, got %v", items)
	}
}

// add-fields must never overwrite: that is the credential-substitution hole
// the update gate exists for. A refused write leaves the vault byte-identical,
// even when other fields in the same call would have been allowed, and the
// error names fields, never the value.
func TestAddFieldsNeverOverwrites(t *testing.T) {
	a, db := newFixtureAdapter(t)
	orig := readFile(t, db)
	const attacker = "attacker-chosen-PW-4711"
	for _, fields := range []map[string]string{
		{"Password": attacker},
		{"otp": testSeed, "password": attacker}, // mixed, and a different case
	} {
		_, err := a.WriteEntry("", "GitHub", fields, "otp", addFields)
		if err == nil || !strings.Contains(err.Error(), "never overwrites") {
			t.Fatalf("expected a no-overwrite refusal, got %v", err)
		}
		if strings.Contains(err.Error(), attacker) {
			t.Fatalf("error leaks the value: %v", err)
		}
		if !bytes.Equal(readFile(t, db), orig) {
			t.Fatal("a refused write modified the vault")
		}
	}
	if got := mustResolve(t, db, "sec://keepass/GitHub/Password"); got != fixturePassword {
		t.Fatal("password changed")
	}
}

// KeePassXC writes every entry with empty URL/Notes; an empty field counts as
// missing, so add-fields may fill it.
func TestAddFieldsFillsEmptyField(t *testing.T) {
	a, db := newFixtureAdapter(t)
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"Notes": "recovery: see paper"}, "Notes", addFields); err != nil {
		t.Fatal(err)
	}
	if got := mustResolve(t, db, "sec://keepass/GitHub/Notes"); got != "recovery: see paper" {
		t.Fatalf("Notes = %q", got)
	}
	if n := strings.Count(strings.ToLower(keysOf(entryOnDisk(t, db, "GitHub"))), "|notes|"); n != 1 {
		t.Fatalf("expected one Notes field, got %d", n)
	}
}

// ...except the fields that decide where a login is offered. The fixture's
// GitHub URL is empty; filling it with a phishing origin would make the user's
// own KeePassXC-Browser offer the GitHub password there. Needs update.
func TestAddFieldsCannotRouteAutofill(t *testing.T) {
	for _, k := range []string{"URL", "url", "KP2A_URL", "KP2A_URL_1", "KPH: browser"} {
		a, db := newFixtureAdapter(t)
		orig := readFile(t, db)
		_, err := a.WriteEntry("", "GitHub", map[string]string{k: "https://evil.example"}, k, addFields)
		if err == nil || !strings.Contains(err.Error(), "which sites") || strings.Contains(err.Error(), "evil.example") {
			t.Fatalf("%s: want a refusal naming the field, not the value; got %v", k, err)
		}
		if !bytes.Equal(readFile(t, db), orig) {
			t.Fatalf("%s: refused write modified the vault", k)
		}
	}
	// With update it is an ordinary (deliberate) change.
	a, db := newFixtureAdapter(t)
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"URL": "https://github.com"}, "URL",
		policy.WriteMode{AddFields: true, Update: true}); err != nil {
		t.Fatal(err)
	}
	if got := mustResolve(t, db, "sec://keepass/GitHub/URL"); got != "https://github.com" {
		t.Fatalf("URL = %q", got)
	}
	// And a NEW entry may carry a URL under create alone: it holds only what
	// the agent itself put there.
	if _, err := a.WriteEntry("", "Fresh", map[string]string{"Password": "p", "URL": "https://fresh.example"}, "Password",
		policy.WriteMode{Create: true}); err != nil {
		t.Fatal(err)
	}
}

func keysOf(e *keepasslib.Entry) string {
	var b strings.Builder
	b.WriteString("|")
	for _, v := range e.Values {
		b.WriteString(v.Key + "|")
	}
	return b.String()
}

// Each grant covers exactly its case; with the wrong one, nothing is written.
func TestWriteModesAreSeparate(t *testing.T) {
	cases := []struct {
		name  string
		title string
		mode  policy.WriteMode
		want  string
	}{
		{"new entry without create", "BrandNew", policy.WriteMode{AddFields: true, Update: true}, "sb write-allow keepass create"},
		{"add to existing with create only", "GitHub", policy.WriteMode{Create: true}, "sb write-allow keepass add-fields"},
		{"no grant at all", "GitHub", policy.WriteMode{}, "sb write-allow keepass add-fields"},
	}
	for _, c := range cases {
		a, db := newFixtureAdapter(t)
		orig := readFile(t, db)
		_, err := a.WriteEntry("", c.title, map[string]string{"otp": testSeed}, "otp", c.mode)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error naming %q, got %v", c.name, c.want, err)
		}
		if !bytes.Equal(readFile(t, db), orig) {
			t.Errorf("%s: refused write modified the vault", c.name)
		}
	}
}

// An entry is found where Resolve finds it. Writing beside it under the same
// title would duplicate the entry, and the ref would keep resolving to the
// old one — without the field just written.
func TestWriteFindsEntryInAnyGroup(t *testing.T) {
	a, db := newFixtureAdapter(t)
	if _, err := a.WriteEntry("Agents/Deep", "Nested", map[string]string{"Password": "nested-pw"}, "Password",
		policy.WriteMode{Create: true}); err != nil {
		t.Fatal(err)
	}
	res, err := a.WriteEntry("", "nested", map[string]string{"otp": testSeed}, "otp", addFields) // other case, no group
	if err != nil {
		t.Fatal(err)
	}
	if got := mustResolve(t, db, res.Ref); got != testSeed {
		t.Fatalf("ref %s does not resolve to the seed", res.Ref)
	}
	n := 0
	items, _ := fresh(t, db).List()
	for _, it := range items {
		if strings.HasSuffix(strings.ToLower(it), "/nested") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one Nested entry, got %v", items)
	}
}

// Update overwrites what it names and keeps everything else — the old update
// replaced the whole entry, so rotating a password silently dropped its
// username, TOTP seed and notes.
func TestUpdateKeepsUnnamedFieldsAndHistory(t *testing.T) {
	a, db := newFixtureAdapter(t)
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"otp": testSeed}, "otp", addFields); err != nil {
		t.Fatal(err)
	}
	user := entryOnDisk(t, db, "GitHub").GetContent("UserName")
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"Password": "rotated-PW"}, "Password",
		policy.WriteMode{AddFields: true, Update: true}); err != nil {
		t.Fatal(err)
	}
	e := entryOnDisk(t, db, "GitHub")
	if e.GetContent("Password") != "rotated-PW" || e.GetContent("UserName") != user {
		t.Fatal("update did not overwrite the password, or lost the username")
	}
	if mustResolve(t, db, "sec://keepass/GitHub/otp") != testSeed {
		t.Fatal("update lost the TOTP seed")
	}
	var old []string
	for _, h := range e.Histories {
		for _, he := range h.Entries {
			old = append(old, he.GetContent("Password"))
		}
	}
	if len(old) < 2 || old[len(old)-1] != fixturePassword {
		t.Fatalf("history should end with the pre-rotation password; has %d items", len(old))
	}
}

// Secret fields are stored protected: the field being spent (refField), the
// password, and TOTP seeds under every name KeePass/KeePassXC use. Ordinary
// fields are not.
func TestSecretFieldsAreProtected(t *testing.T) {
	a, db := newFixtureAdapter(t)
	fields := map[string]string{
		"Password": "p", "otp": testSeed, "TOTP Seed": "GEZDGNBVGY3TQOJQ",
		"TimeOtp-Secret-Base32": "GEZDGNBVGY3TQOJQ", "Recovery Codes": "aaaa-bbbb",
		"URL": "https://example.com", "UserName": "alex",
	}
	if _, err := a.WriteEntry("", "Protect", fields, "Recovery Codes", policy.WriteMode{Create: true}); err != nil {
		t.Fatal(err)
	}
	e := entryOnDisk(t, db, "Protect")
	want := map[string]bool{"Password": true, "otp": true, "TOTP Seed": true, "TimeOtp-Secret-Base32": true,
		"Recovery Codes": true, "URL": false, "UserName": false}
	for k, w := range want {
		i := valueIndex(e, k)
		if i < 0 {
			t.Fatalf("%s missing", k)
		}
		if e.Values[i].Value.Protected.Bool != w {
			t.Errorf("%s protected=%v, want %v", k, e.Values[i].Value.Protected.Bool, w)
		}
	}
}

func TestTitleIsNotAField(t *testing.T) {
	a, _ := newFixtureAdapter(t)
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"title": "Renamed"}, "Password",
		policy.WriteMode{Create: true, AddFields: true, Update: true}); err == nil {
		t.Fatal("renaming an entry through a field must be refused")
	}
	if _, err := a.WriteEntry("", " ", map[string]string{"Password": "x"}, "Password", policy.WriteMode{Create: true}); err == nil {
		t.Fatal("an empty title must be refused")
	}
}

// KeePassXC itself must read the seed the broker stored, show it as a
// protected attribute, and compute the same code from it.
func TestKeepassxcComputesOurTOTP(t *testing.T) {
	if _, err := exec.LookPath("keepassxc-cli"); err != nil {
		t.Skip("keepassxc-cli not available")
	}
	a, db := newFixtureAdapter(t)
	seed, err := totp.Normalize("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", "GitHub") // as a user would paste it
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteEntry("", "GitHub", map[string]string{"otp": seed}, "otp", addFields); err != nil {
		t.Fatal(err)
	}
	kpxc := func(args ...string) string {
		cmd := exec.Command("keepassxc-cli", args...)
		cmd.Stdin = strings.NewReader(kdbxPassword + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("keepassxc-cli %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	// `show -a <attr>` prints even protected attributes in clear; the full
	// listing without -s is where KeePassXC masks them.
	if out := kpxc("show", "--all", db, "GitHub"); !strings.Contains(out, "otp: PROTECTED") || strings.Contains(out, "GEZDGNBV") {
		t.Fatalf("keepassxc-cli does not treat otp as protected:\n%s", out)
	}
	before, _ := totp.At(seed, time.Now())
	out := kpxc("show", "--totp", db, "GitHub")
	after, _ := totp.At(seed, time.Now())
	got := ""
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); len(l) == 6 && strings.Trim(l, "0123456789") == "" {
			got = l
		}
	}
	if got == "" || (got != before && got != after) {
		t.Fatalf("keepassxc computed %q, broker computes %s/%s\n%s", got, before, after, out)
	}
	// The history item the write added must be one KeePassXC accepts: an
	// <Entry> inside the entry's <History> carrying the entry's own UUID.
	xml := kpxc("export", "--format", "xml", db)
	uuidLine := ""
	for _, line := range strings.Split(xml, "\n") {
		if strings.Contains(line, "<UUID>") {
			uuidLine = strings.TrimSpace(line) // fixture: GitHub is the only entry; last UUID wins
		}
	}
	if !strings.Contains(xml, "<History>") || uuidLine == "" || strings.Count(xml, uuidLine) < 2 {
		t.Fatalf("KeePassXC export shows no history item with the entry's UUID")
	}
}
