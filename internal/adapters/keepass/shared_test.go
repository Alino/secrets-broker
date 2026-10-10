package keepass

import (
	"os"
	"strings"
	"testing"

	keepasslib "github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// The vault is shared: the human's KeePassXC (or Syncthing delivering an edit
// made on another device) writes the same .kdbx the broker has open. These
// tests stand in for that writer with rewriteExternally, which replaces the
// file the way KeePassXC's safe-save does — atomically via rename, and without
// knowing about the broker's .sblock.

func pwFn() (string, error) { return kdbxPassword, nil }

// rewriteExternally decodes the vault with oldPW, applies edit, and replaces
// the file encrypted under newPW.
func rewriteExternally(t *testing.T, path, oldPW, newPW string, edit func(*keepasslib.Database)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db := keepasslib.NewDatabase()
	db.Credentials = keepasslib.NewPasswordCredentials(oldPW)
	err = keepasslib.NewDecoder(f).Decode(db)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(db)
	}
	db.Credentials = keepasslib.NewPasswordCredentials(newPW)
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	tmp := path + ".external"
	out, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := keepasslib.NewEncoder(out).Encode(db); err != nil {
		t.Fatal(err)
	}
	out.Close()
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// externalAdd adds an entry to the root group, as a human would in KeePassXC.
func externalAdd(t *testing.T, path, title, password string) {
	t.Helper()
	rewriteExternally(t, path, kdbxPassword, kdbxPassword, func(db *keepasslib.Database) {
		e := keepasslib.NewEntry()
		e.Values = []keepasslib.ValueData{
			{Key: "Title", Value: keepasslib.V{Content: title}},
			{Key: "Password", Value: keepasslib.V{Content: password, Protected: w.NewBoolWrapper(true)}},
		}
		root := &db.Content.Root.Groups[0]
		root.Entries = append(root.Entries, e)
	})
}

// replaceFile swaps in new bytes atomically (new inode, as any sync tool does).
func replaceFile(t *testing.T, path string, b []byte) {
	t.Helper()
	tmp := path + ".restore"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// DATA-LOSS regression. A long-running broker used to write back the copy of
// the vault it decoded at first unlock, deleting every entry the human had
// added since. The write must apply to the file as it is on disk now.
func TestWriteKeepsEntriesAddedByAnotherWriter(t *testing.T) {
	db := copyFixture(t)
	broker := &Adapter{DBPath: db, PasswordFn: pwFn}
	if _, err := broker.Resolve("sec://keepass/GitHub/password"); err != nil {
		t.Fatal(err) // broker is now unlocked and holding a decoded copy
	}

	externalAdd(t, db, "HumanAdded", "human-pw")

	if _, err := broker.CreateEntry("", "AgentAdded", map[string]string{"Password": "agent-pw"}); err != nil {
		t.Fatal(err)
	}

	fresh := &Adapter{DBPath: db, PasswordFn: pwFn}
	if got, err := fresh.Resolve("sec://keepass/HumanAdded/Password"); err != nil || got != "human-pw" {
		t.Fatalf("the human's entry was lost by the agent's write: %q %v", got, err)
	}
	if got, err := fresh.Resolve("sec://keepass/AgentAdded/Password"); err != nil || got != "agent-pw" {
		t.Fatalf("agent entry: %q %v", got, err)
	}
}

// A long-running broker must see entries added after it unlocked, without a
// restart — both through Resolve and List.
func TestResolveSeesEntriesAddedAfterUnlock(t *testing.T) {
	db := copyFixture(t)
	broker := &Adapter{DBPath: db, PasswordFn: pwFn}
	if _, err := broker.Resolve("sec://keepass/GitHub/password"); err != nil {
		t.Fatal(err)
	}

	externalAdd(t, db, "LateEntry", "late-pw")

	if got, err := broker.Resolve("sec://keepass/LateEntry/Password"); err != nil || got != "late-pw" {
		t.Fatalf("broker answered from a stale copy: %q %v", got, err)
	}
	items, err := broker.List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if strings.HasSuffix(it, "LateEntry") {
			found = true
		}
	}
	if !found {
		t.Fatalf("List is stale: %v", items)
	}
}

// The MCP server uses ONE adapter for reads and writes, so values read back on
// the same instance after a write must be plaintext — not the protected-stream
// ciphertext that encoding leaves in the encoder's copy.
func TestSameInstanceResolvesPlaintextAfterWrite(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: pwFn}
	before, err := a.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateEntry("Agents", "Same", map[string]string{"Password": "same-pw"}); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Resolve("sec://keepass/Agents/Same/Password"); err != nil || got != "same-pw" {
		t.Fatalf("own new entry after write: %q %v", got, err)
	}
	if got, err := a.Resolve("sec://keepass/GitHub/password"); err != nil || got != before {
		t.Fatalf("existing entry changed after write: got %q want %q (%v)", got, before, err)
	}
}

// When the vault changes to something the stored password cannot open (the
// human changed the master password, or the file is damaged), the broker must
// refuse rather than keep answering from the old copy — and must NOT write the
// old copy over it. Recovery needs no restart: this is a retry with the same
// password, so it guesses nothing and is not sticky.
func TestChangedVaultThatNoLongerOpensFailsClosed(t *testing.T) {
	db := copyFixture(t)
	orig, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	broker := &Adapter{DBPath: db, PasswordFn: pwFn}
	want, err := broker.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}

	rewriteExternally(t, db, kdbxPassword, "a-new-master-password", nil)
	rekeyed, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := broker.Resolve("sec://keepass/GitHub/password"); err == nil {
		t.Fatalf("served %q from the stale copy of a vault that no longer opens", got)
	}
	if _, err := broker.CreateEntry("", "ShouldNotLand", map[string]string{"Password": "x"}); err == nil {
		t.Fatal("write must be refused while the vault cannot be re-read")
	}
	now, _ := os.ReadFile(db)
	if string(now) != string(rekeyed) {
		t.Fatal("refused write still modified the vault file")
	}

	replaceFile(t, db, orig)
	if got, err := broker.Resolve("sec://keepass/GitHub/password"); err != nil || got != want {
		t.Fatalf("did not recover once the vault opened again: %q %v", got, err)
	}
}

// KeePassXC does not know the broker's .sblock, so it can save while a write is
// being encoded (a second or more of Argon2). That write must be redone against
// the new version, not rename the stale encoding over it.
func TestWriteRedoneWhenVaultChangesMidWrite(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: pwFn}
	calls := 0
	testHookBeforeReplace = func() {
		calls++
		if calls == 1 {
			externalAdd(t, db, "SavedMidWrite", "mid-pw")
		}
	}
	defer func() { testHookBeforeReplace = nil }()

	if _, err := a.CreateEntry("", "AgentRetry", map[string]string{"Password": "retry-pw"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected the write to be redone once, hook ran %d times", calls)
	}
	fresh := &Adapter{DBPath: db, PasswordFn: pwFn}
	for ref, want := range map[string]string{
		"sec://keepass/SavedMidWrite/Password": "mid-pw",
		"sec://keepass/AgentRetry/Password":    "retry-pw",
	} {
		if got, err := fresh.Resolve(ref); err != nil || got != want {
			t.Fatalf("%s: %q %v", ref, got, err)
		}
	}
	if _, err := os.Stat(db + ".sbtmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}

// A vault that changes on every attempt makes the write give up and leave the
// other writer's version in place.
func TestWriteGivesUpWhenVaultNeverSettles(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: pwFn}
	n := 0
	testHookBeforeReplace = func() {
		n++
		externalAdd(t, db, "Churn"+strings.Repeat("x", n), "c")
	}
	defer func() { testHookBeforeReplace = nil }()

	if _, err := a.CreateEntry("", "NeverLands", map[string]string{"Password": "x"}); err == nil {
		t.Fatal("expected the write to give up")
	}
	fresh := &Adapter{DBPath: db, PasswordFn: pwFn}
	if _, err := fresh.Resolve("sec://keepass/NeverLands/Password"); err == nil {
		t.Fatal("abandoned write still landed")
	}
	if _, err := fresh.Resolve("sec://keepass/Churn" + strings.Repeat("x", n) + "/Password"); err != nil {
		t.Fatalf("the other writer's last save was overwritten: %v", err)
	}
}

// Reads run concurrently with writes in the MCP server (one adapter, many
// tool calls). Run with -race.
func TestConcurrentResolveAndWrite(t *testing.T) {
	db := copyFixture(t)
	a := &Adapter{DBPath: db, PasswordFn: pwFn}
	want, err := a.Resolve("sec://keepass/GitHub/password")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			if _, err := a.CreateEntry("", "Concurrent"+strings.Repeat("y", i+1), map[string]string{"Password": "p"}); err != nil {
				errs <- err
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			select {
			case err := <-errs:
				t.Fatal(err)
			default:
			}
			return
		default:
		}
		if got, err := a.Resolve("sec://keepass/GitHub/password"); err != nil || got != want {
			t.Fatalf("read during write: %q %v", got, err)
		}
	}
}
