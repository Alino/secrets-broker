# For agents: setting up secrets-broker

You are an AI agent and the user pointed you at this repo to set up
secrets-broker so you can use their secrets **without ever seeing the values**.
Read this fully before running anything.

## The rule you must not break

There are two modes:

- **Single-uid mode** — you may set this up yourself, start to finish. It is
  **not a security boundary** (the broker runs as the same user as you, so
  anything running as you could bypass it). It is the right choice when the user
  wants it working quickly and accepts that trade-off.
- **Isolated mode** — a real boundary. **You must NOT set this up yourself.**
  It requires `sudo`, and its entire security value collapses if the agent runs
  the privileged steps. Your job is to *prepare* and then hand the commands
  below to the human to run themselves.

If the user asks for "the secure setup" / "isolated mode", do the **hand-off**
below. Otherwise default to single-uid and tell them what they're getting.

## Build first (either mode)

```bash
make build      # or see the Makefile for the individual go build / swiftc lines
```

## Single-uid setup (you may do all of this)

```bash
# 1. create the policy file
./bin/sb init
# 2. store the vault master password — ASK THE USER TO RUN THIS THEMSELVES.
#    Never type, echo, or read a master password yourself.
#    It prompts on the terminal with echo off and writes 0600.
SB_SECRET_DIR=$HOME/.secrets-broker/secrets \
  ./bin/sb set-password keepass /path/to/vault.kdbx
# 3. bind each secret to the exact command allowed to receive it
./bin/sb allow sec://keepass/GitHub/token /usr/bin/gh -- api /user
# 4. opt in to writes if you need to create/store secrets
./bin/sb write-allow keepass create
# 5. register the MCP server with your client, passing the SAME env the
#    CLI used (SB_SECRET_DIR included, or the daemon cannot unlock):
claude mcp add secrets-broker \
  --env SB_KEEPASS_DB=/path/to/vault.kdbx \
  --env SB_SECRET_DIR=$HOME/.secrets-broker/secrets \
  --env SB_POLICY_FILE=$HOME/.secrets-broker/policy.json \
  --env SB_AUDIT_LOG=$HOME/.secrets-broker/audit.jsonl \
  -- ./bin/secrets-broker-mcp
# 6. verify
./bin/sb doctor
```

### Storing the master password: keychain vs secret dir

`sb set-password` (secret dir) is the **default recommendation**, not the
fallback. The OS keychain is only usable when the broker runs in a GUI login
session.

**The keychain silently cannot work when the agent runs headless.** Many agents
run under a background service manager (launchd `Background` session, systemd,
ssh, cron) with no GUI login. There, macOS refuses every keychain operation with
`SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.`
— including *reads*, so even a keychain item created by hand is unreadable by
the broker. Check before choosing:

```bash
launchctl managername           # "Background" => keychain is NOT available
stat -f%Su /dev/console          # a different user => no GUI session of your own
security add-generic-password -s sb-probe -a t -w x && \
  security delete-generic-password -s sb-probe -a t   # must succeed
```

If any of those fail, use `sb set-password` and set `SB_SECRET_DIR` everywhere
(CLI *and* the MCP registration). The lookup order is `SB_*_PASSWORD` env →
secret dir → OS keychain, so the file wins with no extra configuration. It must
be mode `0600`; the broker refuses a group/world-readable file with an
actionable error.

### Pitfalls that cost real time

- **`sb set-password` needs a real terminal** and refuses when there is no
  controlling tty ("an agent cannot enter the master password"). That is
  deliberate. Hand the command to the user; don't try to drive the prompt.
- **Give the user a command that cannot mis-expand.** `~` and `$HOME` resolve to
  whoever runs the shell. If they paste it into a `su`/admin window the glob
  silently hits the wrong home (`zsh: no matches found`) and an empty account
  string gets stored. Tell them which user to run as, and prefer
  `"$(ls ~/vaultdir/*.kdbx)"` over a pasted filename.
- **Avoid `read -s -p` in commands you hand over.** It is a bashism; zsh (the
  macOS default) parses `-p` as "read from coprocess" and fails with
  `read: -p: no coprocess`. `sb set-password` avoids the problem entirely.
- **Registering the MCP may be interactive.** Some clients prompt to enable the
  discovered tools and save *nothing* on EOF. If the add appears to succeed but
  the server is missing afterwards, pipe a confirmation (`printf 'y\n' | …`).
  Always verify with the client's `mcp list`, never with the add command's
  own output.
- **`keepassxc-cli` blocks forever reading a password from a pipe** (it wants a
  tty), and the `.pw` file has no trailing newline, which makes the hang look
  like a vault problem. On macOS its first launch from a freshly installed
  `.app` also raises a Gatekeeper "downloaded from the internet" dialog that a
  background session cannot see — the process waits for a click and the
  timeout reads as a corrupt vault, while the dialog sits on the user's
  screen. Don't verify the install that way — verify through the broker
  (below). If you did trigger the dialog, tell the user.
- **Don't run the MCP server with stdin from `/dev/null`** (or any closed
  stdin) to keep it "in the background". It serves MCP on stdio, sees EOF,
  and exits — taking the `-browser-socket` listener with it, so the socket
  file exists but every connection is refused. Give it an open stdin or run it
  the way your client launches it.

### Verifying without seeing anything

The vault decrypts iff a resolve gets *past* unlock. Request a ref you know does
not exist, bound to a harmless exec:

- `entry "__probe__" not found` → **password is correct** (unlock succeeded).
- a decrypt/HMAC error → wrong password.

To confirm a secret you just created, run a command that prints only its
**length and a keyed hash**, never the value: an HMAC-SHA256 under a random
key generated for that one run and discarded afterwards. A plain `shasum` of
a short password is not safe to print — it is a dictionary lookup away from
the value. Then check the value itself comes back `<concealed>` in the masked
output. Use a throwaway `SB_POLICY_FILE` for that check so the real policy
keeps its deny-by-default shape.

To check whether an **entry exists** — before binding it, or before telling
the user it is missing — use `sb probe` rather than guessing refs through
`exec_with_secret`:

```bash
./bin/sb probe keepass "$SB_KEEPASS_DB" password GitHub Steam store.steampowered.com
# FOUND     sec://keepass/GitHub/password
# NO_ENTRY  Steam
# NO_FIELD  store.steampowered.com (entry exists; "password" is absent or empty)
```

It answers only for titles you name, prints no values, and unlocks the same
way the broker does (no prompt). Pass the vault path exactly as
`SB_KEEPASS_DB` has it. In isolated mode it cannot unlock as your user — that
is the boundary working; ask the human for the title instead.


## Isolated setup (STOP — hand these to the human)

Do everything you can *without* sudo (build the binaries, draft the policy
you'll want), then print exactly this for the user to run themselves, filling in
their vault path. Do **not** run these:

```bash
sudo sb install --dry-run --vault keepass:$HOME/Shared/agent.kdbx   # they review
sudo sb install           --vault keepass:$HOME/Shared/agent.kdbx   # prompts for the password
```

`install` prompts for the vault master password as its final step, so this is
normally the only command they need. (`sudo sb set-password keepass <path>`
still exists, to change it later.)

**Check the dry-run's "create client group … and add `<user>`" line before they
run the real thing.** `sb install` takes that user from `SUDO_USER`, and only
that user can reach the daemon socket. If the human will `sudo` from a *different*
account than the one the agent runs as (an admin window, `su`, a second login),
that line names the wrong user and the finished daemon is unreachable by the
agent — everything installs "successfully" and every call then fails. In that
case they must pass the agent's user explicitly:

```bash
sudo env SUDO_USER=<agent-user> sb install --vault keepass:/path/to/agent.kdbx
```

Group membership also only applies to **new** shells, so the agent's session may
need a restart before it can connect.

Then they register the daemon (this line you may run):

```bash
claude mcp add secrets-broker -- \
  /usr/local/libexec/secrets-broker/secrets-broker-mcp -connect \
  /usr/local/var/secrets-broker/run/sb.sock
```

Full walkthrough (vault sharing, verification): [docs/setup.md](docs/setup.md).

## Optional: sync the vault with the user's computer (Syncthing)

**Offer this when the broker runs somewhere the user doesn't sit** — a VPS, a
Mac mini, a home server. With KeePassXC on their computer and Syncthing
between, they keep editing their vault as usual, you see new entries seconds
later, and what you store appears in their KeePassXC. Ask once; it's their
choice. Recipe and the layout diagram: [docs/setup.md § Syncing the vault
between machines](docs/setup.md#syncing-the-vault-between-machines).

The split is fixed by who can touch which machine:

- **You (server side):** install Syncthing with the package manager, run it as
  the user as a service that survives logout (`systemctl --user enable --now
  syncthing` + `loginctl enable-linger`; macOS `brew services`, or
  `launchctl bootstrap user/$(id -u) …` from a headless session), create the
  `sb-vault` folder with versioning, add their computer's device ID, then
  verify and point `SB_KEEPASS_DB` at the synced file.
- **The human (their computer):** install Syncthing, add the server's device
  ID — print it for them with `syncthing device-id`; device IDs are not
  secrets — accept the `sb-vault` share, put the `.kdbx` in it, and send you
  their device ID. And, as always, they type the master password
  (`sb set-password`); you never do.

Pitfalls:

- **Start with the vault on ONE side.** Two different `.kdbx` files under the
  same name make the first sync a conflict.
- **Verify, don't assume.** `syncthing cli show connections` must show their
  device connected, and `/rest/db/status?folder=sb-vault` (API key in
  Syncthing's `config.xml`) must report `needFiles: 0`. Then prove the vault
  unlocks with the not-found probe above (`sb probe` / an `entry "…" not found`
  error). An empty `find_secrets_for_site` means no `sb allow` yet, not a
  missing entry.
- **The policy doesn't sync.** An entry the user adds on their computer still
  needs its `sb allow` on the server.
- **Conflicts:** a `*.sync-conflict-*.kdbx` appears if both sides edited before
  syncing. Don't merge it yourself; tell the user to merge it in KeePassXC
  (Database → Merge from database) and delete the copy.
- **Isolated mode:** Syncthing replaces the file on every change, so the
  service-account group must be set on the *directory* (Linux: setgid,
  `chmod 2770`). Re-check with `sudo sb doctor` (the human) after the first
  sync.

## How to behave once it's set up

- **When a task needs a secret, use the broker — do not ask the user to paste a
  value, and never write a secret into a file, `.env`, or the shell history.**
  To spend an existing secret: `exec_with_secret`. To make a new one:
  `create_secret` (value never returned to you). To store one the user just
  gave you: `save_secret`.
- **You will not see secret values, and that is correct.** Responses carry refs
  and masked output only. Do not try to work around it.
- **Deny-by-default is expected.** If `exec_with_secret` / `create_secret` is
  refused, the error names the exact command to fix it (e.g. `sb allow …` or
  `sb write-allow …`). In isolated mode those are the user's to run — relay the
  command, don't attempt it. In single-uid mode you may run it.
- **Prefer `find_secrets_for_site` over guessing refs** for web credentials.
  An empty result — like an empty `list_secrets` — means no *policy binding*
  yet, not an empty or locked vault. Entry titles are the user's, not
  hostnames (`Steam`, not `store.steampowered.com`): check candidates with
  `sb probe` (above), then bind the one that exists.
- **Browser logins over CDP need `sb-cdpfill`.** `exec_with_secret` delivers a
  secret into a child process's environment; a form you drive over the
  DevTools protocol has no child process. Bind the login to the helper, pinned
  to the site's exact origin — the trailing `...` allows the target id,
  selectors and `--port=` that every real fill adds:

  ```bash
  for f in username password; do
    ./bin/sb allow "sec://keepass/GitHub/$f" "$PWD/bin/sb-cdpfill" \
      --host=https://github.com --agent-browser --force -- https://github.com ...
  done
  ```

  Then call `exec_with_secret` with
  `argv: [sb-cdpfill, "https://github.com", "<target-id-prefix>", "<user-selector>", "<password-selector>", "<submit-selector>"]`
  and `env_refs: {FILL_USER: …/username, FILL_PASS: …/password}`. It refuses
  (exit 3) unless the page is on that origin, prefers the visible element when
  a page renders a hidden duplicate form, and prints only lengths. For a
  second factor, pass the entry's TOTP seed as `FILL_TOTP` instead of
  `FILL_PASS` — it types the current code, never the seed. `sb probe … otp
  <Title>` tells you beforehand whether the login can finish unattended
  (`FOUND`) or will need a code only the user receives (`NO_FIELD`: say so up
  front). In single-uid mode the binary is user-owned, so `sb allow` needs
  `--force`; `sudo sb install` puts a root-owned copy in
  `/usr/local/libexec/secrets-broker/`. Know its limit: you drive that
  browser, so you *could* read a filled field back over CDP. Don't — the
  helper keeps the value out of your transcript only if you cooperate.
- **A value a page shows once (a freshly generated API token):** read it from
  the DOM and pass it to `save_secret` inside one helper process, printing
  only its length and the returned ref. Never let it pass through your context
  or a file, and when inspecting the page, dump the reveal widget's *shape*
  (mask long token-like runs), not its text.
- **Stop after one rejected login.** Repeated failures can lock the account.
  If the site rejects a vault credential, check that the entry is what you
  think it is — e.g. the password field is not just the username again
  (compare lengths and keyed hashes, never values) — and ask the user to fix
  the entry. With update writes denied, you must not rewrite it yourself.
- **Policy is per machine.** A sync tool copies the vault, not
  `policy.json`: an entry the user added on another machine still needs its
  `sb allow` on this one.
- **Offer `--no-network` for local tools.** When a credential is spent by
  something that has no business calling out (a formatter, a build, a local
  CLI), `sb allow <ref> <exe> --no-network` denies the child and all its
  descendants any network access, so the tool cannot exfiltrate what it was
  given. Works on macOS (`sandbox-exec`) and Linux (network namespace). It
  fails closed: where the jail cannot be applied — notably inside containers,
  whose default seccomp profile blocks unprivileged user namespaces — the
  exec is REFUSED, so don't set it in an environment that cannot enforce it.


- **`exec_with_secret` takes `argv` (array, `argv[0]` is the executable) and
  `env_refs` (map of env var → `sec://` ref).** Not `exec`/`args`/`ref`. Wrong
  keys fail with `unexpected additional properties`, which reads like a server
  bug but is the schema rejecting the call.
- **`sb allow` refuses shells, interpreters and network clients** (`/bin/sh`,
  `curl`, …) unless you pass `--force`, because masking cannot survive
  `base64`/`tr`/`rev`. Allow-list the specific tool instead; that refusal is the
  product working.

## Running the tests

`go test ./...` **as root produces two false failures** — `TestPathSafe` and
`TestFileSecretErrorIsNotSwallowed` both assert that something is unreadable or
unsafe, and root defeats both. That is a common trap in a container, where the
default user is root. Run as a normal user:

```bash
docker run --rm --user 1000:1000 -e HOME=/tmp \
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
  -v "$PWD":/work -w /work golang:1.25 go test ./...
```

Don't "fix" those tests.

Two more traps when building or testing in a container:

- **`go build` over a bind-mounted checkout as a different uid needs
  `-buildvcs=false`** (or `GOFLAGS=-buildvcs=false`). git refuses the
  differing-owner checkout, the build fails with `error obtaining VCS status:
  exit status 128`, and in a loop without `set -e` the stale binary stays in
  `bin/`. Check the mtime of what you built.
- **Tests that need the host skip in a container**, and that is not a pass.
  `sb-cdpfill`'s browser test needs Chrome, and the macOS jail, Keychain and
  Secure Enclave paths need macOS. Cross-compile the test binary and run it
  natively:

  ```bash
  docker run --rm --user 1000:1000 -e HOME=/tmp -e GOCACHE=/tmp/gocache \
    -e GOMODCACHE=/tmp/gomod -e GOOS=darwin -e GOARCH=arm64 \
    -v "$PWD":/work -w /work golang:1.25 \
    go test -c -o bin/sb-cdpfill.test ./cmd/sb-cdpfill/
  (cd cmd/sb-cdpfill && ../../bin/sb-cdpfill.test -test.v)
  ```

