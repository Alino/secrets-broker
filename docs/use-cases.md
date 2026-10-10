# Use cases

What secrets-broker is for. The through-line: **a secret is used without the
caller ever seeing its value.** The broker holds the vault, injects the secret
into a specific command or request at the moment it runs, and masks it on the
way back. Everything below is a variation on that.

## 1. AI coding agent runs a command that needs a token

The canonical case. An agent (Claude Code, Cursor, an SDK loop) needs to run
`gh`, `aws`, `terraform`, `npm publish`, `psql` — a command that reads a token
from the environment. Handing the agent the token means it lands in the
transcript, the model's context, and any log it writes.

Instead the agent calls `exec_with_secret` over MCP with a *reference*
(`sec://…`), not a value. The broker checks the command against the policy
allow-list, injects the real secret into that child process's environment,
runs it, and masks the value out of stdout/stderr. The agent sees the command
output; it never sees the token.

Binding is exact: the policy pins the executable **and** its argv, so a
reference approved for `gh release create` cannot be replayed as
`gh api /user` or piped into `sh`.

## 2. Agent makes an authenticated API call

Same shape, network edition. The agent needs to call a service whose CLI wants
an API key (`stripe`, `gh`, `hcloud`, a deploy tool). The reference is bound to
that exact executable **and** argument prefix —
`sb allow sec://keepass/Stripe/key /usr/local/bin/stripe -- charges list` — so
the key cannot be handed to a different subcommand, a different binary, or a
shell. Generic network clients (`curl`, `wget`) are refused unless forced,
because a key approved for one URL would then work against any.

What binding does not do is choose *where* the allowed tool sends the key:
once it is in that process, the process decides. There is deliberately no
per-host egress allow-list (enforcing one means terminating the child's TLS,
and a hostname list defeated by an IP literal or a redirect is worse than
none — see [security.md](security.md)). For a tool with no business on the
network, `--no-network` removes the network from it entirely. `--host=` is a
different control: it scopes which web pages the browser integration may fill
a login into (§6), not where a command connects.

## 3. Human and agent share one vault

You and your agent both work from the same KeePassXC vault (the documented
default). You manage secrets in the GUI; the agent reads and writes through the
broker. The broker re-reads the vault whenever the file changes, and applies
each write to the file as it is on disk at that moment, so what the agent adds
shows up in your GUI and what you add is usable by the agent without a
restart. Writes preserve the vault file's group and mode — no separate "agent
vault" to keep in sync.

Two writers on one machine are safe: KeePassXC notices the broker's write and
reloads (or offers to merge if you have unsaved edits), and the broker redoes
its write if KeePassXC saved while it was writing. **Sync tools are a
different matter.** Syncthing and friends copy whole files; they do not merge
a `.kdbx`. If the vault is edited on two devices before they sync, you get a
`.sync-conflict` copy, which you merge by hand in KeePassXC (Database → Merge
from database). See [setup.md](setup.md#syncing-the-vault-between-machines).

## 4. Agent provisions a brand-new credential, then uses it

The agent is setting up a new service. It calls `create_secret` to generate a
strong password and store it as a login for `newsite.example.com`; the value
never crosses into its context, only the returned ref does. The entry appears
in your GUI vault immediately, and the agent can spend the ref in the same
session — fill the signup form, call the API — without seeing it. (For a value
the agent already holds, such as an API key a signup response displayed,
`save_secret` stores it instead.) Verified end-to-end: create → use → correctly
denied when the binding doesn't match.

## 5. Human-in-the-loop approval for sensitive secrets

Some secrets shouldn't be usable by an agent unattended. Mark a reference as
gated and the broker refuses to inject it until a human approves *this specific
request* — the approval signs a nonce bound to the exact command being run
(Secure Enclave / Touch ID on macOS). Approval is one-shot and per-request: it
cannot be reused for a different command or a later call.

> Note: in isolated mode this requires a code-signed approval helper. Without a
> signing identity it fails closed (deny), which is the safe default.

## 6. Browser autofill for a human, without the vendor extension

The broker speaks the KeePassXC-Browser native-messaging protocol, so it can
fill logins in the browser for a *human* user — an alternative to the vendor
extension, backed by the same local vault. Associations act as principals with
human/agent scope, so browser autofill and agent injection are distinguishable
and separately governable.

## 7. Migrate existing secrets out of dotfiles

Secrets are already scattered across `~/.aws/credentials`, `.netrc`, `.env`
files. `sb import scan` discovers credential-shaped material and shows it
**redacted** (names and sources, never values); `sb import apply` moves the
chosen ones into the vault via the daemon. This is how you get from "secrets in
plaintext files the agent can read" to "secrets behind the broker."

## 8. Isolated mode: agent runs privileged but can't read the vault key

The agent may run as an admin/root-capable account, but the vault password
lives in a directory owned by a separate hidden service account
(`_secretsbroker`) that the agent's account can't read. The agent talks to the
broker over a unix socket and gets *injection*, never the key material or the
master password. Even with broad local privileges, the agent cannot exfiltrate
the vault — it can only ask the broker to use it, within policy.

---

## Platforms

Isolated mode installs on **macOS** (`launchd` + a hidden Directory Services
service account + Secure Enclave approval) and **Linux** (`systemd` unit +
`useradd --system` service account). `sb install` picks the right path for the
host; `sb install --dry-run` prints the exact steps first.

Linux has no Secure Enclave, so approval-gated refs **fail closed** there (the
same behaviour as macOS without a code-signed `sb-seauth`). If you need
interactive approval on Linux, use single-uid mode.

## Where it does **not** (yet) fit

- **Cloud/remote secret managers.** The broker is local-vault-first (KeePassXC,
  Bitwarden/Vaultwarden, opvault). It is not a Vault/Secrets-Manager client.
- **Authoritative-app vaults for live agent writes.** 1Password (opvault)
  treats its app as the source of truth; the broker can read but live agent
  writes are unreliable. Use keepass or bitwarden when the agent must write.

