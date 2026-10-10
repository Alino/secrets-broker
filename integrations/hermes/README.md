# Hermes integration: type a credential straight into the vault

`sb_capture_secret` is a Hermes tool (a plugin) that asks the **user** for a credential in a
masked field on their Hermes surface and stores it in the vault through this broker's
`save_secret`. The model only ever gets `sec://` refs back.

| `kind`   | What the user is asked                                   | Stored as |
|----------|----------------------------------------------------------|-----------|
| `login`  | username (shown) → password (hidden) → TOTP key if `ask_totp` (hidden, Esc skips) | one NEW entry: `UserName`, `Password`, `otp`, `URL` |
| `totp`   | the authenticator key (hidden)                           | `otp` on the entry (existing or new) |
| `secret` | one value (hidden)                                       | `field` (default `Password`) |

The value goes surface → plugin → the MCP connection Hermes already holds → broker → vault.
It is never a tool argument the model wrote, never in a tool result, never in the transcript,
and it is registered for Hermes's output redaction. Existing values are never overwritten
(the broker's `add-fields` grant); a TOTP key is validated and stored the way KeePassXC keeps it.
Where nobody can answer a prompt (cron, `hermes -z`, messaging gateways) the tool refuses with
`prompt_unavailable` instead of falling back to asking in chat.

## Install

```bash
# 1. the plugin
cp -R integrations/hermes/secrets-broker ~/.hermes/plugins/
hermes plugins enable secrets-broker
hermes config set plugins.entries.secrets-broker.mcp_allowlist '["secrets-broker"]'

# 2. vault writes the plugin needs (new entries + fields an entry lacks; never overwrite)
sb write-allow keepass create,add-fields
```

**Hermes core:** the `login` card already exists in Hermes. The hidden single-value card
(`totp`, `secret`, and the TOTP step of `login`) needs a small hook,
`agent.vault_backends.unlock.get_secret_input_prompt_callback`, provided by
`hermes-secret-input-prompt.patch` (3 files, Python only — the TUI reuses its existing masked
"secret" card). Apply it in the Hermes checkout with `git apply`. Without it, `login` still
works and the other kinds refuse with `prompt_unavailable`.

## Test

```bash
python3 -m unittest discover -s integrations/hermes/secrets-broker -p 'test_*.py'
```

Live: create a throwaway profile (`hermes profile create sbtest --clone`), point its
`mcp_servers.secrets-broker.env` at a copy of `testdata/fixture.kdbx` (with
`SB_KEEPASS_PASSWORD=fixture-master-pw` and a throwaway `SB_POLICY_FILE`), install the plugin
into `~/.hermes/profiles/sbtest/plugins/`, run `hermes -p sbtest`, ask it to save a login, type
throwaway values, then check the entry with `keepassxc-cli` and grep the profile for the typed
values (there must be no hits). Delete the profile afterwards: a clone carries your `.env`.
