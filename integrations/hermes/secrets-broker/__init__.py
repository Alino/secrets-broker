"""secrets-broker for Hermes: the USER types a credential into a masked field on their own surface
(TUI card), this handler hands it straight to the broker's ``save_secret`` over the MCP connection
Hermes already holds, and the model gets back only the ``sec://`` ref.

The value never becomes a tool argument the model wrote, never enters a tool result, and is
registered for redaction in case anything later echoes it. Where nobody can answer a prompt
(cron, ``-q``, messaging gateways, a Hermes without the masked-input hook) the tool refuses
rather than falling back to asking in chat.

Config (``~/.hermes/config.yaml`` or the profile's)::

    plugins:
      enabled: [secrets-broker]
      entries:
        secrets-broker:
          mcp_allowlist: [secrets-broker]   # the MCP server name this plugin may call
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

SERVER = "secrets-broker"  # mcp_servers key of the broker
TOOL = "sb_capture_secret"
KINDS = ("login", "totp", "secret")

SCHEMA = {
    "name": TOOL,
    "description": (
        "Store a credential the USER types into their KeePass vault (secrets-broker): they type it into a "
        "masked field in their Hermes UI and you get back only sec:// refs - you never see the value. "
        "This is the user's vault for logins - prefer it over browser_vault_save_login, which writes to "
        "Hermes's separate local vault. "
        "USE THIS whenever a task needs a credential only the user knows (the password of an "
        "existing account, an API key or token they hold, recovery codes, or the authenticator/TOTP "
        "key of a login) instead of asking them to paste it in chat. Do NOT use it for a new random "
        "password (use create_secret) or for a token a web page shows once (capture that from the "
        "page). kind=login asks username then password (ask_totp=true adds the TOTP key) and makes a "
        "NEW entry; kind=totp adds the TOTP key to an entry (new or existing); kind=secret stores one "
        "value in `field`. Existing values are never overwritten. If the user declines, do not ask "
        "again this turn. Spend the refs with exec_with_secret / sb-cdpfill after binding them "
        "(sb allow)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Vault entry title: the site/brand name the user would recognise, e.g. 'GitHub', 'Steam'.",
            },
            "kind": {
                "type": "string",
                "enum": list(KINDS),
                "description": "login = username + password (+ TOTP with ask_totp); totp = the authenticator key; "
                               "secret = one value stored in `field`.",
            },
            "field": {
                "type": "string",
                "description": "kind=secret only: field name to store the value in, e.g. 'API Key', "
                               "'Recovery Codes', 'Token' (default 'Password').",
            },
            "url": {"type": "string", "description": "kind=login only: the site's URL, stored on the new entry."},
            "group": {"type": "string", "description": "Optional vault group path, e.g. 'Agents'."},
            "ask_totp": {
                "type": "boolean",
                "description": "kind=login only: after the password, also ask for the authenticator (TOTP) key; "
                               "the user can skip it.",
            },
        },
        "required": ["title", "kind"],
    },
}


def _result(**kw: Any) -> str:
    return json.dumps(kw, ensure_ascii=False)


def _refuse(error_type: str, error: str) -> str:
    return _result(success=False, error_type=error_type, error=error)


def _prompts() -> tuple[Optional[Callable], Optional[Callable]]:
    """(save-login prompt, masked single-value prompt) for the surface owning this turn, or None
    where nobody can answer. The masked-input hook is a newer Hermes API: absent -> None."""
    try:
        from agent.vault_backends import unlock as u
    except Exception:  # not running inside Hermes
        return None, None
    login = u.get_save_login_prompt_callback()
    secret = getattr(u, "get_secret_input_prompt_callback", lambda: None)()
    return login, secret


def _redact(value: str) -> None:
    """Make Hermes redact the exact value from anything model-facing, should anything echo it."""
    try:
        from agent.redact import register_vault_redaction_value
        register_vault_redaction_value(value)
    except Exception:
        logger.debug("redaction registration unavailable", exc_info=True)


def _ref(group: str, title: str, field: str) -> str:
    return "sec://keepass/" + (group.strip("/") + "/" if group else "") + title + "/" + field


def make_handler(call_mcp: Callable[..., Dict[str, Any]]):
    """Tool handler bound to ``call_mcp(server, tool, arguments, timeout=...)`` (PluginContext.call_mcp)."""

    def handle(args: Dict[str, Any], **_kw: Any) -> str:
        title = str(args.get("title") or "").strip()
        kind = str(args.get("kind") or "").strip().lower()
        group = str(args.get("group") or "").strip()
        if not title or kind not in KINDS:
            return _refuse("bad_arguments", f"title and kind ({', '.join(KINDS)}) are required")
        if "/" in title:
            return _refuse("bad_arguments", "put the group in `group`, not in the title")

        ask_login, ask_secret = _prompts()
        values: Dict[str, str] = {}  # field -> value, cleared in finally
        notes = []
        try:
            if kind == "login":
                if ask_login is None:
                    return _unavailable()
                answer = ask_login(str(args.get("url") or title), f"{title} (KeePass)")
                try:
                    if not answer or not answer.get("identifier") or not answer.get("password"):
                        return _declined()
                    values["UserName"] = str(answer["identifier"]).strip()
                    values["Password"] = str(answer["password"])
                finally:
                    if isinstance(answer, dict):
                        answer.clear()
                main = "Password"
                if args.get("ask_totp"):
                    if ask_secret is None:
                        notes.append("TOTP key not asked: this Hermes has no masked-input prompt")
                    else:
                        seed = ask_secret(f"Authenticator (TOTP) key for {title} - optional, Esc skips",
                                          _ref(group, title, "otp"))
                        if seed:
                            values["otp"] = seed
                        else:
                            notes.append("user skipped the TOTP key")
            else:
                if ask_secret is None:
                    return _unavailable()
                if kind == "totp":
                    main = "otp"
                    label = f"Authenticator (TOTP) key for {title}"
                else:
                    main = str(args.get("field") or "Password").strip() or "Password"
                    label = f"{main} for {title}"
                value = ask_secret(f"{label} - hidden, never shown to the model, Esc cancels",
                                   _ref(group, title, main))
                if not value:
                    return _declined()
                values[main] = value

            for v in values.values():
                _redact(v)
            fields = {k: v for k, v in values.items() if k != main}
            if kind == "login" and args.get("url"):
                fields["URL"] = str(args["url"])
            mcp_args: Dict[str, Any] = {"title": title, "field": main, "value": values[main]}
            if fields:
                mcp_args["fields"] = fields
            if group:
                mcp_args["group"] = group
            try:
                env = call_mcp(SERVER, "save_secret", mcp_args, timeout=60)
            except PermissionError:
                return _refuse("not_allowed", f"this plugin may not call the '{SERVER}' MCP server: add it to "
                                              f"plugins.entries.secrets-broker.mcp_allowlist in config.yaml")
            finally:
                mcp_args.clear()
                fields.clear()
        finally:
            values_stored = sorted(values)
            values.clear()

        if not env.get("ok"):
            # The broker's refusal names fields and the fix (`sb write-allow ...`), never values.
            return _refuse("vault_refused", str(env.get("error") or "save_secret failed")[:600])
        out = env.get("structuredContent")
        if not isinstance(out, dict):
            try:
                out = json.loads(env.get("result") or "{}")
            except (TypeError, ValueError):
                out = {}
        refs = {f: _ref(group, title, f) for f in values_stored}
        if out.get("ref"):
            refs[main] = out["ref"]
        return _result(
            success=True, refs=refs, created=bool(out.get("created")), stored_fields=values_stored,
            notes=notes or None,
            next=("Bind each ref to the one command allowed to use it (sb allow, single-uid: run it yourself), "
                  "then spend it with exec_with_secret; for a TOTP ref use sb-cdpfill with FILL_TOTP."),
        )

    return handle


def _unavailable() -> str:
    return _refuse("prompt_unavailable",
                   "This session cannot show the user a masked prompt (headless/cron/messaging, or a Hermes "
                   "without the masked-input hook). Ask the user to run this from the Hermes TUI, or to add "
                   "the entry in KeePassXC - never ask them to paste the value in chat.")


def _declined() -> str:
    return _refuse("declined", "The user chose not to enter it. Do not ask again this turn.")


PROMPT_SECTION = (
    "Credentials: the user's logins live in their KeePass vault behind the secrets-broker MCP server. "
    "When they want to give you one (a password, an authenticator/TOTP key, an API key, recovery codes), "
    "call sb_capture_secret: they type it into a masked field and you only get a sec:// ref. Do not use "
    "browser_vault_save_login for that - it writes to Hermes's separate local vault - and never ask for a "
    "secret in chat."
)


def register(ctx) -> None:
    ctx.register_tool(
        name=TOOL,
        toolset="secrets_broker",
        schema=SCHEMA,
        handler=make_handler(ctx.call_mcp),
        description=SCHEMA["description"],
        emoji="🔐",
    )
    # Without it the model reaches for the built-in browser_vault_save_login (a different store) when
    # the user says "save my login" - seen in the first live test.
    register_section = getattr(ctx, "register_system_prompt_section", None)
    if register_section is not None:
        register_section("secrets-broker-credentials", PROMPT_SECTION)
