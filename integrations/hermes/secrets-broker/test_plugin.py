"""Unit tests for the secrets-broker Hermes plugin (stdlib unittest; no Hermes needed).

    python3 -m unittest discover -s integrations/hermes/secrets-broker -p 'test_*.py'
"""

import importlib.util
import json
import os
import unittest

_spec = importlib.util.spec_from_file_location(
    "sb_plugin", os.path.join(os.path.dirname(os.path.abspath(__file__)), "__init__.py"))
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

USER, PW, SEED, KEY = "alex@example.com", "typed-PW-31337", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "sk-live-typed-KEY-9"
SECRETS = (PW, SEED, KEY)


class FakeMCP:
    def __init__(self, envelope=None, raise_exc=None):
        self.calls = []
        self.envelope = envelope
        self.raise_exc = raise_exc

    def __call__(self, server, tool, arguments, timeout=30):
        self.calls.append((server, tool, json.loads(json.dumps(arguments)), timeout))  # snapshot before clear()
        if self.raise_exc:
            raise self.raise_exc
        if self.envelope is not None:
            return self.envelope
        field = arguments["field"]
        out = {"ref": f"sec://keepass/{arguments['title']}/{field}", "field": field, "created": True,
               "stored": True, "value_returned": False}
        return {"ok": True, "result": json.dumps(out)}


class PluginTest(unittest.TestCase):
    def setUp(self):
        self.redacted = []
        self.login_answers = []
        self.secret_answers = []
        self.secret_prompts = []
        self.login_dicts = []
        plugin._redact = self.redacted.append
        self._orig_prompts = plugin._prompts

        def login(origin, site):
            ans = self.login_answers.pop(0) if self.login_answers else None
            if isinstance(ans, dict):
                self.login_dicts.append(ans)
            return ans

        def secret(title, destination):
            self.secret_prompts.append((title, destination))
            return self.secret_answers.pop(0) if self.secret_answers else ""

        plugin._prompts = lambda: (login, secret)

    def tearDown(self):
        plugin._prompts = self._orig_prompts

    def run_tool(self, mcp, **args):
        out = plugin.make_handler(mcp)(args)
        for s in SECRETS:
            self.assertNotIn(s, out, "a typed value reached the model-facing result")
        return json.loads(out)

    def test_login_with_totp_goes_to_save_secret_in_one_write(self):
        self.login_answers = [{"identifier": USER, "password": PW}]
        self.secret_answers = [SEED]
        mcp = FakeMCP()
        r = self.run_tool(mcp, title="GitHub", kind="login", url="https://github.com", ask_totp=True)
        self.assertTrue(r["success"])
        self.assertEqual(len(mcp.calls), 1)
        server, tool, a, _ = mcp.calls[0]
        self.assertEqual((server, tool), ("secrets-broker", "save_secret"))
        self.assertEqual((a["title"], a["field"], a["value"]), ("GitHub", "Password", PW))
        self.assertEqual(a["fields"], {"UserName": USER, "otp": SEED, "URL": "https://github.com"})
        self.assertEqual(r["refs"]["Password"], "sec://keepass/GitHub/Password")
        self.assertEqual(r["refs"]["otp"], "sec://keepass/GitHub/otp")
        self.assertEqual(sorted(r["stored_fields"]), ["Password", "UserName", "otp"])
        for s in (PW, SEED):
            self.assertIn(s, self.redacted)
        self.assertEqual(self.login_dicts[0], {}, "the prompt's answer dict must be cleared")
        # the TOTP prompt shows exactly where the value goes
        self.assertEqual(self.secret_prompts[0][1], "sec://keepass/GitHub/otp")

    def test_login_totp_skipped_still_saves_login(self):
        self.login_answers = [{"identifier": USER, "password": PW}]
        self.secret_answers = [""]
        mcp = FakeMCP()
        r = self.run_tool(mcp, title="Wise", kind="login", ask_totp=True)
        self.assertTrue(r["success"])
        self.assertNotIn("otp", mcp.calls[0][2].get("fields", {}))
        self.assertIn("user skipped the TOTP key", r["notes"])

    def test_totp_kind_targets_the_otp_field(self):
        self.secret_answers = [SEED]
        mcp = FakeMCP()
        r = self.run_tool(mcp, title="Steam", kind="totp", group="Games")
        a = mcp.calls[0][2]
        self.assertEqual((a["field"], a["value"], a["group"]), ("otp", SEED, "Games"))
        self.assertNotIn("fields", a)
        self.assertEqual(self.secret_prompts[0][1], "sec://keepass/Games/Steam/otp")
        self.assertTrue(r["success"])

    def test_secret_kind_uses_the_named_field(self):
        self.secret_answers = [KEY]
        mcp = FakeMCP()
        r = self.run_tool(mcp, title="Hetzner", kind="secret", field="API Key")
        self.assertEqual((mcp.calls[0][2]["field"], mcp.calls[0][2]["value"]), ("API Key", KEY))
        self.assertEqual(r["refs"]["API Key"], "sec://keepass/Hetzner/API Key")

    def test_declined_writes_nothing(self):
        for kind, setup in (("login", lambda: setattr(self, "login_answers", [None])),
                            ("login", lambda: setattr(self, "login_answers", [{"identifier": USER, "password": ""}])),
                            ("totp", lambda: setattr(self, "secret_answers", [""])),
                            ("secret", lambda: setattr(self, "secret_answers", [""]))):
            setup()
            mcp = FakeMCP()
            r = self.run_tool(mcp, title="X", kind=kind)
            self.assertEqual(r["error_type"], "declined")
            self.assertEqual(mcp.calls, [])

    def test_no_prompt_means_refusal_not_chat(self):
        plugin._prompts = lambda: (None, None)
        for kind in ("login", "totp", "secret"):
            mcp = FakeMCP()
            r = self.run_tool(mcp, title="X", kind=kind)
            self.assertEqual(r["error_type"], "prompt_unavailable")
            self.assertIn("never ask them to paste", r["error"])
            self.assertEqual(mcp.calls, [])

    def test_login_without_masked_input_hook_skips_totp_only(self):
        self.login_answers = [{"identifier": USER, "password": PW}]
        login, _ = plugin._prompts()
        plugin._prompts = lambda: (login, None)
        mcp = FakeMCP()
        r = self.run_tool(mcp, title="Old", kind="login", ask_totp=True)
        self.assertTrue(r["success"])
        self.assertIn("no masked-input prompt", " ".join(r["notes"]))

    def test_broker_refusal_is_reported_without_the_value(self):
        self.secret_answers = [KEY]
        mcp = FakeMCP(envelope={"ok": False, "error": "keepass: entry \"GitHub\" already has a value in Password; "
                                                       "adding fields never overwrites one"})
        r = self.run_tool(mcp, title="GitHub", kind="secret")
        self.assertEqual(r["error_type"], "vault_refused")
        self.assertIn("never overwrites", r["error"])

    def test_missing_mcp_grant_names_the_config_key(self):
        self.secret_answers = [KEY]
        r = self.run_tool(FakeMCP(raise_exc=PermissionError("no")), title="X", kind="secret")
        self.assertEqual(r["error_type"], "not_allowed")
        self.assertIn("mcp_allowlist", r["error"])

    def test_bad_arguments(self):
        for args in ({"title": "", "kind": "login"}, {"title": "X", "kind": "password"}, {"title": "A/B", "kind": "totp"}):
            mcp = FakeMCP()
            r = self.run_tool(mcp, **args)
            self.assertEqual(r["error_type"], "bad_arguments")
            self.assertEqual(mcp.calls, [])

    def test_register(self):
        seen, sections = {}, {}

        class Ctx:
            def call_mcp(self, *a, **k):
                return {}

            def register_tool(self, **kw):
                seen.update(kw)

            def register_system_prompt_section(self, id, content, **kw):
                sections[id] = content

        plugin.register(Ctx())
        self.assertEqual(seen["name"], "sb_capture_secret")
        self.assertEqual(seen["schema"]["name"], "sb_capture_secret")
        self.assertEqual(seen["schema"]["parameters"]["required"], ["title", "kind"])
        self.assertIn("browser_vault_save_login", sections["secrets-broker-credentials"])
        self.assertIn("browser_vault_save_login", seen["schema"]["description"])


if __name__ == "__main__":
    unittest.main()
