import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import agentlint  # noqa: E402


def rules(path):
    files = agentlint.discover([str(path)], include_home=False)
    return [f for p in files for f in agentlint.lint_file(p)]


class Risky(unittest.TestCase):
    def setUp(self):
        self.f = rules(ROOT / "examples/risky")
        self.ids = {f.rule for f in self.f}

    def test_all_rule_families_fire(self):
        for r in ["CC001", "CC003", "CC004", "CC005", "CC006", "CC007", "CC008",
                  "MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006"]:
            self.assertIn(r, self.ids, r)

    def test_secret_is_masked(self):
        text = json.dumps([f.message for f in self.f])
        self.assertNotIn("EXAMPLEexampleEXAMPLE", text)
        self.assertNotIn("abcdefghijklmnop1234", text)

    def test_exit_code(self):
        self.assertEqual(agentlint.main(["--json", str(ROOT / "examples/risky")]), 1)


class Tight(unittest.TestCase):
    def test_clean(self):
        f = rules(ROOT / "examples/tight")
        self.assertEqual([(x.rule, x.where) for x in f], [])
        self.assertEqual(agentlint.main(["--json", str(ROOT / "examples/tight")]), 0)


class Units(unittest.TestCase):
    def test_bash_prefix(self):
        self.assertEqual(agentlint.bash_prefix("Bash"), "*")
        self.assertEqual(agentlint.bash_prefix("Bash(*)"), "*")
        self.assertEqual(agentlint.bash_prefix("Bash(git push:*)"), "git push")
        self.assertEqual(agentlint.bash_prefix("Bash(npm run test)"), "npm run test")
        self.assertIsNone(agentlint.bash_prefix("WebFetch"))

    def test_placeholders_are_not_secrets(self):
        for v in ["${GITHUB_TOKEN}", "$TOKEN", "${input:token}", "<your token>", "changeme", "",
                  "${env:GITHUB_TOKEN}", "${env:API_TOKEN}", "${localEnv:API_TOKEN}", "${containerEnv:API_TOKEN}",
                  "${input:api-token}", "${API_TOKEN:-}", "${secret:api-token}"]:
            self.assertIsNone(agentlint.looks_secret("GITHUB_TOKEN", v), v)
        self.assertIsNone(agentlint.looks_secret("API_TOKEN", "${env:API_TOKEN}"))

    def test_fake_literal_still_flagged(self):
        # control: a real-looking literal under the same names must still be reported
        for v in ["abcd1234efgh5678ijkl9012", "ghp_" + "a1B2c3D4" * 5, "${env:X}abcd1234efgh5678"]:
            self.assertIsNotNone(agentlint.looks_secret("API_TOKEN", v), v)

    def test_vscode_env_placeholder_in_mcp_json(self):
        import tempfile
        cfg = {"servers": {"s": {"command": "node", "args": ["srv.js"],
                                 "env": {"API_TOKEN": "${env:API_TOKEN}"},
                                 "headers": {"Authorization": "Bearer ${env:API_TOKEN}"}}}}
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".vscode").mkdir()
            (Path(d) / ".vscode/mcp.json").write_text(json.dumps(cfg))
            self.assertFalse([f for f in rules(Path(d)) if f.rule == "MCP001"])
            cfg["servers"]["s"]["env"]["API_TOKEN"] = "abcd1234efgh5678ijkl9012"
            (Path(d) / ".vscode/mcp.json").write_text(json.dumps(cfg))
            self.assertTrue([f for f in rules(Path(d)) if f.rule == "MCP001"])

    def test_bypass_star(self):
        out = []
        agentlint.check_settings("s", {"permissions": {"allow": ["Bash(*)"]}}, "", out)
        self.assertIn("CC002", {f.rule for f in out})


class Wildcards(unittest.TestCase):
    def check(self, rule):
        out = []
        agentlint.check_settings("s", {"permissions": {"allow": [rule], "deny": ["Read(.env)"]}}, "", out)
        return {f.rule for f in out}

    def test_exact_commands_pass(self):
        for r in ["Bash(bash scripts/restart.sh)", "Bash(python3 tools/check.py)", "Bash(git push)",
                  "Bash(sudo which:*)", "Bash(npm test)"]:
            self.assertEqual(self.check(r), set(), r)

    def test_open_runners_flagged(self):
        for r in ["Bash(python3:*)", "Bash(sudo:*)", "Bash(sudo bash:*)", "Bash(ssh host:*)", "Bash(rm:*)",
                  "Bash(git push:*)"]:
            self.assertIn("CC003", self.check(r), r)


if __name__ == "__main__":
    unittest.main()
