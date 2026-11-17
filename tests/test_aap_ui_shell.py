from pathlib import Path
import tempfile
import shlex
import unittest
import time
from unittest.mock import patch

import aap_ui


class ShellPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reviewer = patch("aap_ui.run_python_review", return_value={
            "decision": "approved", "explanation": "Prints a value.", "deny_reason": "",
        })
        reviewer.start()
        self.addCleanup(reviewer.stop)
        self.addCleanup(self.wait_for_reviews)
        self.hub = aap_ui.ApprovalHub(aap_ui.RuleStore(Path(tmp.name) / "rules.json"))

    def wait_for_reviews(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.hub._cond:
                targets = [
                    target
                    for record in self.hub._requests.values()
                    for target in [record, *(record.get("subcommands") or [])]
                ]
                if not any((target.get("review") or {}).get("status") == "running" for target in targets):
                    return
            time.sleep(0.01)
        self.fail("Background reviews did not finish")

    def request(self, command):
        record, _ = self.hub.create_request(
            {"tool": "Bash", "arguments": {"command": command}},
            str(len(self.hub._requests)),
        )
        return record

    def test_unsupported_syntax_is_denied_before_tool_rules(self):
        self.hub.rules.add_rule(aap_ui.Rule(
            id="allow-bash", kind="tool", tool="Bash", action="allow"
        ))
        commands = (
            "for x in 1 2; do echo x; done", "while true; do echo x; done",
            "if true; then echo yes; fi", "case x in x) echo yes;; esac",
            "f() { echo hi; }; f", "(echo hi)", "{ echo hi; }",
            "echo $(whoami)", 'echo "$(whoami)"', "echo `whoami`",
            "cat <(echo hi)", "echo hi >(cat)",
            "cat <<EOF\nhello\nEOF", "cat <<END\nhello\nEND",
            "cat <<-EOF\n\thello\nEOF", "cat <<'EOF'\nhello\nEOF",
            'cat <<< "hello"', "echo hi &", "echo hi |& cat",
            "S=/tmp", "S=/tmp && echo hi", 'echo "$S"', "echo $HOME",
            "echo $((1+2))", "ls *.py", "echo file?.txt", "echo [ab]",
            "echo {a,b}", "ls ~/tmp", "echo hi # comment",
            "echo 'unterminated", "echo trailing\\", "echo hi &&",
            "echo hi |", "&& echo hi", "echo hi && || echo bye",
            "echo hi >", "echo hi; ; echo bye", "", "\n",
            "echo hi && >/dev/null\necho bye",
            "f\\\nor x in a; do echo hi; done",
            "coproc echo hi", "echo hi\vthere", "echo hi\rthere",
        )
        for command in commands:
            with self.subTest(command=command):
                record = self.request(command)
                self.assertEqual(record["status"], "denied")
                self.assertEqual(record["decision"]["reason"], aap_ui.UNSUPPORTED_SHELL_REASON)
                self.assertFalse(record["in_queue"])
                self.assertEqual(record["subcommands"], [])

    def test_quoted_metacharacters_are_literal(self):
        for command in (
            "echo '$HOME *.py {a,b} ~ $(whoami) `whoami`'",
            'echo "a && b | c; d <<EOF"', r"echo \$HOME \* \~ \(x\)",
            "FOO='two words' cmd --flag",
            "python3 -c 'print(\"<<EOF $HOME *.py\")'",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.request(command)["status"], "pending")

    def test_chain_operators_and_original_source_are_preserved(self):
        command = "FOO='a b' first && second || third; fourth | fifth\nsixth"
        record = self.request(command)
        self.assertEqual(record["arguments"]["command"], command)
        self.assertEqual(
            [sc["operator_after"] for sc in record["subcommands"]],
            ["&&", "||", ";", "|", "\n", ""],
        )

    def test_bash_quoting_and_escaping_are_decoded_without_evaluation(self):
        part, = aap_ui.parse_shell_command(r'''echo "\$HOME" "a\qb" 'x"y' a\ b''')
        self.assertEqual(part.words, ["echo", "$HOME", r"a\qb", 'x"y', "a b"])
        self.assertFalse(aap_ui._command_matches_prefix(
            "'FOO=bar' cmd", "FOO=bar cmd *"
        ))

    def test_pipeline_requires_both_approvals(self):
        record = self.request("first | second")
        record = self.hub.decide_request(record["id"], "approved", sub_index=0)
        self.assertEqual(record["status"], "pending")
        record = self.hub.decide_request(record["id"], "approved", sub_index=1)
        self.assertEqual(record["status"], "approved")
        record = self.request("first | other")
        record = self.hub.decide_request(record["id"], "denied", sub_index=1)
        self.assertEqual(record["status"], "denied")

    def test_python_requires_one_time_approval_even_with_existing_allow_rule(self):
        for kind, prefix in (("tool", ""), ("command_prefix", "python3 *")):
            self.hub.rules.add_rule(aap_ui.Rule(
                id=kind, kind=kind, tool="Bash", action="allow", prefix=prefix
            ))
        for command in ("python3 -c " + shlex.quote("print(1)\n# line 2\n# line 3\n# line 4"),
                        "FOO=bar python3 -c " + shlex.quote("print(1)\n# line 2\n# line 3\n# line 4")):
            with self.subTest(command=command):
                record = self.request(command)
                self.assertEqual(record["status"], "pending")
                before = len(self.hub.rules.list_rules())
                decided = self.hub.decide_request(
                    record["id"], "approved", allow_always="prefix", prefix="python3 *"
                )
                self.assertEqual(decided["status"], "approved")
                self.assertEqual(len(self.hub.rules.list_rules()), before)
                self.assertEqual(self.request(command)["status"], "pending")


if __name__ == "__main__":
    unittest.main()
