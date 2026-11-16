"""File redirections must use file operations checked by path-based rules."""

from pathlib import Path
import tempfile
import unittest

import aap_ui


FILE_REDIRECTION_REASON = (
    "File redirections are not supported. Perform file operations separately "
    "using tools whose file access is checked against path-based rules."
)


class FileRedirectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.hub = aap_ui.ApprovalHub(
            aap_ui.RuleStore(Path(self.tmp.name) / "rules.json")
        )
        # A broad command rule must not bypass the file-access policy.
        self.hub.rules.add_rule(
            aap_ui.Rule(
                id="allow-git-status", kind="command_prefix", tool="Bash",
                action="allow", prefix="git status *",
            )
        )

    def request(self, command):
        record, _ = self.hub.create_request(
            {"tool": "Bash", "arguments": {"command": command}}, command
        )
        return record

    def test_file_redirections_are_denied_with_path_rule_guidance(self):
        for command in (
            "git status > output.txt",
            "git status >> output.txt",
            "git status 2> errors.txt",
            "git status 2>> errors.txt",
            "git status &> output.txt",
            "git status &>> output.txt",
            "git status < input.txt",
            "git status <> data.txt",
            "git status >| output.txt",
            "git status>output.txt",
            "git status > 'file with spaces.txt'",
            "git status >/dev/null 2>errors.txt",
            "git status >/dev/null && git status > output.txt",
            "git status | git status > output.txt",
        ):
            with self.subTest(command=command):
                record = self.request(command)
                self.assertEqual(record["status"], "denied")
                self.assertEqual(
                    record["decision"]["reason"], FILE_REDIRECTION_REASON
                )
                self.assertFalse(record["in_queue"])

    def test_fd_duplication_and_discarding_output_are_allowed(self):
        for suffix in (
            "2>&1", "1>&2", ">/dev/null", "2>/dev/null",
            ">>/dev/null", "&>/dev/null", ">/dev/null 2>&1",
        ):
            with self.subTest(suffix=suffix):
                record = self.request("git status " + suffix)
                self.assertEqual(record["status"], "approved")

    def test_quoted_and_escaped_operators_are_arguments(self):
        for argument in (
            "'>'", "'2>errors.txt'", '"<input.txt"', r"\>output.txt",
        ):
            with self.subTest(argument=argument):
                record = self.request("git status " + argument)
                self.assertEqual(record["status"], "approved")


if __name__ == "__main__":
    unittest.main()
