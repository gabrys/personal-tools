"""Contract for command-local environment assignments in approval parsing."""

import shlex
import unittest

import aap_ui


class CommandEnvironmentTests(unittest.TestCase):
    def test_assignments_stay_attached_to_the_command(self):
        commands = [
            "FOO=bar cmd --flag",
            "FOO=bar CI=1 cmd --flag",
            "FOO= cmd",
            "_NAME2=value cmd",
            "FOO='two words' cmd",
            'FOO="a && b; c | d" cmd',
            "FOO='first\nsecond' cmd",
            r"FOO=two\ words cmd",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(aap_ui.split_compound_command(command), [command])

    def test_assignments_are_local_to_each_chain_or_pipeline_part(self):
        for separator in (" && ", " || ", "; ", "\n", " | "):
            with self.subTest(separator=separator):
                self.assertEqual(
                    aap_ui.split_compound_command(
                        "FOO='a | b' cmd --flag" + separator + "OTHER=two next"
                    ),
                    ["FOO='a | b' cmd --flag", "OTHER=two next"],
                )

    def test_redirections_remain_with_the_environment_and_command(self):
        self.assertEqual(
            aap_ui.split_compound_command(
                "CI=1 pytest -q 2>&1 | LABEL=tests tail -1"
            ),
            ["CI=1 pytest -q 2>&1", "LABEL=tests tail -1"],
        )

    def test_bare_command_rule_does_not_allow_environment_changes(self):
        for command in (
            "CI=1 git status",
            "PATH=/tmp/bin git status",
            "LD_PRELOAD=/tmp/custom.so git status",
        ):
            with self.subTest(command=command):
                self.assertFalse(
                    aap_ui._command_matches_prefix(command, "git status *")
                )

    def test_environment_rule_includes_values_and_all_assignments(self):
        prefix = "FOO=bar CI=1 cmd *"
        self.assertTrue(aap_ui._command_matches_prefix("FOO=bar CI=1 cmd", prefix))
        self.assertTrue(
            aap_ui._command_matches_prefix("FOO=bar CI=1 cmd --flag", prefix)
        )
        for command in (
            "FOO=other CI=1 cmd",
            "FOO=bar CI=0 cmd",
            "FOO=bar cmd",
            "cmd",
            "FOO=bar CI=1 LD_PRELOAD=/tmp/custom.so cmd",
            "FOO=bar CI=1 other",
        ):
            with self.subTest(command=command):
                self.assertFalse(aap_ui._command_matches_prefix(command, prefix))

    def test_quoted_assignment_values_match_without_losing_word_boundaries(self):
        self.assertTrue(
            aap_ui._command_matches_prefix(
                'FOO="two words" cmd --flag', "FOO='two words' cmd *"
            )
        )
        self.assertFalse(
            aap_ui._command_matches_prefix(
                "FOO=two words cmd --flag", "FOO='two words' cmd *"
            )
        )

    def test_generated_prefixes_include_environment_and_executable(self):
        command = "FOO='two words' CI=1 cmd --flag"
        _, interactive_prefixes = aap_ui.command_tokens_and_prefixes(command)
        suggested_prefixes = aap_ui.suggest_command_prefixes(command)
        required_words = ["FOO=two words", "CI=1", "cmd"]
        for source, prefixes in (
            ("interactive", interactive_prefixes),
            ("suggested", suggested_prefixes),
        ):
            with self.subTest(source=source):
                self.assertTrue(prefixes)
                for prefix in prefixes:
                    with self.subTest(prefix=prefix):
                        self.assertEqual(shlex.split(prefix)[:3], required_words)

    def test_inline_python_is_detected_after_environment_assignments(self):
        script = 'import os; print(os.environ["FOO"])'
        for assignments in ("FOO=bar", "FOO='two words' CI=1", "FOO="):
            with self.subTest(assignments=assignments):
                self.assertEqual(
                    aap_ui.extract_python_c_script(
                        f"{assignments} python3 -c {shlex.quote(script)}"
                    ),
                    script,
                )

    def test_assignment_arguments_are_not_treated_as_environment_prefixes(self):
        self.assertIsNone(
            aap_ui.extract_python_c_script("echo FOO=bar python3 -c 'print(1)'")
        )
        self.assertIsNone(
            aap_ui.extract_python_c_script("FOO=bar echo python3 -c 'print(1)'")
        )


if __name__ == "__main__":
    unittest.main()
