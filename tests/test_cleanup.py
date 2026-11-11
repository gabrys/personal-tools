import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


loader = importlib.machinery.SourceFileLoader(
    "cleanup", str(Path(__file__).resolve().parents[1] / "prefix-cleanup")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
cleanup = importlib.util.module_from_spec(spec)
loader.exec_module(cleanup)


class CleanupTests(unittest.TestCase):
    def simplify(self, source, answers):
        replies = iter(answers)
        with contextlib.redirect_stdout(io.StringIO()):
            return cleanup.simplify(source, lambda _: next(replies))

    def test_groups_and_keeps_refused_rules_and_comments(self):
        source = ('# Unicode header — preserved\n'
                  'prefix_rule(pattern=["git", "add", "abc"], decision="allow") # keep\n'
                  'prefix_rule(pattern=["git", "add", "xyz"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "commit", "-m"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "add", "secret"], decision="forbidden")\n')
        result, count = self.simplify(source, ["a", "s", "y", "y"])
        self.assertEqual(count, 3)
        self.assertIn('pattern=["git", "add"], decision="allow")', result)
        self.assertIn("# keep", result)
        self.assertNotIn('"xyz"', result)
        self.assertIn('pattern=["git", "commit", "-m"]', result)
        self.assertIn('decision="forbidden"', result)
        self.assertIn('# Unicode header — preserved', result)
        self.assertEqual(self.simplify(result, ["s"]), (result, 0))

    def test_existing_short_rule_and_multiline_unicode(self):
        source = ('prefix_rule(pattern=["café", "add"], decision="allow")\n'
                  'prefix_rule(\n pattern=["café", "add", "a"],\n decision="allow") # comment\n')
        result, count = self.simplify(source, ["yes"])
        self.assertEqual(count, 1)
        self.assertEqual(result.count("prefix_rule"), 1)
        self.assertIn("# comment", result)
        self.assertEqual(cleanup.proposals(result), {})

    def test_no_execution_and_unknown_attributes_untouched(self):
        source = ('raise RuntimeError("must not execute")\n'
                  'prefix_rule(pattern=["git", "add", "a"], decision="allow", extra=True)\n')
        self.assertEqual(self.simplify(source, []), (source, 0))

    def test_each_proposal_is_one_english_line(self):
        source = ('prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "log\\n", "b"], decision="allow")\n')
        prompts = []
        output = io.StringIO()

        def ask(prompt):
            prompts.append(prompt)
            return "s"

        with contextlib.redirect_stdout(output):
            result = cleanup.simplify(source, ask)
        self.assertEqual(result, (source, 0))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(len(prompts), 2)
        self.assertEqual(prompts[0], 'Prefix "git add ..."? [A]llow [p]rompt [d]eny [s]kip [v]iew [l]onger ')
        for prompt in prompts:
            self.assertEqual(len(prompt.splitlines()), 1)
            self.assertTrue(prompt.startswith('Prefix "git '))
            self.assertTrue(prompt.endswith(' ..."? [A]llow [p]rompt [d]eny [s]kip [v]iew [l]onger '))

    def test_enter_accepts_proposal(self):
        source = 'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
        result, count = self.simplify(source, ["", "y", "n"])
        self.assertEqual(count, 1)
        self.assertIn('pattern=["git", "add"]', result)

    def test_add_confirmation_defaults_to_no(self):
        source = 'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
        self.assertEqual(self.simplify(source, ["", ""]), (source, 0))

    def test_existing_prefix_cleanup_is_independent(self):
        source = ('prefix_rule(pattern=["git"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n')
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return "y"

        result, count = cleanup.simplify(source, ask)
        self.assertEqual(prompts, ['Remove 1 rule(s) covered by shorter prefixes? [y/N] '])
        self.assertEqual(count, 1)
        self.assertNotIn('"add"', result)
        self.assertEqual(self.simplify(source, [""]), (source, 0))

    def test_add_and_delete_confirmations_are_separate(self):
        source = 'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
        prompts = []
        answers = iter(["a", "y", "n"])

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result, count = cleanup.simplify(source, ask)
        self.assertEqual(count, 1)
        self.assertEqual(result.count("prefix_rule"), 2)
        self.assertEqual(prompts, [
            'Prefix "git add ..."? [A]llow [p]rompt [d]eny [s]kip [v]iew [l]onger ',
            'Add 1 rule(s)? [y/N] ',
            'Remove 1 rule(s) covered by shorter prefixes? [y/N] ',
        ])

    def test_prompt_option_adds_prompt_rule_and_keeps_allow_rules(self):
        source = ('prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "push", "x"], decision="allow")\n')
        prompts = []
        answers = iter(["p", "prompt", "y"])

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result, count = cleanup.simplify(source, ask)
        self.assertEqual(count, 2)
        self.assertIn('prefix_rule(pattern=["git", "add"], decision="prompt")', result)
        self.assertIn('prefix_rule(pattern=["git", "push"], decision="prompt")', result)
        # Prompt rules do not make longer allow rules redundant.
        self.assertIn('pattern=["git", "add", "a"]', result)
        self.assertIn('pattern=["git", "push", "x"]', result)
        self.assertEqual(len(prompts), 3)
        # Prefixes that already have a prompt rule are not proposed again.
        self.assertEqual(cleanup.proposals(result), {})

    def test_deny_adds_forbidden_rule_and_unknown_answer_asks_again(self):
        source = 'prefix_rule(pattern=["rm", "-rf", "build"], decision="allow")\n'
        prompts = []
        answers = iter(["x", "D", "y"])

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result, count = cleanup.simplify(source, ask)
        self.assertEqual(count, 1)
        self.assertIn('prefix_rule(pattern=["rm", "-rf"], decision="forbidden")', result)
        self.assertEqual(prompts[0], prompts[1])
        self.assertEqual(cleanup.proposals(result), {})

    def test_view_shows_rules_behind_proposal_and_asks_again(self):
        source = ('# header\n'
                  'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
                  'prefix_rule(pattern=["git", "status"], decision="allow")\n'
                  'prefix_rule(\n pattern=["git", "add", "b"],\n decision="allow")\n')
        prompts = []
        answers = iter(["v", "s"])
        output = io.StringIO()

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        with contextlib.redirect_stdout(output):
            result = cleanup.simplify(source, ask)
        self.assertEqual(result, (source, 0))
        self.assertEqual(prompts[0], prompts[1])
        self.assertEqual(output.getvalue(),
                         '  git add a\n'
                         '  git add b\n')

    def test_shell_command_is_readable_and_single_line(self):
        self.assertEqual(cleanup.shell_command(["git", "commit", "-m", "fix bug"]),
                         "git commit -m 'fix bug'")
        self.assertEqual(cleanup.shell_command(["printf", "a\nb"]), "printf $'a\\nb'")

    def test_longer_splits_proposal_into_longer_prefixes(self):
        source = ('prefix_rule(pattern=["python3", "-m", "unittest"], decision="allow")\n'
                  'prefix_rule(pattern=["python3", "-m", "py_compile", "a.py"], decision="allow")\n'
                  'prefix_rule(pattern=["python3", "-m", "py_compile", "b.py"], decision="allow")\n'
                  'prefix_rule(pattern=["python3", "-m", "http.server", "8000"], decision="allow")\n')
        prompts = []
        answers = iter(["l", "a", "s", "y", "y"])

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result, count = cleanup.simplify(source, ask)
        self.assertEqual([prompt.split("?")[0] for prompt in prompts[:3]], [
            'Prefix "python3 -m ..."',
            'Prefix "python3 -m py_compile ..."',
            'Prefix "python3 -m http.server ..."',
        ])
        self.assertEqual(count, 3)
        self.assertIn('prefix_rule(pattern=["python3", "-m", "py_compile"], decision="allow")',
                      result)
        self.assertNotIn('"a.py"', result)
        self.assertNotIn('"b.py"', result)
        self.assertIn('pattern=["python3", "-m", "unittest"]', result)
        self.assertIn('"http.server", "8000"', result)
        self.assertNotIn('pattern=["python3", "-m"]', result)

    def test_longer_without_longer_prefix_asks_again(self):
        source = 'prefix_rule(pattern=["git", "add", "a"], decision="allow")\n'
        prompts = []
        answers = iter(["l", "s"])
        output = io.StringIO()

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        with contextlib.redirect_stdout(output):
            self.assertEqual(cleanup.simplify(source, ask), (source, 0))
        self.assertEqual(prompts[0], prompts[1])
        self.assertEqual(output.getvalue(), "  No longer prefix to propose.\n")

    def test_backup_and_concurrent_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "default.rules"
            path.write_bytes(b"original\r\n")
            backup = cleanup.save(path, b"original\r\n", "updated\r\n")
            self.assertEqual(backup.read_bytes(), b"original\r\n")
            self.assertEqual(path.read_bytes(), b"updated\r\n")
            with self.assertRaises(OSError):
                cleanup.save(path, b"original\r\n", "overwrite")
            self.assertEqual(path.read_bytes(), b"updated\r\n")


if __name__ == "__main__":
    unittest.main()
