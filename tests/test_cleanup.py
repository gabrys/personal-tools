import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


loader = importlib.machinery.SourceFileLoader(
    "cleanup", str(Path(__file__).resolve().parents[1] / "codex-prefix-cleanup")
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
        result, count = self.simplify(source, ["y", "n", "y", "y"])
        self.assertEqual(count, 3)
        self.assertIn('pattern=["git", "add"], decision="allow")', result)
        self.assertIn("# keep", result)
        self.assertNotIn('"xyz"', result)
        self.assertIn('pattern=["git", "commit", "-m"]', result)
        self.assertIn('decision="forbidden"', result)
        self.assertIn('# Unicode header — preserved', result)
        self.assertEqual(self.simplify(result, ["n"]), (result, 0))

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
            return "n"

        with contextlib.redirect_stdout(output):
            result = cleanup.simplify(source, ask)
        self.assertEqual(result, (source, 0))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(len(prompts), 2)
        self.assertEqual(prompts[0], 'Allow "git add ..."? [Y/n] ')
        for prompt in prompts:
            self.assertEqual(len(prompt.splitlines()), 1)
            self.assertTrue(prompt.startswith('Allow "git '))
            self.assertTrue(prompt.endswith(' ..."? [Y/n] '))

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
        answers = iter(["y", "y", "n"])

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result, count = cleanup.simplify(source, ask)
        self.assertEqual(count, 1)
        self.assertEqual(result.count("prefix_rule"), 2)
        self.assertEqual(prompts, [
            'Allow "git add ..."? [Y/n] ',
            'Add 1 rule(s)? [y/N] ',
            'Remove 1 rule(s) covered by shorter prefixes? [y/N] ',
        ])

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
