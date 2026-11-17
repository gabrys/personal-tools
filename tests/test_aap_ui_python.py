import shlex
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import aap_ui


class PythonRequestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rules = aap_ui.RuleStore(Path(self.tmp.name) / "rules.json")
        self.hub = aap_ui.ApprovalHub(self.rules)
        self.started = threading.Event()
        self.finished = threading.Event()
        self.review_patch = patch("aap_ui.run_python_review", side_effect=self.fake_review)
        self.runner = self.review_patch.start()
        self.addCleanup(self.review_patch.stop)

    def fake_review(self, command, script):
        self.started.set()
        return {"decision": "approved", "explanation": "Prints a value.", "deny_reason": ""}

    def request(self, script, key=None, suffix=""):
        return self.hub.create_request(
            {"tool": "Bash", "arguments": {"command": "python3 -c " + shlex.quote(script) + suffix}},
            key or str(len(self.hub._requests)),
        )[0]

    def wait_review(self, req_id, sub_index=None):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            record = self.hub.get_request(req_id)
            target = record if sub_index is None else record["subcommands"][sub_index]
            if (target.get("review") or {}).get("status") == "done":
                return record
            time.sleep(0.01)
        self.fail("Review did not finish")

    def test_exact_thresholds_and_raw_extraction(self):
        for script, expected in (
            ("#" * 200, False),
            ("#" * 201, True),
            ("print(1)\nprint(2)", False),
            ("print(1)\nprint(2)\n", False),
            ("print(1)\nprint(2)\nprint(3)", False),
            ("print(1)\nprint(2)\nprint(3)\n", False),
            ("print(1)\nprint(2)\nprint(3)\nprint(4)", True),
        ):
            with self.subTest(script=script):
                command = "python3 -c " + shlex.quote(script)
                self.assertEqual(aap_ui.extract_python_c_script(command), script)
                self.assertEqual(aap_ui.extract_reviewable_python_script(command), script if expected else None)

    def test_short_python_is_regular_command_and_can_create_rule(self):
        record = self.request("print(1)")
        self.assertIsNone(record["python_script"])
        self.assertIsNone(record["review"])
        self.runner.assert_not_called()
        accepted = self.hub.decide_request(record["id"], "approved")
        self.assertIn("rule_id", accepted["decision"])
        self.assertEqual(self.request("print(1)")["status"], "approved")

    def test_short_python_matches_existing_tool_rule(self):
        self.rules.add_rule(aap_ui.Rule(id="allow", kind="tool", tool="Bash", action="allow"))
        self.assertEqual(self.request("print(1)")["status"], "approved")
        self.runner.assert_not_called()

    def test_long_script_auto_review_is_idempotent_and_stays_pending(self):
        script = "print(1)\nprint(2)\nprint(3)\nprint(4)"
        self.request(script, key="same")
        record = self.request(script, key="same")
        done = self.wait_review(record["id"])
        self.assertEqual(done["status"], "pending")
        self.assertEqual(done["review"]["decision"], "approved")
        self.assertEqual(done["python_script"], script)
        self.runner.assert_called_once()
        self.assertEqual(self.rules.list_rules(), [])

    def test_long_script_never_creates_rules(self):
        script = "#" * 201
        for mode in (None, "exact", "prefix", "tool"):
            with self.subTest(mode=mode):
                record = self.request(script)
                self.wait_review(record["id"])
                accepted = self.hub.decide_request(record["id"], "approved", allow_always=mode, prefix="python3 *")
                self.assertEqual(accepted["status"], "approved")
                self.assertNotIn("rule_id", accepted["decision"])
                self.assertEqual(self.rules.list_rules(), [])

    def test_compound_reviews_only_long_python_step(self):
        long = "print(1)\nprint(2)\nprint(3)\nprint(4)"
        record = self.request("print(0)", suffix="; python3 -c " + shlex.quote(long) + "; echo done")
        done = self.wait_review(record["id"], 1)
        self.assertIsNone(done["subcommands"][0]["python_script"])
        self.assertIsNone(done["subcommands"][0]["review"])
        self.assertEqual(done["subcommands"][1]["python_script"], long)
        self.assertIsNone(done["subcommands"][2]["review"])
        self.runner.assert_called_once()

    def test_denied_requests_do_not_start_review(self):
        self.rules.add_rule(aap_ui.Rule(id="deny", kind="tool", tool="Bash", action="deny"))
        self.assertEqual(self.request("#" * 201)["status"], "denied")
        self.runner.assert_not_called()

    def test_reload_removes_legacy_short_script_classification(self):
        record = self.request("print(1)")
        self.hub._requests[record["id"]]["python_script"] = "print(1)"
        self.hub._requests[record["id"]]["review"] = {"status": "done", "decision": "denied"}
        self.hub._save_queue()
        reloaded = aap_ui.ApprovalHub(self.rules).get_request(record["id"])
        self.assertIsNone(reloaded["python_script"])
        self.assertNotIn("review", reloaded)


    def block_review(self):
        def delayed(command, script):
            self.started.set()
            self.finished.wait(2)
            return {"decision": "approved", "explanation": "Prints a value.", "deny_reason": ""}
        self.started.clear()
        self.finished.clear()
        self.runner.side_effect = delayed

    def test_visibility_deadline_uses_arrival_and_not_retry_time(self):
        self.block_review()
        with patch("aap_ui.time.time", return_value=1000.0) as clock, patch("aap_ui.threading.Timer") as timer:
            record = self.request("#" * 201, key="same")
            try:
                self.assertTrue(self.started.wait(1))
                self.assertEqual(self.hub.ui_state()["pending"], [])
                self.assertEqual(self.hub.get_request(record["id"])["status"], "pending")
                clock.return_value = 1005.0
                self.request("#" * 201, key="same")
                self.assertEqual(self.hub.get_request(record["id"])["ui_visible_after"], 1010.0)
                clock.return_value = 1009.999
                self.assertEqual(self.hub.ui_state()["pending"], [])
                clock.return_value = 1010.0
                self.assertEqual(self.hub.ui_state()["pending"][0]["id"], record["id"])
                self.assertEqual(timer.call_args.args[0], 10.0)
                subscriber = self.hub.subscribe()
                timer.call_args.args[1]()
                self.assertEqual(subscriber.get_nowait(), "update")
                self.hub.unsubscribe(subscriber)
            finally:
                self.finished.set()
                self.wait_review(record["id"])

    def test_ready_review_is_visible_early_and_does_not_hide_on_rereview(self):
        self.block_review()
        with patch("aap_ui.time.time", return_value=1000.0) as clock, patch("aap_ui.threading.Timer"):
            record = self.request("#" * 201)
            try:
                self.assertTrue(self.started.wait(1))
                self.assertEqual(self.hub.ui_state()["pending"], [])
                clock.return_value = 1002.0
                self.finished.set()
                self.wait_review(record["id"])
                self.assertEqual(self.hub.ui_state()["pending"][0]["id"], record["id"])
                self.block_review()
                self.hub.review_request(record["id"])
                self.assertTrue(self.started.wait(1))
                self.assertEqual(self.hub.ui_state()["pending"][0]["id"], record["id"])
            finally:
                self.finished.set()
                self.wait_review(record["id"])

    def test_regular_request_is_visible_immediately(self):
        with patch("aap_ui.time.time", return_value=1000.0), patch("aap_ui.threading.Timer") as timer:
            record = self.request("print(1)")
            self.assertEqual(self.hub.ui_state()["pending"][0]["id"], record["id"])
            timer.assert_not_called()

    def test_visibility_deadline_survives_reload(self):
        self.block_review()
        with patch("aap_ui.time.time", return_value=1000.0) as clock, patch("aap_ui.threading.Timer"):
            record = self.request("#" * 201)
            try:
                self.assertTrue(self.started.wait(1))
                reloaded = aap_ui.ApprovalHub(self.rules)
                clock.return_value = 1009.0
                self.assertEqual(reloaded.ui_state()["pending"], [])
                clock.return_value = 1010.0
                self.assertEqual(reloaded.ui_state()["pending"][0]["id"], record["id"])
            finally:
                self.finished.set()
                self.wait_review(record["id"])

if __name__ == "__main__":
    unittest.main()
