import json
import subprocess
import unittest
from unittest.mock import patch

import aap_ui
import review_python


class ReviewerResponseTests(unittest.TestCase):
    def run_agent(self, payload, agent="codex"):
        output = json.dumps(payload)
        if agent == "claude":
            output = json.dumps({"result": output})
        with patch.object(review_python, "_find_agent", return_value=agent), patch.object(
            review_python.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            return review_python.review("print(1)", agent=agent)

    def test_both_agents_preserve_separate_fields(self):
        for agent in ("codex", "claude"):
            for decision, reason in (("accept", ""), ("reject", "Uses eval. Replace it with json.loads.")):
                with self.subTest(agent=agent, decision=decision):
                    payload = {"decision": decision, "explanation": "Parses input.", "deny_reason": reason}
                    self.assertEqual(self.run_agent(payload, agent), payload)

    def test_invalid_response_fails_closed(self):
        for payload in (
            {"decision": "accept", "comment": "Safe"},
            {"decision": "accept", "explanation": {}, "deny_reason": ""},
            {"decision": "accept", "explanation": "Prints 1.", "deny_reason": "Unsafe"},
            {"decision": "reject", "explanation": "Uses eval.", "deny_reason": ""},
        ):
            with self.subTest(payload=payload):
                result = self.run_agent(payload)
                self.assertEqual(result["decision"], "reject")
                self.assertEqual(set(result), {"decision", "explanation", "deny_reason"})
                self.assertTrue(result["deny_reason"])

    def test_operational_errors_keep_response_shape(self):
        expected = {"decision", "explanation", "deny_reason"}
        self.assertEqual(set(review_python.review("")), expected)
        with patch.object(review_python, "_find_agent", return_value=None):
            self.assertEqual(set(review_python.review("print(1)")), expected)
        with patch.object(review_python, "_find_agent", return_value="codex"), patch.object(
            review_python.subprocess, "run", side_effect=subprocess.TimeoutExpired("codex", 25),
        ):
            result = review_python.review("print(1)")
            self.assertEqual(set(result), expected)
            self.assertEqual(result["decision"], "reject")

    def test_ui_keeps_description_out_of_deny_reason(self):
        payload = {"decision": "reject", "explanation": "Evaluates input.", "deny_reason": "Uses eval. Use json.loads instead."}
        with patch.object(aap_ui.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
            result = aap_ui.run_python_review(["reviewer"], "eval(data)")
        self.assertEqual(result["explanation"], payload["explanation"])
        self.assertEqual(result["deny_reason"], payload["deny_reason"] + " " + aap_ui.SIMPLE_SCRIPT_HINT)
        self.assertNotIn(payload["explanation"], result["deny_reason"])

    def test_ui_acceptance_has_no_deny_hint(self):
        payload = {"decision": "accept", "explanation": "Prints 1.", "deny_reason": ""}
        with patch.object(aap_ui.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
            result = aap_ui.run_python_review(["reviewer"], "print(1)")
        self.assertEqual(result, {**payload, "decision": "approved"})

    def test_ui_invalid_response_fails_closed(self):
        with patch.object(aap_ui.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{"decision":"accept"}', "")):
            result = aap_ui.run_python_review(["reviewer"], "print(1)")
        self.assertEqual(result["decision"], "denied")
        self.assertTrue(result["deny_reason"].endswith(aap_ui.SIMPLE_SCRIPT_HINT))


if __name__ == "__main__":
    unittest.main()
