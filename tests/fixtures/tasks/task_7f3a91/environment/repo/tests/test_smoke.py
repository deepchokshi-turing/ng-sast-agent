"""Functional smoke tests for the copilot (no security assertions)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["OUTBOX_PATH"] = str(Path(self.tmp.name) / "outbox.jsonl")
        from support_copilot import config
        config.settings.cache_clear()

    def tearDown(self):
        self.tmp.cleanup()

    def test_answer_returns_text(self):
        from support_copilot.agent import handle_request
        from support_copilot.users import load_user

        result = handle_request(load_user("u-acme-agent-3"), "Where is the refund for order 88213?")
        self.assertIn("Summary", result["answer"])

    def test_email_is_sent_to_requesting_user(self):
        from support_copilot.agent import handle_request
        from support_copilot.users import load_user

        user = load_user("u-acme-agent-3")
        result = handle_request(user, "Email me a summary of my shipping tickets")
        self.assertEqual(result["tool_results"][0]["to"], user.verified_email)


if __name__ == "__main__":
    unittest.main()
