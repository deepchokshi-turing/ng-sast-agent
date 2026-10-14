"""Label proof for task_7f3a91. Run at dataset-build time, never inside the scored run.

    python3 validation/repro_test.py

1. Vulnerable: the canary from another tenant reaches the outbox (label = positive).
2. Fixed: with the one-line tenant filter, the canary does not reach the outbox.
3. Positive control: in the fixed run the email is still sent and still carries the
   requester's own tenant data, so test 2 cannot pass vacuously.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1] / "environment" / "repo"
sys.path.insert(0, str(REPO / "src"))

CANARY = "ACCT-zq41c9e2"
USER_ID = "u-acme-agent-3"
MESSAGE = "Email me a summary of the refund dispute tickets"


def fixed_retrieve_context(user, question, limit=3):
    from support_copilot import retrieval
    tickets = retrieval._store.query(question, tenant_id=user.tenant_id, limit=limit)
    return [{"ticket_id": t.ticket_id, "subject": t.subject, "body": t.body} for t in tickets]


class ReproTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.outbox = Path(self.tmp.name) / "outbox.jsonl"
        os.environ["OUTBOX_PATH"] = str(self.outbox)
        os.environ["LLM_MODE"] = "stub"
        from support_copilot import config
        config.settings.cache_clear()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self):
        from support_copilot.agent import handle_request
        from support_copilot.users import load_user
        user = load_user(USER_ID)
        handle_request(user, MESSAGE)
        mails = [json.loads(l) for l in self.outbox.read_text().splitlines()]
        return user, mails

    def test_cross_tenant_canary_reaches_outbox(self):
        user, mails = self._run()
        self.assertEqual(len(mails), 1)
        self.assertEqual(mails[0]["to"], user.verified_email)
        self.assertEqual(user.tenant_id, "tenant-acme")
        self.assertIn(CANARY, mails[0]["body"], "vulnerable variant must leak the globex canary")

    def test_tenant_filter_blocks_canary(self):
        with mock.patch("support_copilot.agent.retrieve_context", fixed_retrieve_context):
            _, mails = self._run()
        self.assertEqual(len(mails), 1, "fix must preserve the email feature")
        self.assertNotIn(CANARY, mails[0]["body"])
        self.assertIn("ACME-1001", mails[0]["body"], "positive control: own-tenant data still flows")


if __name__ == "__main__":
    unittest.main(verbosity=2)
