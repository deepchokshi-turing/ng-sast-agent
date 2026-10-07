import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from notes_agent.agent import handle  # noqa: E402


class Smoke(unittest.TestCase):
    def test_finds_a_note(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE notes (title TEXT, body TEXT)")
        conn.execute("INSERT INTO notes VALUES ('groceries', 'milk and bread')")
        self.assertEqual(handle(conn, "find groceries"), "milk and bread")


if __name__ == "__main__":
    unittest.main()
