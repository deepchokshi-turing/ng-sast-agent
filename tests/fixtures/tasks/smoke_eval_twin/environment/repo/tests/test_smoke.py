import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from calc_agent.agent import handle  # noqa: E402


class Smoke(unittest.TestCase):
    def test_answers(self):
        self.assertEqual(handle("what is two plus two"), "4")


if __name__ == "__main__":
    unittest.main()
