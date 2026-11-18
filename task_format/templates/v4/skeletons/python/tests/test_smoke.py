import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from app.__main__ import main  # noqa: E402


class Smoke(unittest.TestCase):
    def test_runs(self):
        self.assertEqual(main(["hello"]), 0)


if __name__ == "__main__":
    unittest.main()
