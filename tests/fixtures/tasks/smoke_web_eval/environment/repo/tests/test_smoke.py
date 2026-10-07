import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from calc_service.server import calculate  # noqa: E402


class Smoke(unittest.TestCase):
    def test_calculates(self):
        self.assertEqual(calculate("2 + 2"), "4")


if __name__ == "__main__":
    unittest.main()
