#!/usr/bin/env python3
"""Non-interactive, isolated tests. Any failure or empty discovery exits nonzero."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(ROOT / "test"), pattern="test_*.py", top_level_dir=str(ROOT))
    if suite.countTestCases() == 0:
        raise SystemExit("no tests discovered")
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
