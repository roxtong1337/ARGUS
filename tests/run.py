"""Fallback test runner so REA can be verified without pytest installed.

    python -m tests.run
"""

from __future__ import annotations

import os
import sys
import unittest


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(root, "tests"), pattern="test_*.py", top_level_dir=root)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
