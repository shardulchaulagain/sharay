"""Run the foundation suite and fail if discovery finds zero tests."""
import sys
import unittest
from pathlib import Path


if __name__ == '__main__':
    # Script entrypoints do not put the application root on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    suite = unittest.defaultTestLoader.discover('tests')
    if suite.countTestCases() == 0:
        print('No tests discovered', file=sys.stderr)
        sys.exit(2)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
