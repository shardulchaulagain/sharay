"""Run the foundation suite and fail if discovery finds zero tests."""

import json
import os
import re
import stat
import sys
import unittest
from pathlib import Path
from typing import cast

# Script entrypoints do not put the application root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from packages.secret_patterns import RULES

RESULT_ENV = "SHARAY_TEST_RESULT_PATH"
MAX_RESULT_BYTES = 65536
MAX_TEST_IDS = 100
COUNT_FIELDS = ("tests_run", "failures", "errors", "skipped", "expected_failures", "unexpected_successes")
ID_FIELDS = ("failure_test_ids", "error_test_ids")
# Identifier boundaries can surround a token inside a Python method name.
# Use the shared token shapes without their text-boundary assertions here.
TOKEN_SHAPES = tuple(
    re.compile(re.sub(rb"\(\?(?:<!|!)[^)]*\)", b"", pattern.pattern)) for _, pattern in RULES
)


def safe_test_id(value):
    return (
        isinstance(value, str)
        and len(value) <= 200
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", value) is not None
        and not any(pattern.search(value.encode("ascii")) for pattern in TOKEN_SHAPES)
    )


def validate_metadata(data):
    """Accept only the small metadata protocol, never arbitrary test output."""
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "ids_truncated",
        *COUNT_FIELDS,
        *ID_FIELDS,
    }:
        return False
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        return False
    if type(data["ids_truncated"]) is not bool:
        return False
    if any(type(data[field]) is not int or data[field] < 0 for field in COUNT_FIELDS):
        return False
    for field, count in zip(ID_FIELDS, (data["failures"] + data["unexpected_successes"], data["errors"])):
        ids = data[field]
        if (
            not isinstance(ids, list)
            or len(ids) > min(MAX_TEST_IDS, count)
            or not all(safe_test_id(value) for value in ids)
            or len(set(ids)) != len(ids)
        ):
            return False
    return True


class MetadataResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failure_test_ids = set()
        self.error_test_ids = set()
        self.ids_truncated = False

    def record_id(self, test, destination):
        try:
            value = test.id()
        except Exception:
            self.ids_truncated = True
            return
        if not safe_test_id(value) or (value not in destination and len(destination) >= MAX_TEST_IDS):
            self.ids_truncated = True
        else:
            destination.add(value)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record_id(test, self.failure_test_ids)

    def addError(self, test, err):
        super().addError(test, err)
        self.record_id(test, self.error_test_ids)

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record_id(test, self.failure_test_ids)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            destination = (
                self.failure_test_ids if issubclass(err[0], test.failureException) else self.error_test_ids
            )
            self.record_id(test, destination)

    def metadata(self):
        return {
            "schema_version": 1,
            "tests_run": self.testsRun,
            "failures": len(self.failures),
            "errors": len(self.errors),
            "skipped": len(self.skipped),
            "expected_failures": len(self.expectedFailures),
            "unexpected_successes": len(self.unexpectedSuccesses),
            "failure_test_ids": sorted(self.failure_test_ids),
            "error_test_ids": sorted(self.error_test_ids),
            "ids_truncated": self.ids_truncated,
        }


def write_metadata(data, path):
    """Fill a parent-created private regular sidecar; failure leaves it unavailable."""
    if not path or not hasattr(os, "O_NOFOLLOW") or not validate_metadata(data):
        return
    fd = None
    try:
        encoded = json.dumps(data, ensure_ascii=True).encode("ascii")
        if len(encoded) > MAX_RESULT_BYTES:
            return
        fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != 0
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            return
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(encoded)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def main():
    # Nested runners belong to their own gate, never this runner's sidecar.
    path = os.environ.pop(RESULT_ENV, None)
    suite = unittest.defaultTestLoader.discover("tests")
    if suite.countTestCases() == 0:
        write_metadata(
            {
                "schema_version": 1,
                **dict.fromkeys(COUNT_FIELDS, 0),
                "failure_test_ids": [],
                "error_test_ids": [],
                "ids_truncated": False,
            },
            path,
        )
        print("No tests discovered", file=sys.stderr)
        return 2
    result = cast(MetadataResult, unittest.TextTestRunner(verbosity=2, resultclass=MetadataResult).run(suite))
    write_metadata(result.metadata(), path)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
