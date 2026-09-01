"""Run unittest discovery without exposing failure details in public CI logs."""

from __future__ import annotations

import io
import sys
import unittest


def _emit_annotation(category: str, test: object) -> None:
    test_identifier = getattr(test, "id", lambda: str(test))()
    print(
        f"::error title={category}: {test_identifier}::"
        "A test failed; reproduce it locally for restricted details.",
        file=sys.stderr,
    )


def main() -> int:
    captured_details = io.StringIO()
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(
        stream=captured_details,
        verbosity=0,
    ).run(suite)
    print(
        f"Ran {result.testsRun} tests: "
        f"{len(result.failures)} failures, "
        f"{len(result.errors)} errors, "
        f"{len(result.skipped)} skipped."
    )
    if result.wasSuccessful():
        return 0

    for category, failures in (
        ("Failure", result.failures),
        ("Error", result.errors),
    ):
        for test, _ in failures:
            _emit_annotation(category, test)

    for test in result.unexpectedSuccesses:
        _emit_annotation("Unexpected success", test)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
