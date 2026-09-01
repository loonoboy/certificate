from pathlib import Path
import os
import subprocess
import sys
import time
from threading import Event, Thread
import unittest
from unittest.mock import patch

from certificat import CancellationToken, ConversionCancelledError
from certificat.infrastructure.openssl.commands import P12_PASSWORD_ENV
from certificat.infrastructure.openssl.runner import OpenSSLRunner


class OpenSSLRunnerTests(unittest.TestCase):
    def test_error_text_redacts_secret_and_is_bounded(self) -> None:
        secret = "very-secret-value"
        text = OpenSSLRunner._sanitize(  # noqa: SLF001 - direct security unit test
            (f"failure: {secret}\n" + "x" * 20_000).encode(),
            (secret,),
        )

        self.assertNotIn(secret, text)
        self.assertIn("[REDACTED]", text)
        self.assertIn("[stderr truncated]", text)

    def test_scoped_environment_does_not_mutate_parent_environment(self) -> None:
        previous = os.environ.get(P12_PASSWORD_ENV)
        try:
            os.environ[P12_PASSWORD_ENV] = "parent value"
            runner = OpenSSLRunner(Path(sys.executable))
            result = runner.run(
                [
                    "-c",
                    f"import os; print(os.environ[{P12_PASSWORD_ENV!r}])",
                ],
                environment={P12_PASSWORD_ENV: "child value"},
                secret_values=("child value",),
            )

            self.assertEqual(result.stdout.strip(), b"child value")
            self.assertEqual(os.environ[P12_PASSWORD_ENV], "parent value")
        finally:
            if previous is None:
                os.environ.pop(P12_PASSWORD_ENV, None)
            else:
                os.environ[P12_PASSWORD_ENV] = previous

    def test_cancellation_stops_an_active_process(self) -> None:
        runner = OpenSSLRunner(Path(sys.executable))
        cancellation = CancellationToken()
        process_started = Event()
        original_popen = subprocess.Popen

        def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)  # type: ignore[arg-type]
            process_started.set()
            return process

        def request_cancellation() -> None:
            if process_started.wait(timeout=2):
                cancellation.cancel()

        canceller = Thread(target=request_cancellation, daemon=True)
        started_at = time.monotonic()
        with patch(
            "certificat.infrastructure.openssl.runner.subprocess.Popen",
            side_effect=tracked_popen,
        ):
            canceller.start()
            with self.assertRaises(ConversionCancelledError):
                runner.run(
                    ["-c", "import time; time.sleep(30)"],
                    cancellation=cancellation,
                )
        canceller.join(timeout=2)

        self.assertTrue(process_started.is_set())
        self.assertLess(time.monotonic() - started_at, 5)

    def test_cancellation_stops_both_pipeline_processes(self) -> None:
        runner = OpenSSLRunner(Path(sys.executable))
        cancellation = CancellationToken()
        pipeline_started = Event()
        original_popen = subprocess.Popen
        process_count = 0

        def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal process_count
            process = original_popen(*args, **kwargs)  # type: ignore[arg-type]
            process_count += 1
            if process_count == 2:
                pipeline_started.set()
            return process

        def request_cancellation() -> None:
            if pipeline_started.wait(timeout=2):
                cancellation.cancel()

        canceller = Thread(target=request_cancellation, daemon=True)
        started_at = time.monotonic()
        with patch(
            "certificat.infrastructure.openssl.runner.subprocess.Popen",
            side_effect=tracked_popen,
        ):
            canceller.start()
            with self.assertRaises(ConversionCancelledError):
                runner.run_pipeline(
                    ["-c", "import time; time.sleep(30)"],
                    ["-c", "import sys; sys.stdin.buffer.read()"],
                    source_environment={},
                    sink_environment={},
                    cancellation=cancellation,
                )
        canceller.join(timeout=2)

        self.assertTrue(pipeline_started.is_set())
        self.assertEqual(process_count, 2)
        self.assertLess(time.monotonic() - started_at, 5)


if __name__ == "__main__":
    unittest.main()

