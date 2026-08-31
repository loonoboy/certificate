from pathlib import Path
import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()

