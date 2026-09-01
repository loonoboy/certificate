from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Callable, cast
import unittest
from unittest.mock import patch

from certificat.__main__ import main
from certificat.domain.errors import InputValidationError
from certificat.domain.events import ProgressEvent, ProgressStep
from certificat.domain.models import (
    ConversionResult,
    LegacyMode,
    OpenSSLInstallation,
)


class CertificatCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.installation = OpenSSLInstallation(Path("/openssl"), "3.test")
        self.result = ConversionResult(
            certificate_path=Path("/output/client.crt"),
            private_key_path=Path("/output/client_private_encrypted.key"),
            mode=LegacyMode.NORMAL,
            openssl_version="3.test",
        )

    def test_success_uses_hidden_password_prompts_and_prints_paths(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        with (
            patch(
                "certificat.__main__.discover_openssl",
                return_value=self.installation,
            ) as discover,
            patch(
                "certificat.__main__.getpass.getpass",
                side_effect=["container secret", "key secret", "key secret"],
            ),
            patch(
                "certificat.__main__.convert_pkcs12",
                return_value=self.result,
            ) as convert,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = main(
                [
                    "/input/client.p12",
                    "--overwrite",
                    "--openssl",
                    "/custom/openssl",
                    "--quiet",
                ]
            )

        self.assertEqual(exit_code, 0)
        discover.assert_called_once_with(Path("/custom/openssl"))
        request = convert.call_args.args[0]
        self.assertEqual(request.p12_path, Path("/input/client.p12"))
        self.assertEqual(request.p12_password, "container secret")
        self.assertEqual(request.private_key_password, "key secret")
        self.assertTrue(request.overwrite)
        self.assertIs(convert.call_args.kwargs["openssl"], self.installation)
        self.assertIn("Certificate: /output/client.crt", stdout.getvalue())
        self.assertIn(
            "Private key: /output/client_private_encrypted.key",
            stdout.getvalue(),
        )
        self.assertNotIn("container secret", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("key secret", stdout.getvalue() + stderr.getvalue())

    def test_progress_is_written_to_stderr(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        def convert(*_: object, **kwargs: object) -> ConversionResult:
            progress = cast(
                Callable[[ProgressEvent], None],
                kwargs["progress"],
            )
            progress(
                ProgressEvent(ProgressStep.VALIDATING_INPUT, "Validating input")
            )
            return self.result

        with (
            patch(
                "certificat.__main__.discover_openssl",
                return_value=self.installation,
            ),
            patch(
                "certificat.__main__.getpass.getpass",
                side_effect=["container", "key", "key"],
            ),
            patch("certificat.__main__.convert_pkcs12", side_effect=convert),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = main(["client.p12"])

        self.assertEqual(exit_code, 0)
        self.assertIn("Validating input", stderr.getvalue())

    def test_three_password_confirmation_failures_return_usage_error(self) -> None:
        stderr = StringIO()

        with (
            patch(
                "certificat.__main__.discover_openssl",
                return_value=self.installation,
            ),
            patch(
                "certificat.__main__.getpass.getpass",
                side_effect=[
                    "container",
                    "key-1",
                    "different-1",
                    "",
                    "",
                    "key-3",
                    "different-3",
                ],
            ),
            patch("certificat.__main__.convert_pkcs12") as convert,
            redirect_stderr(stderr),
        ):
            exit_code = main(["client.p12"])

        self.assertEqual(exit_code, 2)
        convert.assert_not_called()
        self.assertEqual(stderr.getvalue().count("Error:"), 3)

    def test_conversion_error_has_nonzero_exit_code(self) -> None:
        stderr = StringIO()

        with (
            patch(
                "certificat.__main__.discover_openssl",
                return_value=self.installation,
            ),
            patch(
                "certificat.__main__.getpass.getpass",
                side_effect=["container", "key", "key"],
            ),
            patch(
                "certificat.__main__.convert_pkcs12",
                side_effect=InputValidationError("invalid input"),
            ),
            redirect_stderr(stderr),
        ):
            exit_code = main(["client.p12"])

        self.assertEqual(exit_code, 1)
        self.assertIn("Error: invalid input", stderr.getvalue())

    def test_keyboard_interrupt_returns_standard_cancel_exit_code(self) -> None:
        stderr = StringIO()

        with (
            patch(
                "certificat.__main__.discover_openssl",
                return_value=self.installation,
            ),
            patch(
                "certificat.__main__.getpass.getpass",
                side_effect=["container", "key", "key"],
            ),
            patch(
                "certificat.__main__.convert_pkcs12",
                side_effect=KeyboardInterrupt,
            ),
            redirect_stderr(stderr),
        ):
            exit_code = main(["client.p12"])

        self.assertEqual(exit_code, 130)
        self.assertIn("Cancelled", stderr.getvalue())

    def test_backend_failure_happens_before_password_prompt(self) -> None:
        stderr = StringIO()

        with (
            patch(
                "certificat.__main__.discover_openssl",
                side_effect=InputValidationError("OpenSSL unavailable"),
            ),
            patch("certificat.__main__.getpass.getpass") as prompt,
            redirect_stderr(stderr),
        ):
            exit_code = main(["client.p12"])

        self.assertEqual(exit_code, 1)
        prompt.assert_not_called()
        self.assertIn("OpenSSL unavailable", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
