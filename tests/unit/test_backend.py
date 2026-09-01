from pathlib import Path
import tempfile
import unittest

from certificat import CancellationToken
from certificat.domain.errors import OpenSSLExecutionError, Pkcs12OpenError
from certificat.domain.models import LegacyMode, OpenSSLInstallation
from certificat.infrastructure.openssl.backend import OpenSSLBackend
from certificat.infrastructure.openssl.commands import (
    P12_PASSWORD_ENV,
    PRIVATE_KEY_PASSWORD_ENV,
)
from certificat.infrastructure.openssl.runner import CommandResult


class FakeRunner:
    def __init__(self, results: list[CommandResult] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[dict[str, object]] = []
        self.pipeline_calls: list[dict[str, object]] = []
        self.pipeline_error: BaseException | None = None

    def run(self, args: list[str], **kwargs: object) -> CommandResult:
        self.calls.append({"args": args, **kwargs})
        if self.results:
            return self.results.pop(0)
        return CommandResult(0, b"", "")

    def run_pipeline(
        self,
        source_args: list[str],
        sink_args: list[str],
        **kwargs: object,
    ) -> None:
        self.pipeline_calls.append(
            {"source_args": source_args, "sink_args": sink_args, **kwargs}
        )
        if self.pipeline_error is not None:
            raise self.pipeline_error


def result(returncode: int, stdout: bytes = b"", stderr: str = "") -> CommandResult:
    return CommandResult(returncode, stdout, stderr)


class OpenSSLBackendTests(unittest.TestCase):
    def make_backend(
        self,
        runner: FakeRunner,
        *,
        version: str = "3.0.0",
    ) -> OpenSSLBackend:
        installation = OpenSSLInstallation(
            executable=Path("/openssl"),
            version=version,
            legacy_provider_dir=(
                None if version.startswith("1.1.1") else Path("/modules")
            ),
        )
        return OpenSSLBackend(installation, runner=runner)  # type: ignore[arg-type]

    def test_normal_probe_short_circuits_legacy(self) -> None:
        runner = FakeRunner([result(0)])
        backend = self.make_backend(runner)

        mode = backend.detect_pkcs12_mode(Path("client.p12"), "secret")

        self.assertIs(mode, LegacyMode.NORMAL)
        self.assertEqual(len(runner.calls), 1)
        self.assertNotIn("-legacy", runner.calls[0]["args"])

    def test_failed_normal_probe_falls_back_to_legacy(self) -> None:
        runner = FakeRunner([result(1, stderr="normal failed"), result(0)])
        backend = self.make_backend(runner)

        mode = backend.detect_pkcs12_mode(Path("client.p12"), "secret")

        self.assertIs(mode, LegacyMode.LEGACY)
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("-legacy", runner.calls[1]["args"])
        environment = runner.calls[1]["environment"]
        self.assertEqual(environment["OPENSSL_MODULES"], str(Path("/modules")))
        self.assertEqual(environment[P12_PASSWORD_ENV], "secret")

    def test_openssl_1_1_1_does_not_repeat_failed_probe_as_legacy(self) -> None:
        runner = FakeRunner([result(1, stderr="OpenSSL 1.1.1 failed")])
        backend = self.make_backend(runner, version="1.1.1w")

        with self.assertRaises(Pkcs12OpenError) as raised:
            backend.detect_pkcs12_mode(Path("client.p12"), "secret")

        self.assertFalse(raised.exception.legacy_attempted)
        self.assertEqual(raised.exception.normal_details, "OpenSSL 1.1.1 failed")
        self.assertEqual(len(runner.calls), 1)

    def test_failure_of_both_probes_is_ambiguous_pkcs12_error(self) -> None:
        runner = FakeRunner([
            result(1, stderr="normal details"),
            result(1, stderr="legacy details"),
        ])
        backend = self.make_backend(runner)

        with self.assertRaises(Pkcs12OpenError) as raised:
            backend.detect_pkcs12_mode(Path("client.p12"), "secret")

        self.assertEqual(raised.exception.normal_details, "normal details")
        self.assertEqual(raised.exception.legacy_details, "legacy details")

    def test_certificate_extraction_and_normalization_are_separate(self) -> None:
        runner = FakeRunner([result(0), result(0)])
        backend = self.make_backend(runner)

        backend.extract_certificate(
            Path("client.p12"),
            "secret",
            LegacyMode.NORMAL,
            Path("raw.pem"),
            Path("clean.crt"),
        )

        self.assertEqual(runner.calls[0]["args"][0], "pkcs12")
        self.assertEqual(runner.calls[1]["args"][0], "x509")

    def test_cancellation_is_forwarded_to_runner(self) -> None:
        runner = FakeRunner([result(0)])
        backend = self.make_backend(runner)
        cancellation = CancellationToken()

        backend.validate_certificate(
            Path("certificate.crt"),
            cancellation=cancellation,
        )

        self.assertIs(runner.calls[0]["cancellation"], cancellation)

    def test_private_key_uses_direct_pipeline_and_scoped_passwords(self) -> None:
        runner = FakeRunner()
        backend = self.make_backend(runner)

        backend.extract_and_encrypt_private_key(
            Path("client.p12"),
            "container secret",
            LegacyMode.LEGACY,
            "key secret",
            Path("encrypted.key"),
        )

        call = runner.pipeline_calls[0]
        self.assertIn("-noenc", call["source_args"])
        self.assertIn("-topk8", call["sink_args"])
        self.assertEqual(
            call["source_environment"][P12_PASSWORD_ENV],
            "container secret",
        )
        self.assertNotIn(
            PRIVATE_KEY_PASSWORD_ENV,
            call["source_environment"],
        )
        self.assertEqual(
            call["sink_environment"][PRIVATE_KEY_PASSWORD_ENV],
            "key secret",
        )

    def test_failed_private_key_pipeline_removes_partial_output(self) -> None:
        runner = FakeRunner()
        runner.pipeline_error = OpenSSLExecutionError("encrypt", 1)
        backend = self.make_backend(runner)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "partial.key"
            output.write_bytes(b"partial")

            with self.assertRaises(OpenSSLExecutionError):
                backend.extract_and_encrypt_private_key(
                    Path("client.p12"),
                    "container secret",
                    LegacyMode.NORMAL,
                    "key secret",
                    output,
                )

            self.assertFalse(output.exists())

    def test_private_key_validation_is_explicit(self) -> None:
        runner = FakeRunner([result(0)])
        backend = self.make_backend(runner)

        backend.validate_private_key(Path("encrypted.key"), "key secret")

        args = runner.calls[0]["args"]
        self.assertIn("-check", args)
        self.assertIn("-noout", args)

    def test_public_key_comparison_detects_match_and_mismatch(self) -> None:
        matching = FakeRunner([result(0, b"public"), result(0, b"public")])
        backend = self.make_backend(matching)
        self.assertTrue(
            backend.certificate_matches_private_key(
                Path("certificate.crt"), Path("private.key"), "key secret"
            )
        )

        mismatching = FakeRunner([result(0, b"public-a"), result(0, b"public-b")])
        backend = self.make_backend(mismatching)
        self.assertFalse(
            backend.certificate_matches_private_key(
                Path("certificate.crt"), Path("private.key"), "key secret"
            )
        )


if __name__ == "__main__":
    unittest.main()

