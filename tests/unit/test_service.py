from pathlib import Path
import tempfile
import unittest

from certificat.application.cancellation import CancellationToken
from certificat.application.conversion_service import ConversionService
from certificat.application.ports import CancellationTokenPort
from certificat.domain.errors import (
    CertificateKeyMismatchError,
    ConversionCancelledError,
    InputValidationError,
    OutputExistsError,
)
from certificat.domain.events import ProgressEvent, ProgressStep
from certificat.domain.models import ConversionRequest, LegacyMode
from certificat.infrastructure.filesystem.publisher import TransactionalOutputPublisher


class FakeBackend:
    version = "3.test"

    def __init__(self, *, matches: bool = True) -> None:
        self.matches = matches
        self.calls: list[str] = []

    @staticmethod
    def check_cancellation(
        cancellation: CancellationTokenPort | None,
    ) -> None:
        if cancellation is not None:
            cancellation.raise_if_cancelled()

    def detect_pkcs12_mode(
        self,
        p12_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> LegacyMode:
        self.check_cancellation(cancellation)
        self.calls.append("detect")
        return LegacyMode.LEGACY

    def extract_certificate(
        self,
        p12_path: Path,
        password: str,
        mode: LegacyMode,
        raw_output: Path,
        certificate_output: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        self.check_cancellation(cancellation)
        self.calls.append("extract_certificate")
        raw_output.write_bytes(b"raw certificate")
        certificate_output.write_bytes(b"clean certificate")

    def extract_and_encrypt_private_key(
        self,
        p12_path: Path,
        p12_password: str,
        mode: LegacyMode,
        private_key_password: str,
        encrypted_output: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        self.check_cancellation(cancellation)
        self.calls.append("extract_private_key")
        encrypted_output.write_bytes(b"encrypted private key")

    def validate_certificate(
        self,
        certificate_path: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        self.check_cancellation(cancellation)
        self.calls.append("validate_certificate")

    def validate_private_key(
        self,
        private_key_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        self.check_cancellation(cancellation)
        self.calls.append("validate_private_key")

    def certificate_matches_private_key(
        self,
        certificate_path: Path,
        private_key_path: Path,
        private_key_password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> bool:
        self.check_cancellation(cancellation)
        self.calls.append("match")
        return self.matches


class FakePermissions:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []

    def secure_workspace(self, path: Path) -> None:
        self.calls.append(("secure_workspace", path))

    def prepare_certificate(self, path: Path) -> None:
        self.calls.append(("prepare_certificate", path))

    def prepare_private_key(self, path: Path) -> None:
        self.calls.append(("prepare_private_key", path))


class ConversionServiceTests(unittest.TestCase):
    def make_service(self, backend: FakeBackend) -> ConversionService:
        self.permissions = FakePermissions()
        return ConversionService(
            backend,  # type: ignore[arg-type]
            permissions=self.permissions,
            publisher=TransactionalOutputPublisher(),
        )

    def request(self, p12_path: Path, *, overwrite: bool = False) -> ConversionRequest:
        return ConversionRequest(
            p12_path=p12_path,
            p12_password="container secret",
            private_key_password="key secret",
            overwrite=overwrite,
        )

    def test_complete_pipeline_order_and_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "Клиент $ test.p12"
            p12_path.write_bytes(b"synthetic p12")
            backend = FakeBackend()
            events: list[ProgressStep] = []

            result = self.make_service(backend).convert(
                self.request(p12_path),
                progress=lambda event: events.append(event.step),
            )

            self.assertEqual(
                backend.calls,
                [
                    "detect",
                    "extract_certificate",
                    "extract_private_key",
                    "validate_certificate",
                    "validate_private_key",
                    "match",
                ],
            )
            self.assertEqual(result.mode, LegacyMode.LEGACY)
            self.assertEqual(result.certificate_path.read_bytes(), b"clean certificate")
            self.assertEqual(
                result.private_key_path.read_bytes(), b"encrypted private key"
            )
            self.assertEqual(
                [name for name, _ in self.permissions.calls],
                [
                    "secure_workspace",
                    "prepare_certificate",
                    "prepare_private_key",
                ],
            )
            self.assertEqual(events[0], ProgressStep.VALIDATING_INPUT)
            self.assertEqual(events[-1], ProgressStep.COMPLETED)
            self.assertFalse(
                any(root.glob(f".{p12_path.stem}.certificat-*")),
                "workspace must be removed",
            )

    def test_mismatch_preserves_existing_output_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "client.p12"
            p12_path.write_bytes(b"synthetic p12")
            certificate = root / "client.crt"
            private_key = root / "client_private_encrypted.key"
            certificate.write_bytes(b"old certificate")
            private_key.write_bytes(b"old encrypted key")
            backend = FakeBackend(matches=False)

            with self.assertRaises(CertificateKeyMismatchError):
                self.make_service(backend).convert(
                    self.request(p12_path, overwrite=True)
                )

            self.assertEqual(certificate.read_bytes(), b"old certificate")
            self.assertEqual(private_key.read_bytes(), b"old encrypted key")

    def test_existing_output_stops_before_openssl_when_overwrite_is_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "client.p12"
            p12_path.write_bytes(b"synthetic p12")
            (root / "client.crt").write_bytes(b"old certificate")
            backend = FakeBackend()

            with self.assertRaises(OutputExistsError):
                self.make_service(backend).convert(self.request(p12_path))

            self.assertEqual(backend.calls, [])

    def test_rejects_empty_passwords_and_non_pkcs12_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong_suffix = root / "client.bin"
            wrong_suffix.write_bytes(b"data")
            backend = FakeBackend()

            with self.assertRaises(InputValidationError):
                self.make_service(backend).convert(self.request(wrong_suffix))

            p12_path = root / "client.p12"
            p12_path.write_bytes(b"data")
            with self.assertRaises(InputValidationError):
                self.make_service(backend).convert(
                    ConversionRequest(
                        p12_path=p12_path,
                        p12_password="",
                        private_key_password="key secret",
                    )
                )

            self.assertEqual(backend.calls, [])

    def test_pre_cancelled_request_stops_before_backend_and_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "client.p12"
            p12_path.write_bytes(b"synthetic p12")
            backend = FakeBackend()
            cancellation = CancellationToken()
            cancellation.cancel()

            with self.assertRaises(ConversionCancelledError):
                self.make_service(backend).convert(
                    self.request(p12_path),
                    cancellation=cancellation,
                )

            self.assertEqual(backend.calls, [])
            self.assertFalse((root / "client.crt").exists())
            self.assertFalse((root / "client_private_encrypted.key").exists())
            self.assertFalse(any(root.glob(".client.certificat-*")))

    def test_progress_callback_can_cancel_before_openssl_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "client.p12"
            p12_path.write_bytes(b"synthetic p12")
            backend = FakeBackend()
            cancellation = CancellationToken()
            events: list[ProgressStep] = []

            def on_progress(event: ProgressEvent) -> None:
                step = event.step
                events.append(step)
                if step is ProgressStep.CHECKING_CONTAINER:
                    cancellation.cancel()

            with self.assertRaises(ConversionCancelledError):
                self.make_service(backend).convert(
                    self.request(p12_path),
                    progress=on_progress,
                    cancellation=cancellation,
                )

            self.assertEqual(backend.calls, [])
            self.assertEqual(events[-1], ProgressStep.CHECKING_CONTAINER)
            self.assertFalse((root / "client.crt").exists())
            self.assertFalse((root / "client_private_encrypted.key").exists())
            self.assertFalse(any(root.glob(".client.certificat-*")))

    def test_passwords_are_not_present_in_request_repr(self) -> None:
        request = ConversionRequest(
            p12_path=Path("client.p12"),
            p12_password="container secret",
            private_key_password="key secret",
        )

        representation = repr(request)
        self.assertNotIn("container secret", representation)
        self.assertNotIn("key secret", representation)


if __name__ == "__main__":
    unittest.main()

