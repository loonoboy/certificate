import os
from pathlib import Path
import tempfile
import unittest

from certificat import CancellationToken, ConversionCancelledError
from certificat.domain.models import OutputPaths
from certificat.infrastructure.filesystem.publisher import TransactionalOutputPublisher


class CancellationTokenTests(unittest.TestCase):
    def test_cancel_is_idempotent_and_raises_typed_error(self) -> None:
        cancellation = CancellationToken()

        self.assertFalse(cancellation.is_cancelled)
        cancellation.raise_if_cancelled()

        cancellation.cancel()
        cancellation.cancel()

        self.assertTrue(cancellation.is_cancelled)
        with self.assertRaises(ConversionCancelledError):
            cancellation.raise_if_cancelled()


class TransactionalPublisherCancellationTests(unittest.TestCase):
    def test_token_cancellation_during_commit_rolls_back_old_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            staged_certificate = workspace / "certificate.crt"
            staged_key = workspace / "private.key"
            staged_certificate.write_bytes(b"new certificate")
            staged_key.write_bytes(b"new encrypted key")
            outputs = OutputPaths(
                root / "client.crt",
                root / "client_private_encrypted.key",
            )
            outputs.certificate.write_bytes(b"old certificate")
            outputs.private_key.write_bytes(b"old encrypted key")
            cancellation = CancellationToken()
            call_count = 0

            def replace(source: Path, destination: Path) -> None:
                nonlocal call_count
                call_count += 1
                os.replace(source, destination)
                if call_count == 3:
                    cancellation.cancel()

            publisher = TransactionalOutputPublisher(replace=replace)

            with self.assertRaises(ConversionCancelledError):
                publisher.publish(
                    staged_certificate,
                    staged_key,
                    outputs,
                    overwrite=True,
                    cancellation=cancellation,
                )

            self.assertEqual(outputs.certificate.read_bytes(), b"old certificate")
            self.assertEqual(outputs.private_key.read_bytes(), b"old encrypted key")
            self.assertEqual(staged_certificate.read_bytes(), b"new certificate")
            self.assertEqual(staged_key.read_bytes(), b"new encrypted key")
            self.assertFalse((root / ".client.certificat.lock").exists())


if __name__ == "__main__":
    unittest.main()
