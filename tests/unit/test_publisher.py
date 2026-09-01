import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from certificat.domain.errors import OutputExistsError, PublicationError, UnsafePathError
from certificat.domain.models import OutputPaths
from certificat.infrastructure.filesystem.publisher import TransactionalOutputPublisher


class TransactionalOutputPublisherTests(unittest.TestCase):
    def make_paths(self, root: Path) -> tuple[Path, Path, OutputPaths]:
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        staged_certificate = workspace / "certificate.crt"
        staged_key = workspace / "private.key"
        staged_certificate.write_bytes(b"new certificate")
        staged_key.write_bytes(b"new encrypted key")
        outputs = OutputPaths(root / "client.crt", root / "client_private_encrypted.key")
        return staged_certificate, staged_key, outputs

    def test_refuses_existing_output_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            outputs.certificate.write_bytes(b"old certificate")

            with self.assertRaises(OutputExistsError):
                TransactionalOutputPublisher().publish(
                    staged_certificate,
                    staged_key,
                    outputs,
                    overwrite=False,
                )

            self.assertEqual(outputs.certificate.read_bytes(), b"old certificate")
            self.assertFalse(outputs.private_key.exists())

    def test_publishes_both_validated_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)

            TransactionalOutputPublisher().publish(
                staged_certificate,
                staged_key,
                outputs,
                overwrite=False,
            )

            self.assertEqual(outputs.certificate.read_bytes(), b"new certificate")
            self.assertEqual(outputs.private_key.read_bytes(), b"new encrypted key")
            self.assertFalse(staged_certificate.exists())
            self.assertFalse(staged_key.exists())
            self.assertFalse(
                (root / ".client.certificat.lock").exists(),
            )

    def test_rolls_back_when_second_install_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            outputs.certificate.write_bytes(b"old certificate")
            outputs.private_key.write_bytes(b"old encrypted key")
            call_count = 0

            def replace(source: Path, destination: Path) -> None:
                nonlocal call_count
                call_count += 1
                # Two backup moves, first install, then fail second install.
                if call_count == 4:
                    raise OSError("injected second-install failure")
                os.replace(source, destination)

            publisher = TransactionalOutputPublisher(replace=replace)

            with self.assertRaises(PublicationError) as raised:
                publisher.publish(
                    staged_certificate,
                    staged_key,
                    outputs,
                    overwrite=True,
                )

            self.assertFalse(raised.exception.rollback_failed)
            self.assertEqual(outputs.certificate.read_bytes(), b"old certificate")
            self.assertEqual(outputs.private_key.read_bytes(), b"old encrypted key")
            self.assertFalse((root / ".client.certificat.lock").exists())

    @unittest.skipIf(not hasattr(os, "symlink"), "symlinks are unsupported")
    def test_rejects_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            target = root / "outside.crt"
            target.write_bytes(b"outside")
            try:
                outputs.certificate.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")

            with self.assertRaises(UnsafePathError):
                TransactionalOutputPublisher().publish(
                    staged_certificate,
                    staged_key,
                    outputs,
                    overwrite=True,
                )
            self.assertEqual(target.read_bytes(), b"outside")


    def test_windows_sync_uses_writable_descriptor(self) -> None:
        path = Path("client.crt")
        with (
            patch(
                "certificat.infrastructure.filesystem.publisher.os.name",
                "nt",
            ),
            patch(
                "certificat.infrastructure.filesystem.publisher.os.open",
                return_value=42,
            ) as open_file,
            patch("certificat.infrastructure.filesystem.publisher.os.fsync"),
            patch("certificat.infrastructure.filesystem.publisher.os.close"),
        ):
            TransactionalOutputPublisher._sync_file(path)

        open_file.assert_called_once_with(path, os.O_RDWR)


if __name__ == "__main__":
    unittest.main()

