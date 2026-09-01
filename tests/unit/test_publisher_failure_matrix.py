import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from certificat.domain.errors import PublicationError
from certificat.domain.models import OutputPaths
from certificat.infrastructure.filesystem.publisher import TransactionalOutputPublisher


class TransactionalOutputFailureMatrixTests(unittest.TestCase):
    def make_paths(self, root: Path) -> tuple[Path, Path, OutputPaths]:
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
        return staged_certificate, staged_key, outputs

    def assert_rollback_restored_original_state(
        self,
        root: Path,
        staged_certificate: Path,
        staged_key: Path,
        outputs: OutputPaths,
    ) -> None:
        self.assertEqual(outputs.certificate.read_bytes(), b"old certificate")
        self.assertEqual(outputs.private_key.read_bytes(), b"old encrypted key")
        self.assertEqual(staged_certificate.read_bytes(), b"new certificate")
        self.assertEqual(staged_key.read_bytes(), b"new encrypted key")
        self.assertFalse((root / ".client.certificat.lock").exists())

    def test_failure_before_first_install_restores_both_backups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            call_count = 0

            def replace(source: Path, destination: Path) -> None:
                nonlocal call_count
                call_count += 1
                # Calls 1-2 move the old pair to backups. Call 3 would install
                # the new certificate.
                if call_count == 3:
                    raise PermissionError("injected first-install failure")
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
            self.assert_rollback_restored_original_state(
                root,
                staged_certificate,
                staged_key,
                outputs,
            )

    def test_sync_failure_after_both_installs_restores_old_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            publisher = TransactionalOutputPublisher()

            with patch.object(
                publisher,
                "_sync_file",
                side_effect=OSError("injected post-install sync failure"),
            ):
                with self.assertRaises(PublicationError) as raised:
                    publisher.publish(
                        staged_certificate,
                        staged_key,
                        outputs,
                        overwrite=True,
                    )

            self.assertFalse(raised.exception.rollback_failed)
            self.assert_rollback_restored_original_state(
                root,
                staged_certificate,
                staged_key,
                outputs,
            )

    def test_cancellation_during_commit_rolls_back_and_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)
            call_count = 0

            def replace(source: Path, destination: Path) -> None:
                nonlocal call_count
                call_count += 1
                if call_count == 4:
                    raise KeyboardInterrupt()
                os.replace(source, destination)

            publisher = TransactionalOutputPublisher(replace=replace)

            with self.assertRaises(KeyboardInterrupt):
                publisher.publish(
                    staged_certificate,
                    staged_key,
                    outputs,
                    overwrite=True,
                )

            self.assert_rollback_restored_original_state(
                root,
                staged_certificate,
                staged_key,
                outputs,
            )

    def test_directory_access_failure_does_not_touch_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged_certificate, staged_key, outputs = self.make_paths(root)

            with patch(
                "certificat.infrastructure.filesystem.publisher.os.open",
                side_effect=PermissionError("injected lock access failure"),
            ):
                with self.assertRaises(PublicationError):
                    TransactionalOutputPublisher().publish(
                        staged_certificate,
                        staged_key,
                        outputs,
                        overwrite=True,
                    )

            self.assert_rollback_restored_original_state(
                root,
                staged_certificate,
                staged_key,
                outputs,
            )


if __name__ == "__main__":
    unittest.main()
