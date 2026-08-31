from pathlib import Path
import subprocess
import tempfile
import unittest

from certificat.domain.errors import PermissionHardeningError
from certificat.infrastructure.filesystem.permissions import PlatformPermissions


class PosixPermissionsTests(unittest.TestCase):
    def test_posix_modes_match_legacy_security_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            certificate = root / "certificate.crt"
            private_key = root / "private.key"
            certificate.write_bytes(b"certificate")
            private_key.write_bytes(b"encrypted key")
            permissions = PlatformPermissions(os_name="posix")

            permissions.secure_workspace(root)
            permissions.prepare_certificate(certificate)
            permissions.prepare_private_key(private_key)

            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o644)
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)


class WindowsPermissionsTests(unittest.TestCase):
    def test_windows_key_acl_uses_current_user_sid_and_local_system(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command[0] == "whoami.exe":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    '"DESKTOP\\user","S-1-5-21-1-2-3-1001"\r\n',
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "processed", "")

        permissions = PlatformPermissions(os_name="nt", command_runner=runner)
        permissions.prepare_private_key(Path(r"C:\output\private.key"))

        self.assertEqual(calls[0][0], "whoami.exe")
        self.assertEqual(calls[1][0], "icacls.exe")
        self.assertIn("/inheritance:r", calls[1])
        self.assertIn("*S-1-5-21-1-2-3-1001:F", calls[1])
        self.assertIn("*S-1-5-18:F", calls[1])

    def test_windows_acl_failure_is_not_silently_ignored(self) -> None:
        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if command[0] == "whoami.exe":
                return subprocess.CompletedProcess(
                    command, 0, '"user","S-1-5-21-1001"\r\n', ""
                )
            return subprocess.CompletedProcess(command, 5, "", "denied")

        permissions = PlatformPermissions(os_name="nt", command_runner=runner)

        with self.assertRaises(PermissionHardeningError):
            permissions.prepare_private_key(Path(r"C:\output\private.key"))


if __name__ == "__main__":
    unittest.main()

