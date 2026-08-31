from pathlib import Path
import subprocess
import tempfile
import unittest

from certificat.domain.errors import OpenSSLNotFoundError
from certificat.infrastructure.openssl.locator import OpenSSLLocator


class FakeCommandRunner:
    def __init__(self, module_directory: Path, version: str = "OpenSSL 3.2.1 1 Jan 2026") -> None:
        self.module_directory = module_directory
        self.version = version
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(command)
        if command[-1] == "-m":
            stdout = f'MODULESDIR: "{self.module_directory}"\n'.encode()
        else:
            stdout = f"{self.version}\n".encode()
        return subprocess.CompletedProcess(command, 0, stdout, b"")


class OpenSSLLocatorTests(unittest.TestCase):
    def test_locates_openssl_3_and_legacy_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "openssl"
            executable.write_bytes(b"test executable")
            executable.chmod(0o700)
            modules = root / "modules"
            modules.mkdir()
            (modules / "legacy.so").write_bytes(b"provider")
            runner = FakeCommandRunner(modules)

            installation = OpenSSLLocator(
                platform_name="linux",
                command_runner=runner,
            ).locate(executable)

            self.assertEqual(installation.executable, executable.resolve())
            self.assertEqual(installation.version, "3.2.1")
            self.assertEqual(installation.legacy_provider_dir, modules.resolve())

    def test_rejects_non_openssl_or_pre_version_3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "openssl"
            executable.write_bytes(b"test executable")
            executable.chmod(0o700)
            runner = FakeCommandRunner(
                Path(directory),
                version="OpenSSL 1.1.1 11 Sep 2018",
            )

            with self.assertRaises(OpenSSLNotFoundError):
                OpenSSLLocator(
                    platform_name="linux",
                    command_runner=runner,
                ).locate(executable)

    def test_explicit_missing_path_does_not_fall_back_to_path(self) -> None:
        locator = OpenSSLLocator(which=lambda _: "/usr/bin/openssl")

        with self.assertRaises(OpenSSLNotFoundError):
            locator.locate(Path("/definitely/missing/openssl"))


if __name__ == "__main__":
    unittest.main()

