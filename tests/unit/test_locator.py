from pathlib import Path
import subprocess
import tempfile
import unittest

from certificat.domain.errors import OpenSSLNotFoundError
from certificat.domain.models import OpenSSLGeneration
from certificat.infrastructure.openssl.locator import OpenSSLLocator


class FakeCommandRunner:
    def __init__(
        self,
        module_directory: Path,
        version: str = "OpenSSL 3.2.1 1 Jan 2026",
    ) -> None:
        self.module_directory = module_directory
        self.version = version
        self.calls: list[list[str]] = []

    def __call__(
        self,
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(command)
        if command[-1] == "-m":
            stdout = f'MODULESDIR: "{self.module_directory}"\n'.encode()
        else:
            stdout = f"{self.version}\n".encode()
        return subprocess.CompletedProcess(command, 0, stdout, b"")


class OpenSSLLocatorTests(unittest.TestCase):
    def make_executable(self, directory: str) -> Path:
        executable = Path(directory) / "openssl"
        executable.write_bytes(b"test executable")
        executable.chmod(0o700)
        return executable

    def test_locates_openssl_1_1_1_without_provider_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_executable(directory)
            runner = FakeCommandRunner(
                Path(directory),
                version="OpenSSL 1.1.1w-fips 11 Sep 2023",
            )

            installation = OpenSSLLocator(
                platform_name="linux",
                command_runner=runner,
            ).locate(executable)

            self.assertIs(installation.generation, OpenSSLGeneration.V1_1_1)
            self.assertEqual(installation.version, "1.1.1w-fips")
            self.assertIsNone(installation.legacy_provider_dir)
            self.assertEqual(runner.calls, [[str(executable), "version"]])

    def test_locates_openssl_3_and_legacy_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.make_executable(directory)
            modules = root / "modules"
            modules.mkdir()
            (modules / "legacy.so").write_bytes(b"provider")
            runner = FakeCommandRunner(modules)

            installation = OpenSSLLocator(
                platform_name="linux",
                command_runner=runner,
            ).locate(executable)

            self.assertIs(installation.generation, OpenSSLGeneration.V3)
            self.assertEqual(installation.version, "3.2.1")
            self.assertEqual(installation.legacy_provider_dir, modules.resolve())

    def test_locates_openssl_4_and_legacy_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.make_executable(directory)
            modules = root / "modules"
            modules.mkdir()
            (modules / "legacy.so").write_bytes(b"provider")
            runner = FakeCommandRunner(
                modules,
                version="OpenSSL 4.0.0 14 Apr 2026",
            )

            installation = OpenSSLLocator(
                platform_name="linux",
                command_runner=runner,
            ).locate(executable)

            self.assertIs(installation.generation, OpenSSLGeneration.V4)
            self.assertEqual(installation.version, "4.0.0")
            self.assertEqual(installation.legacy_provider_dir, modules.resolve())

    def test_rejects_unsupported_generations_and_other_implementations(self) -> None:
        unsupported = (
            "OpenSSL 1.1.0 25 Aug 2016",
            "OpenSSL 2.0.0 1 Jan 2020",
            "OpenSSL 5.0.0 1 Oct 2027",
            "LibreSSL 4.0.0",
        )
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_executable(directory)
            for version in unsupported:
                with self.subTest(version=version):
                    runner = FakeCommandRunner(Path(directory), version=version)
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

