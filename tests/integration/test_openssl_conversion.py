from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from certificat.application.conversion_service import ConversionService
from certificat.domain.models import ConversionRequest, LegacyMode
from certificat.infrastructure.openssl.backend import OpenSSLBackend
from certificat.infrastructure.openssl.locator import OpenSSLLocator

P12_PASSWORD = "synthetic container password"
KEY_PASSWORD = "synthetic output key password"


class OpenSSLConversionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.installation = OpenSSLLocator().locate()
        except Exception as error:  # pragma: no cover - depends on test host
            raise unittest.SkipTest(f"OpenSSL 3 is unavailable: {error}") from error

    def run_openssl(
        self,
        arguments: list[str],
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        child_environment = os.environ.copy()
        if environment:
            child_environment.update(environment)
        return subprocess.run(
            [str(self.installation.executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            shell=False,
            check=False,
        )

    def make_material(self, root: Path, *, legacy: bool = False) -> Path:
        source_key = root / "fixture-private.pem"
        source_certificate = root / "fixture-certificate.pem"
        request = self.run_openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-subj",
                "/CN=Certificat Synthetic Test",
                "-days",
                "1",
                "-keyout",
                str(source_key),
                "-out",
                str(source_certificate),
            ]
        )
        if request.returncode != 0:
            self.fail(request.stderr.decode(errors="replace"))

        p12_path = root / ("legacy.p12" if legacy else "client.p12")
        arguments = ["pkcs12", "-export"]
        if legacy:
            arguments.append("-legacy")
            if self.installation.legacy_provider_dir is not None:
                arguments.extend(
                    [
                        "-provider-path",
                        str(self.installation.legacy_provider_dir),
                    ]
                )
        arguments.extend(
            [
                "-out",
                str(p12_path),
                "-inkey",
                str(source_key),
                "-in",
                str(source_certificate),
                "-passout",
                "env:CERTIFICAT_TEST_P12_PASSWORD",
            ]
        )
        exported = self.run_openssl(
            arguments,
            environment={
                "CERTIFICAT_TEST_P12_PASSWORD": P12_PASSWORD,
                **(
                    {"OPENSSL_MODULES": str(self.installation.legacy_provider_dir)}
                    if legacy and self.installation.legacy_provider_dir is not None
                    else {}
                ),
            },
        )
        if exported.returncode != 0:
            if legacy:
                self.skipTest(
                    "Local OpenSSL cannot create the synthetic legacy fixture: "
                    + exported.stderr.decode(errors="replace")
                )
            self.fail(exported.stderr.decode(errors="replace"))
        return p12_path

    def test_end_to_end_normal_conversion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = self.make_material(root)
            service = ConversionService(OpenSSLBackend(self.installation))

            result = service.convert(
                ConversionRequest(
                    p12_path=p12_path,
                    p12_password=P12_PASSWORD,
                    private_key_password=KEY_PASSWORD,
                )
            )

            self.assertIs(result.mode, LegacyMode.NORMAL)
            self.assertTrue(result.certificate_path.is_file())
            self.assertTrue(result.private_key_path.is_file())
            self.assertIn(
                b"BEGIN CERTIFICATE",
                result.certificate_path.read_bytes(),
            )
            self.assertIn(
                b"BEGIN ENCRYPTED PRIVATE KEY",
                result.private_key_path.read_bytes(),
            )
            verified_key = self.run_openssl(
                [
                    "pkey",
                    "-in",
                    str(result.private_key_path),
                    "-passin",
                    "env:CERTIFICAT_TEST_KEY_PASSWORD",
                    "-check",
                    "-noout",
                ],
                environment={"CERTIFICAT_TEST_KEY_PASSWORD": KEY_PASSWORD},
            )
            self.assertEqual(
                verified_key.returncode,
                0,
                verified_key.stderr.decode(errors="replace"),
            )

    def test_real_legacy_container_uses_automatic_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p12_path = self.make_material(Path(directory), legacy=True)
            backend = OpenSSLBackend(self.installation)

            normal = backend.check_pkcs12(
                p12_path,
                P12_PASSWORD,
                LegacyMode.NORMAL,
            )
            if normal.succeeded:
                self.skipTest("This OpenSSL build reads the legacy fixture normally")

            result = ConversionService(backend).convert(
                ConversionRequest(
                    p12_path=p12_path,
                    p12_password=P12_PASSWORD,
                    private_key_password=KEY_PASSWORD,
                )
            )
            self.assertIs(result.mode, LegacyMode.LEGACY)
            self.assertTrue(result.certificate_path.is_file())
            self.assertTrue(result.private_key_path.is_file())


if __name__ == "__main__":
    unittest.main()
