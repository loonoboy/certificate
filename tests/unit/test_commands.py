from pathlib import Path
import unittest

from certificat.domain.models import LegacyMode, OpenSSLInstallation
from certificat.infrastructure.openssl.commands import (
    P12_PASSWORD_ENV,
    PRIVATE_KEY_PASSWORD_ENV,
    OpenSSLCommands,
)


class OpenSSLCommandsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.installation = OpenSSLInstallation(
            executable=Path("/opt/openssl/bin/openssl"),
            version="3.0.0",
            legacy_provider_dir=Path("/opt/openssl/lib/ossl-modules"),
        )
        self.commands = OpenSSLCommands(self.installation)

    def test_normal_probe_has_no_legacy_provider_flags(self) -> None:
        args = self.commands.pkcs12_probe(Path("client file.p12"), LegacyMode.NORMAL)

        self.assertEqual(args[0], "pkcs12")
        self.assertNotIn("-legacy", args)
        self.assertNotIn("-provider-path", args)
        self.assertIn(f"env:{P12_PASSWORD_ENV}", args)

    def test_legacy_probe_has_provider_path(self) -> None:
        args = self.commands.pkcs12_probe(Path("client.p12"), LegacyMode.LEGACY)

        self.assertEqual(
            args[:4],
            [
                "pkcs12",
                "-legacy",
                "-provider-path",
                str(self.installation.legacy_provider_dir),
            ],
        )

    def test_private_key_commands_form_a_streaming_pipeline(self) -> None:
        extract = self.commands.extract_private_key(
            Path("client.p12"), LegacyMode.NORMAL
        )
        encrypt = self.commands.encrypt_private_key(Path("encrypted.key"))

        self.assertIn("-noenc", extract)
        self.assertNotIn("-out", extract)
        self.assertNotIn("-in", encrypt)
        self.assertIn("-topk8", encrypt)
        self.assertIn("aes-256-cbc", encrypt)
        self.assertIn(f"env:{PRIVATE_KEY_PASSWORD_ENV}", encrypt)

    def test_openssl_1_1_1_uses_nodes_without_provider_options(self) -> None:
        installation = OpenSSLInstallation(
            executable=Path("/opt/openssl-1.1.1/bin/openssl"),
            version="1.1.1w",
            legacy_provider_dir=Path("/ignored/modules"),
        )
        commands = OpenSSLCommands(installation)

        probe = commands.pkcs12_probe(Path("legacy.p12"), LegacyMode.LEGACY)
        extract = commands.extract_private_key(
            Path("legacy.p12"),
            LegacyMode.LEGACY,
        )

        self.assertNotIn("-legacy", probe)
        self.assertNotIn("-provider-path", probe)
        self.assertIn("-nodes", extract)
        self.assertNotIn("-noenc", extract)

    def test_openssl_4_uses_provider_legacy_and_noenc(self) -> None:
        installation = OpenSSLInstallation(
            executable=Path("/opt/openssl-4/bin/openssl"),
            version="4.0.0",
            legacy_provider_dir=Path("/opt/openssl-4/lib/ossl-modules"),
        )
        commands = OpenSSLCommands(installation)

        probe = commands.pkcs12_probe(Path("legacy.p12"), LegacyMode.LEGACY)
        extract = commands.extract_private_key(
            Path("legacy.p12"),
            LegacyMode.LEGACY,
        )

        self.assertIn("-legacy", probe)
        self.assertIn("-provider-path", probe)
        self.assertIn("-noenc", extract)
        self.assertNotIn("-nodes", extract)

    def test_password_values_never_appear_in_arguments(self) -> None:
        secret = "a password with spaces;$(unsafe)"
        commands = [
            self.commands.pkcs12_probe(Path("client.p12"), LegacyMode.NORMAL),
            self.commands.extract_certificate(
                Path("client.p12"), Path("certificate.pem"), LegacyMode.LEGACY
            ),
            self.commands.extract_private_key(
                Path("client.p12"), LegacyMode.LEGACY
            ),
            self.commands.encrypt_private_key(Path("private.key")),
            self.commands.validate_private_key(Path("private.key")),
        ]

        self.assertTrue(
            all(
                secret not in argument
                for args in commands
                for argument in args
            )
        )


if __name__ == "__main__":
    unittest.main()

