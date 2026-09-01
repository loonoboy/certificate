"""Pure construction of OpenSSL argument arrays.

Passwords are referenced by environment-variable name and never embedded in an
argument. Keeping this module side-effect free makes the security-sensitive
command shapes straightforward to test.
"""

from __future__ import annotations

from pathlib import Path

from ...domain.models import LegacyMode, OpenSSLInstallation

P12_PASSWORD_ENV = "CERTIFICAT_P12_PASSWORD"
PRIVATE_KEY_PASSWORD_ENV = "CERTIFICAT_PRIVATE_KEY_PASSWORD"


class OpenSSLCommands:
    def __init__(self, installation: OpenSSLInstallation) -> None:
        self.installation = installation

    def _pkcs12_prefix(self, mode: LegacyMode) -> list[str]:
        args = ["pkcs12"]
        if (
            mode is LegacyMode.LEGACY
            and self.installation.generation.supports_legacy_provider
        ):
            args.append("-legacy")
            if self.installation.legacy_provider_dir is not None:
                args.extend(
                    ["-provider-path", str(self.installation.legacy_provider_dir)]
                )
        return args

    def pkcs12_probe(self, p12_path: Path, mode: LegacyMode) -> list[str]:
        return self._pkcs12_prefix(mode) + [
            "-in",
            str(p12_path),
            "-passin",
            f"env:{P12_PASSWORD_ENV}",
            "-noout",
        ]

    def extract_certificate(
        self,
        p12_path: Path,
        output_path: Path,
        mode: LegacyMode,
    ) -> list[str]:
        return self._pkcs12_prefix(mode) + [
            "-in",
            str(p12_path),
            "-passin",
            f"env:{P12_PASSWORD_ENV}",
            "-clcerts",
            "-nokeys",
            "-out",
            str(output_path),
        ]

    @staticmethod
    def normalize_certificate(input_path: Path, output_path: Path) -> list[str]:
        return [
            "x509",
            "-in",
            str(input_path),
            "-outform",
            "PEM",
            "-out",
            str(output_path),
        ]

    def extract_private_key(
        self,
        p12_path: Path,
        mode: LegacyMode,
    ) -> list[str]:
        # No -out option: OpenSSL writes to stdout, which is connected directly
        # to the pkcs8 process by OpenSSLRunner.run_pipeline.
        return self._pkcs12_prefix(mode) + [
            "-in",
            str(p12_path),
            "-passin",
            f"env:{P12_PASSWORD_ENV}",
            "-nocerts",
            self.installation.generation.unencrypted_key_option,
        ]

    @staticmethod
    def encrypt_private_key(output_path: Path) -> list[str]:
        # No -in option: plaintext is consumed from the extraction pipe.
        return [
            "pkcs8",
            "-topk8",
            "-v2",
            "aes-256-cbc",
            "-passout",
            f"env:{PRIVATE_KEY_PASSWORD_ENV}",
            "-out",
            str(output_path),
        ]

    @staticmethod
    def validate_certificate(certificate_path: Path) -> list[str]:
        return ["x509", "-in", str(certificate_path), "-noout"]

    @staticmethod
    def validate_private_key(private_key_path: Path) -> list[str]:
        return [
            "pkey",
            "-in",
            str(private_key_path),
            "-passin",
            f"env:{PRIVATE_KEY_PASSWORD_ENV}",
            "-check",
            "-noout",
        ]

    @staticmethod
    def certificate_public_key(certificate_path: Path) -> list[str]:
        return ["x509", "-in", str(certificate_path), "-pubkey", "-noout"]

    @staticmethod
    def private_key_public_key(private_key_path: Path) -> list[str]:
        return [
            "pkey",
            "-in",
            str(private_key_path),
            "-passin",
            f"env:{PRIVATE_KEY_PASSWORD_ENV}",
            "-pubout",
        ]

