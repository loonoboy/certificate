"""OpenSSL implementation of all cryptographic conversion operations."""

from __future__ import annotations

import hmac
from pathlib import Path

from ...application.ports import CancellationTokenPort
from ...domain.errors import OpenSSLExecutionError, Pkcs12OpenError
from ...domain.models import LegacyMode, OpenSSLInstallation
from .commands import (
    P12_PASSWORD_ENV,
    PRIVATE_KEY_PASSWORD_ENV,
    OpenSSLCommands,
)
from .runner import CommandResult, OpenSSLRunner


class OpenSSLBackend:
    """Perform PKCS#12 conversion and validation through OpenSSL 3."""

    def __init__(
        self,
        installation: OpenSSLInstallation,
        runner: OpenSSLRunner | None = None,
    ) -> None:
        self.installation = installation
        self.version = installation.version
        self.commands = OpenSSLCommands(installation)
        self.runner = runner or OpenSSLRunner(installation.executable)

    def _legacy_environment(self, mode: LegacyMode) -> dict[str, str]:
        if (
            mode is LegacyMode.LEGACY
            and self.installation.legacy_provider_dir is not None
        ):
            return {
                "OPENSSL_MODULES": str(self.installation.legacy_provider_dir),
            }
        return {}

    def _password_environment(
        self,
        name: str,
        value: str,
        mode: LegacyMode | None = None,
    ) -> dict[str, str]:
        environment = self._legacy_environment(mode) if mode is not None else {}
        environment[name] = value
        return environment

    def check_pkcs12(
        self,
        p12_path: Path,
        password: str,
        mode: LegacyMode,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> CommandResult:
        """Probe a container in exactly one requested provider mode."""

        return self.runner.run(
            self.commands.pkcs12_probe(p12_path, mode),
            environment=self._password_environment(
                P12_PASSWORD_ENV, password, mode
            ),
            capture_stdout=False,
            secret_values=(password,),
            cancellation=cancellation,
        )

    def detect_pkcs12_mode(
        self,
        p12_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> LegacyMode:
        normal = self.check_pkcs12(
            p12_path,
            password,
            LegacyMode.NORMAL,
            cancellation=cancellation,
        )
        if normal.succeeded:
            return LegacyMode.NORMAL

        legacy = self.check_pkcs12(
            p12_path,
            password,
            LegacyMode.LEGACY,
            cancellation=cancellation,
        )
        if legacy.succeeded:
            return LegacyMode.LEGACY

        raise Pkcs12OpenError(normal.stderr, legacy.stderr)

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
        extracted = self.runner.run(
            self.commands.extract_certificate(p12_path, raw_output, mode),
            environment=self._password_environment(
                P12_PASSWORD_ENV, password, mode
            ),
            capture_stdout=False,
            secret_values=(password,),
            cancellation=cancellation,
        )
        self._require_success(extracted, "extract certificate")

        normalized = self.runner.run(
            self.commands.normalize_certificate(raw_output, certificate_output),
            capture_stdout=False,
            cancellation=cancellation,
        )
        self._require_success(normalized, "normalize certificate")

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
        """Compose separate extraction/encryption commands through an OS pipe."""

        try:
            self.runner.run_pipeline(
                self.commands.extract_private_key(p12_path, mode),
                self.commands.encrypt_private_key(encrypted_output),
                source_environment=self._password_environment(
                    P12_PASSWORD_ENV, p12_password, mode
                ),
                sink_environment=self._password_environment(
                    PRIVATE_KEY_PASSWORD_ENV, private_key_password
                ),
                source_secret_values=(p12_password,),
                sink_secret_values=(private_key_password,),
                cancellation=cancellation,
            )
        except BaseException:
            try:
                encrypted_output.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def validate_certificate(
        self,
        certificate_path: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        result = self.runner.run(
            self.commands.validate_certificate(certificate_path),
            capture_stdout=False,
            cancellation=cancellation,
        )
        self._require_success(result, "validate certificate")

    def validate_private_key(
        self,
        private_key_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        result = self.runner.run(
            self.commands.validate_private_key(private_key_path),
            environment=self._password_environment(
                PRIVATE_KEY_PASSWORD_ENV, password
            ),
            capture_stdout=False,
            secret_values=(password,),
            cancellation=cancellation,
        )
        self._require_success(result, "validate private key")

    def certificate_matches_private_key(
        self,
        certificate_path: Path,
        private_key_path: Path,
        private_key_password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> bool:
        certificate_public_key = self.runner.run(
            self.commands.certificate_public_key(certificate_path),
            cancellation=cancellation,
        )
        self._require_success(
            certificate_public_key,
            "extract public key from certificate",
        )

        private_public_key = self.runner.run(
            self.commands.private_key_public_key(private_key_path),
            environment=self._password_environment(
                PRIVATE_KEY_PASSWORD_ENV, private_key_password
            ),
            secret_values=(private_key_password,),
            cancellation=cancellation,
        )
        self._require_success(
            private_public_key,
            "extract public key from private key",
        )
        return hmac.compare_digest(
            certificate_public_key.stdout,
            private_public_key.stdout,
        )

    @staticmethod
    def _require_success(result: CommandResult, operation: str) -> None:
        if not result.succeeded:
            raise OpenSSLExecutionError(
                operation,
                result.returncode,
                result.stderr,
            )

