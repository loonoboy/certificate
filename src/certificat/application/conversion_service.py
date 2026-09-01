"""Headless orchestration of the complete secure conversion pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ..domain.errors import (
    CertificateKeyMismatchError,
    InputValidationError,
    UnsafePathError,
)
from ..domain.events import ProgressEvent, ProgressStep
from ..domain.models import (
    ConversionRequest,
    ConversionResult,
    OpenSSLInstallation,
    OutputPaths,
)
from ..infrastructure.filesystem.permissions import PlatformPermissions
from ..infrastructure.filesystem.publisher import TransactionalOutputPublisher
from ..infrastructure.filesystem.workspace import SecureWorkspace
from ..infrastructure.openssl.backend import OpenSSLBackend
from ..infrastructure.openssl.locator import OpenSSLLocator
from .ports import (
    CancellationTokenPort,
    CryptoBackend,
    OutputPublisherPort,
    PermissionsPort,
)

ProgressCallback = Callable[[ProgressEvent], None]


class ConversionService:
    """Execute all operations before publishing either final output file."""

    def __init__(
        self,
        backend: CryptoBackend,
        *,
        permissions: PermissionsPort | None = None,
        publisher: OutputPublisherPort | None = None,
    ) -> None:
        self.backend = backend
        self.permissions = permissions or PlatformPermissions()
        self.publisher = publisher or TransactionalOutputPublisher()

    def convert(
        self,
        request: ConversionRequest,
        *,
        progress: ProgressCallback | None = None,
        cancellation: CancellationTokenPort | None = None,
    ) -> ConversionResult:
        self._check_cancellation(cancellation)
        self._emit(progress, ProgressStep.VALIDATING_INPUT, "Validating input")
        p12_path = self._validate_request(request)
        outputs = OutputPaths.for_pkcs12(p12_path)
        self._check_cancellation(cancellation)

        # Fail before invoking OpenSSL when overwrite has not been authorized.
        self.publisher.preflight(outputs, overwrite=request.overwrite)
        self._check_cancellation(cancellation)

        with SecureWorkspace(
            outputs.directory,
            self.permissions,
            prefix=f".{p12_path.stem}.certificat-",
        ) as workspace:
            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.CHECKING_CONTAINER,
                "Checking PKCS#12 container and legacy compatibility",
            )
            mode = self.backend.detect_pkcs12_mode(
                p12_path,
                request.p12_password,
                cancellation=cancellation,
            )

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.EXTRACTING_CERTIFICATE,
                "Extracting certificate",
            )
            self.backend.extract_certificate(
                p12_path,
                request.p12_password,
                mode,
                workspace.raw_certificate,
                workspace.certificate,
                cancellation=cancellation,
            )

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.EXTRACTING_PRIVATE_KEY,
                "Extracting and encrypting private key as PKCS#8",
            )
            self.backend.extract_and_encrypt_private_key(
                p12_path,
                request.p12_password,
                mode,
                request.private_key_password,
                workspace.encrypted_private_key,
                cancellation=cancellation,
            )

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.VALIDATING_CERTIFICATE,
                "Validating certificate syntax",
            )
            self.backend.validate_certificate(
                workspace.certificate,
                cancellation=cancellation,
            )

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.VALIDATING_PRIVATE_KEY,
                "Validating private key",
            )
            self.backend.validate_private_key(
                workspace.encrypted_private_key,
                request.private_key_password,
                cancellation=cancellation,
            )

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.MATCHING_KEY_PAIR,
                "Checking certificate/private-key match",
            )
            if not self.backend.certificate_matches_private_key(
                workspace.certificate,
                workspace.encrypted_private_key,
                request.private_key_password,
                cancellation=cancellation,
            ):
                raise CertificateKeyMismatchError(
                    "Certificate and private key do not match."
                )

            self._check_cancellation(cancellation)
            self.permissions.prepare_certificate(workspace.certificate)
            self.permissions.prepare_private_key(workspace.encrypted_private_key)

            self._check_cancellation(cancellation)
            self._emit(
                progress,
                ProgressStep.SAVING_RESULTS,
                "Publishing validated output files",
            )
            self.publisher.publish(
                workspace.certificate,
                workspace.encrypted_private_key,
                outputs,
                overwrite=request.overwrite,
                cancellation=cancellation,
            )

        result = ConversionResult(
            certificate_path=outputs.certificate,
            private_key_path=outputs.private_key,
            mode=mode,
            openssl_version=self.backend.version,
        )
        self._emit(progress, ProgressStep.COMPLETED, "Conversion completed")
        return result

    @staticmethod
    def _validate_request(request: ConversionRequest) -> Path:
        raw_path = Path(request.p12_path).expanduser()
        if raw_path.suffix.lower() not in {".p12", ".pfx"}:
            raise InputValidationError("Input file must have a .p12 or .pfx suffix.")
        try:
            raw_path.lstat()
        except FileNotFoundError as error:
            raise InputValidationError(f"Input file was not found: {raw_path}") from error
        if raw_path.is_symlink():
            # Resolve once so output paths cannot be redirected through a symlink
            # whose target changes between validation and publication.
            try:
                raw_path = raw_path.resolve(strict=True)
                raw_path.stat()
            except OSError as error:
                raise UnsafePathError(f"Unable to resolve input path: {raw_path}") from error
        if not raw_path.is_file():
            raise InputValidationError(f"Input is not a regular file: {raw_path}")
        if not request.p12_password:
            raise InputValidationError("The PKCS#12 password must not be empty.")
        if not request.private_key_password:
            raise InputValidationError("The private-key password must not be empty.")
        if "\x00" in request.p12_password or "\x00" in request.private_key_password:
            raise InputValidationError("Passwords must not contain a NUL character.")
        try:
            return raw_path.resolve(strict=True)
        except OSError as error:
            raise InputValidationError(f"Unable to resolve input file: {raw_path}") from error

    @staticmethod
    def _check_cancellation(
        cancellation: CancellationTokenPort | None,
    ) -> None:
        if cancellation is not None:
            cancellation.raise_if_cancelled()

    @staticmethod
    def _emit(
        callback: ProgressCallback | None,
        step: ProgressStep,
        message: str,
    ) -> None:
        if callback is not None:
            callback(ProgressEvent(step=step, message=message))


def discover_openssl(explicit: Path | None = None) -> OpenSSLInstallation:
    """Discover and validate an OpenSSL 3 installation."""

    return OpenSSLLocator().locate(explicit)


def convert_pkcs12(
    request: ConversionRequest,
    *,
    openssl: OpenSSLInstallation | None = None,
    progress: ProgressCallback | None = None,
    cancellation: CancellationTokenPort | None = None,
) -> ConversionResult:
    """Convenience API for a complete headless conversion."""

    ConversionService._check_cancellation(cancellation)
    installation = openssl or discover_openssl()
    ConversionService._check_cancellation(cancellation)
    service = ConversionService(OpenSSLBackend(installation))
    return service.convert(
        request,
        progress=progress,
        cancellation=cancellation,
    )
