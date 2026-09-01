"""Typed, secret-free errors exposed by the conversion core."""

from __future__ import annotations


class ConversionError(Exception):
    """Base class for expected conversion failures."""


class ConversionCancelledError(ConversionError):
    """The caller requested cooperative cancellation of the conversion."""


class InputValidationError(ConversionError):
    """The conversion request is incomplete or points to an unsafe input."""


class OpenSSLNotFoundError(ConversionError):
    """No executable reporting an OpenSSL 3.x version was found."""


class OpenSSLExecutionError(ConversionError):
    """One OpenSSL operation failed.

    The operation name and sanitized stderr are safe to surface to a caller.
    Command environments and password values are deliberately not retained.
    """

    def __init__(
        self,
        operation: str,
        returncode: int,
        details: str = "",
    ) -> None:
        self.operation = operation
        self.returncode = returncode
        self.details = details
        message = f"OpenSSL operation '{operation}' failed (exit {returncode})."
        if details:
            message = f"{message} {details}"
        super().__init__(message)


class Pkcs12OpenError(ConversionError):
    """Neither normal nor legacy mode could open a PKCS#12 container."""

    def __init__(self, normal_details: str = "", legacy_details: str = "") -> None:
        self.normal_details = normal_details
        self.legacy_details = legacy_details
        super().__init__(
            "Unable to open the PKCS#12 container in normal or legacy mode. "
            "The password may be incorrect, the file may be damaged, or its "
            "algorithms/provider may be unsupported."
        )


class CertificateKeyMismatchError(ConversionError):
    """The certificate and private key contain different public keys."""


class OutputExistsError(ConversionError):
    """An output exists and overwrite was not authorized."""


class UnsafePathError(ConversionError):
    """A symlink, reparse point, or non-regular target was encountered."""


class PermissionHardeningError(ConversionError):
    """Required file permissions or ACL could not be applied."""


class WorkspaceError(ConversionError):
    """A protected temporary workspace could not be created or cleaned."""


class PublicationError(ConversionError):
    """The validated output pair could not be committed safely."""

    def __init__(self, message: str, *, rollback_failed: bool = False) -> None:
        self.rollback_failed = rollback_failed
        super().__init__(message)

