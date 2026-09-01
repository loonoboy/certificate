"""Public API for the headless Certificat conversion core."""

from .application.cancellation import CancellationToken
from .application.conversion_service import (
    ConversionService,
    convert_pkcs12,
    discover_openssl,
)
from .domain.errors import (
    CertificateKeyMismatchError,
    ConversionCancelledError,
    ConversionError,
    InputValidationError,
    OpenSSLNotFoundError,
    OutputExistsError,
    Pkcs12OpenError,
    PublicationError,
)
from .domain.events import ProgressEvent, ProgressStep
from .domain.models import (
    ConversionRequest,
    ConversionResult,
    LegacyMode,
    OpenSSLInstallation,
    OutputPaths,
)
from .infrastructure.openssl.backend import OpenSSLBackend
from .infrastructure.openssl.locator import OpenSSLLocator

__all__ = [
    "CancellationToken",
    "CertificateKeyMismatchError",
    "ConversionCancelledError",
    "ConversionError",
    "ConversionRequest",
    "ConversionResult",
    "ConversionService",
    "InputValidationError",
    "LegacyMode",
    "OpenSSLInstallation",
    "OpenSSLBackend",
    "OpenSSLLocator",
    "OpenSSLNotFoundError",
    "OutputExistsError",
    "OutputPaths",
    "Pkcs12OpenError",
    "ProgressEvent",
    "ProgressStep",
    "PublicationError",
    "convert_pkcs12",
    "discover_openssl",
]
