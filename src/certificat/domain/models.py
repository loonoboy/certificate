"""Immutable domain models for PKCS#12 conversion."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class LegacyMode(str, Enum):
    """The PKCS#12 provider mode selected by the probe."""

    NORMAL = "normal"
    LEGACY = "legacy"


@dataclass(frozen=True)
class OpenSSLInstallation:
    """A validated OpenSSL 3 executable and its optional provider directory."""

    executable: Path
    version: str
    legacy_provider_dir: Path | None = None


@dataclass(frozen=True)
class ConversionRequest:
    """Inputs needed by the headless conversion service.

    Password fields are excluded from the generated representation so an
    exception or debug log cannot reveal them accidentally.
    """

    p12_path: Path
    p12_password: str = field(repr=False)
    private_key_password: str = field(repr=False)
    overwrite: bool = False


@dataclass(frozen=True)
class OutputPaths:
    """The two final files produced for one PKCS#12 input."""

    certificate: Path
    private_key: Path

    @classmethod
    def for_pkcs12(cls, p12_path: Path) -> OutputPaths:
        base = p12_path.stem
        return cls(
            certificate=p12_path.parent / f"{base}.crt",
            private_key=p12_path.parent / f"{base}_private_encrypted.key",
        )

    @property
    def directory(self) -> Path:
        return self.certificate.parent


@dataclass(frozen=True)
class ConversionResult:
    """Non-secret result returned after both output files are committed."""

    certificate_path: Path
    private_key_path: Path
    mode: LegacyMode
    openssl_version: str

