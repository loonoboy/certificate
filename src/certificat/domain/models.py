"""Immutable domain models for PKCS#12 conversion."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class LegacyMode(str, Enum):
    """The PKCS#12 provider mode selected by the probe."""

    NORMAL = "normal"
    LEGACY = "legacy"


class OpenSSLGeneration(str, Enum):
    """Supported OpenSSL command-line generations."""

    V1_1_1 = "1.1.1"
    V3 = "3"
    V4 = "4"

    @classmethod
    def from_version(cls, version: str) -> OpenSSLGeneration:
        if re.fullmatch(r"1\.1\.1[a-z]*(?:[-+][^\s]+)?", version):
            return cls.V1_1_1
        if re.fullmatch(r"3\.\d+(?:\.\d+)*(?:[-+][^\s]+)?", version):
            return cls.V3
        if re.fullmatch(r"4\.\d+(?:\.\d+)*(?:[-+][^\s]+)?", version):
            return cls.V4
        raise ValueError(f"Unsupported OpenSSL version: {version}")

    @property
    def supports_legacy_provider(self) -> bool:
        """Whether pkcs12 -legacy and providers are available."""

        return self in {OpenSSLGeneration.V3, OpenSSLGeneration.V4}

    @property
    def unencrypted_key_option(self) -> str:
        """Return the generation-appropriate PKCS#12 extraction option."""

        if self is OpenSSLGeneration.V1_1_1:
            return "-nodes"
        return "-noenc"


@dataclass(frozen=True)
class OpenSSLInstallation:
    """A validated supported OpenSSL executable and provider directory."""

    executable: Path
    version: str
    legacy_provider_dir: Path | None = None
    generation: OpenSSLGeneration = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "generation",
            OpenSSLGeneration.from_version(self.version),
        )


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

