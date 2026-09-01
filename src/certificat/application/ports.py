"""Ports used by the conversion service."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..domain.models import LegacyMode, OutputPaths


class CancellationTokenPort(Protocol):
    @property
    def is_cancelled(self) -> bool: ...

    def raise_if_cancelled(self) -> None: ...


class CryptoBackend(Protocol):
    version: str

    def detect_pkcs12_mode(
        self,
        p12_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> LegacyMode: ...

    def extract_certificate(
        self,
        p12_path: Path,
        password: str,
        mode: LegacyMode,
        raw_output: Path,
        certificate_output: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None: ...

    def extract_and_encrypt_private_key(
        self,
        p12_path: Path,
        p12_password: str,
        mode: LegacyMode,
        private_key_password: str,
        encrypted_output: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None: ...

    def validate_certificate(
        self,
        certificate_path: Path,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None: ...

    def validate_private_key(
        self,
        private_key_path: Path,
        password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> None: ...

    def certificate_matches_private_key(
        self,
        certificate_path: Path,
        private_key_path: Path,
        private_key_password: str,
        *,
        cancellation: CancellationTokenPort | None = None,
    ) -> bool: ...


class OutputPublisherPort(Protocol):
    def preflight(self, outputs: OutputPaths, *, overwrite: bool) -> None: ...

    def publish(
        self,
        staged_certificate: Path,
        staged_private_key: Path,
        outputs: OutputPaths,
        *,
        overwrite: bool,
        cancellation: CancellationTokenPort | None = None,
    ) -> None: ...


class PermissionsPort(Protocol):
    def secure_workspace(self, path: Path) -> None: ...

    def prepare_certificate(self, path: Path) -> None: ...

    def prepare_private_key(self, path: Path) -> None: ...

