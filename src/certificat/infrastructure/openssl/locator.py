"""Cross-platform discovery of an OpenSSL 3 executable and legacy provider."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

from ...domain.errors import OpenSSLNotFoundError
from ...domain.models import OpenSSLInstallation

_VERSION_PATTERN = re.compile(r"^OpenSSL\s+(3\.\d+(?:\.\d+)*(?:[-+][^\s]+)?)")
_MODULES_PATTERN = re.compile(r'MODULESDIR:\s*"([^"]+)"')


class OpenSSLLocator:
    """Locate the first candidate that identifies itself as OpenSSL 3.x."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        which: Callable[[str], str | None] = shutil.which,
        command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
        extra_candidates: Sequence[Path] = (),
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self._which = which
        self._run = command_runner
        self._extra_candidates = tuple(extra_candidates)

    def locate(self, explicit: Path | None = None) -> OpenSSLInstallation:
        candidates: Iterable[Path]
        if explicit is not None:
            candidates = (explicit,)
        else:
            candidates = self._candidates()

        for candidate in self._unique(candidates):
            installation = self._inspect(candidate)
            if installation is not None:
                return installation

        if explicit is not None:
            raise OpenSSLNotFoundError(
                f"The requested executable is not OpenSSL 3.x: {explicit}"
            )
        raise OpenSSLNotFoundError(
            "OpenSSL 3.x was not found. Install OpenSSL 3 or provide its path."
        )

    def _candidates(self) -> list[Path]:
        candidates = list(self._extra_candidates)
        discovered = self._which("openssl")
        if discovered:
            candidates.append(Path(discovered))

        if self.platform_name == "darwin":
            candidates.extend(
                Path(path)
                for path in (
                    "/opt/homebrew/opt/openssl@3/bin/openssl",
                    "/usr/local/opt/openssl@3/bin/openssl",
                    "/opt/homebrew/bin/openssl",
                    "/usr/local/bin/openssl",
                )
            )
        elif self.platform_name.startswith("win"):
            candidates.extend(
                Path(path)
                for path in (
                    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
                    r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
                    r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
                    r"C:\Program Files\Git\usr\bin\openssl.exe",
                    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
                )
            )
        return candidates

    def _inspect(self, candidate: Path) -> OpenSSLInstallation | None:
        try:
            if not candidate.is_file():
                return None
            if os.name != "nt" and not os.access(candidate, os.X_OK):
                return None
            version_result = self._run(
                [str(candidate), "version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        if version_result.returncode != 0:
            return None
        version_text = version_result.stdout.decode("utf-8", errors="replace").strip()
        match = _VERSION_PATTERN.match(version_text)
        if match is None:
            return None

        executable = candidate.resolve()
        return OpenSSLInstallation(
            executable=executable,
            version=match.group(1),
            legacy_provider_dir=self._find_legacy_provider_dir(executable),
        )

    def _find_legacy_provider_dir(self, executable: Path) -> Path | None:
        candidates: list[Path] = []
        try:
            module_result = self._run(
                [str(executable), "version", "-m"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=5,
            )
            if module_result.returncode == 0:
                module_text = module_result.stdout.decode(
                    "utf-8", errors="replace"
                )
                match = _MODULES_PATTERN.search(module_text)
                if match:
                    candidates.append(Path(match.group(1)))
        except (OSError, subprocess.SubprocessError):
            pass

        executable_dir = executable.parent
        candidates.extend(
            [
                executable_dir,
                executable_dir / "ossl-modules",
                executable_dir.parent / "lib" / "ossl-modules",
                executable_dir.parent / "lib64" / "ossl-modules",
                executable_dir.parent.parent / "lib" / "ossl-modules",
                executable_dir.parent.parent / "lib64" / "ossl-modules",
            ]
        )

        if self.platform_name.startswith("win"):
            candidates.extend(
                [
                    Path(r"C:\Program Files\OpenSSL-Win64\bin"),
                    Path(r"C:\Program Files\OpenSSL-Win64\lib\ossl-modules"),
                    Path(r"C:\Program Files\OpenSSL-Win32\bin"),
                    Path(r"C:\Program Files\OpenSSL-Win32\lib\ossl-modules"),
                ]
            )

        module_names = self._legacy_module_names()
        for directory in self._unique(candidates):
            if any((directory / name).is_file() for name in module_names):
                try:
                    return directory.resolve()
                except OSError:
                    return directory
        return None

    def _legacy_module_names(self) -> tuple[str, ...]:
        if self.platform_name.startswith("win"):
            return ("legacy.dll",)
        if self.platform_name == "darwin":
            return ("legacy.dylib", "legacy.so")
        return ("legacy.so",)

    def _unique(self, paths: Iterable[Path]) -> list[Path]:
        seen: set[str] = set()
        unique: list[Path] = []
        for path in paths:
            text = os.path.normcase(os.fspath(path))
            if text in seen:
                continue
            seen.add(text)
            unique.append(path)
        return unique

