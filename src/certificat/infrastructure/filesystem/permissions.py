"""Platform-specific file mode and ACL hardening."""

from __future__ import annotations

import csv
import io
import os
import subprocess
from pathlib import Path
from typing import Callable

from ...domain.errors import PermissionHardeningError


class PlatformPermissions:
    """Apply POSIX modes or a restricted Windows DACL.

    Windows uses inbox `whoami.exe` and `icacls.exe`. The private key and
    workspace are restricted to the current user SID and LocalSystem. Certificate
    access continues to follow the destination directory policy.
    """

    def __init__(
        self,
        *,
        os_name: str | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.os_name = os_name or os.name
        self._run = command_runner
        self._current_user_sid: str | None = None

    def secure_workspace(self, path: Path) -> None:
        if self.os_name == "nt":
            self._restrict_windows(path, directory=True)
        else:
            self._chmod(path, 0o700)

    def prepare_certificate(self, path: Path) -> None:
        if self.os_name != "nt":
            self._chmod(path, 0o644)

    def prepare_private_key(self, path: Path) -> None:
        if self.os_name == "nt":
            self._restrict_windows(path, directory=False)
        else:
            self._chmod(path, 0o600)

    @staticmethod
    def _chmod(path: Path, mode: int) -> None:
        try:
            path.chmod(mode, follow_symlinks=False)
        except (NotImplementedError, OSError) as error:
            raise PermissionHardeningError(
                f"Unable to apply required permissions to {path}."
            ) from error

    def _restrict_windows(self, path: Path, *, directory: bool) -> None:
        sid = self._get_current_user_sid()
        inheritance = "(OI)(CI)F" if directory else "F"
        grants = [
            f"*{sid}:{inheritance}",
            f"*S-1-5-18:{inheritance}",
        ]
        completed = self._run(
            [
                "icacls.exe",
                str(path),
                "/inheritance:r",
                "/grant:r",
                *grants,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            raise PermissionHardeningError(
                f"Unable to apply a restricted Windows ACL to {path}."
            )

    def _get_current_user_sid(self) -> str:
        if self._current_user_sid is not None:
            return self._current_user_sid
        completed = self._run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            raise PermissionHardeningError("Unable to determine the current user SID.")
        try:
            row = next(csv.reader(io.StringIO(completed.stdout)))
            sid = row[1].strip()
        except (IndexError, StopIteration) as error:
            raise PermissionHardeningError(
                "Unable to parse the current user SID."
            ) from error
        if not sid.startswith("S-"):
            raise PermissionHardeningError("The current user SID is invalid.")
        self._current_user_sid = sid
        return sid

