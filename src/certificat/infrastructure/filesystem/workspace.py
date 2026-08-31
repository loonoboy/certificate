"""A private temporary workspace on the output filesystem."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ...application.ports import PermissionsPort
from ...domain.errors import WorkspaceError


@dataclass(frozen=True)
class WorkspacePaths:
    root: Path
    raw_certificate: Path
    certificate: Path
    encrypted_private_key: Path


class SecureWorkspace:
    def __init__(
        self,
        parent: Path,
        permissions: PermissionsPort,
        *,
        prefix: str = ".certificat-",
    ) -> None:
        self.parent = parent
        self.permissions = permissions
        self.prefix = prefix
        self.paths: WorkspacePaths | None = None

    def __enter__(self) -> WorkspacePaths:
        try:
            root = Path(tempfile.mkdtemp(prefix=self.prefix, dir=self.parent))
            self.permissions.secure_workspace(root)
        except BaseException as error:
            if "root" in locals():
                shutil.rmtree(root, ignore_errors=True)
            if isinstance(error, KeyboardInterrupt):
                raise
            raise WorkspaceError(
                f"Unable to create a protected workspace in {self.parent}."
            ) from error

        self.paths = WorkspacePaths(
            root=root,
            raw_certificate=root / "certificate-raw.pem",
            certificate=root / "certificate.crt",
            encrypted_private_key=root / "private-encrypted.key",
        )
        return self.paths

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self.paths is None:
            return False
        try:
            shutil.rmtree(self.paths.root)
        except FileNotFoundError:
            pass
        except OSError as error:
            if exc is None:
                raise WorkspaceError(
                    f"Unable to remove workspace {self.paths.root}."
                ) from error
        return False

