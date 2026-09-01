"""Publish a validated certificate/key pair with backup and rollback."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from ...application.ports import CancellationTokenPort
from ...domain.errors import (
    ConversionCancelledError,
    OutputExistsError,
    PublicationError,
    UnsafePathError,
)
from ...domain.models import OutputPaths


class TransactionalOutputPublisher:
    """Best-effort transaction for a pair of files.

    Filesystems cannot atomically replace two paths at once. Existing outputs
    are therefore moved to protected backups, staged files are installed with
    `os.replace`, and any partial install is rolled back before an error escapes.
    """

    def __init__(
        self,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        unlink: Callable[[Path], None] | None = None,
    ) -> None:
        self._replace = replace
        self._unlink = unlink or (lambda path: path.unlink())

    def preflight(self, outputs: OutputPaths, *, overwrite: bool) -> None:
        self._validate_target(outputs.certificate)
        self._validate_target(outputs.private_key)
        existing = [path for path in self._targets(outputs) if self._lexists(path)]
        if existing and not overwrite:
            joined = ", ".join(str(path) for path in existing)
            raise OutputExistsError(f"Output already exists: {joined}")

    def publish(
        self,
        staged_certificate: Path,
        staged_private_key: Path,
        outputs: OutputPaths,
        *,
        overwrite: bool,
        cancellation: CancellationTokenPort | None = None,
    ) -> None:
        staged = (staged_certificate, staged_private_key)
        targets = self._targets(outputs)

        for path in staged:
            self._validate_staged(path)

        self._raise_if_cancelled(cancellation)
        with self._output_lock(outputs):
            self._raise_if_cancelled(cancellation)
            self.preflight(outputs, overwrite=overwrite)
            backups: dict[Path, Path] = {}
            installed: list[tuple[Path, Path]] = []
            try:
                for index, target in enumerate(targets):
                    self._raise_if_cancelled(cancellation)
                    if self._lexists(target):
                        backup = staged_certificate.parent / f"backup-{index}"
                        self._replace(target, backup)
                        backups[target] = backup

                for staged_path, target in zip(staged, targets):
                    self._raise_if_cancelled(cancellation)
                    self._replace(staged_path, target)
                    installed.append((staged_path, target))

                # This is the final safe cancellation point. Once durability
                # syncing starts, completing the committed pair wins the race.
                self._raise_if_cancelled(cancellation)
                self._sync_file(outputs.certificate)
                self._sync_file(outputs.private_key)
                self._sync_directory(outputs.directory)
            except BaseException as error:
                rollback_failed = not self._rollback(
                    installed,
                    backups,
                    outputs.directory,
                )
                if isinstance(
                    error,
                    (KeyboardInterrupt, SystemExit, ConversionCancelledError),
                ):
                    raise
                raise PublicationError(
                    "Unable to publish the validated output pair."
                    + (
                        " Rollback was incomplete; inspect the output directory."
                        if rollback_failed
                        else " Previous outputs were restored."
                    ),
                    rollback_failed=rollback_failed,
                ) from error

            for backup in backups.values():
                try:
                    self._unlink(backup)
                except OSError:
                    # Backups live inside the protected workspace and its context
                    # performs a second cleanup attempt.
                    pass

    def _rollback(
        self,
        installed: list[tuple[Path, Path]],
        backups: dict[Path, Path],
        output_directory: Path,
    ) -> bool:
        succeeded = True
        for staged_path, target in reversed(installed):
            if not self._lexists(target):
                continue
            try:
                self._replace(target, staged_path)
            except OSError:
                succeeded = False
        for target, backup in reversed(tuple(backups.items())):
            if not self._lexists(backup):
                succeeded = False
                continue
            try:
                self._replace(backup, target)
            except OSError:
                succeeded = False
        try:
            self._sync_directory(output_directory)
        except OSError:
            succeeded = False
        return succeeded

    @contextmanager
    def _output_lock(self, outputs: OutputPaths) -> Iterator[None]:
        lock_path = outputs.directory / f".{outputs.certificate.stem}.certificat.lock"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except FileExistsError as error:
            raise PublicationError(
                f"Another conversion appears to be publishing {outputs.certificate.name}."
            ) from error
        except OSError as error:
            raise PublicationError("Unable to create the output lock file.") from error

        try:
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.fsync(descriptor)
            yield
        finally:
            os.close(descriptor)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _raise_if_cancelled(
        cancellation: CancellationTokenPort | None,
    ) -> None:
        if cancellation is not None:
            cancellation.raise_if_cancelled()

    @staticmethod
    def _targets(outputs: OutputPaths) -> tuple[Path, Path]:
        return outputs.certificate, outputs.private_key

    @staticmethod
    def _lexists(path: Path) -> bool:
        return os.path.lexists(path)

    def _validate_target(self, path: Path) -> None:
        if not self._lexists(path):
            return
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(metadata.st_mode) or (attributes & reparse_flag):
            raise UnsafePathError(f"Output must not be a symlink/reparse point: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafePathError(f"Output must be a regular file: {path}")

    @staticmethod
    def _validate_staged(path: Path) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise PublicationError(f"Staged output is missing: {path}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise UnsafePathError(f"Staged output must be a regular file: {path}")

    @staticmethod
    def _sync_file(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
