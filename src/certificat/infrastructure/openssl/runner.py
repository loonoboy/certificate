"""Subprocess runner that keeps passwords out of argv and secret output off disk."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import Mapping, Sequence

from ...domain.errors import OpenSSLExecutionError
from .commands import P12_PASSWORD_ENV, PRIVATE_KEY_PASSWORD_ENV

_MAX_ERROR_BYTES = 16 * 1024
_SECRET_ENV_NAMES = (P12_PASSWORD_ENV, PRIVATE_KEY_PASSWORD_ENV)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0


class OpenSSLRunner:
    """Run one validated OpenSSL executable without using a shell."""

    def __init__(self, executable: Path) -> None:
        self.executable = executable

    @staticmethod
    def _environment(updates: Mapping[str, str] | None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in _SECRET_ENV_NAMES:
            environment.pop(name, None)
        if updates:
            environment.update(updates)
        return environment

    @staticmethod
    def _sanitize(data: bytes, secret_values: Sequence[str]) -> str:
        truncated = data[:_MAX_ERROR_BYTES]
        text = truncated.decode("utf-8", errors="replace").strip()
        for secret in secret_values:
            if secret:
                text = text.replace(secret, "[REDACTED]")
        if len(data) > _MAX_ERROR_BYTES:
            text = f"{text}\n[stderr truncated]" if text else "[stderr truncated]"
        return text

    def run(
        self,
        args: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        capture_stdout: bool = True,
        secret_values: Sequence[str] = (),
    ) -> CommandResult:
        completed = subprocess.run(
            [str(self.executable), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=self._environment(environment),
            shell=False,
            check=False,
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout if capture_stdout else b"",
            stderr=self._sanitize(completed.stderr, secret_values),
        )

    def run_pipeline(
        self,
        source_args: Sequence[str],
        sink_args: Sequence[str],
        *,
        source_environment: Mapping[str, str],
        sink_environment: Mapping[str, str],
        source_secret_values: Sequence[str] = (),
        sink_secret_values: Sequence[str] = (),
    ) -> None:
        """Pipe source stdout directly into sink stdin.

        Source stdout contains the unencrypted private key. It is never read by
        Python, captured for diagnostics, or written to a file.
        """

        source = subprocess.Popen(
            [str(self.executable), *source_args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(source_environment),
            shell=False,
        )
        assert source.stdout is not None
        assert source.stderr is not None

        try:
            sink = subprocess.Popen(
                [str(self.executable), *sink_args],
                stdin=source.stdout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=self._environment(sink_environment),
                shell=False,
            )
        except BaseException:
            source.stdout.close()
            self._stop_process(source)
            raise

        source.stdout.close()
        assert sink.stderr is not None

        source_stderr_parts: list[bytes] = []

        def drain_source_stderr() -> None:
            source_stderr_parts.append(source.stderr.read())

        stderr_thread = Thread(target=drain_source_stderr, daemon=True)
        stderr_thread.start()
        try:
            # Drain source stderr concurrently. Otherwise a verbose source can
            # fill its stderr pipe while the sink waits for more input.
            _, sink_stderr_bytes = sink.communicate()
            source_returncode = source.wait()
            stderr_thread.join()
            source_stderr_bytes = source_stderr_parts[0]
        except BaseException:
            self._stop_process(sink)
            self._stop_process(source)
            stderr_thread.join(timeout=2)
            raise
        finally:
            source.stderr.close()
            sink.stderr.close()

        if source_returncode != 0:
            raise OpenSSLExecutionError(
                "extract private key",
                source_returncode,
                self._sanitize(source_stderr_bytes, source_secret_values),
            )
        if sink.returncode != 0:
            raise OpenSSLExecutionError(
                "encrypt private key as PKCS#8",
                sink.returncode,
                self._sanitize(sink_stderr_bytes, sink_secret_values),
            )

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
