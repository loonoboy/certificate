"""Background conversion worker used by the Qt controller."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from PySide6.QtCore import QObject, Signal, Slot

from ..application.cancellation import CancellationToken
from ..application.conversion_service import convert_pkcs12
from ..application.ports import CancellationTokenPort
from ..domain.errors import ConversionCancelledError, ConversionError
from ..domain.events import ProgressEvent
from ..domain.models import ConversionRequest, ConversionResult


class Converter(Protocol):
    def __call__(
        self,
        request: ConversionRequest,
        *,
        progress: Callable[[ProgressEvent], None] | None = None,
        cancellation: CancellationTokenPort | None = None,
    ) -> ConversionResult: ...


class ConversionWorker(QObject):
    """Run one conversion in a worker thread and expose secret-free signals."""

    progress = Signal(object)
    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()
    finished = Signal()

    def __init__(
        self,
        request: ConversionRequest,
        *,
        converter: Converter = convert_pkcs12,
    ) -> None:
        super().__init__()
        self._request = request
        self._converter = converter
        self._cancellation = CancellationToken()

    def cancel(self) -> None:
        """Request cancellation directly; the token is safe across threads."""

        self._cancellation.cancel()

    @Slot()
    def run(self) -> None:
        try:
            result = self._converter(
                self._request,
                progress=self.progress.emit,
                cancellation=self._cancellation,
            )
        except ConversionCancelledError:
            self.cancelled.emit()
        except ConversionError as error:
            self.failed.emit(str(error))
        except Exception:
            # Unexpected exceptions may contain unsafe implementation details.
            self.failed.emit("An unexpected internal error occurred.")
        else:
            self.succeeded.emit(result)
        finally:
            self.finished.emit()
