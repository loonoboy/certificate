"""Thread-safe cooperative cancellation for conversion operations."""

from threading import Event

from ..domain.errors import ConversionCancelledError


class CancellationToken:
    """A token that can be cancelled safely from a GUI or worker thread."""

    def __init__(self) -> None:
        self._cancelled = Event()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise ConversionCancelledError("Conversion was cancelled.")
