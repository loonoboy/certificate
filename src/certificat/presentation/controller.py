"""Qt thread lifecycle and single-operation coordination."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThread, Signal

from ..domain.models import ConversionRequest
from .worker import ConversionWorker

WorkerFactory = Callable[[ConversionRequest], ConversionWorker]


class ConversionController(QObject):
    """Own the worker thread and allow at most one active conversion."""

    started = Signal()
    progress = Signal(object)
    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()
    cancelling = Signal()
    finished = Signal()

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        worker_factory: WorkerFactory = ConversionWorker,
    ) -> None:
        super().__init__(parent)
        self._worker_factory = worker_factory
        self._thread: QThread | None = None
        self._worker: ConversionWorker | None = None

    @property
    def active(self) -> bool:
        return self._thread is not None

    def start(self, request: ConversionRequest) -> None:
        if self.active:
            raise RuntimeError("A conversion is already running.")

        thread = QThread(self)
        worker = self._worker_factory(request)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.progress.connect(self.progress.emit)
        worker.succeeded.connect(self.succeeded.emit)
        worker.failed.connect(self.failed.emit)
        worker.cancelled.connect(self.cancelled.emit)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._thread_finished)
        thread.finished.connect(thread.deleteLater)

        self._thread = thread
        self._worker = worker
        thread.start()
        self.started.emit()

    def cancel(self) -> None:
        worker = self._worker
        if worker is None:
            return
        self.cancelling.emit()
        worker.cancel()

    def _thread_finished(self) -> None:
        self._worker = None
        self._thread = None
        self.finished.emit()
