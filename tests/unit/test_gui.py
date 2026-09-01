from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PYSIDE_AVAILABLE = importlib.util.find_spec("PySide6") is not None

if PYSIDE_AVAILABLE:
    from PySide6.QtCore import QEventLoop, QObject, QTimer, Signal
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QApplication, QMessageBox

    from certificat.domain.errors import ConversionCancelledError
    from certificat.domain.events import ProgressEvent, ProgressStep
    from certificat.domain.models import (
        ConversionRequest,
        ConversionResult,
        LegacyMode,
    )
    from certificat.presentation.controller import ConversionController
    from certificat.presentation.main_window import MainWindow
    from certificat.presentation.worker import ConversionWorker


    class FakeController(QObject):
        started = Signal()
        progress = Signal(object)
        succeeded = Signal(object)
        failed = Signal(str)
        cancelled = Signal()
        cancelling = Signal()
        finished = Signal()

        def __init__(self) -> None:
            super().__init__()
            self.active = False
            self.requests: list[ConversionRequest] = []
            self.cancel_calls = 0

        def start(self, request: ConversionRequest) -> None:
            if self.active:
                raise RuntimeError("already active")
            self.active = True
            self.requests.append(request)
            self.started.emit()

        def cancel(self) -> None:
            if not self.active:
                return
            self.cancel_calls += 1
            self.cancelling.emit()

        def complete(self) -> None:
            self.active = False
            self.finished.emit()


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 is not installed")
class MainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.controller = FakeController()
        self.window = MainWindow(self.controller)  # type: ignore[arg-type]
        self.window.show()
        self.application.processEvents()

    def tearDown(self) -> None:
        self.controller.active = False
        self.window.close()
        self.application.processEvents()

    def start_conversion(self, p12_path: Path) -> ConversionRequest:
        self.window.path_input.setText(str(p12_path))
        self.window.p12_password_input.setText("container secret")
        self.window.key_password_input.setText("key secret")
        self.window.confirm_password_input.setText("key secret")
        self.window.convert_button.click()
        self.application.processEvents()
        return self.controller.requests[-1]

    def test_start_builds_request_clears_passwords_and_enforces_single_operation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p12_path = Path(directory) / "client.p12"
            p12_path.write_bytes(b"synthetic")

            request = self.start_conversion(p12_path)
            self.window.convert_button.click()

            self.assertEqual(request.p12_path, p12_path)
            self.assertEqual(request.p12_password, "container secret")
            self.assertEqual(request.private_key_password, "key secret")
            self.assertFalse(request.overwrite)
            self.assertEqual(len(self.controller.requests), 1)
            self.assertEqual(self.window.p12_password_input.text(), "")
            self.assertEqual(self.window.key_password_input.text(), "")
            self.assertEqual(self.window.confirm_password_input.text(), "")
            self.assertFalse(self.window.convert_button.isEnabled())
            self.assertTrue(self.window.cancel_button.isEnabled())

    def test_success_displays_result_and_reenables_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p12_path = root / "client.p12"
            p12_path.write_bytes(b"synthetic")
            self.start_conversion(p12_path)
            result = ConversionResult(
                certificate_path=root / "client.crt",
                private_key_path=root / "client_private_encrypted.key",
                mode=LegacyMode.NORMAL,
                openssl_version="3.test",
            )

            self.controller.succeeded.emit(result)
            self.controller.complete()
            self.application.processEvents()

            self.assertEqual(
                self.window.result_certificate.text(),
                str(result.certificate_path),
            )
            self.assertEqual(
                self.window.result_private_key.text(),
                str(result.private_key_path),
            )
            self.assertEqual(self.window.result_mode.text(), "normal")
            self.assertTrue(self.window.convert_button.isEnabled())
            self.assertFalse(self.window.cancel_button.isEnabled())

    def test_cancel_button_requests_cooperative_cancellation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p12_path = Path(directory) / "client.p12"
            p12_path.write_bytes(b"synthetic")
            self.start_conversion(p12_path)

            self.window.cancel_button.click()
            self.application.processEvents()

            self.assertEqual(self.controller.cancel_calls, 1)
            self.assertFalse(self.window.cancel_button.isEnabled())
            self.assertIn("Cancelling", self.window.status_label.text())

    def test_close_during_operation_requests_cancel_and_waits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            p12_path = Path(directory) / "client.p12"
            p12_path.write_bytes(b"synthetic")
            self.start_conversion(p12_path)
            event = QCloseEvent()

            with patch(
                "certificat.presentation.main_window.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Yes,
            ):
                self.window.closeEvent(event)

            self.assertFalse(event.isAccepted())
            self.assertEqual(self.controller.cancel_calls, 1)


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 is not installed")
class ConversionWorkerTests(unittest.TestCase):
    def request(self) -> ConversionRequest:
        return ConversionRequest(
            p12_path=Path("client.p12"),
            p12_password="container secret",
            private_key_password="key secret",
        )

    def test_worker_forwards_progress_and_result_without_exposing_passwords(
        self,
    ) -> None:
        result = ConversionResult(
            certificate_path=Path("client.crt"),
            private_key_path=Path("client_private_encrypted.key"),
            mode=LegacyMode.NORMAL,
            openssl_version="3.test",
        )

        def converter(
            request: ConversionRequest,
            **kwargs: object,
        ) -> ConversionResult:
            progress = kwargs["progress"]
            progress(
                ProgressEvent(ProgressStep.VALIDATING_INPUT, "Validating input")
            )
            return result

        worker = ConversionWorker(
            self.request(),
            converter=converter,  # type: ignore[arg-type]
        )
        progress_events: list[ProgressEvent] = []
        results: list[ConversionResult] = []
        failures: list[str] = []
        finished: list[bool] = []
        worker.progress.connect(progress_events.append)
        worker.succeeded.connect(results.append)
        worker.failed.connect(failures.append)
        worker.finished.connect(lambda: finished.append(True))

        worker.run()

        self.assertEqual(results, [result])
        self.assertEqual(progress_events[0].step, ProgressStep.VALIDATING_INPUT)
        self.assertEqual(failures, [])
        self.assertEqual(finished, [True])
        signal_text = repr(progress_events) + repr(results) + repr(failures)
        self.assertNotIn("container secret", signal_text)
        self.assertNotIn("key secret", signal_text)

    def test_worker_emits_distinct_cancelled_signal(self) -> None:
        def converter(*_: object, **__: object) -> ConversionResult:
            raise ConversionCancelledError("cancelled")

        worker = ConversionWorker(
            self.request(),
            converter=converter,  # type: ignore[arg-type]
        )
        cancellations: list[bool] = []
        failures: list[str] = []
        worker.cancelled.connect(lambda: cancellations.append(True))
        worker.failed.connect(failures.append)

        worker.run()

        self.assertEqual(cancellations, [True])
        self.assertEqual(failures, [])


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 is not installed")
class ConversionControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_controller_runs_off_ui_thread_and_rejects_second_operation(
        self,
    ) -> None:
        request = ConversionRequest(
            p12_path=Path("client.p12"),
            p12_password="container secret",
            private_key_password="key secret",
        )
        result = ConversionResult(
            certificate_path=Path("client.crt"),
            private_key_path=Path("client_private_encrypted.key"),
            mode=LegacyMode.NORMAL,
            openssl_version="3.test",
        )
        worker_thread_ids: list[int] = []

        def converter(*_: object, **__: object) -> ConversionResult:
            worker_thread_ids.append(threading.get_ident())
            return result

        def worker_factory(value: ConversionRequest) -> ConversionWorker:
            return ConversionWorker(
                value,
                converter=converter,  # type: ignore[arg-type]
            )

        controller = ConversionController(worker_factory=worker_factory)
        results: list[ConversionResult] = []
        finished: list[bool] = []
        event_loop = QEventLoop()
        controller.succeeded.connect(results.append)
        controller.finished.connect(lambda: finished.append(True))
        controller.finished.connect(event_loop.quit)

        controller.start(request)
        with self.assertRaises(RuntimeError):
            controller.start(request)
        QTimer.singleShot(5000, event_loop.quit)
        event_loop.exec()
        self.application.processEvents()

        self.assertEqual(results, [result])
        self.assertEqual(finished, [True])
        self.assertFalse(controller.active)
        self.assertEqual(len(worker_thread_ids), 1)
        self.assertNotEqual(worker_thread_ids[0], threading.get_ident())


if __name__ == "__main__":
    unittest.main()
