"""Main desktop window for PKCS#12 conversion."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QTimer, Qt, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..domain.events import ProgressEvent
from ..domain.models import ConversionRequest, ConversionResult, OutputPaths
from .controller import ConversionController


class MainWindow(QMainWindow):
    def __init__(
        self,
        controller: ConversionController | None = None,
    ) -> None:
        super().__init__()
        self.controller = controller or ConversionController(self)
        self._close_after_operation = False

        self.setWindowTitle("Certificat")
        self.setMinimumWidth(680)
        self._build_ui()
        self._connect_signals()
        self._set_busy(False)

    def _build_ui(self) -> None:
        central = QWidget(self)
        root = QVBoxLayout(central)

        intro = QLabel(
            "Extract a client certificate and an encrypted PKCS#8 private key "
            "from a .p12 or .pfx container. Certificate trust, expiry, and "
            "revocation are not checked."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        input_group = QGroupBox("Conversion input")
        form = QFormLayout(input_group)

        file_row = QWidget()
        file_layout = QHBoxLayout(file_row)
        file_layout.setContentsMargins(0, 0, 0, 0)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("/path/to/client.p12")
        self.browse_button = QPushButton("&Browse…")
        file_layout.addWidget(self.path_input, 1)
        file_layout.addWidget(self.browse_button)
        path_label = QLabel("&PKCS#12 container:")
        path_label.setBuddy(self.path_input)
        form.addRow(path_label, file_row)

        self.p12_password_input = self._password_input()
        p12_label = QLabel("Container &password:")
        p12_label.setBuddy(self.p12_password_input)
        form.addRow(p12_label, self.p12_password_input)

        self.key_password_input = self._password_input()
        key_label = QLabel("&New key password:")
        key_label.setBuddy(self.key_password_input)
        form.addRow(key_label, self.key_password_input)

        self.confirm_password_input = self._password_input()
        confirm_label = QLabel("Con&firm key password:")
        confirm_label.setBuddy(self.confirm_password_input)
        form.addRow(confirm_label, self.confirm_password_input)
        root.addWidget(input_group)

        output_group = QGroupBox("Output files")
        output_form = QFormLayout(output_group)
        self.output_certificate = self._selectable_label("—")
        self.output_private_key = self._selectable_label("—")
        output_form.addRow("Certificate:", self.output_certificate)
        output_form.addRow("Encrypted private key:", self.output_private_key)
        root.addWidget(output_group)

        self.status_label = QLabel("Ready")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        root.addWidget(self.progress_bar)

        result_group = QGroupBox("Last result")
        result_form = QFormLayout(result_group)
        self.result_certificate = self._selectable_label("—")
        self.result_private_key = self._selectable_label("—")
        self.result_mode = self._selectable_label("—")
        result_form.addRow("Certificate:", self.result_certificate)
        result_form.addRow("Private key:", self.result_private_key)
        result_form.addRow("PKCS#12 mode:", self.result_mode)
        root.addWidget(result_group)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.convert_button = QPushButton("&Convert")
        self.convert_button.setDefault(True)
        self.cancel_button = QPushButton("&Cancel")
        button_row.addWidget(self.convert_button)
        button_row.addWidget(self.cancel_button)
        root.addLayout(button_row)

        self.setCentralWidget(central)

    @staticmethod
    def _password_input() -> QLineEdit:
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        field.setDragEnabled(False)
        return field

    @staticmethod
    def _selectable_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setWordWrap(True)
        return label

    def _connect_signals(self) -> None:
        self.browse_button.clicked.connect(self._browse)
        self.path_input.textChanged.connect(self._update_output_preview)
        self.convert_button.clicked.connect(self._start_conversion)
        self.cancel_button.clicked.connect(self.controller.cancel)
        self.controller.started.connect(self._operation_started)
        self.controller.progress.connect(self._progress_changed)
        self.controller.succeeded.connect(self._conversion_succeeded)
        self.controller.failed.connect(self._conversion_failed)
        self.controller.cancelled.connect(self._conversion_cancelled)
        self.controller.cancelling.connect(self._cancelling)
        self.controller.finished.connect(self._operation_finished)

    @Slot()
    def _browse(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select PKCS#12 container",
            self.path_input.text(),
            "PKCS#12 containers (*.p12 *.pfx);;All files (*)",
        )
        if selected:
            self.path_input.setText(selected)

    @Slot(str)
    def _update_output_preview(self, value: str) -> None:
        if not value.strip():
            self.output_certificate.setText("—")
            self.output_private_key.setText("—")
            return
        outputs = OutputPaths.for_pkcs12(Path(value).expanduser())
        self.output_certificate.setText(str(outputs.certificate))
        self.output_private_key.setText(str(outputs.private_key))

    @Slot()
    def _start_conversion(self) -> None:
        if self.controller.active:
            return

        path_text = self.path_input.text().strip()
        p12_password = self.p12_password_input.text()
        key_password = self.key_password_input.text()
        confirmation = self.confirm_password_input.text()
        if not path_text:
            self._warning("Missing input", "Select a .p12 or .pfx container.")
            return
        if not p12_password:
            self._warning("Missing password", "Enter the PKCS#12 password.")
            return
        if not key_password:
            self._warning("Missing password", "Enter a new private-key password.")
            return
        if key_password != confirmation:
            self._warning("Password mismatch", "Private-key passwords do not match.")
            return

        p12_path = Path(path_text).expanduser()
        outputs = OutputPaths.for_pkcs12(p12_path)
        existing = [
            path
            for path in (outputs.certificate, outputs.private_key)
            if os.path.lexists(path)
        ]
        overwrite = False
        if existing:
            names = "\n".join(f"• {path}" for path in existing)
            answer = QMessageBox.question(
                self,
                "Replace existing output?",
                "The following output file(s) already exist:\n"
                f"{names}\n\nReplace them only after conversion validation succeeds?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            overwrite = True

        request = ConversionRequest(
            p12_path=p12_path,
            p12_password=p12_password,
            private_key_password=key_password,
            overwrite=overwrite,
        )
        self._clear_passwords()
        self._clear_result()
        try:
            self.controller.start(request)
        except RuntimeError as error:
            self._conversion_failed(str(error))

    def _clear_passwords(self) -> None:
        # setText clears QLineEdit's undo/redo history as well as visible text.
        self.p12_password_input.setText("")
        self.key_password_input.setText("")
        self.confirm_password_input.setText("")

    def _clear_result(self) -> None:
        self.result_certificate.setText("—")
        self.result_private_key.setText("—")
        self.result_mode.setText("—")

    @Slot()
    def _operation_started(self) -> None:
        self._set_busy(True)
        self.status_label.setText("Starting conversion…")

    @Slot(object)
    def _progress_changed(self, event: object) -> None:
        if isinstance(event, ProgressEvent):
            self.status_label.setText(event.message)

    @Slot(object)
    def _conversion_succeeded(self, result: object) -> None:
        if not isinstance(result, ConversionResult):
            self._conversion_failed("The conversion returned an invalid result.")
            return
        self.result_certificate.setText(str(result.certificate_path))
        self.result_private_key.setText(str(result.private_key_path))
        self.result_mode.setText(result.mode.value)
        self.status_label.setText("Conversion completed successfully.")

    @Slot(str)
    def _conversion_failed(self, message: str) -> None:
        self.status_label.setText("Conversion failed.")
        QMessageBox.critical(self, "Conversion failed", message)

    @Slot()
    def _conversion_cancelled(self) -> None:
        self.status_label.setText("Conversion cancelled. No new output was published.")

    @Slot()
    def _cancelling(self) -> None:
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Cancelling conversion…")

    @Slot()
    def _operation_finished(self) -> None:
        self._set_busy(False)
        self._clear_passwords()
        if self._close_after_operation:
            self._close_after_operation = False
            QTimer.singleShot(0, self.close)

    def _set_busy(self, busy: bool) -> None:
        self.path_input.setEnabled(not busy)
        self.browse_button.setEnabled(not busy)
        self.p12_password_input.setEnabled(not busy)
        self.key_password_input.setEnabled(not busy)
        self.confirm_password_input.setEnabled(not busy)
        self.convert_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress_bar.setRange(0, 0 if busy else 1)
        if not busy:
            self.progress_bar.setValue(0)

    def _warning(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self.controller.active:
            event.accept()
            return
        if self._close_after_operation:
            event.ignore()
            return
        answer = QMessageBox.question(
            self,
            "Conversion in progress",
            "Cancel the active conversion and close after cleanup completes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._close_after_operation = True
            self.controller.cancel()
        event.ignore()
