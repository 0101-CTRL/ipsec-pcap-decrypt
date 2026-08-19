from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QEasingCurve, QObject, Property, QPropertyAnimation, QThread, Qt, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPainterPath, QPen
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import DecryptResult, decrypt_capture, parse_xfrm


APP_STYLE = """
QMainWindow, QWidget {
    background: #0b1017;
    color: #e8eef6;
    font-family: "Segoe UI";
    font-size: 10.5pt;
}

QFrame#card {
    background: #111923;
    border: 1px solid #223044;
    border-radius: 16px;
}

QLabel#title {
    font-size: 22pt;
    font-weight: 700;
}

QLabel#subtitle {
    color: #91a0b5;
    font-size: 10pt;
}

QLabel#sectionTitle {
    font-size: 12pt;
    font-weight: 700;
}

QLabel#status {
    color: #91a0b5;
}

QPlainTextEdit {
    background: #0b1119;
    border: 1px solid #26364c;
    border-radius: 10px;
    padding: 10px;
    selection-background-color: #1f8f55;
    font-family: "Cascadia Mono", "Consolas";
    font-size: 9.5pt;
}

QPushButton {
    background: #1b2635;
    border: 1px solid #30445f;
    border-radius: 9px;
    padding: 9px 14px;
    font-weight: 600;
}

QPushButton:hover {
    background: #243349;
}

QPushButton:disabled {
    color: #647387;
    background: #141d29;
    border-color: #223044;
}

QPushButton#primary {
    background: #159957;
    border-color: #20b869;
    color: white;
    font-size: 11pt;
}

QPushButton#primary:hover {
    background: #18aa61;
}

QProgressBar {
    background: #0b1119;
    border: 1px solid #26364c;
    border-radius: 7px;
    text-align: center;
    height: 14px;
}

QProgressBar::chunk {
    background: #22c66f;
    border-radius: 6px;
}

QCheckBox {
    color: #a8b5c7;
}
"""


class LockWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._unlock = 0.0
        self._success = False
        self.setMinimumSize(150, 145)
        self.setMaximumHeight(170)

        self.animation = QPropertyAnimation(self, b"unlockProgress", self)
        self.animation.setDuration(850)
        self.animation.setEasingCurve(QEasingCurve.Type.OutBack)

    def get_unlock_progress(self):
        return self._unlock

    def set_unlock_progress(self, value):
        self._unlock = float(value)
        self.update()

    unlockProgress = Property(float, get_unlock_progress, set_unlock_progress)

    def reset(self):
        self._success = False
        self.animation.stop()
        self.set_unlock_progress(0.0)

    def unlock(self):
        self._success = True
        self.animation.stop()
        self.animation.setStartValue(self._unlock)
        self.animation.setEndValue(1.0)
        self.animation.start()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        green = QColor("#2ee889")
        muted = QColor("#435168")
        body_color = green if self._success else QColor("#76859a")

        cx = self.width() / 2
        body_w = 88
        body_h = 67
        body_x = cx - body_w / 2
        body_y = 66

        # Glow on success
        if self._success:
            for width, alpha in ((22, 18), (14, 28), (8, 40)):
                glow = QColor(green)
                glow.setAlpha(alpha)
                painter.setPen(QPen(glow, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                painter.drawRoundedRect(body_x, body_y, body_w, body_h, 15, 15)

        # Shackle. Right side lifts and rotates slightly as it unlocks.
        painter.save()
        painter.translate(cx, 67)
        painter.rotate(-24 * self._unlock)
        painter.translate(-cx, -67)

        pen = QPen(body_color, 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        shackle = QPainterPath()
        shackle.moveTo(cx - 28, 69)
        shackle.lineTo(cx - 28, 51)
        shackle.cubicTo(cx - 28, 20, cx + 28, 20, cx + 28, 51)
        shackle.lineTo(cx + 28, 69 - (18 * self._unlock))
        painter.drawPath(shackle)
        painter.restore()

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(body_color)
        painter.drawRoundedRect(body_x, body_y, body_w, body_h, 15, 15)

        # Keyhole
        painter.setBrush(QColor("#0b1017"))
        painter.drawEllipse(int(cx - 6), 86, 12, 12)
        painter.drawRoundedRect(int(cx - 3), 96, 6, 18, 3, 3)


class Worker(QObject):
    progress = Signal(int, str)
    success = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, xfrm_text: str, pcap: Path, dedupe: bool):
        super().__init__()
        self.xfrm_text = xfrm_text
        self.pcap = pcap
        self.dedupe = dedupe

    def run(self):
        try:
            result = decrypt_capture(
                self.xfrm_text,
                self.pcap,
                remove_duplicates=self.dedupe,
                progress=lambda p, m: self.progress.emit(p, m),
            )
            self.success.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPsec PCAP Decryptor")
        self.resize(1080, 720)
        self.setMinimumSize(920, 650)
        self.pcap_path: Path | None = None
        self.thread: QThread | None = None
        self.worker: Worker | None = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        title = QLabel("IPsec PCAP Decryptor")
        title.setObjectName("title")
        subtitle = QLabel(
            "Paste the router's XFRM state, choose an ESP capture, and export the decrypted inner traffic."
        )
        subtitle.setObjectName("subtitle")

        root.addWidget(title)
        root.addWidget(subtitle)

        content = QHBoxLayout()
        content.setSpacing(18)
        root.addLayout(content, 1)

        # XFRM card
        left_card = QFrame()
        left_card.setObjectName("card")
        left = QVBoxLayout(left_card)
        left.setContentsMargins(18, 18, 18, 18)
        left.setSpacing(10)

        xfrm_title = QLabel("1  XFRM State")
        xfrm_title.setObjectName("sectionTitle")
        xfrm_hint = QLabel("Paste the complete output of  ip xfrm state")
        xfrm_hint.setObjectName("subtitle")

        self.xfrm_edit = QPlainTextEdit()
        self.xfrm_edit.setPlaceholderText(
            "src 1.1.1.1 dst 48.120.119.206\n"
            "    proto esp spi 0xc7cea1aa reqid 1 mode tunnel\n"
            "    auth-trunc hmac(sha512) 0x... 256\n"
            "    enc cbc(aes) 0x..."
        )

        self.parse_btn = QPushButton("Validate XFRM")
        self.parse_btn.clicked.connect(self.validate_xfrm)
        self.xfrm_status = QLabel("Waiting for XFRM state")
        self.xfrm_status.setObjectName("status")

        left.addWidget(xfrm_title)
        left.addWidget(xfrm_hint)
        left.addWidget(self.xfrm_edit, 1)
        left.addWidget(self.parse_btn)
        left.addWidget(self.xfrm_status)

        # Capture/decrypt card
        right_card = QFrame()
        right_card.setObjectName("card")
        right = QVBoxLayout(right_card)
        right.setContentsMargins(18, 18, 18, 18)
        right.setSpacing(11)

        capture_title = QLabel("2  Capture & Decrypt")
        capture_title.setObjectName("sectionTitle")
        right.addWidget(capture_title)

        self.lock = LockWidget()
        right.addWidget(self.lock, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.lock_status = QLabel("LOCKED")
        self.lock_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lock_status.setStyleSheet("font-size: 11pt; font-weight: 700; color: #7f8da1;")
        right.addWidget(self.lock_status)

        self.file_label = QLabel("No capture selected")
        self.file_label.setObjectName("status")
        self.file_label.setWordWrap(True)
        right.addWidget(self.file_label)

        browse_btn = QPushButton("Choose PCAP / PCAPNG")
        browse_btn.clicked.connect(self.choose_capture)
        right.addWidget(browse_btn)

        self.dedupe = QCheckBox("Remove duplicate exported packets")
        self.dedupe.setChecked(True)
        right.addWidget(self.dedupe)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        right.addWidget(self.progress)

        self.activity = QLabel("Ready")
        self.activity.setObjectName("status")
        self.activity.setWordWrap(True)
        right.addWidget(self.activity)

        self.decrypt_btn = QPushButton("Decrypt Capture")
        self.decrypt_btn.setObjectName("primary")
        self.decrypt_btn.clicked.connect(self.start_decrypt)
        right.addWidget(self.decrypt_btn)

        self.open_output_btn = QPushButton("Open Output Folder")
        self.open_output_btn.setEnabled(False)
        self.open_output_btn.clicked.connect(self.open_output_folder)
        right.addWidget(self.open_output_btn)

        self.output_label = QLabel("")
        self.output_label.setObjectName("status")
        self.output_label.setWordWrap(True)
        right.addWidget(self.output_label)

        right.addStretch()

        content.addWidget(left_card, 3)
        content.addWidget(right_card, 2)

    def validate_xfrm(self):
        try:
            sas = parse_xfrm(self.xfrm_edit.toPlainText())
            if not sas:
                raise ValueError("No usable ESP SAs found.")
            self.xfrm_status.setText(f"✓ {len(sas)} usable ESP Security Association(s) found")
            self.xfrm_status.setStyleSheet("color: #2ee889;")
        except Exception as exc:
            self.xfrm_status.setText(f"✕ {exc}")
            self.xfrm_status.setStyleSheet("color: #ff6b73;")

    def choose_capture(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Choose encrypted capture",
            "",
            "Packet Captures (*.pcap *.pcapng *.cap);;All Files (*)",
        )
        if filename:
            self.pcap_path = Path(filename)
            self.file_label.setText(str(self.pcap_path))
            self.lock.reset()
            self.lock_status.setText("LOCKED")
            self.lock_status.setStyleSheet(
                "font-size: 11pt; font-weight: 700; color: #7f8da1;"
            )
            self.progress.setValue(0)
            self.output_label.clear()
            self.open_output_btn.setEnabled(False)

    def start_decrypt(self):
        xfrm = self.xfrm_edit.toPlainText().strip()
        if not xfrm:
            QMessageBox.warning(self, "Missing XFRM", "Paste the router's XFRM state first.")
            return
        if not self.pcap_path:
            QMessageBox.warning(self, "Missing capture", "Choose a .pcap or .pcapng first.")
            return

        self.lock.reset()
        self.lock_status.setText("DECRYPTING…")
        self.lock_status.setStyleSheet(
            "font-size: 11pt; font-weight: 700; color: #f0c75e;"
        )
        self.progress.setValue(0)
        self.decrypt_btn.setEnabled(False)
        self.parse_btn.setEnabled(False)
        self.activity.setText("Starting…")
        self.output_label.clear()
        self.open_output_btn.setEnabled(False)

        self.thread = QThread(self)
        self.worker = Worker(xfrm, self.pcap_path, self.dedupe.isChecked())
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.success.connect(self.on_success)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.on_finished)
        self.thread.start()

    def on_progress(self, percent: int, message: str):
        self.progress.setValue(percent)
        self.activity.setText(message)

    def on_success(self, result: DecryptResult):
        self.progress.setValue(100)
        self.activity.setText(
            f"Confirmed: {result.final_packet_count:,} plaintext packet(s) exported."
        )
        self.lock_status.setText("UNLOCKED")
        self.lock_status.setStyleSheet(
            "font-size: 11pt; font-weight: 800; color: #2ee889;"
        )
        self.lock.unlock()
        self.output_label.setText(f"Plaintext capture:\n{result.plaintext_path}")
        self.open_output_btn.setEnabled(True)

    def on_failed(self, message: str):
        self.progress.setValue(0)
        self.activity.setText("Decryption failed.")
        self.lock_status.setText("LOCKED")
        self.lock_status.setStyleSheet(
            "font-size: 11pt; font-weight: 700; color: #ff6b73;"
        )
        QMessageBox.critical(self, "Decryption failed", message)

    def on_finished(self):
        self.decrypt_btn.setEnabled(True)
        self.parse_btn.setEnabled(True)

    def open_output_folder(self):
        if self.pcap_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.pcap_path.parent)))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("IPsec PCAP Decryptor")
    app.setStyleSheet(APP_STYLE)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
