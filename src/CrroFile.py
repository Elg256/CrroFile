import hashlib
import sys
import os

import qdarkstyle

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QWidget, QVBoxLayout, QLineEdit\
    , QFrame, QMessageBox, QProgressBar
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QIcon

from cryptcrro.symetric import ChaCha20
from cryptcrro.hmac import hmac_sha256_chunk


def pbkdf2(password: bytes):
    key = hashlib.pbkdf2_hmac(
        "sha256", password=password,
        salt=b"CRRO_Encryption", iterations=4000
    )
    return key


def create_separator():
    # separator
    separator = QFrame()
    separator.setFrameShape(QFrame.Shape.HLine)
    separator.setFixedHeight(0)
    return separator


class Encrypt(QThread):
    def __init__(self, file_path, password, output_path):
        super().__init__()
        self.file_path = file_path
        self.password = password
        self.output_path = output_path

    def run(self):
        try:

            with open(self.file_path, "rb") as infile, open(self.output_path, "wb") as outfile:
                key = pbkdf2(self.password.encode())
                chacha20 = ChaCha20(key)
                nonce = chacha20.get_nonce()
                outfile.write(b"\x00" * 32 + nonce)

                inner, outer = hmac_sha256_chunk(key)
                inner.update(nonce)
                print(nonce)

                while chunk := infile.read(64 * 1024):
                    encrypted = chacha20.encrypt_chunk(chunk)
                    inner.update(encrypted)
                    outfile.write(encrypted)

                outer.update(inner.digest())
                hmac = outer.digest()

                print("hmac", hmac)
                outfile.seek(0, 0)
                outfile.write(hmac)

        except Exception as e:
            print("Error", str(e))


class Decrypt(QThread):
    hmac_failed = pyqtSignal()

    def __init__(self, file_path, password, output_path):
        super().__init__()
        self.file_path = file_path
        self.password = password
        self.output_path = output_path

    def run(self):
        try:

            with open(self.file_path, "rb") as infile, open(self.output_path, "wb") as outfile:
                key = pbkdf2(self.password.encode())
                chacha20 = ChaCha20(key)
                header = infile.read(40)
                verif_hmac = header[0:32]
                nonce = header[32:40]
                chacha20.set_nonce(nonce)

                inner, outer = hmac_sha256_chunk(key)
                inner.update(nonce)
                print(nonce)

                while chunk := infile.read(64 * 1024):
                    inner.update(chunk)
                    decrypted = chacha20.decrypt_chunk(chunk)
                    outfile.write(decrypted)

                outer.update(inner.digest())
                hmac = outer.digest()

                print(hmac)
                print(verif_hmac)

                if hmac != verif_hmac:
                    self.hmac_failed.emit()

        except Exception as e:
            print(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.file_name = "Drop file into this windows"
        self.output_path = ""
        self.file_path = ""

        self.setWindowTitle("CrroFile")
        self.setWindowIcon(QIcon("./images/Crro_File_logo.png"))

        self.setAcceptDrops(True)

        # file path
        self.label_file_path = QLabel(self.file_name)
        self.label_file_path.setStyleSheet("font-size: 15px;"
                                           "padding: 3px 20px;")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.first_layout = QVBoxLayout()

        self.layout_file_path = QVBoxLayout()
        self.layout_file_path.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.layout_file_path.addWidget(self.label_file_path)



        # password layout
        self.layout_password = QVBoxLayout()

        self.label_password = QLabel("Password: ")
        self.layout_password.addWidget(self.label_password)

        self.entry_password = QLineEdit()
        self.entry_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_password.setAcceptDrops(False)
        self.layout_password.addWidget(self.entry_password)

        self.label_confirm_password = QLabel("Confirm Password: ")
        self.layout_password.addWidget(self.label_confirm_password)

        self.entry_confirm_password = QLineEdit()
        self.entry_confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_confirm_password.setPlaceholderText("Confirm...")
        self.entry_confirm_password.setAcceptDrops(False)
        self.layout_password.addWidget(self.entry_confirm_password)


        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.layout_password.addWidget(self.progress_bar)
        self.progress_bar.hide()

        # output path
        self.layout_output_path = QVBoxLayout()
        self.label_output_path = QLabel("Save output at: ")
        self.layout_output_path.addWidget(self.label_output_path)

        self.entry_output_path = QLineEdit()
        self.layout_output_path.addWidget(self.entry_output_path)

        self.label_as = QLabel("As: ")
        self.layout_output_path.addWidget(self.label_as)

        self.entry_file_name = QLineEdit()
        self.layout_output_path.addWidget(self.entry_file_name)

        self.entry_output_path.setAcceptDrops(False)
        self.entry_file_name.setAcceptDrops(False)

        # encrypt decrypt button
        self.layout_encrypt_decrypt_button = QVBoxLayout()

        self.encrypt_decrypt_button = QPushButton("Encrypt")
        self.layout_encrypt_decrypt_button.addWidget(self.encrypt_decrypt_button)
        self.encrypt_decrypt_button.setStyleSheet("padding: 10px 40px;")
        self.encrypt_decrypt_button.clicked.connect(self.encrypt_decrypt)

        self.central_widget.setLayout(self.first_layout)
        self.first_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.first_layout.addLayout(self.layout_file_path)
        self.first_layout.addWidget(create_separator())
        self.first_layout.addLayout(self.layout_password)
        self.first_layout.addWidget(create_separator())
        self.first_layout.addLayout(self.layout_output_path)
        self.first_layout.addWidget(create_separator())
        self.first_layout.addLayout(self.layout_encrypt_decrypt_button)

        self.setFixedSize(self.minimumSizeHint())



    def show_messagebox(self, windows_title: str, text: str):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(text)
        msg.setWindowTitle(windows_title)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)

        msg.exec()

    def encrypt_decrypt(self):
        try:
            self.entry_confirm_password.hide()
            self.progress_bar.show()
            if self.file_path.endswith(".crro"):
                self.decrypt()
            else:
                self.encrypt()

        except Exception as e:
            self.show_messagebox("Error", "Error: " + str(e))
            self.entry_confirm_password.show()
            self.progress_bar.hide()

    def on_encryption_decryption_end(self):
        self.entry_confirm_password.setVisible(True)
        self.progress_bar.setVisible(False)

    def show_hmac_error(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText("HMAC failed, file integrity cannot be guaranteed.")
        msg.setWindowTitle("HMAC Error")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def encrypt(self):
        if self.entry_password.text() != self.entry_confirm_password.text() or not self.entry_password.text().strip():
            self.show_messagebox("Password Error", "Passwords are not the same or empty")
            return

        self.entry_confirm_password.setVisible(False)
        self.progress_bar.setVisible(True)

        output_path = os.path.join(self.entry_output_path.text(), self.entry_file_name.text())

        self.thread = Encrypt(self.file_path, self.entry_password.text().strip(), output_path)
        self.thread.finished.connect(self.on_encryption_decryption_end)
        self.thread.start()

    def decrypt(self):
        self.entry_confirm_password.setVisible(False)
        self.progress_bar.setVisible(True)

        output_path = os.path.join(self.entry_output_path.text(), self.entry_file_name.text())

        self.thread = Decrypt(self.file_path, self.entry_password.text().strip(), output_path)
        self.thread.finished.connect(self.on_encryption_decryption_end)
        self.thread.hmac_failed.connect(self.show_hmac_error)
        self.thread.start()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            self.file_path = urls[0].toLocalFile()
            self.output_path = os.path.dirname(self.file_path)
            self.file_name = os.path.basename(self.file_path)

            self.label_file_path.setText(self.file_name)
            self.entry_output_path.setText(self.output_path)

            if self.file_name.endswith(".crro"):
                self.encrypt_decrypt_button.setText("Decrypt")
                self.entry_confirm_password.setDisabled(True)
                self.entry_file_name.setText(self.file_name.removesuffix(".crro"))
            else:
                self.encrypt_decrypt_button.setText("Encrypt")
                self.entry_confirm_password.setDisabled(False)
                self.entry_file_name.setText(self.file_name + ".crro")


app = QApplication(sys.argv)
app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
window = MainWindow()
window.show()

app.exec()
