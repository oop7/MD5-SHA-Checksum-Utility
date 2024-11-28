import sys
import hashlib
import base64
import json
from PyQt5.QtWidgets import (QApplication, QWidget, QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QMessageBox, QProgressBar)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt
from io import BytesIO
from PIL import Image

# Base64 encoded icon (example, replace with your actual base64 data)
icon_base64 = """
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAsQAAALEBxi1JjQAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAATHSURBVFiFvZd/TJR1HMdfd94PO5x2GSpO8W5OtGaSZRP17gQUaOFAR9PmH9qk3GiVbJj4T9xzpo5INmZZW2ZGbbWZiAr245I44UBTJDMnMf8AsSmWjhBRDpDrj/vBc88PPKT13p49z/P5vL/P5/398fl8vw+MDQLgH82lG6f1AamhD+jGKABnfgpCfkrUfI2lyGCOMf7Q1etLBzxaFZ4eOMLIvRnG48th1ruBexQ4vjFdb44xuoFUtREYANZNNBqqXpgZaz+xKcNk1I0b7sW2/fIW3XXwz6moBNg/rgLQ63Xa70ecgiFAE3qZORfiLHD2RzkxysAA/vYd4WeNpcigOgUTjIaqpJmx9upNGSajZS5kbYbOqw8NoLEUhS8Aoaw2/C6U1cr4SiOgn2A0VNmsU23HNqabDLMSIDsPqvYz0HZZNbDnTBueM+0AfH3Dz/o4DUJZLZ7TbeQUOAMcbzkCRCxaqQD9RKOhapl1qv2oQvDscve9IM8kF9DOoV+GwsFyCpxcAp60OXhqaTIALYCr1KUq4KHBG9pueoPcdNWhGCVCa0AfWvGVG9JkwVd/6b7nbes8e8fXn3XH178KqJR+KDnJwtrFWipKXQBUlLqY/6COW95yWho9tDR6uOUtxympGVqA2Jjxny2xTLF9l/uiyTh5SiD48U+h4w/yKr09DW2djT2+gQzARzBF5QKssoIk5KeQvMQ6zFki5+j8xZvjO3ruLp824bEYwzgtdN+Gr3bDndsAHfOemPRKd9/AeaBf1G5AKkAoq8UlWeWhTMgpcADgCnLEqahz/dx0YbxOZ5Z+sG9wsOuLc1e+ae/qcQAOifsUcEbaJqfASc5WAQhkgsy/VWB9nCbCphPczebCPLuMDEbzutnPFkqt3nNXab54feh+/+AKqa+i1EVFqSuchmJhIb8UOoDiwrThOv6QqiaU1WLqfqBtun7L3dXr84TtwU1JYymiYo8ABKqeUFbLocYATWnjGk7DSY5APY8CfmBZ/FR9dUtHmtTnzE+BB3XMDwZKTrIA7aLnSAwLiHIzsS2Kp883CEBXjNwv7WFykpXkJKucKBMgCn7tRjdv7ajhZH0rAKnL5rBnewoJ1smstM1mpW12IJhCbRejuqaVHXs9XL7yN0/PicW5JYXM1AQVAaLgi7I/J23zNkp2bwCg4XA5trUf0Hw8lxlxEyP4DU0dvP9JfYStMM9OdU0rbxad4EDJapIWzuB08zVeKzwGrCIzNSHcRgP4xXm55o0jmBauZca8Zzj4Ti4ajYZX9xzkz8sX6PvtWyo+WhPmBnO/AfASie3AueC9RmRPA3YCi4FixRH4qa6Vkl0bcb30HEf3ZTE05OflLZsoOnGe7Xt3SekAJwmcDaVYANRLbKeARJFIuYDeu/cxT5vOXzdusvT5eABuXu/EPG06PT29SgLUYCCyehJ8N4oNI56IQqX0EeCX3JX8mhEFKJXSUSkoeV3VJz5TqgqQ1uxHFVTo/pUP6y/ytn0BxekLZX61MyEQKKXiDHkU7PP+zuEjlexruKToVxQg7b2aLRrkOxLJzMwk37FA0S+bAqUej2UUdq5MZJf7LO+tSFT0jzgF/xVGWpBj/jdUg+Lf0/8oYFQLZlS/1wqXMBal/wJknuGtsItVcQAAAABJRU5ErkJggg==
"""

def get_icon_from_base64(icon_base64):
    image_data = base64.b64decode(icon_base64)
    image = Image.open(BytesIO(image_data))
    bytes_io = BytesIO()
    image.save(bytes_io, format='PNG')
    qpixmap = QPixmap()
    qpixmap.loadFromData(bytes_io.getvalue())
    return QIcon(qpixmap)

def calculate_checksum(file_path, algorithm='md5'):
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

class ChecksumApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("MD5 & SHA Checksum Utility v1.0")
        self.setWindowIcon(get_icon_from_base64(icon_base64))
        self.setGeometry(400, 100, 600, 400)

        # Apply dark mode stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #222;
                color: #fff;
            }
            QLabel {
                color: #ccc;
            }
            QLineEdit, QCheckBox {
                background-color: #333;
                color: #fff;
                border: 1px solid #555;
            }
            QPushButton {
                background-color: #444;
                color: #fff;
                border: 1px solid #555;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #555;
            }
            QProgressBar {
                background-color: #333;
                color: #fff;
                border: 1px solid #555;
            }
            QProgressBar::chunk {
                background-color: #0078d7;
            }
        """)

        grid = QGridLayout()

        # File label, entry, and browse button
        file_label = QLabel("File:")
        grid.addWidget(file_label, 0, 0)

        self.file_entry = QLineEdit()
        grid.addWidget(self.file_entry, 0, 1)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.open_file)
        grid.addWidget(self.browse_button, 0, 2)

        # Checkboxes and hash result fields
        self.md5_var = QCheckBox("MD5")
        self.md5_var.setChecked(True)
        grid.addWidget(self.md5_var, 1, 0)

        self.md5_result = QLineEdit()
        self.md5_result.setReadOnly(True)
        grid.addWidget(self.md5_result, 1, 1)

        self.md5_copy_button = QPushButton("Copy MD5")
        self.md5_copy_button.clicked.connect(lambda: self.copy_to_clipboard(self.md5_result.text()))
        grid.addWidget(self.md5_copy_button, 1, 2)

        self.sha1_var = QCheckBox("SHA-1")
        self.sha1_var.setChecked(True)
        grid.addWidget(self.sha1_var, 2, 0)

        self.sha1_result = QLineEdit()
        self.sha1_result.setReadOnly(True)
        grid.addWidget(self.sha1_result, 2, 1)

        self.sha1_copy_button = QPushButton("Copy SHA-1")
        self.sha1_copy_button.clicked.connect(lambda: self.copy_to_clipboard(self.sha1_result.text()))
        grid.addWidget(self.sha1_copy_button, 2, 2)

        self.sha256_var = QCheckBox("SHA-256")
        self.sha256_var.setChecked(True)
        grid.addWidget(self.sha256_var, 3, 0)

        self.sha256_result = QLineEdit()
        self.sha256_result.setReadOnly(True)
        grid.addWidget(self.sha256_result, 3, 1)

        self.sha256_copy_button = QPushButton("Copy SHA-256")
        self.sha256_copy_button.clicked.connect(lambda: self.copy_to_clipboard(self.sha256_result.text()))
        grid.addWidget(self.sha256_copy_button, 3, 2)

        self.sha512_var = QCheckBox("SHA-512")
        self.sha512_var.setChecked(True)
        grid.addWidget(self.sha512_var, 4, 0)

        self.sha512_result = QLineEdit()
        self.sha512_result.setReadOnly(True)
        grid.addWidget(self.sha512_result, 4, 1)

        self.sha512_copy_button = QPushButton("Copy SHA-512")
        self.sha512_copy_button.clicked.connect(lambda: self.copy_to_clipboard(self.sha512_result.text()))
        grid.addWidget(self.sha512_copy_button, 4, 2)

        # Save report button
        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.save_report)
        grid.addWidget(self.save_button, 5, 1)

        # Verify Hash section
        verify_label = QLabel("Verify Hash with Generated Hash (MD5, SHA-1, SHA-256, or SHA-512)")
        grid.addWidget(verify_label, 6, 0, 1, 3)

        self.expected_hash_entry = QLineEdit()
        self.expected_hash_entry.setPlaceholderText("Paste expected hash here")
        grid.addWidget(self.expected_hash_entry, 7, 1)

        self.verify_button = QPushButton("Verify")
        self.verify_button.clicked.connect(self.verify_hash)
        grid.addWidget(self.verify_button, 7, 2)

        # Progress bar for hashing operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        grid.addWidget(self.progress_bar, 8, 0, 1, 3)

        # Set layout
        self.setLayout(grid)

        # Enable drag and drop
        self.setAcceptDrops(True)

    # Function to open file dialog and calculate checksums
    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File')
        if file_path:
            self.file_entry.setText(file_path)
            self.display_checksums(file_path)

    # Function to display checksums
    def display_checksums(self, file_path):
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        try:
            if self.md5_var.isChecked():
                md5_checksum = calculate_checksum(file_path, 'md5')
                self.md5_result.setText(md5_checksum)
            if self.sha1_var.isChecked():
                sha1_checksum = calculate_checksum(file_path, 'sha1')
                self.sha1_result.setText(sha1_checksum)
            if self.sha256_var.isChecked():
                sha256_checksum = calculate_checksum(file_path, 'sha256')
                self.sha256_result.setText(sha256_checksum)
            if self.sha512_var.isChecked():
                sha512_checksum = calculate_checksum(file_path, 'sha512')
                self.sha512_result.setText(sha512_checksum)
            self.progress_bar.setValue(100)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
        finally:
            self.progress_bar.setVisible(False)

    # Function to copy checksum to clipboard
    def copy_to_clipboard(self, checksum):
        clipboard = QApplication.clipboard()
        clipboard.setText(checksum)
        QMessageBox.information(self, "Copied", "Checksum copied to clipboard!")

    # Function to save report to a file
    def save_report(self):
        report_data = {
            "File": self.file_entry.text(),
            "MD5": self.md5_result.text(),
            "SHA1": self.sha1_result.text(),
            "SHA256": self.sha256_result.text(),
            "SHA512": self.sha512_result.text()
        }

        file_path, _ = QFileDialog.getSaveFileName(self, 'Save Report', '', 'Text files (*.txt);;JSON files (*.json)')
        if file_path:
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(report_data, f, indent=4)
            else:
                with open(file_path, 'w') as f:
                    for key, value in report_data.items():
                        f.write(f"{key}: {value}\n")
            QMessageBox.information(self, "Saved", "Report saved to file!")

    # Function to verify the hash
    def verify_hash(self):
        expected_hash = self.expected_hash_entry.text().strip()
        if not expected_hash:
            QMessageBox.warning(self, "Warning", "Please enter an expected hash.")
            return

        computed_hashes = {
            "MD5": self.md5_result.text(),
            "SHA1": self.sha1_result.text(),
            "SHA256": self.sha256_result.text(),
            "SHA512": self.sha512_result.text()
        }

        if expected_hash in computed_hashes.values():
            QMessageBox.information(self, "Success", "The input hash matches one of the computed hashes.")
        else:
            QMessageBox.critical(self, "Mismatch", "The input hash does not match any computed hash.")

    # Enable drag and drop functionality
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_entry.setText(file_path)
            self.display_checksums(file_path)

# Run the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ChecksumApp()
    window.show()
    sys.exit(app.exec_())