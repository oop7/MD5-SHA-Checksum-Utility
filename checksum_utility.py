import sys
import hashlib
import base64
from PyQt5.QtWidgets import (QApplication, QWidget, QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QMessageBox, QProgressBar, QTabWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSpacerItem, QSizePolicy)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from io import BytesIO
from PIL import Image
import os

# Base64 encoded icon (example, replace with your actual base64 data)
icon_base64 = """<your_icon_base64_data_here>"""

def get_icon_from_base64(icon_base64):
    """Decode a base64 string to create a QIcon."""
    image_data = base64.b64decode(icon_base64)
    image = Image.open(BytesIO(image_data))
    bytes_io = BytesIO()
    image.save(bytes_io, format='PNG')
    qpixmap = QPixmap()
    qpixmap.loadFromData(bytes_io.getvalue())
    return QIcon(qpixmap)

def calculate_checksum(file_path, algorithm='md5', progress_callback=None):
    """Calculate checksum of a file with the given algorithm and provide progress feedback."""
    hash_func = getattr(hashlib, algorithm)()
    file_size = os.path.getsize(file_path)
    with open(file_path, 'rb') as f:
        bytes_read = 0
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
            bytes_read += len(chunk)
            if progress_callback:
                progress_callback(bytes_read / file_size * 100)
    return hash_func.hexdigest()

class ChecksumThread(QThread):
    """Thread to calculate checksums for multiple algorithms."""
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, file_path, hash_algorithms):
        super().__init__()
        self.file_path = file_path
        self.hash_algorithms = hash_algorithms

    def run(self):
        try:
            results = {}
            for i, algorithm in enumerate(self.hash_algorithms):
                if algorithm['enabled']:
                    results[algorithm['name']] = calculate_checksum(self.file_path, algorithm['name'])
                self.progress.emit(int((i + 1) / len(self.hash_algorithms) * 100))
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))

class ChecksumApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.files_data = []

    def init_ui(self):
        self.setWindowTitle("MD5 & SHA Checksum Utility v2.0")
        self.setWindowIcon(get_icon_from_base64(icon_base64))
        self.setGeometry(400, 100, 800, 600)

        # Modern dark theme
        self.setStyleSheet("""<your_stylesheet_here>""")

        main_layout = QVBoxLayout()

        tab_widget = QTabWidget()

        # Single File Tab
        single_file_tab = QWidget()
        single_file_layout = QVBoxLayout()

        # File selection area
        file_layout = QHBoxLayout()
        file_label = QLabel("File:")
        self.file_entry = QLineEdit()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.open_file)

        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_entry)
        file_layout.addWidget(self.browse_button)
        single_file_layout.addLayout(file_layout)

        # Checksum options and results
        for hash_type in [('MD5', 'md5'), ('SHA-1', 'sha1'),
                         ('SHA-256', 'sha256'), ('SHA-512', 'sha512')]:
            self.create_hash_section(single_file_layout, hash_type)

        # Verify hash section
        self.create_verify_section(single_file_layout)

        # Save report button
        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.save_report)
        single_file_layout.addWidget(self.save_button)

        single_file_tab.setLayout(single_file_layout)

        # Folder Tab
        folder_tab = QWidget()
        folder_layout = QVBoxLayout()

        self.create_folder_section(folder_layout)

        tab_widget.addTab(single_file_tab, "Single File")
        tab_widget.addTab(folder_tab, "Folder")

        main_layout.addWidget(tab_widget)
        self.setLayout(main_layout)

    def create_hash_section(self, layout, hash_type):
        """Create hash type section (MD5, SHA-1, etc.) in the layout."""
        hash_layout = QHBoxLayout()

        checkbox = QCheckBox(hash_type[0])
        checkbox.setChecked(True)
        setattr(self, f"{hash_type[1]}_var", checkbox)

        result_field = QLineEdit()
        result_field.setReadOnly(True)
        setattr(self, f"{hash_type[1]}_result", result_field)

        copy_button = QPushButton(f"Copy {hash_type[0]}")
        copy_button.clicked.connect(
            lambda x, field=result_field: self.copy_to_clipboard(field.text())
        )

        hash_layout.addWidget(checkbox)
        hash_layout.addWidget(result_field)
        hash_layout.addWidget(copy_button)
        layout.addLayout(hash_layout)

    def create_verify_section(self, layout):
        """Create verify hash section in the layout."""
        verify_layout = QVBoxLayout()
        verify_label = QLabel("Verify Hash:")
        self.expected_hash_entry = QLineEdit()
        self.expected_hash_entry.setPlaceholderText("Paste hash to verify")
        self.verify_button = QPushButton("Verify")
        self.verify_button.clicked.connect(self.verify_hash)

        verify_layout.addWidget(verify_label)
        verify_layout.addWidget(self.expected_hash_entry)
        verify_layout.addWidget(self.verify_button)
        layout.addLayout(verify_layout)

    def create_folder_section(self, layout):
        """Create folder section in the layout."""
        folder_header = QHBoxLayout()
        folder_label = QLabel("Folder:")
        self.folder_entry = QLineEdit()
        self.browse_folder_button = QPushButton("Browse Folder")
        self.browse_folder_button.clicked.connect(self.open_folder)

        folder_header.addWidget(folder_label)
        folder_header.addWidget(self.folder_entry)
        folder_header.addWidget(self.browse_folder_button)
        layout.addLayout(folder_header)

        options_layout = QHBoxLayout()
        self.include_subfolders = QCheckBox("Include Subfolders")
        self.include_subfolders.setChecked(True)
        self.include_hidden = QCheckBox("Include Hidden Files")

        options_layout.addWidget(self.include_subfolders)
        options_layout.addWidget(self.include_hidden)
        options_layout.addStretch()
        layout.addLayout(options_layout)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(['File', 'Checksum', 'Status', 'Verify'])
        layout.addWidget(self.results_table)

    def open_file(self):
        """Open file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File')
        if file_path:
            self.file_entry.setText(file_path)
            self.start_checksum_thread(file_path)

    def start_checksum_thread(self, file_path):
        """Start the checksum calculation thread."""
        hash_algorithms = [
            {'name': 'md5', 'enabled': self.md5_var.isChecked()},
            {'name': 'sha1', 'enabled': self.sha1_var.isChecked()},
            {'name': 'sha256', 'enabled': self.sha256_var.isChecked()},
            {'name': 'sha512', 'enabled': self.sha512_var.isChecked()},
        ]

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.checksum_thread = ChecksumThread(file_path, hash_algorithms)
        self.checksum_thread.progress.connect(self.update_progress_bar)
        self.checksum_thread.result.connect(self.display_checksum_results)
        self.checksum_thread.error.connect(self.handle_checksum_error)
        self.checksum_thread.start()

    def update_progress_bar(self, value):
        """Update the progress bar."""
        self.progress_bar.setValue(value)

    def display_checksum_results(self, results):
        """Display the checksum results."""
        self.progress_bar.setVisible(False)
        if 'md5' in results:
            self.md5_result.setText(results.get('md5', ''))
        if 'sha1' in results:
            self.sha1_result.setText(results.get('sha1', ''))
        if 'sha256' in results:
            self.sha256_result.setText(results.get('sha256', ''))
        if 'sha512' in results:
            self.sha512_result.setText(results.get('sha512', ''))

    def handle_checksum_error(self, error_message):
        """Handle checksum calculation errors."""
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", f"Checksum calculation failed: {error_message}")

    def copy_to_clipboard(self, checksum):
        """Copy checksum to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(checksum)
        QMessageBox.information(self, "Copied", "Checksum copied to clipboard!")

    def save_report(self):
        """Save the checksum report to a file."""
        report_data = {
            "File": self.file_entry.text(),
            "MD5": self.md5_result.text(),
            "SHA1": self.sha1_result.text(),
            "SHA256": self.sha256_result.text(),
            "SHA512": self.sha512_result.text()
        }

        file_path, _ = QFileDialog.getSaveFileName(self, 'Save Report', '', 'Text files (*.txt);;JSON files (*.json)')
        if file_path:
            with open(file_path, 'w') as f:
                if file_path.endswith('.json'):
                    import json
                    json.dump(report_data, f, indent=4)
                else:
                    for key, value in report_data.items():
                        f.write(f"{key}: {value}\n")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ChecksumApp()
    window.show()
    sys.exit(app.exec_())