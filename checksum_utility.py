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

class ChecksumWorker(QThread):
    """Worker thread for checksum calculation to avoid blocking the main thread."""
    progress = pyqtSignal(int)
    result = pyqtSignal(str)

    def __init__(self, file_path, algorithm):
        super().__init__()
        self.file_path = file_path
        self.algorithm = algorithm

    def run(self):
        checksum = calculate_checksum(self.file_path, self.algorithm, progress_callback=self.update_progress)
        self.result.emit(checksum)

    def update_progress(self, progress):
        self.progress.emit(int(progress))

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
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a File")
        if file_path:
            self.file_entry.setText(file_path)

    def open_folder(self):
        """Open folder dialog to select a folder."""
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder_path:
            self.folder_entry.setText(folder_path)

    def copy_to_clipboard(self, text):
        """Copy text to the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def verify_hash(self):
        """Verify the hash of a file against the expected hash."""
        expected_hash = self.expected_hash_entry.text()
        if not expected_hash:
            QMessageBox.warning(self, "Error", "Please enter a hash to verify.")
            return

        file_path = self.file_entry.text()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file.")
            return

        calculated_hash = self.calculate_checksum(file_path)
        if calculated_hash == expected_hash:
            QMessageBox.information(self, "Success", "Hash matches!")
        else:
            QMessageBox.warning(self, "Failure", "Hash does not match!")

    def save_report(self):
        """Save the checksum report to a file."""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, 'w') as f:
                f.write("Checksum Report\n")
                f.write("===============\n")
                for file_data in self.files_data:
                    f.write(f"File: {file_data['file']}\n")
                    f.write(f"MD5: {file_data['md5']}\n")
                    f.write(f"SHA-1: {file_data['sha1']}\n")
                    f.write(f"SHA-256: {file_data['sha256']}\n")
                    f.write(f"SHA-512: {file_data['sha512']}\n\n")

    def calculate_checksum(self, file_path):
        """Calculate checksum for all selected hash algorithms."""
        result = {}
        for hash_type in [('md5', self.md5_var), ('sha1', self.sha1_var),
                         ('sha256', self.sha256_var), ('sha512', self.sha512_var)]:
            if hash_type[1].isChecked():
                checksum = calculate_checksum(file_path, hash_type[0])
                result[hash_type[0]] = checksum
                getattr(self, f"{hash_type[0]}_result").setText(checksum)
        return result

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ChecksumApp()
    window.show()
    sys.exit(app.exec_())
