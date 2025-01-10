import sys
import hashlib
import base64
import json
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QMessageBox, QProgressBar, QTabWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from io import BytesIO
from PIL import Image
import os

# Base64 encoded icon
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
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):  # Read file in 64KB chunks
                hash_func.update(chunk)
    except Exception as e:
        raise Exception(f"Error reading file {file_path}: {e}")
    return hash_func.hexdigest()

class ChecksumThread(QThread):
    finished = pyqtSignal(str, str)

    def __init__(self, file_path, algorithm):
        super().__init__()
        self.file_path = file_path
        self.algorithm = algorithm

    def run(self):
        try:
            checksum = calculate_checksum(self.file_path, self.algorithm)
            self.finished.emit(self.algorithm, checksum)
        except Exception as e:
            self.finished.emit(self.algorithm, str(e))

class ChecksumApp(QWidget):
    progress_update = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.init_ui()
        self.files_data = []
        self.threads = []
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress_bar)
        self.current_file_size = 0
        self.total_bytes_read = 0
        self.finished_threads_count = 0
        self.algorithms = []  # Store the algorithms to be calculated
        self.file_path = ""

    def init_ui(self):
        self.setWindowTitle("MD5 & SHA Checksum Utility v3.0")
        self.setWindowIcon(get_icon_from_base64(icon_base64))
        self.setGeometry(400, 100, 800, 600)

        # Modern dark theme
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                font-size: 10pt;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background: #2b2b2b;
            }
            QTabBar::tab {
                background: #1e1e1e;
                color: #ffffff;
                padding: 8px 20px;
                border: 1px solid #444;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0078d7;
                border-bottom: none;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                padding: 5px;
                background-color: #3b3b3b;
                border: 1px solid #555;
                border-radius: 3px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #1e88e5;
            }
            QPushButton:pressed {
                background-color: #005fb3;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QProgressBar {
                border: 1px solid #444;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078d7;
            }
            QTableWidget {
                background-color: #2b2b2b;
                gridline-color: #444;
                border: 1px solid #444;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                padding: 5px;
                border: 1px solid #444;
            }
        """)

        # Main layout
        main_layout = QVBoxLayout()
        
        # Create tab widget
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
            single_file_layout.addLayout(hash_layout)

        # Verify hash section
        verify_layout = QVBoxLayout()
        verify_label = QLabel("Verify Hash:")
        self.expected_hash_entry = QLineEdit()
        self.expected_hash_entry.setPlaceholderText("Paste hash to verify")
        self.verify_button = QPushButton("Verify")
        self.verify_button.clicked.connect(self.verify_hash)
        
        verify_layout.addWidget(verify_label)
        verify_layout.addWidget(self.expected_hash_entry)
        verify_layout.addWidget(self.verify_button)
        single_file_layout.addLayout(verify_layout)

        # Save report button
        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.save_report)
        single_file_layout.addWidget(self.save_button)
        
        single_file_tab.setLayout(single_file_layout)

        # Folder Tab
        folder_tab = QWidget()
        folder_layout = QVBoxLayout()
        
        # Folder selection
        folder_header = QHBoxLayout()
        folder_label = QLabel("Folder:")
        self.folder_entry = QLineEdit()
        self.browse_folder_button = QPushButton("Browse Folder")
        self.browse_folder_button.clicked.connect(self.open_folder)
        
        folder_header.addWidget(folder_label)
        folder_header.addWidget(self.folder_entry)
        folder_header.addWidget(self.browse_folder_button)
        folder_layout.addLayout(folder_header)

        # Options
        options_layout = QHBoxLayout()
        self.include_subfolders = QCheckBox("Include Subfolders")
        self.include_subfolders.setChecked(True)
        self.include_hidden = QCheckBox("Include Hidden Files")
        
        options_layout.addWidget(self.include_subfolders)
        options_layout.addWidget(self.include_hidden)
        options_layout.addStretch()
        folder_layout.addLayout(options_layout)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(
            ['File Name', 'Path', 'MD5', 'SHA-1', 'SHA-256', 'SHA-512']
        )
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        folder_layout.addWidget(self.results_table)

        # Save folder results button
        self.save_folder_results = QPushButton("Save Folder Results")
        self.save_folder_results.clicked.connect(self.save_folder_report)
        folder_layout.addWidget(self.save_folder_results)
        
        folder_tab.setLayout(folder_layout)

        # Add tabs to widget
        tab_widget.addTab(single_file_tab, "Single File")
        tab_widget.addTab(folder_tab, "Folder Scan")
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)  # Make sure the text is visible
        
        # Add everything to main layout
        main_layout.addWidget(tab_widget)
        main_layout.addWidget(self.progress_bar)
        
        self.setLayout(main_layout)
        
        # Enable drag and drop
        self.setAcceptDrops(True)

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File')
        if file_path:
            self.file_entry.setText(file_path)
            self.display_checksums(file_path)

    def display_checksums(self, file_path):
        self.file_path = file_path
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Calculating...")  # Initial text
        self.current_file_size = os.path.getsize(file_path)
        self.total_bytes_read = 0
        self.finished_threads_count = 0
        self.algorithms = []

        self.threads = []
        for algorithm in ['md5', 'sha1', 'sha256', 'sha512']:
            if getattr(self, f"{algorithm}_var").isChecked():
                self.algorithms.append(algorithm)
                thread = ChecksumThread(file_path, algorithm)
                thread.finished.connect(self.update_checksum_result)
                thread.start()
                self.threads.append(thread)

        # Use a signal-slot connection for updating the progress
        self.progress_update.connect(self.update_progress_bar)

        # Start the timer to simulate progress (since we don't track bytes)
        self.progress_value = 0
        self.progress_timer.start(50)  # Update every 50 milliseconds

    def update_progress_bar(self):
        if self.finished_threads_count < len(self.threads):
            # Simulate progress if not all threads are finished
            self.progress_value = (self.progress_value + 1) % 101  # Update from 0 to 100
            self.progress_bar.setValue(self.progress_value)
            self.progress_bar.setFormat(f"Calculating... {self.progress_value}%")
        else:
            # All threads are finished
            self.progress_timer.stop()
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Complete")
            self.file_path = ""

    def update_checksum_result(self, algorithm, checksum):
        if checksum.startswith("Error"):
            QMessageBox.critical(self, "Error", checksum)
        else:
            getattr(self, f"{algorithm}_result").setText(checksum)
        self.finished_threads_count += 1

    def copy_to_clipboard(self, checksum):
        clipboard = QApplication.clipboard()
        clipboard.setText(checksum)
        QMessageBox.information(self, "Copied", "Checksum copied to clipboard!")

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

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_entry.setText(file_path)
            self.display_checksums(file_path)

    def open_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder_path:
            self.folder_entry.setText(folder_path)
            self.scan_folder(folder_path)

    def scan_folder(self, folder_path):
        self.files_data = []
        self.progress_bar.setVisible(True)
        self.results_table.setRowCount(0)
        
        files_to_scan = []
        for root, dirs, files in os.walk(folder_path):
            if not self.include_subfolders.isChecked() and root != folder_path:
                continue
                
            for file in files:
                if not self.include_hidden.isChecked() and file.startswith('.'):
                    continue
                    
                full_path = os.path.join(root, file)
                files_to_scan.append(full_path)

        total_files = len(files_to_scan)
        for i, file_path in enumerate(files_to_scan):
            try:
                relative_path = os.path.relpath(file_path, folder_path)
                file_data = {
                    'name': os.path.basename(file_path),
                    'path': relative_path,
                    'md5': calculate_checksum(file_path, 'md5') if self.md5_var.isChecked() else '',
                    'sha1': calculate_checksum(file_path, 'sha1') if self.sha1_var.isChecked() else '',
                    'sha256': calculate_checksum(file_path, 'sha256') if self.sha256_var.isChecked() else '',
                    'sha512': calculate_checksum(file_path, 'sha512') if self.sha512_var.isChecked() else ''
                }
                self.files_data.append(file_data)
                
                # Add to table
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(file_data['name']))
                self.results_table.setItem(row, 1, QTableWidgetItem(file_data['path']))
                self.results_table.setItem(row, 2, QTableWidgetItem(file_data['md5']))
                self.results_table.setItem(row, 3, QTableWidgetItem(file_data['sha1']))
                self.results_table.setItem(row, 4, QTableWidgetItem(file_data['sha256']))
                self.results_table.setItem(row, 5, QTableWidgetItem(file_data['sha512']))
                
                progress = int((i + 1) / total_files * 100)
                self.progress_bar.setValue(progress)
                QApplication.processEvents()

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

        self.progress_bar.setVisible(False)

    def save_folder_report(self):
        if not self.files_data:
            QMessageBox.warning(self, "Warning", "No files have been scanned yet.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, 'Save Folder Report', '', 
            'CSV files (*.csv);;JSON files (*.json);;Text files (*.txt)'
        )
        
        if not file_path:
            return

        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(self.files_data, f, indent=4)
            
            elif file_path.endswith('.csv'):
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['name', 'path', 'md5', 'sha1', 'sha256', 'sha512'])
                    writer.writeheader()
                    writer.writerows(self.files_data)
            
            else:  # .txt
                with open(file_path, 'w') as f:
                    for data in self.files_data:
                        f.write(f"File: {data['name']}\n")
                        f.write(f"Path: {data['path']}\n")
                        if data['md5']: f.write(f"MD5: {data['md5']}\n")
                        if data['sha1']: f.write(f"SHA1: {data['sha1']}\n")
                        if data['sha256']: f.write(f"SHA256: {data['sha256']}\n")
                        if data['sha512']: f.write(f"SHA512: {data['sha512']}\n")
                        f.write("\n")

            QMessageBox.information(self, "Success", "Folder report saved successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save report: {e}")

# Run the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ChecksumApp()
    window.show()
    sys.exit(app.exec())