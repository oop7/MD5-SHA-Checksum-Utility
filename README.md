# MD5-SHA-Checksum-Utility

## ❓ Overview
The **MD5-SHA-Checksum-Utility** is an intuitive graphical tool designed to easily calculate and verify checksums using various algorithms (MD5, SHA-1, SHA-256, and SHA-512). With a clean and user-friendly interface, the utility supports drag-and-drop functionality, copying checksum results to the clipboard, and saving results to text or JSON files. Additionally, it allows for folder scanning, making it ideal for batch processing multiple files.

## 💪 Features

- **Drag-and-Drop Support**: Simply drag files into the application to calculate their checksums.
- **Multiple Hash Algorithms**: Supports MD5, SHA-1, SHA-256, and SHA-512 hash algorithms.
- **Copy to Clipboard**: Quickly copy any checksum result to the clipboard for easy sharing.
- **Save Results**: Save generated checksum results to a text or JSON file for record-keeping.
- **Verify Hashes**: Easily verify the integrity of files by comparing the generated hash with a provided hash.
- **Folder Scanning**: Scan entire folders (including subfolders) to calculate and display checksums for multiple files at once.
- **Save Folder Results**: Save the results of folder scans as CSV, JSON, or text files for easy documentation and further analysis.

## ✅ Screenshots

![Screenshot 2024-11-29 130057](https://github.com/user-attachments/assets/81608166-8aeb-42f7-8226-9bdbed41ca16)

![Screenshot 2024-11-29 130124](https://github.com/user-attachments/assets/31fce673-7b7e-41ec-8059-33c40dcde353)

![Screenshot 2024-11-29 130229](https://github.com/user-attachments/assets/a261fa9d-e3f9-4087-9733-0aca82b852fa)

## 🔽 Download
Download the latest version of the **MD5-SHA-Checksum-Utility**, including the executable, from the [releases page](https://github.com/oop7/MD5-SHA-Checksum-Utility/releases).

## ⚙️ Installation

### Install Required Packages
Make sure you have **Python** installed on your system. Then, install the required dependencies via pip:
```bash
pip install PyQt5 Pillow
```

## 💻 Usage

Launch the application by either double-clicking the executable or running it directly with Python:
```bash
python checksum_utility.py
```

## 🛠️ How to Use

### Single File Checksum Generation

1. **Open File**: Click the "Browse" button to select a file, or drag and drop the file into the designated area.
2. **Generate Checksums**: The tool will automatically calculate and display the MD5, SHA-1, SHA-256, and SHA-512 checksums.
3. **Copy Checksums**: Use the "Copy" buttons to quickly copy any checksum to the clipboard.
4. **Save Results**: Click the "Save Report" button to save the checksum results to a text or JSON file.
5. **Verify Hash**: Enter a hash in the "Hash" field and click "Verify" to compare it against the calculated checksum.

### Folder Scan

1. **Select Folder**: Click the "Browse Folder" button to choose the folder you want to scan.
2. **Options**: Opt to include subfolders and hidden files if necessary.
3. **Scan Folder**: The utility will scan the selected folder and compute the checksums for all files within.
4. **View Results**: The results are displayed in a table, showing file names, paths, and their corresponding checksums.
5. **Save Folder Results**: Click "Save Folder Results" to save the scan results as CSV, JSON, or text files.

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](https://github.com/oop7/MD5-SHA-Checksum-Utility/blob/main/LICENSE) file for more details.

## 📙 Contributing
Contributions are welcome! To contribute, feel free to open an issue or submit a pull request with improvements or bug fixes.
