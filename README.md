# MD5-SHA-Checksum-Utility

## ❓ Overview
MD5-SHA-Checksum-Utility is a user-friendly graphical tool designed to calculate and verify MD5, SHA-1, SHA-256, and SHA-512 checksums. The tool features a clean GUI with drag-and-drop file support, copy-to-clipboard functionality, and the ability to save results to a file. It also supports scanning folders to calculate hashes for multiple files.

## 💪 Features

- **Drag and Drop Support**: Easily drag files into the application to calculate checksums.
- **Multiple Hash Algorithms**: Supports MD5, SHA-1, SHA-256, and SHA-512.
- **Copy to Clipboard**: Quickly copy checksum results to the clipboard.
- **Save Results**: Save checksum results to a text or JSON file.
- **Verify Hashes**: Verify the integrity of files by comparing generated and provided hashes.
- **Folder Scanning**: Scan folders and subfolders to calculate hashes for multiple files.
- **Save Folder Results**: Save folder scan results as CSV, JSON, or text files.

## ✅ Screenshots

![Screenshot 2024-11-29 130057](https://github.com/user-attachments/assets/81608166-8aeb-42f7-8226-9bdbed41ca16)


![Screenshot 2024-11-29 130124](https://github.com/user-attachments/assets/31fce673-7b7e-41ec-8059-33c40dcde353)


![Screenshot 2024-11-29 130229](https://github.com/user-attachments/assets/a261fa9d-e3f9-4087-9733-0aca82b852fa)



## 🔽 Download
You can download the most recent version of the tool, including the executable, [here](https://github.com/oop7/MD5-SHA-Checksum-Utility/releases).

## ⚙️ Installation

### Install Required Packages
Ensure you have Python installed. Install required packages using pip:
```bash
pip install PyQt5 Pillow
```

## 💻 Usage

Run the application by double-clicking the executable or using Python:
```bash
python checksum_utility.py
```

## 🛠️ How to Use

### Single File

1. **Open File**: Click the "Browse" button to select a file, or drag and drop a file into the entry field.
2. **Generate Checksums**: The tool will automatically calculate and display the MD5, SHA-1, SHA-256, and SHA-512 checksums.
3. **Copy Checksums**: Use the "Copy" buttons to copy any checksum to the clipboard.
4. **Save Results**: Click the "Save Report" button to save the checksums to a text or JSON file.
5. **Verify Hash**: Enter a hash in the "Hash" field and click "Verify" to check against the generated hashes.

### Folder Scan

1. **Select Folder**: Click the "Browse Folder" button to select a folder.
2. **Options**: Choose to include subfolders and hidden files if needed.
3. **Scan Folder**: The tool will scan the folder and calculate checksums for all files.
4. **View Results**: Results are displayed in a table with file names, paths, and checksums.
5. **Save Results**: Click the "Save Folder Results" button to save the results as a CSV, JSON, or text file.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/oop7/MD5-SHA-Checksum-Utility/blob/main/LICENSE) file for details.

## 📙 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.




