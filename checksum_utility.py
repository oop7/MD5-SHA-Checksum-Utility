import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import hashlib
from tkinterdnd2 import DND_FILES, TkinterDnD

# Function to calculate checksum
def calculate_checksum(file_path, algorithm='md5'):
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Function to open file dialog and calculate checksums
def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        display_checksums(file_path)

# Function to display checksums
def display_checksums(file_path):
    try:
        if md5_var.get():
            md5_checksum = calculate_checksum(file_path, 'md5')
            md5_result.delete(0, tk.END)
            md5_result.insert(0, md5_checksum)
        if sha1_var.get():
            sha1_checksum = calculate_checksum(file_path, 'sha1')
            sha1_result.delete(0, tk.END)
            sha1_result.insert(0, sha1_checksum)
        if sha256_var.get():
            sha256_checksum = calculate_checksum(file_path, 'sha256')
            sha256_result.delete(0, tk.END)
            sha256_result.insert(0, sha256_checksum)
        if sha512_var.get():
            sha512_checksum = calculate_checksum(file_path, 'sha512')
            sha512_result.delete(0, tk.END)
            sha512_result.insert(0, sha512_checksum)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to copy checksum to clipboard
def copy_to_clipboard(checksum):
    app.clipboard_clear()
    app.clipboard_append(checksum)
    messagebox.showinfo("Copied", "Checksum copied to clipboard!")

# Function to save results to a file
def save_results():
    result_text = f"File: {file_entry.get()}\n\n"
    if md5_var.get():
        result_text += f"MD5: {md5_result.get()}\n"
    if sha1_var.get():
        result_text += f"SHA1: {sha1_result.get()}\n"
    if sha256_var.get():
        result_text += f"SHA256: {sha256_result.get()}\n"
    if sha512_var.get():
        result_text += f"SHA512: {sha512_result.get()}\n"
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write(result_text)
        messagebox.showinfo("Saved", "Results saved to file!")

# Function to handle drag and drop files
def drop(event):
    file_path = event.data
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)
    display_checksums(file_path)

# Function to verify the hash
def verify_hash():
    input_hash = hash_entry.get().strip()
    if md5_result.get() == input_hash or sha1_result.get() == input_hash or sha256_result.get() == input_hash or sha512_result.get() == input_hash:
        messagebox.showinfo("Success", "The input hash matches the calculated hash.")
    else:
        messagebox.showerror("Mismatch", "The input hash does not match any calculated hash.")

# Setting up the main application window
app = TkinterDnD.Tk()
app.title("MD5 & SHA Checksum Utility v1.0")
app.configure(bg='#d3d3d3')  # Set background color to light gray

# Style for rounded buttons
style = ttk.Style(app)
style.configure("RoundedButton.TButton", 
                relief="flat", 
                padding=6, 
                background="#ffffff", 
                foreground="#000000", 
                borderwidth=0)
style.map("RoundedButton.TButton",
          background=[('active', '#e0e0e0')])

# Instructions label
instructions = tk.Label(app, text="Generate Hash", bg='#d3d3d3')
instructions.grid(row=0, column=0, columnspan=3, pady=5)

# File entry and browse button
file_label = tk.Label(app, text="File:", bg='#d3d3d3')
file_label.grid(row=1, column=0, sticky=tk.E)
file_entry = tk.Entry(app, width=50)
file_entry.grid(row=1, column=1, padx=5)
browse_button = ttk.Button(app, text="Browse", command=open_file, style="RoundedButton.TButton")
browse_button.grid(row=1, column=2, padx=5)

# MD5 Checksum
md5_var = tk.BooleanVar(value=True)
md5_check = tk.Checkbutton(app, text="MD5", variable=md5_var, bg='#d3d3d3')
md5_check.grid(row=2, column=0, sticky=tk.E)
md5_result = tk.Entry(app, width=50)
md5_result.grid(row=2, column=1, padx=5)
md5_copy_button = ttk.Button(app, text="Copy MD5", command=lambda: copy_to_clipboard(md5_result.get()), style="RoundedButton.TButton")
md5_copy_button.grid(row=2, column=2, padx=5)

# SHA1 Checksum
sha1_var = tk.BooleanVar(value=True)
sha1_check = tk.Checkbutton(app, text="SHA-1", variable=sha1_var, bg='#d3d3d3')
sha1_check.grid(row=3, column=0, sticky=tk.E)
sha1_result = tk.Entry(app, width=50)
sha1_result.grid(row=3, column=1, padx=5)
sha1_copy_button = ttk.Button(app, text="Copy SHA-1", command=lambda: copy_to_clipboard(sha1_result.get()), style="RoundedButton.TButton")
sha1_copy_button.grid(row=3, column=2, padx=5)

# SHA256 Checksum
sha256_var = tk.BooleanVar(value=True)
sha256_check = tk.Checkbutton(app, text="SHA-256", variable=sha256_var, bg='#d3d3d3')
sha256_check.grid(row=4, column=0, sticky=tk.E)
sha256_result = tk.Entry(app, width=50)
sha256_result.grid(row=4, column=1, padx=5)
sha256_copy_button = ttk.Button(app, text="Copy SHA-256", command=lambda: copy_to_clipboard(sha256_result.get()), style="RoundedButton.TButton")
sha256_copy_button.grid(row=4, column=2, padx=5)

# SHA512 Checksum
sha512_var = tk.BooleanVar(value=True)
sha512_check = tk.Checkbutton(app, text="SHA-512", variable=sha512_var, bg='#d3d3d3')
sha512_check.grid(row=5, column=0, sticky=tk.E)
sha512_result = tk.Entry(app, width=50)
sha512_result.grid(row=5, column=1, padx=5)
sha512_copy_button = ttk.Button(app, text="Copy SHA-512", command=lambda: copy_to_clipboard(sha512_result.get()), style="RoundedButton.TButton")
sha512_copy_button.grid(row=5, column=2, padx=5)

# Save results button
save_button = ttk.Button(app, text="Save Results", command=save_results, style="RoundedButton.TButton")
save_button.grid(row=6, column=1, pady=10)

# Verify Hash
verify_label = tk.Label(app, text="Verify Hash with Generated Hash (MD5, SHA-1, SHA-256, or SHA-512)", bg='#d3d3d3')
verify_label.grid(row=7, column=0, columnspan=3, pady=5)
hash_entry = tk.Entry(app, width=50)
hash_entry.grid(row=8, column=1, padx=5)
verify_button = ttk.Button(app, text="Verify", command=verify_hash, style="RoundedButton.TButton")
verify_button.grid(row=8, column=2, padx=5)

# Bind drag and drop event
app.drop_target_register(DND_FILES)
app.dnd_bind('<<Drop>>', drop)

# Start the application
app.mainloop()
