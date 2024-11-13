# Mobile Security Cheat Sheets 📱

### Purpose
These cheat sheets provide essential commands, tools, and techniques for security testing on Android and iOS platforms, along with best practices for reverse engineering mobile applications. Perfect for ethical hacking and mobile application security analysis.

---

## 📖 Table of Contents

1. [Android Security Testing Cheat Sheet](#android-security-testing-cheat-sheet)
2. [iOS Security Cheat Sheet](#ios-security-cheat-sheet)
3. [Mobile Application Reverse Engineering Cheat Sheet](#mobile-application-reverse-engineering-cheat-sheet)

---

## 1. Android Security Testing Cheat Sheet

### 🔧 ADB (Android Debug Bridge) Commands

- **Basic ADB Setup**:
  - **Connect to Device**:
    ```bash
    adb devices  # List connected devices
    adb connect <device_ip>  # Connect to a remote device
    ```
  - **Access Device Shell**:
    ```bash
    adb shell
    ```
  - **Push/Pull Files**:
    ```bash
    adb push <local_file> /sdcard/  # Upload file to device
    adb pull /sdcard/<file> <local_directory>  # Download file from device
    ```
  - **Install/Uninstall APKs**:
    ```bash
    adb install <path_to_apk>
    adb uninstall <package_name>
    ```

- **App Management Commands**:
  - **List Installed Packages**:
    ```bash
    adb shell pm list packages
    ```
  - **Get App Info**:
    ```bash
    adb shell dumpsys package <package_name>
    ```
  - **Extract APK from Device**:
    ```bash
    adb shell pm path <package_name>  # Find APK path
    adb pull <path_to_apk>
    ```

### 🛠 Mobile Penetration Tools

1. **Drozer**:
   - **Setup**: Drozer is an Android security assessment tool for testing app security.
   ```bash
   drozer console connect
   ```
   - **Find Attack Surface**:
     ```bash
     run app.package.list  # List installed apps
     run app.package.attacksurface <package_name>  # Get app attack surface
     ```
   - **Exploit Activities**:
     ```bash
     run app.activity.start --component <package_name> <activity_name>
     ```

2. **Frida**:
   - **Inject Frida Script**:
     ```bash
     frida -U -f <package_name> -l <script.js> --no-pause
     ```
   - **Run Interactive Session**:
     ```bash
     frida -U -n <package_name>
     ```

3. **Objection**:
   - **Bypass Root Detection**:
     ```bash
     objection -g <package_name> explore
     android root disable
     ```
   - **Inspect Application Files**:
     ```bash
     objection -g <package_name> explore
     android filesystem list
     ```

---

## 2. iOS Security Cheat Sheet

### 📱 Jailbreaking and iOS Security Testing Tools

- **Jailbreaking Basics**:
  - **Popular Jailbreaking Tools**:
    - **Checkra1n**: Semi-tethered jailbreak for devices up to iPhone X.
    - **Unc0ver**: Semi-untethered jailbreak supporting iOS 11 through iOS 14.
  - **Jailbreaking Resources**:
    - [Checkra1n](https://checkra.in/)
    - [Unc0ver](https://unc0ver.dev/)

- **SSH into Jailbroken Device**:
  ```bash
  ssh root@<device_ip>
  ```

- **Popular iOS Security Testing Tools**:
  1. **Frida**:
     - **Inject Frida Script**:
       ```bash
       frida -U -f <bundle_identifier> -l <script.js> --no-pause
       ```
  2. **Objection**:
     - **Bypass Jailbreak Detection**:
       ```bash
       objection -g <bundle_identifier> explore
       ios jailbreak disable
       ```

### 🛠 Commands for Analyzing IPA Files

1. **Unpack IPA Files**:
   - **Convert to `.zip` and Extract**:
     ```bash
     unzip <app.ipa> -d <output_folder>
     ```

2. **Analyze Executable**:
   - **List Symbols with `nm`**:
     ```bash
     nm -gU <executable_path>
     ```
   - **Use Class-dump** to extract class information:
     ```bash
     class-dump -H <executable_path> -o <output_folder>
     ```

3. **Inspect Plist Files**:
   - **Extract Information from `Info.plist`**:
     ```bash
     plutil -p <output_folder>/Payload/<AppName.app>/Info.plist
     ```

4. **Decrypt iOS Apps** (requires a jailbroken device and Clutch/Frida):
   - **Using Frida**:
     ```bash
     frida -U -f <bundle_id> -l dump.js --no-pause
     ```

---

## 3. Mobile Application Reverse Engineering Cheat Sheet

### 🛠 Common Tools

1. **APKTool**:
   - **Decompile APK**:
     ```bash
     apktool d <app.apk> -o <output_folder>
     ```
   - **Recompile Modified APK**:
     ```bash
     apktool b <output_folder> -o <new_app.apk>
     ```

2. **JD-GUI**:
   - **View Decompiled Java Classes**:
     - Open `.jar` or `.dex` files after extraction to view the app's Java source code.

3. **Ghidra**:
   - **Analyze Native Libraries (`.so` files)**:
     - Load and analyze shared objects or ELF binaries extracted from APKs or IPAs.
   - **Decompile Functions**:
     - Use Ghidra’s decompiler view to understand the app’s native methods.

### 📡 Steps for Analyzing Mobile Application Traffic

1. **Setup Burp Suite as a Proxy**:
   - **Configure Burp Proxy**:
     - Go to **Proxy > Options** in Burp and ensure an HTTP listener is active.
   - **Export Burp’s CA Certificate**:
     - Go to **Proxy > Options > Import / Export CA Certificate** to install the certificate on the mobile device.

2. **Configure Mobile Device to Use Proxy**:
   - **Android**:
     - Go to **Settings > Wi-Fi > Modify Network**.
     - Set Proxy to **Manual**, then enter Burp’s IP and Port.
   - **iOS**:
     - Go to **Settings > Wi-Fi > Proxy Configuration**.
     - Set Proxy to **Manual**, then enter Burp’s IP and Port.

3. **Install Burp’s Certificate on Device**:
   - **Android**:
     - Download and install the `.cer` file, then install it in **Settings > Security > Install from Storage**.
   - **iOS**:
     - Download the certificate file, go to **Settings > General > Profile** and trust the certificate.

4. **Capture and Inspect HTTPS Traffic**:
   - Once the device is configured to use Burp as a proxy, launch the app and monitor traffic in Burp’s **HTTP history**.
   - **Decrypt HTTPS traffic** by ensuring that SSL/TLS interception is enabled in Burp.

---

### 📘 Additional Tools and Resources

1. **MobSF (Mobile Security Framework)**:
   - An open-source tool for automated mobile app analysis on Android and iOS.
   - **Setup**:
     ```bash
     python3 manage.py runserver
     ```
   - **Upload APK/IPA** to MobSF web UI to perform static and dynamic analysis.

2. **Appmon**:
   - AppMon is a tool to monitor and tamper with API calls made by mobile applications.
   - **Useful for Runtime Analysis**:
     ```bash
     python appmon.py
     ```

3. **Burp Suite Mobile Assistant**:
   - Available in Burp Suite’s Pro edition, helps configure Android/iOS devices to proxy traffic through Burp.
   - **Usage**: Follow the wizard in Burp Suite under the **Mobile Assistant** tab.

4. **iOS Mobile Device Management (MDM)**:
   - Tools like **Apple Configurator** allow for more fine-grained control of app permissions and configurations during testing.

---

### 📘 Resources

- **Android Developer Documentation**: [Android Debug Bridge (adb)](https://developer.android.com/studio/command-line/adb)
- **iOS Developer Documentation**: [iOS Security Guide](https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf)
- **Mobile Security Testing Guide (MSTG)**: [OWASP MSTG](https://owasp.org/www-project-mobile-security-testing-guide/)
