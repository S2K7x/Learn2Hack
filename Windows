# Windows Cheat Sheet for Penetration Testers and Security Auditors

## 1. PowerShell Basics

PowerShell is a powerful command-line shell and scripting language in Windows, designed for task automation and configuration management.

| Command                                        | Description                                            |
|------------------------------------------------|--------------------------------------------------------|
| `Get-Help <cmdlet>`                            | Display help for a command (use `-Examples` for specific examples). |
| `Get-Command`                                  | List all available cmdlets.                            |
| `Get-Process`                                  | List running processes (similar to Task Manager).      |
| `Get-Service`                                  | List all Windows services.                             |
| `Start-Service <service>`                      | Start a service (e.g., `Start-Service wuauserv`).       |
| `Stop-Service <service>`                       | Stop a service.                                        |
| `Get-EventLog -LogName Security`               | View security event logs.                              |
| `Get-ItemProperty -Path <path>`                | Retrieve properties of a file or registry key.         |
| `Set-ExecutionPolicy RemoteSigned`             | Allow scripts to run (required to run unsigned local scripts). |
| `Select-String -Path <file> -Pattern <text>`    | Search for specific text in files (similar to `grep`). |
| `Invoke-WebRequest -Uri <URL>`                 | Fetch data from a URL (useful for downloading files in pentesting). |
| `Test-Connection <IP>`                         | Test network connectivity (similar to `ping`).         |

### PowerShell Scripting

Basic PowerShell script:

```powershell
# Save as script.ps1
$variable = "Hello, World"
Write-Output $variable
```

To execute:

```powershell
.\script.ps1
```

---

## 2. Windows File System and Navigation

| Command                                         | Description                                         |
|-------------------------------------------------|-----------------------------------------------------|
| `Get-ChildItem <path>`                          | List files and directories (similar to `ls`).       |
| `Set-Location <path>`                           | Change directory (similar to `cd`).                 |
| `Copy-Item <source> <destination>`              | Copy files or directories.                         |
| `Move-Item <source> <destination>`              | Move or rename files/directories.                   |
| `Remove-Item <path>`                            | Delete files or directories.                       |
| `New-Item -ItemType <type> -Path <path>`        | Create new files or folders (`-ItemType` can be File or Directory). |
| `Get-Content <file>`                            | View contents of a file.                            |
| `Set-Content <file> -Value <text>`              | Write text to a file.                               |
| `Out-File -FilePath <file>`                     | Save command output to a file.                      |
| `Get-ACL <path>`                                | Display file/folder permissions.                    |
| `Set-ACL <path> -ACLObject <acl>`               | Set file or folder permissions.                     |

### Important Windows Directories

| Path                                    | Description                                    |
|-----------------------------------------|------------------------------------------------|
| `C:\Windows\System32`                   | Core system files.                             |
| `C:\Windows\SysWOW64`                   | 32-bit system files on 64-bit Windows.         |
| `C:\Users`                              | Home directories for users.                    |
| `C:\Program Files`                      | Installed 64-bit programs.                     |
| `C:\Program Files (x86)`                | Installed 32-bit programs on 64-bit systems.   |
| `C:\Windows\Temp`                       | Temporary files directory.                     |
| `%APPDATA%`                             | Roaming application data (user-specific).      |

---

## 3. Windows Registry

The Windows registry is a hierarchical database that stores settings and options for Windows OS, applications, and services.

### Basic Registry Structure

| Root Key                           | Description                                           |
|-------------------------------------|-------------------------------------------------------|
| `HKEY_LOCAL_MACHINE (HKLM)`         | Configuration settings for the system and software.    |
| `HKEY_CURRENT_USER (HKCU)`          | Settings specific to the current user.                |
| `HKEY_CLASSES_ROOT (HKCR)`          | File associations and COM object information.         |
| `HKEY_USERS (HKU)`                  | Profile information for all loaded users.            |
| `HKEY_CURRENT_CONFIG (HKCC)`        | Hardware profile information.                         |

### Common Registry Manipulation Commands

| Command                                              | Description                                             |
|------------------------------------------------------|---------------------------------------------------------|
| `Get-Item -Path 'HKLM:\<path>'`                      | View registry key properties.                           |
| `Set-ItemProperty -Path 'HKLM:\<path>' -Name <property> -Value <value>` | Modify a registry key property.                      |
| `New-Item -Path 'HKCU:\<path>' -Name <key>`           | Create a new registry key.                              |
| `Remove-Item -Path 'HKCU:\<path>'`                   | Delete a registry key.                                  |
| `New-ItemProperty -Path 'HKCU:\<path>' -Name <property> -Value <value> -PropertyType <type>` | Create a new registry property. |

**Example**: Disabling Windows Defender via Registry

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name "DisableAntiSpyware" -Value 1
```

---

## 4. Windows Security Settings

| Command                                               | Description                                             |
|-------------------------------------------------------|---------------------------------------------------------|
| `Get-WmiObject -Class Win32_UserAccount`              | List all user accounts.                                 |
| `net user`                                           | List all user accounts (command prompt).               |
| `net user <username> <password>`                       | Change a user’s password.                               |
| `net localgroup administrators`                       | List members of the Administrators group.               |
| `net localgroup administrators <user> /add`           | Add a user to the Administrators group.                 |
| `Get-LocalUser`                                       | List all local users (PowerShell 5+).                   |
| `Get-LocalGroupMember -Group Administrators`          | List members of the Administrators group (PowerShell 5+). |
| `gpedit.msc`                                          | Open Group Policy Editor (for managing security policies). |
| `secedit /analyze`                                    | Analyze system security settings against a baseline.    |
| `secedit /configure /db secedit.sdb /cfg <security-template>.inf` | Apply a security template.                        |

### Windows Firewall Commands

| Command                                               | Description                                             |
|-------------------------------------------------------|---------------------------------------------------------|
| `netsh advfirewall show allprofiles`                  | Display firewall settings for all profiles.             |
| `netsh advfirewall firewall add rule name="<rule>" protocol=TCP dir=in localport=<port> action=allow` | Add a firewall rule to allow incoming TCP traffic on a specific port. |
| `netsh advfirewall set allprofiles state off`         | Disable Windows Firewall (use with caution).            |
| `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False` | Disable firewall for all profiles via PowerShell. |

---

## 5. Network and Connectivity Commands

| Command                                         | Description                                              |
|-------------------------------------------------|----------------------------------------------------------|
| `ipconfig /all`                                 | Display detailed IP information.                         |
| `Get-NetIPAddress`                               | PowerShell alternative to `ipconfig`.                     |
| `Get-NetRoute`                                   | Display route table entries.                              |
| `netstat -an`                                    | Show active connections and listening ports.              |
| `Test-NetConnection -ComputerName <IP> -Port <Port>` | Test network connection to a specified IP and port.      |
| `ping <IP>`                                      | Test connectivity to a remote IP.                        |
| `tracert <IP>`                                   | Trace route to a remote IP.                               |
| `Get-WmiObject -Class Win32_NetworkAdapterConfiguration` | View network adapter configuration.                     |

### SMB and Network Shares

| Command                                               | Description                                             |
|-------------------------------------------------------|---------------------------------------------------------|
| `net view \\<computer>`                               | List shared resources on a remote computer.             |
| `net share`                                          | List shared resources on the local computer.            |
| `net use <drive> \\<server>\<share>`                  | Map a network drive.                                    |
| `net use <drive> /delete`                             | Disconnect a mapped network drive.                      |

---

## 6. Task and Process Management

| Command                                           | Description                                             |
|---------------------------------------------------|---------------------------------------------------------|
| `Get-Process`                                     | List running processes.                                 |
| `Start-Process <program>`                         | Start a process.                                        |
| `Stop-Process -Name <process>`                    | Kill a process by name.                                 |
| `Stop-Process -Id <processID>`                    | Kill a process by ID.                                   |
| `tasklist`                                        | Display running processes (command prompt alternative). |
| `taskkill /PID <processID> /F`                    | Force kill a process by ID (command prompt).            |

---

## 7. System Information and Logs

| Command                                           | Description                                             |
|---------------------------------------------------|---------------------------------------------------------|
| `systeminfo`                                      | Display detailed system information.                    |
| `Get-EventLog -LogName System`                    | Display system event

 logs.                              |
| `Get-WinEvent -LogName Security`                  | Display security event logs.                            |
| `wevtutil qe Security /f:text /c:10`              | Show last 10 entries from the Security log (command line). |
| `Get-LocalGroup`                                  | List all local groups.                                  |
| `Get-WmiObject -Class Win32_ComputerSystem`       | View system details (domain, manufacturer, model, etc.). |

---

## 8. File Permissions and Auditing

| Command                                           | Description                                             |
|---------------------------------------------------|---------------------------------------------------------|
| `icacls <path>`                                   | View or modify file and folder permissions.             |
| `icacls <path> /grant <user>:(F)`                 | Grant a user full control over a file or directory.     |
| `auditpol /get /category:*`                       | View auditing policies.                                 |
| `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` | Enable logon auditing.                          |
| `Get-Acl -Path <file>`                            | Get Access Control List for a file.                     |
| `Set-Acl -Path <file> -AclObject <acl>`           | Set Access Control List for a file.                     |
