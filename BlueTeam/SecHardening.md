# Security Hardening Cheat Sheets 📌

### Purpose
These cheat sheets cover essential configuration changes, commands, and best practices for hardening the security posture of systems, Active Directory, and cloud environments.

---

## 📖 Table of Contents

1. [OS Hardening Cheat Sheet](#os-hardening-cheat-sheet)
2. [Active Directory (AD) Security Cheat Sheet](#active-directory-ad-security-cheat-sheet)
3. [Cloud Security Hardening Cheat Sheet](#cloud-security-hardening-cheat-sheet)

---

## 1. OS Hardening Cheat Sheet

### 🔒 Key Configuration Changes for Windows and Linux

#### Windows Hardening

- **Disable Unused Services**: Stop and disable unnecessary services to reduce attack surface.
  - **Command**:
    ```powershell
    Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'} | Set-Service -StartupType Disabled
    ```

- **Enforce Strong Password Policies**:
  - Set minimum length, complexity requirements, and expiration.
  - **Command**:
    ```powershell
    # Set minimum password length to 12
    net accounts /minpwlen:12
    ```

- **Enable Windows Defender** and configure Real-Time Protection.
- **Configure Windows Firewall**:
  - **Example Rule**:
    ```powershell
    New-NetFirewallRule -DisplayName "Allow Inbound RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
    ```

- **Enable BitLocker**: Encrypt drives to protect data at rest.
  - **Command**:
    ```powershell
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes128
    ```

#### Linux Hardening

- **Disable Root Login**: Edit `/etc/ssh/sshd_config` and set `PermitRootLogin no`.
- **Limit SSH Access**: Allow only specific users to connect via SSH.
  - **Command**:
    ```bash
    echo "AllowUsers user1 user2" >> /etc/ssh/sshd_config
    ```

- **Enforce Strong Password Policies**:
  - **Password Complexity**: Configure in `/etc/pam.d/common-password` (Debian/Ubuntu).
  - **Password Aging**: Use `chage` to set expiration policies.
    ```bash
    chage -M 90 -m 7 -W 14 username
    ```

- **Disable Unused Services**: Identify and disable unnecessary services.
  - **Command**:
    ```bash
    systemctl disable <service_name>
    ```

- **Enable UFW (Uncomplicated Firewall)**: Configure basic firewall rules.
  - **Example Commands**:
    ```bash
    ufw enable
    ufw allow 22/tcp
    ```

### 🔐 Secure SSH Configuration (`sshd_config` Best Practices)

1. **Disable Root Login**:
   ```bash
   PermitRootLogin no
   ```

2. **Disable Password-Based Authentication**:
   ```bash
   PasswordAuthentication no
   ```

3. **Limit Login Attempts**:
   ```bash
   MaxAuthTries 3
   ```

4. **Specify Allowed Users**:
   ```bash
   AllowUsers user1 user2
   ```

5. **Enable SSH Protocol 2 Only**:
   ```bash
   Protocol 2
   ```

6. **Configure Idle Timeout**:
   ```bash
   ClientAliveInterval 300
   ClientAliveCountMax 0
   ```

---

## 2. Active Directory (AD) Security Cheat Sheet

### 🛠 Key AD Security Settings

- **Enable Auditing**: Ensure AD is configured to log critical actions (e.g., login attempts, changes to group memberships).
- **Enforce Password Policies**: Define password length, complexity, and history in the Group Policy Management Console.
  - **Minimum password length**: 12 characters.
  - **Enforce password history**: 10 previous passwords.
  
- **Account Lockout Policy**:
  - **Lockout Duration**: 15 minutes.
  - **Threshold**: 5 invalid login attempts.

- **Secure Administrator Accounts**:
  - Rename the `Administrator` account.
  - Add a honey account to detect brute-force attacks.

- **Use Protected Groups**: Add highly privileged accounts (e.g., Domain Admins) to the **Protected Users** group to prevent credential theft.

### 🔍 Commands for Finding Weak Configurations

- **List All Domain Users**:
  ```powershell
  Get-ADUser -Filter * | Select-Object Name,SamAccountName
  ```

- **Check for Unconstrained Delegation**:
  - Unconstrained delegation is risky as it allows the server to request tickets for any user.
  ```powershell
  Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select-Object Name,SamAccountName
  ```

- **Identify Users with Passwords Set to Never Expire**:
  ```powershell
  Get-ADUser -Filter {PasswordNeverExpires -eq $True} | Select-Object Name,PasswordNeverExpires
  ```

- **List All Admin Group Members**:
  ```powershell
  Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name,SamAccountName
  ```

- **Audit Object Access**: Check permissions on sensitive objects (like organizational units).
  ```powershell
  Get-ACL -Path "AD:\OU=Finance,DC=domain,DC=com" | Format-List
  ```

---

## 3. Cloud Security Hardening Cheat Sheet

### ☁️ Best Practices for AWS

- **Identity and Access Management (IAM)**:
  - Use **IAM Roles** instead of long-term IAM credentials.
  - Enforce **Multi-Factor Authentication (MFA)** for privileged users.
  - **Least Privilege Principle**: Only assign necessary permissions.

- **S3 Bucket Security**:
  - **Enable Encryption** at rest (`AES-256` or `aws:kms`).
  - **Block Public Access** to sensitive buckets.
    ```bash
    aws s3api put-bucket-acl --bucket <bucket-name> --acl private
    ```
  - **Enable Logging** for access and activity monitoring.

- **CloudTrail Setup**:
  - Enable CloudTrail to log all account activity.
  - Configure **Log File Validation** to ensure log integrity.
    ```bash
    aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <s3-bucket-name>
    ```

- **GuardDuty**:
  - Enable Amazon GuardDuty to continuously monitor for malicious activity.
  
- **Key Management**:
  - Use **AWS KMS** for managing encryption keys securely.

### 🔐 Best Practices for Azure

- **Azure AD Security**:
  - **Conditional Access**: Enforce policies like MFA based on user location and device.
  - **Privileged Identity Management (PIM)**: Enable PIM to manage privileged access to Azure resources.

- **Storage Account Security**:
  - Enable **Azure Storage Encryption**.
  - Enforce **Secure Transfer Required** to ensure HTTPS connections only.

- **Network Security**:
  - **Network Security Groups (NSG)**: Apply NSGs to filter network traffic to Azure resources.
  - Use **Azure Firewall** to define and control access to applications.

- **Log Monitoring with Azure Monitor**:
  - Set up **Log Analytics** to collect and analyze logs from Azure resources.
  - Configure **Alerts** to notify administrators of suspicious activities.

### 🛡 Best Practices for Google Cloud Platform (GCP)

- **IAM Policies**:
  - Implement the **Principle of Least Privilege** by granting minimal required permissions.
  - Use **Service Accounts** for applications instead of user credentials.

- **VPC Security**:
  - Use **Firewall Rules** to restrict access by IP range, protocol, and ports.
  - **Enable Private Google Access** to keep cloud resources internal.

- **Cloud Storage Security**:
  - **Disable Uniform Bucket-Level Access** to allow fine-grained access control.
  - **Use Customer-Managed Encryption Keys (CMEK)** for sensitive data.

- **Cloud Audit Logging**:
  - Enable **Audit Logs** for all services to monitor access and changes.
  - Use **Cloud Monitoring** to visualize and set alerts for abnormal activity.

- **Data Loss Prevention (DLP)**:
  - Enable **Cloud DLP** to scan for and mask sensitive data in logs, storage, and databases.

---

### 📘 Resources

- **CIS Benchmarks**:
  - [CIS Benchmark for Windows](https://www.cisecurity.org/benchmark/windows/)
  - [CIS Benchmark for Linux](https://www.cisecurity.org/benchmark/linux/)
  - [CIS Benchmark for AWS](https://www.cisecurity.org/benchmark/amazon_web_services/)
  - [CIS Benchmark for Azure](https://www.cisecurity.org/benchmark/microsoft_azure/)
  - [CIS Benchmark for GCP](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)
