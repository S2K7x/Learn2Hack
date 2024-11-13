# Port 21 - FTP Cheatsheet

## Overview

- **Port Number:** 21
- **Protocol:** TCP
- **Service:** FTP (File Transfer Protocol)
- **Purpose:** Transfers files between a client and a server over a network.
- **Standard:** Defined in RFC 959.

## Key FTP Characteristics

- **Unencrypted Communication:** Data, including credentials, is transmitted in plaintext by default.
- **Modes of Operation:**
  - **Active Mode:** Server initiates a connection to the client for data transfer.
  - **Passive Mode:** Client initiates both control and data connections (commonly used for firewall/NAT compatibility).
- **Authentication:** Typically username and password, though anonymous access is possible (`ftp://user:anonymous`).
- **Transfer Types:**
  - **ASCII Mode:** For text files.
  - **Binary Mode:** For images, executables, and other non-text files.

## Common Uses

- **Website Maintenance:** Uploading website files to web servers.
- **File Transfer:** Sharing files between internal networks.
- **Data Archiving:** Backup and restoration of files.
- **Anonymous File Hosting:** Often used for public file sharing.

## FTP Commands Overview

### Basic FTP Client Commands

```bash
# Connect to an FTP server
ftp ftp.example.com

# Login as a specific user
ftp user@ftp.example.com

# List files in the current directory
ls

# Download a file
get filename.txt

# Upload a file
put localfile.txt

# Change to passive mode
passive

# Close the FTP connection
bye

Common CLI Tools

# Download files from an FTP server using wget (non-interactive)
wget ftp://ftp.example.com/remote_file.txt

# Download files from an FTP server using curl (non-interactive)
curl -O ftp://ftp.example.com/remote_file.txt

# Using lftp for secure file transfer (supports FTP, SFTP, etc.)
lftp -u user,password ftp.example.com

# FTP over SSL/TLS (secure connection)
curl --ftp-ssl -O ftp://ftp.example.com/remote_file.txt

Active vs. Passive Mode (Key Differences)

	•	Active Mode:
	•	Client connects from a random port (N) to server port 21 (command channel).
	•	Server initiates a connection from port 20 to client port (N+1) for data transfer.
	•	Passive Mode:
	•	Client connects from a random port (N) to server port 21.
	•	Server responds with a random port (M) for the client to initiate the data transfer.

Secure Alternatives to FTP

	•	FTPS (FTP Secure): FTP over SSL/TLS (ports 21 or 990).
	•	SFTP (SSH File Transfer Protocol): Uses SSH (port 22) for encrypted file transfer.

Attack Vectors and Common Vulnerabilities

1. Plaintext Transmission

	•	Attack: FTP transmits all data, including credentials, in plaintext. Man-in-the-Middle (MitM) attackers can easily capture sensitive information.
	•	Mitigation:
	•	Prefer secure alternatives like FTPS or SFTP.
	•	Use VPNs to create an encrypted tunnel for FTP traffic.

2. Anonymous Access

	•	Attack: Many FTP servers allow anonymous access (user: anonymous), often exposing sensitive files inadvertently.
	•	Mitigation:
	•	Disable anonymous access unless strictly necessary.
	•	Restrict directories accessible to anonymous users.
	•	Monitor and audit file permissions.

3. Weak or Default Credentials

	•	Attack: Default usernames and passwords are often used, allowing unauthorized access.
	•	Mitigation:
	•	Use strong, complex passwords.
	•	Regularly audit user accounts.
	•	Disable or remove default accounts.

4. Directory Traversal Vulnerabilities

	•	Attack: Improper validation of file paths can lead to directory traversal (../../) attacks, allowing access to restricted directories.
	•	Example Attack String: GET ../../../etc/passwd (on Unix-like systems)
	•	Mitigation:
	•	Implement strict input validation.
	•	Use secure FTP server software with protections against traversal attacks.
	•	Limit permissions of the FTP process user to restrict access.

5. Buffer Overflow

	•	Attack: Poorly implemented FTP servers can be vulnerable to buffer overflow attacks due to malformed input.
	•	Mitigation:
	•	Keep the FTP server software updated.
	•	Apply necessary patches.
	•	Use server software that implements bounds checking.

Example of a Directory Traversal Attack (Using Metasploit)

# Metasploit example for a vulnerable FTP server
use auxiliary/scanner/ftp/ftp_login
set RHOSTS target_ip
set USERNAME anonymous
set PASSWORD anonymous
run

Common FTP Exploits

	•	CVE-2015-3306: ProFTPD Mod_copy Remote Command Execution.
	•	CVE-2010-4221: VSFTPD 2.3.4 Backdoor.
	•	CVE-2009-3023: Heap-based buffer overflow in Windows FTP servers.
	•	CVE-2001-0931: wu-ftpd SITE EXEC Command Remote Root Exploit.

FTP Security Hardening and Configuration

# Example configuration file path
sudo nano /etc/vsftpd.conf

# Disable anonymous access
anonymous_enable=NO

# Enable local users for authentication
local_enable=YES

# Restrict file upload to specific directories
write_enable=YES
local_umask=022

# Use passive mode for compatibility with firewalls
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000

# Chroot users to their home directories
chroot_local_user=YES
allow_writeable_chroot=NO

# Log all FTP transactions for auditing
xferlog_enable=YES

FTP Server Monitoring and Logging

# Monitor FTP log files (example for vsftpd)
tail -f /var/log/vsftpd.log

# Check user login attempts
grep "FAIL LOGIN" /var/log/vsftpd.log

Best Practices for FTP Security

	1.	Disable Anonymous Logins: Limit access to authenticated users only.
	2.	Enforce Strong Password Policies: Require complex passwords and avoid default credentials.
	3.	Restrict Access: Use IP whitelisting, TCP Wrappers, or firewall rules to limit server access.
	4.	Enable Logging: Log FTP transactions and monitor regularly.
	5.	Use Passive Mode: For firewall and NAT compatibility.
	6.	Implement File and Directory Permissions: Grant minimal permissions to the FTP user.
	7.	Regular Updates: Keep FTP server software up-to-date to avoid known vulnerabilities.
	8.	Run as Non-Root: Use a dedicated, unprivileged user for the FTP service.

Additional Security Tools

	•	fail2ban: Blocks IP addresses after repeated failed login attempts.
	•	ModSecurity: Application firewall for FTP protocols.
	•	ClamAV: Antivirus to scan uploaded files for malicious content.

FTP Automation and Scripting

Automating FTP with Bash Script

#!/bin/bash

# Connect and download a file automatically using FTP
ftp -inv $HOST <<EOF
user $USERNAME $PASSWORD
cd /remote/directory/
get file.txt
bye
EOF

Using Python for FTP Tasks

import ftplib

# Connect to an FTP server
ftp = ftplib.FTP('ftp.example.com')
ftp.login(user='username', passwd='password')

# List files in the current directory
ftp.retrlines('LIST')

# Download a file
with open('local_file.txt', 'wb') as local_file:
    ftp.retrbinary('RETR remote_file.txt', local_file.write)

# Close the connection
ftp.quit()

FTP Security Checklist

	•	Disable anonymous access.
	•	Use encrypted FTP (FTPS or SFTP).
	•	Implement IP-based restrictions.
	•	Enforce strong password policies.
	•	Monitor logs and audit regularly.
	•	Restrict file access and use a non-root user.
