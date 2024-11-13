# Port 20 - FTP Data Channel Cheatsheet

## Overview

- **Port Number**: 20
- **Protocol**: TCP
- **Service**: FTP Data Transfer
- **Purpose**: Handles data transfer in Active Mode FTP.
- **Standard**: Defined in RFC 959.

## Key FTP Concepts Involving Port 20

- **Control Channel (Port 21)**: Handles command communication between the FTP client and server.
- **Data Channel (Port 20)**: In Active Mode FTP, Port 20 is used by the server to transfer data (files, directory listings) back to the client.
- **Modes of FTP**:
  - **Active Mode (Data Port 20 Involved)**:
    - Client initiates a connection to Port 21.
    - Server opens a connection from Port 20 to the client’s designated port.
  - **Passive Mode (Data Port Not Fixed)**:
    - Client opens both control and data connections.
    - Server responds with a random port for data transfer (usually above 1024).

## Common Uses

- **File Transfer**: Transfer of files, directories, and data between client and server.
- **Directory Listing**: Listing contents of directories.
- **Data Streaming**: Any data transfer initiated in Active Mode.

## How FTP Uses Port 20

### Active vs. Passive Mode FTP (Data Port Differences)

- **Active Mode (Involves Port 20)**
  - Client connects to Port 21 (control).
  - Client sends PORT command with a random high-numbered port.
  - Server establishes a connection back to the client’s specified port from Port 20 (server-side).
  
- **Passive Mode (Does NOT involve Port 20)**
  - Client connects to Port 21.
  - Server responds with a PASV command and a random high-numbered port for data transfer.
  - Client initiates data connection.

### Network Diagram: Active vs Passive FTP

           +----------------+                +----------------+
           |     Client     |                |     Server     |
           |  (Port 12345)  |                | (Port 21 & 20) |
           +-------+--------+                +--------+-------+
                   |                               |
                   | Connect (Port 21)              |
                   |------------------------------->|
                   |                               |
                   |   PORT Command (Port 12345)    |
                   |------------------------------->|
                   |                               |
                   |   Connects from Port 20        |
                   |<-------------------------------|
                   | (Data Transfer on Port 20)    |
                   |                               |

### FTP Packet Example (Active Mode)

Client -> Server (Control Connection, Port 21):  

PORT 192,168,1,100,123,45  # Instruct server to connect back to IP: 192.168.1.100, Port: 12345

Server -> Client (Data Connection from Port 20):  

Sending file data to 192.168.1.100:12345

## Attack Vectors and Common Vulnerabilities

### 1. Plaintext Communication
- **Attack**: FTP (including data on Port 20) does not encrypt traffic by default, exposing files and credentials to interception.
- **Mitigation**:
  - Use **FTPS** (FTP Secure - encrypted) or **SFTP** (uses SSH, not Port 20).
  - Prefer secure protocols when transferring sensitive data.

### 2. FTP Bounce Attack
- **Attack**: Abusing the PORT command in FTP to connect to and scan other networks or send malicious traffic. This can be leveraged as a port scanner or to bypass firewalls.
- **Mitigation**:
  - Disable the **PORT** command if not needed or use a firewall to prevent unauthorized use.
  - Implement firewall rules to limit connections.

### 3. Data Channel Hijacking
- **Attack**: Intercepting or tampering with the data channel (Port 20), manipulating files or directory listings.
- **Mitigation**:
  - Use encrypted FTP alternatives.
  - Configure the firewall to allow only specific IP addresses to connect.

### 4. Firewall and NAT Issues
- **Challenge**: Active Mode FTP (Port 20) can be blocked by firewalls or cause NAT traversal issues since it requires the server to initiate a data connection back to the client.
- **Mitigation**:
  - Use **Passive Mode** for client-side firewalls/NAT compatibility.
  - Configure firewall exceptions if Active Mode is mandatory.

### 5. Anonymous FTP Data Access
- **Attack**: Public FTP servers often allow anonymous access, potentially exposing sensitive data to the public.
- **Mitigation**:
  - Disable anonymous access unless strictly necessary.
  - Restrict the directories accessible to anonymous users.
  - Set up detailed logging to monitor anonymous activity.

### FTP Bounce Attack Example (Using Nmap)

```bash
# Nmap FTP bounce attack scan example
nmap -v -b anonymous:password@target_ftp_server 192.168.1.0/24

Common FTP Exploits Related to Port 20

	•	CVE-2000-0920: FTP Bounce Attack vulnerability.
	•	CVE-2015-3306: ProFTPD Mod_copy exploit, affecting data transfer.
	•	CVE-2010-2632: Improper permissions on certain FTP commands, enabling data manipulation.

FTP Security Hardening

Firewall Configuration (Limit Access to Port 20)

# Linux iptables example to restrict Port 20 access
iptables -A INPUT -p tcp --dport 20 -s trusted_ip_address -j ACCEPT
iptables -A INPUT -p tcp --dport 20 -j DROP

Server Configuration (Disable Active Mode if not needed)

# Example vsftpd.conf adjustments to enhance security
pasv_enable=YES
pasv_min_port=50000
pasv_max_port=51000
listen_port=21

Encrypt Data Traffic with FTPS

	•	Switch to FTPS to ensure encryption for data channels. This makes use of SSL/TLS over the standard FTP protocol.

# Example for enabling FTPS in vsftpd
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES

FTP Logging and Monitoring

Monitor Active Data Connections

# Check for active FTP connections using netstat
netstat -an | grep ':20'

# Log monitoring example for vsftpd
tail -f /var/log/vsftpd.log

Use Tools for File Integrity Checks

	•	Tripwire: Monitor and detect unauthorized changes to files.
	•	OSSEC: Intrusion detection system for monitoring logs and file changes.

Automation and Scripting with FTP on Port 20

Bash Script for Active Mode FTP Data Transfer

#!/bin/bash

# Automating a data download using Active Mode FTP
ftp -inv <<EOF
open ftp.example.com
user username password
binary
active
get largefile.bin
bye
EOF

Python Script Using Active FTP Mode

import ftplib

# Connect using Active Mode FTP
ftp = ftplib.FTP()
ftp.set_debuglevel(1)   # Enable debugging output
ftp.connect('ftp.example.com', 21)
ftp.login('username', 'password')

# Switch to Active Mode
ftp.set_pasv(False)

# Retrieve a file
with open('downloaded_file.txt', 'wb') as f:
    ftp.retrbinary('RETR remote_file.txt', f.write)

ftp.quit()

FTP Security Checklist for Port 20

	•	Disable plaintext FTP; use FTPS or SFTP.
	•	Restrict IPs allowed to connect via firewall rules.
	•	Monitor FTP logs for suspicious activity.
	•	Avoid using Active Mode unless absolutely necessary.
	•	Secure FTP server with updated software patches.
	•	Disable anonymous logins unless required.
	•	Implement IP-based rate limiting to prevent DoS attacks.
