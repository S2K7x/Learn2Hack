# Port 23 - Telnet Cheatsheet

## Overview

- **Port Number**: 23
- **Protocol**: TCP
- **Service**: Telnet (Telecommunication Network)
- **Purpose**: Provides a command-line interface for remote management.
- **Standard**: Defined in RFC 854.

## Key Telnet Characteristics

- **Unencrypted Communication**: Sends data, including credentials, in plaintext.
- **Client-Server Model**: Provides a bi-directional text-based communication.
- **Used For**: Remote administration, debugging, legacy systems, and network device management.
- **Authentication**: Username and password (sent in clear text by default).

## Common Uses

- **Remote System Management**: Historically used to manage servers and network devices.
- **Debugging**: Basic diagnostics of network services.
- **Legacy Systems**: Interaction with old hardware, mainframes, or networking equipment that still relies on Telnet.

## Telnet Commands Overview

### Basic Telnet Client Commands

```bash
# Connect to a remote server using Telnet
telnet remote_host 23

# Check a specific port on a remote server
telnet remote_host 80  # Check if web server on port 80 is accessible

# Send raw data to a port (like HTTP GET request)
telnet remote_host 80
GET / HTTP/1.1

# Close Telnet connection
quit

Common Telnet Usage in Network Troubleshooting

# Test connection to a mail server (SMTP)
telnet smtp.example.com 25

# Check if FTP service is accessible on a server
telnet ftp.example.com 21

# Connect to a router or switch using Telnet
telnet 192.168.1.1

Using Telnet for Banner Grabbing

	•	Banner Grabbing: Identifying services and versions running on a server by connecting via Telnet.

# Banner grab example to determine the software running on a web server
telnet example.com 80
HEAD / HTTP/1.1

Telnet Alternatives

	•	SSH (Port 22): Provides encrypted communication and secure remote access.
	•	Netcat: More advanced tool for network exploration, debugging, and testing.
	•	Nmap: For detailed port scanning and network reconnaissance.

Attack Vectors and Common Vulnerabilities

	1.	Plaintext Communication
	•	Attack: Telnet transmits all data (including credentials) unencrypted, making it easy for attackers to intercept using a Man-in-the-Middle (MitM) attack.
	•	Mitigation:
	•	Replace Telnet with SSH (uses encryption).
	•	Use VPNs if Telnet is unavoidable to create a secure communication tunnel.
	2.	Weak or Default Credentials
	•	Attack: Telnet often relies on weak or default passwords, making it a target for brute-force attacks.
	•	Mitigation:
	•	Use strong passwords.
	•	Implement password complexity policies.
	•	Regularly change default passwords and audit credentials.
	3.	Unauthorized Access
	•	Attack: Misconfigured Telnet servers may expose internal systems to unauthorized access.
	•	Mitigation:
	•	Limit Telnet access using firewall rules.
	•	Use TCP Wrappers to limit access to trusted IP addresses.
	•	Implement network segmentation to isolate critical systems.
	4.	Telnet DoS (Denial of Service)
	•	Attack: An attacker may flood Telnet services with requests, leading to denial-of-service conditions.
	•	Mitigation:
	•	Limit connection rates with firewalls.
	•	Monitor logs for abnormal connection patterns.
	•	Consider using fail2ban to block malicious IPs after repeated failed login attempts.
	5.	Lack of Auditing and Monitoring
	•	Attack: Limited logging makes it difficult to detect unauthorized access or malicious behavior.
	•	Mitigation:
	•	Enable detailed logging if using Telnet.
	•	Use tools like OSSEC for intrusion detection.
	•	Monitor Telnet connections with tools like Wireshark to detect anomalies.

Example of a Brute-Force Attack Using Hydra

# Using Hydra to brute-force Telnet credentials
hydra -l admin -P /path/to/password_list.txt telnet://target_ip

Common Telnet Vulnerabilities

	•	CVE-2014-4877: Buffer overflow in a Telnet server implementation.
	•	CVE-2007-6750: Misconfigured Telnet servers leading to sensitive data exposure.
	•	CVE-2001-0675: Telnet IAC (Interpret As Command) DoS vulnerabilities.

Telnet Security Hardening and Configuration

Replace or Disable Telnet Services

# Disable Telnet service on Linux (example using systemctl)
sudo systemctl disable telnet.socket
sudo systemctl stop telnet.socket

# Remove Telnet client package (example for Debian-based systems)
sudo apt-get remove telnet

Implement IP Filtering Using TCP Wrappers

# Example of restricting Telnet access in /etc/hosts.allow and /etc/hosts.deny
# Allow specific IPs in /etc/hosts.allow
telnetd : 192.168.1.0/24

# Deny all others in /etc/hosts.deny
telnetd : ALL

Use a Secure Alternative - SSH

# Install and enable OpenSSH server on Linux
sudo apt-get install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Harden SSH configuration (example)
sudo nano /etc/ssh/sshd_config

# Recommended SSH settings
PermitRootLogin no
PasswordAuthentication no
Protocol 2
AllowUsers specific_user

Firewalls and Port Restriction

# Block Telnet (Port 23) access on a Linux firewall (iptables example)
iptables -A INPUT -p tcp --dport 23 -j DROP

Logging and Monitoring Telnet Connections

Enable Telnet Logging

	•	Linux Systems: Ensure that Telnet logs are enabled to monitor connection attempts.
	•	Use System Logs: /var/log/secure or /var/log/auth.log for Telnet connection attempts.

# Tail log file to monitor Telnet connections in real-time
sudo tail -f /var/log/auth.log

Monitor Telnet Connections with Wireshark

	•	Filter for Telnet Traffic: Use the filter tcp.port == 23.
	•	Look for suspicious activity like repeated login attempts or unusual commands.

Automate Telnet Monitoring with fail2ban

# Configure fail2ban to protect Telnet (example configuration snippet)
sudo nano /etc/fail2ban/jail.local

# Add the following entry:
[telnet-iptables]
enabled  = true
filter   = telnet
action   = iptables[name=Telnet, port=23, protocol=tcp]
logpath  = /var/log/auth.log
bantime  = 3600
maxretry = 3

Scripting Telnet Operations

Automating Telnet Sessions with expect in Bash

	•	The expect utility can automate Telnet interactions.

#!/usr/bin/expect

# Automate Telnet login
spawn telnet target_host
expect "login:"
send "username\r"
expect "Password:"
send "password\r"
interact

Python Script for Simple Telnet Interaction

import telnetlib

# Connect to a Telnet server
host = "example.com"
user = "your_username"
password = "your_password"

tn = telnetlib.Telnet(host)

# Provide credentials
tn.read_until(b"login: ")
tn.write(user.encode('ascii') + b"\n")
tn.read_until(b"Password: ")
tn.write(password.encode('ascii') + b"\n")

# Send a command
tn.write(b"ls -l\n")
tn.write(b"exit\n")

# Print the output
print(tn.read_all().decode('ascii'))

Telnet Security Checklist

	•	Replace Telnet with SSH where possible.
	•	Implement IP-based filtering.
	•	Use strong and complex passwords.
	•	Disable Telnet service if not in use.
	•	Regularly audit access logs.
	•	Restrict access using firewalls and TCP Wrappers.
