# Port 22 - SSH

## Overview

- **Port Number**: 22
- **Protocol**: TCP
- **Service**: SSH (Secure Shell)
- **Purpose**: Secure remote administration, file transfer, and tunneling. SSH is widely used to manage servers securely over a network.
- **Standard**: Defined in RFC 4253.

## Key SSH Features

- **Encrypted Communication**: Protects data-in-transit using symmetric encryption.
- **Authentication Mechanisms**:
  - Password-Based: Username and password.
  - Key-Based: Public and private key pairs.
  - GSSAPI: Kerberos-based authentication.
  - Certificate-Based: X.509 certificates.
- **Tunneling**:
  - Local: Forwarding a local port to a remote service.
  - Remote: Forwarding a remote port to a local service.
  - Dynamic: SOCKS proxy for dynamic traffic routing.
- **File Transfer**: SCP (Secure Copy) and SFTP (SSH File Transfer Protocol).

## Common Uses

- **Remote System Administration**: Access servers remotely.
- **Secure File Transfer**: Using SCP, SFTP.
- **Port Forwarding**: Creating encrypted tunnels for other protocols (e.g., VNC, HTTP).
- **Command Execution**: Running commands/scripts remotely.
- **Git Operations**: Secure interaction with Git repositories.

## SSH Commands Overview

### Basic Connection Commands

```bash
# Connect to a remote server
ssh user@remote_host

# Connect to a specific port
ssh -p 2222 user@remote_host

# Execute a single command remotely
ssh user@remote_host 'ls -lah /var/www'

# Use a specific private key
ssh -i /path/to/private_key user@remote_host

Key Management

# Generate a new SSH key pair
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# Copy public key to a remote server
ssh-copy-id user@remote_host

# Manually append public key to authorized_keys file
cat ~/.ssh/id_rsa.pub | ssh user@remote_host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# List SSH keys loaded in the agent
ssh-add -l

# Add a key to the SSH agent
ssh-add ~/.ssh/id_rsa

Port Forwarding (Tunneling)

# Local port forwarding: Access remote database on port 5432 locally
ssh -L 5432:localhost:5432 user@remote_host

# Remote port forwarding: Expose local web server on remote port
ssh -R 8080:localhost:80 user@remote_host

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@remote_host

Secure File Transfer (SCP & SFTP)

# Copy file from local to remote
scp local_file.txt user@remote_host:/remote/directory/

# Copy file from remote to local
scp user@remote_host:/remote/file.txt /local/directory/

# Using SFTP for interactive file management
sftp user@remote_host

Server Hardening and Configuration

# Edit SSH server configuration file (usually /etc/ssh/sshd_config)
sudo nano /etc/ssh/sshd_config

# Example hardening configurations:
PermitRootLogin no         # Disable root login
PasswordAuthentication no  # Enforce key-based authentication
Port 2222                  # Change default port
AllowUsers specific_user   # Restrict user access

SSH Key Management Best Practices

	•	Use ed25519 or ECDSA keys for stronger cryptographic security over RSA.
	•	Use SSH Agent Forwarding cautiously; avoid using on untrusted networks.
	•	Store private keys securely and never share them.
	•	Enforce key rotation periodically.

Logging & Monitoring

# Check SSH logs (Linux systems)
sudo tail -f /var/log/auth.log  # Ubuntu/Debian
sudo tail -f /var/log/secure    # CentOS/RHEL

Automating with SSH

# Use SSH with a Bash script
#!/bin/bash
HOST="user@remote_host"
COMMAND="uptime"
ssh $HOST $COMMAND

Attack Vectors and Common Vulnerabilities

1. Weak Passwords

	•	Attack: Brute-force attacks on SSH credentials are common.
	•	Mitigation:
	•	Enforce strong passwords.
	•	Limit failed authentication attempts using DenyHosts or fail2ban.
	•	Use key-based authentication instead of passwords.

2. Default Port Exposure

	•	Attack: Attackers scan Port 22 for open SSH servers.
	•	Mitigation:
	•	Change default port using Port 2222 (or another port).
	•	Use port-knocking or single-packet authorization (e.g., fwknop).

3. Unauthorized Access via Stolen Keys

	•	Attack: If private keys are compromised, unauthorized access is possible.
	•	Mitigation:
	•	Store private keys securely (e.g., ~/.ssh/id_rsa with chmod 600).
	•	Enable two-factor authentication (2FA) for critical servers.
	•	Use hardware security modules (HSM) or USB keys (YubiKey) for storage.

4. Vulnerable SSH Server Software

	•	Attack: Older SSH versions may have vulnerabilities (e.g., CVE-2020-15778).
	•	Mitigation:
	•	Keep OpenSSH updated to the latest version.
	•	Disable older SSH protocol versions (Protocol 2 only).
	•	Apply security patches promptly.

5. Man-in-the-Middle (MitM) Attacks

	•	Attack: Intercepting SSH traffic to capture credentials or session data.
	•	Mitigation:
	•	Use StrictHostKeyChecking yes to prevent MITM attacks.
	•	Always verify the server’s fingerprint upon first connection.
	•	Use VPNs or trusted networks for connections when possible.

Example of a Brute-Force Attack (Using Hydra)

# Hydra brute-force attack on SSH
hydra -l user -P /path/to/passwords.txt ssh://target_ip

Dangerous Functions and Configurations

	•	PermitRootLogin yes: Allows root login; should be set to no.
	•	PasswordAuthentication yes: Should be set to no to enforce key-only access.
	•	ChallengeResponseAuthentication yes: Should be disabled unless two-factor authentication is needed.
	•	AuthorizedKeysFile: Always ensure this is set to ~/.ssh/authorized_keys.
	•	PermitEmptyPasswords yes: Should never be enabled, allowing empty passwords.

Network Defense and Best Practices

	1.	Use Strong Ciphers: Enforce strong cryptographic ciphers.

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

	2.	Disable Protocol 1: Use SSH Protocol 2 only.

Protocol 2

	3.	Implement Rate Limiting: Protect against brute-force attempts.

# Using fail2ban example:
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

	4.	Use TCP Wrappers: Limit IPs that can connect to SSH.

# Add allowed IPs to /etc/hosts.allow
sshd: 192.168.1.0/24, 10.0.0.0/8

	5.	Regular Audits: Regularly scan logs and perform security audits.

sudo grep "Failed password" /var/log/auth.log | sort | uniq -c | sort -nr

	6.	Use Multi-Factor Authentication: Integrate with Google Authenticator, Duo, or similar services.

SSH Security Checklist

	•	Disable root login.
	•	Enforce key-based authentication.
	•	Use non-default SSH port.
	•	Install intrusion detection/prevention tools.
	•	Regularly update OpenSSH.
	•	Use strong, unique passwords or keys.

