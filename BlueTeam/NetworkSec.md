# Network Security Cheat Sheet 🔒

### Purpose
This cheat sheet serves as a quick reference for network security concepts, tools, techniques, and best practices. It is suitable for ethical hackers, network administrators, security engineers, and penetration testers.

---

## 📖 Table of Contents

1. [Key Network Security Concepts](#key-network-security-concepts)
2. [Common Network Threats](#common-network-threats)
3. [Network Security Tools](#network-security-tools)
4. [Packet Analysis Techniques](#packet-analysis-techniques)
5. [Firewall Rules and Configurations](#firewall-rules-and-configurations)
6. [Network Monitoring](#network-monitoring)
7. [Best Practices for Network Security](#best-practices-for-network-security)

---

## 1. Key Network Security Concepts

- **CIA Triad**:
  - **Confidentiality**: Protecting data from unauthorized access.
  - **Integrity**: Ensuring data is accurate and unaltered.
  - **Availability**: Ensuring data is available to authorized users.

- **Zero Trust**: No one is trusted by default; verification is required before granting access.

- **Defense in Depth**: Layered security strategy combining multiple defense mechanisms (e.g., firewalls, IDS/IPS, anti-malware).

- **Least Privilege Principle**: Granting only the permissions necessary for users or services to perform their roles.

- **Network Segmentation**: Dividing a network into subnetworks to isolate and limit the impact of breaches.

---

## 2. Common Network Threats

### Unauthorized Access
- **Brute Force Attacks**: Repeated attempts to guess passwords.
- **Phishing**: Social engineering attacks that trick users into revealing credentials.
- **Privilege Escalation**: Gaining higher privileges through exploiting vulnerabilities.

### Network Attacks
- **Denial of Service (DoS)**: Overloading a network or server to disrupt services.
- **Distributed Denial of Service (DDoS)**: Multiple compromised systems targeting a single system to cause a service interruption.
- **Man-in-the-Middle (MITM)**: Eavesdropping attack where an attacker intercepts communication between two parties.

### Data Exfiltration
- **SQL Injection**: Exploiting web app vulnerabilities to access a database and steal information.
- **DNS Tunneling**: Encodes data in DNS queries, bypassing network filtering.

### Network Reconnaissance
- **Port Scanning**: Probing a network for open ports to identify services running on the target.
- **Ping Sweep**: Scanning an IP range to discover active hosts.

---

## 3. Network Security Tools

### Network Scanning and Mapping
- **Nmap**: Network discovery and vulnerability scanning.
  ```bash
  nmap -A -T4 <target_ip>
  ```
- **Netcat**: Reads and writes data across network connections, useful for debugging and network exploration.
  ```bash
  nc -lvp <port>
  ```

### Packet Analysis
- **Wireshark**: Captures and analyzes packets, useful for detecting suspicious network traffic.
- **Tcpdump**: Command-line packet analyzer.
  ```bash
  tcpdump -i eth0 -nn -X -s0 'port 80'
  ```

### Intrusion Detection Systems (IDS)
- **Snort**: Network-based intrusion detection system that uses rule-based patterns.
- **Suricata**: Multi-threaded IDS/IPS with features like HTTP logging and TLS encryption detection.

### Firewall and Access Control
- **iptables**: Linux firewall management tool.
  ```bash
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  ```
- **pfSense**: Open-source firewall and router software based on FreeBSD.

---

## 4. Packet Analysis Techniques

### Understanding TCP Handshake
1. **SYN**: Initiates the connection.
2. **SYN-ACK**: Server responds to SYN.
3. **ACK**: Client acknowledges the response.

### Analyzing Suspicious Packets in Wireshark
- **Follow TCP Stream**: Useful to analyze communication between two endpoints.
- **Filter by IP or Port**:
  ```plaintext
  ip.addr == <target_ip> && tcp.port == <port>
  ```
- **Detecting ARP Spoofing**: Look for duplicate IP addresses with different MAC addresses.

### Identifying Malicious Traffic
- **Unusual Port Usage**: Traffic on non-standard ports (e.g., HTTP on 8080).
- **High Volume of SYN Requests**: Could indicate a SYN flood DoS attack.
- **Odd Packet Sizes**: Excessively small or large packets may indicate an exploit attempt.

---

## 5. Firewall Rules and Configurations

### Basic Firewall Rules
- **Allow SSH Access**:
  ```bash
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  ```
- **Allow HTTP and HTTPS Traffic**:
  ```bash
  iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
  ```
- **Deny All Inbound Traffic by Default**:
  ```bash
  iptables -P INPUT DROP
  ```

### Port Knocking
**Description**: Only opens a port after a specific sequence of closed ports are accessed.

**Example Tools**: Knockd

### Configuring a Basic pfSense Firewall
1. **Set Default Deny Policy** for inbound traffic.
2. **Create Whitelist Rules** for allowed traffic.
3. **Enable Logging** for traffic to critical services.

---

## 6. Network Monitoring

### Network Traffic Monitoring Tools
- **Nagios**: Provides monitoring and alerting for services, network health.
- **Zabbix**: Network monitoring and visualization, supports SNMP for network devices.
- **SolarWinds**: Network Performance Monitor for in-depth traffic analysis (commercial).

### Anomaly Detection Techniques
- **Threshold-Based Alerts**: Set thresholds for bandwidth, CPU, memory, or connections.
- **Baseline Traffic Analysis**: Define "normal" network traffic and monitor deviations.
- **Behavioral Analysis**: Detect unusual login times, excessive downloads, or lateral movement.

### Configuring SNMP for Device Monitoring
1. **Install SNMP** on network devices and configure community strings (security context).
2. **Set SNMP Traps** for alerting on specific network events.

---

## 7. Best Practices for Network Security

### Authentication & Access Control
- **Multi-Factor Authentication (MFA)**: Enforce MFA for all network devices.
- **VPN for Remote Access**: Use a VPN with strong encryption for remote access.
- **Network Segmentation**: Segment critical network zones, such as guest networks, internal LAN, DMZ.

### Regular Vulnerability Scanning
- **Automate Scanning**: Use tools like OpenVAS or Nessus for scheduled scans.
- **Patch Management**: Prioritize and apply patches to critical vulnerabilities.

### Secure Network Configurations
- **Disable Unused Services**: Shut down unused services and ports on network devices.
- **Use Strong Encryption**: Enforce TLS/SSL for web traffic and VPNs.

### Logging and Alerting
- **Enable Logging**: Enable logging on all network devices, especially firewalls and access points.
- **Centralize Logs**: Use a SIEM (e.g., Splunk, ELK) to aggregate logs for analysis.
- **Set Alerts**: Configure alerts for critical events such as failed login attempts, unusual port activity.

### Employee Training & Awareness
- **Phishing Awareness**: Regular training to recognize phishing and social engineering attacks.
- **Data Handling Policies**: Define secure data handling procedures and enforce them.

### Incident Response Plan
- **Define Incident Roles**: Define roles for incident response (e.g., Incident Manager, Forensic Analyst).
- **Create Playbooks**: For specific incident types like DDoS, malware infections.
- **Regular Drills**: Conduct simulated incident response exercises to ensure preparedness.

---

### 📘 Resources
- **NIST Cybersecurity Framework**: [NIST.gov](https://www.nist.gov/cyberframework)
- **OWASP Top 10**: [OWASP.org](https://owasp.org/www-project-top-ten/)
- **MITRE ATT&CK**: [MITRE.org](https://attack.mitre.org/)
