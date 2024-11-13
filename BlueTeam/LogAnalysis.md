# Log Analysis Cheat Sheet 📊

### Purpose
This cheat sheet is designed for system administrators, developers, security engineers, and penetration testers to analyze logs efficiently and effectively. It provides commands, techniques, and patterns for finding critical events and signs of compromise across various log types. 

---

## 🌐 Table of Contents

1. [Log Types and Their Purposes](#log-types-and-their-purposes)
2. [Key Log Files by Operating System](#key-log-files-by-operating-system)
3. [Log Analysis Tools](#log-analysis-tools)
4. [Core Log Analysis Techniques](#core-log-analysis-techniques)
5. [Common Log Patterns and Filters](#common-log-patterns-and-filters)
6. [Anomaly Detection in Logs](#anomaly-detection-in-logs)
7. [Suspicious Activity Detection Patterns](#suspicious-activity-detection-patterns)
8. [Tips for Effective Log Analysis](#tips-for-effective-log-analysis)

---

## 1. Log Types and Their Purposes

### System Logs
- **Syslog**: Stores system-related messages (e.g., service start/stop, errors).
- **Authentication Logs**: Logs of login attempts, both successful and failed (e.g., `/var/log/auth.log`).
- **Audit Logs**: Detailed records of system events; critical for forensic analysis.

### Application Logs
- **Web Server Logs**: Stores HTTP requests (e.g., Apache, NGINX).
- **Database Logs**: Logs of queries, errors, and login attempts for SQL databases.
- **Firewall Logs**: Records network traffic that is allowed or blocked.

### Security-Specific Logs
- **IDS/IPS Logs**: Detects suspicious network activity (e.g., Snort, Suricata).
- **SIEM Logs**: Aggregated logs used by Security Information and Event Management tools.

---

## 2. Key Log Files by Operating System

### Linux
| Log File Path                  | Purpose                              |
|--------------------------------|--------------------------------------|
| `/var/log/syslog`              | General system logs                  |
| `/var/log/auth.log`            | Authentication logs                  |
| `/var/log/kern.log`            | Kernel logs                          |
| `/var/log/secure`              | Security-related events              |
| `/var/log/boot.log`            | Boot process logs                    |

### Windows
| Log Type                      | Location in Event Viewer              |
|-------------------------------|---------------------------------------|
| System Logs                   | `Applications and Services Logs`      |
| Security Logs                 | `Windows Logs -> Security`            |
| Application Logs              | `Windows Logs -> Application`         |
| Setup Logs                    | `Windows Logs -> Setup`               |

---

## 3. Log Analysis Tools

### CLI-Based
- **`grep`**: Pattern search tool for finding text in logs (`grep "ERROR" /var/log/syslog`).
- **`awk`**: Extract specific columns or patterns.
- **`sed`**: Stream editor, good for modifying log entries on-the-fly.
- **`journalctl`**: Query systemd logs on Linux.

### GUI-Based
- **Splunk**: Powerful, search-based interface for indexed log data.
- **Elastic Stack (ELK)**: Elasticsearch, Logstash, Kibana — used for storing and visualizing log data.
- **Graylog**: Centralized log management with real-time analysis and alerting.

### Open-Source Security Tools
- **Wazuh**: SIEM solution with agent-based monitoring.
- **OSSEC**: Host-based intrusion detection and log analysis.
- **Suricata**: Network threat detection engine that logs network events.

---

## 4. Core Log Analysis Techniques

### Pattern Matching
- **Keyword Search**: Look for specific keywords (e.g., "error," "unauthorized").
  ```bash
  grep "unauthorized access" /var/log/auth.log
  ```
  
- **Regular Expressions**: Use regex for more flexible matching.
  ```bash
  grep -E "login|failed" /var/log/auth.log
  ```

### Time Range Filtering
- **Limit by Date and Time**: Use `journalctl` or `awk` to extract logs within a specific range.
  ```bash
  journalctl --since "2023-11-01" --until "2023-11-07"
  ```

### Statistical Analysis
- **Frequency Count**: Identify patterns by counting occurrences.
  ```bash
  awk '{print $5}' /var/log/syslog | sort | uniq -c | sort -nr
  ```

### Parsing and Structuring Logs
- **JSON/XML Parsing**: For structured logs, parse fields to JSON/XML for analysis.
  ```bash
  jq '.field' log.json  # Extract field data from JSON logs
  ```

---

## 5. Common Log Patterns and Filters

### Authentication Attempts
- **Failed Logins**:
  ```bash
  grep "Failed password" /var/log/auth.log
  ```
- **Successful Logins**:
  ```bash
  grep "Accepted password" /var/log/auth.log
  ```

### Network Activity
- **SSH Connections**:
  ```bash
  grep "sshd" /var/log/auth.log
  ```
- **Port Scanning**:
  ```bash
  grep "SYN" /var/log/iptables.log
  ```

### System Changes
- **File Changes**:
  ```bash
  grep "audit" /var/log/audit/audit.log | grep "chmod\|chown"
  ```

### Privilege Escalation
- **Sudo Usage**:
  ```bash
  grep "sudo" /var/log/auth.log
  ```

---

## 6. Anomaly Detection in Logs

### Unusual Time Patterns
- **Identify Off-Hours Activity**: Suspicious activities often happen outside regular business hours.
  ```bash
  awk '$3 >= "00:00" && $3 <= "06:00"' /var/log/auth.log
  ```

### IP Address Whitelisting/Blacklisting
- **Identify Repeated IPs**: Detect multiple access attempts from the same IP.
  ```bash
  awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -10
  ```

### Frequency-Based Anomalies
- **Burst of Errors**: Rapid succession of errors or failed logins.
  ```bash
  grep "Failed password" /var/log/auth.log | wc -l
  ```

### User-Agent Analysis
- **Detect Suspicious User-Agents**:
  ```bash
  grep "User-Agent" /var/log/nginx/access.log | sort | uniq -c | sort -nr
  ```

---

## 7. Suspicious Activity Detection Patterns

### Brute Force Attacks
- **High Volume of Login Failures**:
  ```bash
  grep "Failed password" /var/log/auth.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
  ```

### Web Exploits and SQL Injection
- **Suspicious URL Patterns**:
  ```bash
  grep -E "union|select|insert|update|delete|drop" /var/log/nginx/access.log
  ```

### Malware Indicators
- **Unusual Executable Commands**:
  ```bash
  grep "execve" /var/log/audit/audit.log
  ```

### Privilege Escalation Attempts
- **Abnormal Sudo Use**:
  ```bash
  grep "sudo" /var/log/auth.log | awk '{print $1, $2, $9}'
  ```

---

## 8. Tips for Effective Log Analysis

- **Centralize Logs**: Use a log management system (e.g., ELK Stack, Graylog) to aggregate logs in one place.
- **Correlate Logs**: Cross-reference multiple logs (e.g., auth and application logs) to get context on events.
- **Set Alerts**: Automate alerts for high-severity events like failed logins, data exfiltration, and privilege escalations.
- **Regular Audits**: Schedule periodic reviews of logs to stay on top of suspicious activity.
- **Optimize Retention**: Set appropriate log retention policies based on regulatory and forensic needs.
  
---

### 📘 Resources
- **Syslog Protocol**: [RFC 5424](https://tools.ietf.org/html/rfc5424)
- **Log Management Best Practices**: [SANS Whitepaper on Logging](https://www.sans.org/white-papers/logging-best-practices/)
- **ELK Stack Documentation**: [Elastic.co](https://www.elastic.co/guide/en/logstash/current/index.html)
