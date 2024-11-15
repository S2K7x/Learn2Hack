# Cybersecurity Core Concepts Cheat Sheet

A comprehensive cheat sheet covering essential cybersecurity concepts, including the **CIA Triad**, **encryption fundamentals**, **secure configurations**, and an overview of **common cyber threats**. This resource is perfect for beginners in cybersecurity or anyone needing a reference for secure practices and threat awareness.

---

## 1. CIA Triad: Confidentiality, Integrity, and Availability

The **CIA Triad** is a foundational model in cybersecurity, representing three core principles that help secure data and systems.

### **Confidentiality**
- **Goal:** Protect data from unauthorized access.
- **Common Techniques:**
  - **Encryption:** Encrypt data in transit and at rest.
  - **Access Control:** Use strong access control policies (e.g., least privilege, role-based access).
  - **Data Masking:** Hide sensitive information in non-production environments.
  - **Authentication:** Ensure users are who they claim to be (e.g., multi-factor authentication).

### **Integrity**
- **Goal:** Ensure data is accurate, consistent, and protected from unauthorized alteration.
- **Common Techniques:**
  - **Hashing:** Use cryptographic hash functions (e.g., SHA-256) to detect data tampering.
  - **Checksums:** Verify data integrity with checksums (e.g., `md5sum`).
  - **Digital Signatures:** Ensure data origin and authenticity.
  - **Audit Logs:** Maintain logs of changes and monitor for unauthorized modifications.

### **Availability**
- **Goal:** Ensure data and systems are accessible to authorized users when needed.
- **Common Techniques:**
  - **Redundancy:** Use backup systems and failover mechanisms.
  - **Distributed Systems:** Distribute resources across locations to avoid single points of failure.
  - **Load Balancing:** Balance traffic across servers to prevent overload.
  - **DDoS Protection:** Use DDoS mitigation tools to handle large volumes of traffic.

---

## 2. Encryption Basics

Encryption is a method of protecting information by transforming it into unreadable text for unauthorized users. There are two main types of encryption: **symmetric** and **asymmetric**.

### **Symmetric Encryption**
- **Definition:** The same key is used for both encryption and decryption.
- **Common Algorithms:**
  - **AES (Advanced Encryption Standard):** Strong encryption standard used widely in security.
  - **DES (Data Encryption Standard):** Legacy standard, considered weak today.
  - **Blowfish:** Fast encryption, commonly used in network security.
- **Use Cases:** Data-at-rest encryption, disk encryption (e.g., BitLocker).

### **Asymmetric Encryption**
- **Definition:** Uses a pair of keys—public and private—for encryption and decryption.
- **Common Algorithms:**
  - **RSA:** Widely used for secure data transmission.
  - **ECC (Elliptic Curve Cryptography):** Strong encryption with smaller keys, suitable for mobile devices.
- **Use Cases:** SSL/TLS for secure web communication, email encryption (e.g., PGP), and digital signatures.

### **Hashing**
- **Definition:** Converts data into a fixed-size hash, primarily for data integrity checks.
- **Common Algorithms:**
  - **SHA-256:** A strong hash function widely used in digital certificates.
  - **MD5:** Outdated due to collision vulnerabilities; avoid for sensitive data.
  - **SHA-1:** Also deprecated; SHA-256 or SHA-3 is recommended.
- **Use Cases:** Password storage, file integrity checks, and digital signatures.

### **Key Concepts**
- **Encryption vs. Hashing:** 
  - Encryption is reversible with the key, while hashing is a one-way function.
- **Digital Certificates:** Certificates (e.g., X.509) authenticate entities and secure communications.
- **Transport Encryption:** Secures data in transit (e.g., HTTPS with TLS).

---

## 3. Secure Configurations

Proper configurations help secure systems from common vulnerabilities and attacks.

### **OS and Application Hardening**
- **Disable Unnecessary Services:** Stop services that aren’t required to minimize attack surface.
- **Restrict Administrative Access:** Limit root or admin access and use least-privilege principles.
- **Regular Updates and Patching:** Apply security patches to OS and applications regularly.
- **Firewall Rules:** Only allow necessary inbound/outbound connections.
- **Endpoint Protection:** Use antivirus, endpoint detection, and response tools (EDR).

### **Network Hardening**
- **Strong Network Segmentation:** Separate sensitive networks (e.g., by VLANs).
- **Secure Remote Access:** Use VPNs, SSH, or Zero Trust solutions for secure remote connections.
- **Intrusion Detection and Prevention:** Use IDS/IPS systems to detect or block threats.
- **Log and Monitor Activity:** Enable logging and monitor for suspicious activity.

### **Secure Application Configuration**
- **Secure Coding Practices:** Follow OWASP guidelines and secure coding standards.
- **Input Validation:** Sanitize and validate all user inputs to prevent injection attacks.
- **Disable Debugging in Production:** Turn off verbose error messages and debug modes.
- **Access Control:** Implement role-based access and authorization checks.
- **Session Management:** Use secure cookies, set session timeouts, and enforce secure session policies.

### **Cloud Configuration Best Practices**
- **Identity and Access Management (IAM):** Use IAM policies for precise permissions.
- **Data Encryption:** Encrypt data at rest and in transit.
- **Logging and Monitoring:** Enable cloud provider logs (e.g., AWS CloudTrail).
- **Least Privilege for Resources:** Grant only the permissions necessary for users and services.

---

## 4. Common Cyber Threats

Understanding common cyber threats helps in creating robust defenses.

### **1. Malware**
- **Definition:** Malicious software intended to disrupt, damage, or gain unauthorized access to systems.
- **Types:**
  - **Virus:** Attaches itself to files and spreads.
  - **Worm:** Self-replicating and spreads through networks.
  - **Trojan:** Disguises as legitimate software.
  - **Ransomware:** Encrypts files and demands ransom for decryption.
- **Defense:** Use antivirus, regular patching, and user training.

### **2. Phishing**
- **Definition:** Social engineering attack to steal sensitive information by pretending to be a trusted entity.
- **Variants:**
  - **Spear Phishing:** Targeted attack on specific individuals or organizations.
  - **Whaling:** High-profile targets (e.g., executives).
- **Defense:** User education, anti-phishing tools, and email filtering.

### **3. Man-in-the-Middle (MitM) Attacks**
- **Definition:** An attacker intercepts communication between two parties to eavesdrop or manipulate data.
- **Common Forms:**
  - **Wi-Fi Eavesdropping:** Intercepts data on unsecured networks.
  - **Session Hijacking:** Steals session cookies to impersonate a user.
- **Defense:** Use HTTPS/TLS, VPNs, and secure authentication (e.g., MFA).

### **4. SQL Injection**
- **Definition:** An injection attack where malicious SQL statements are inserted into an input field.
- **Impact:** Can lead to data theft, modification, or deletion.
- **Defense:** Use parameterized queries, input validation, and ORM frameworks.

### **5. Denial of Service (DoS) and Distributed Denial of Service (DDoS)**
- **Definition:** Flooding a target with traffic to make a service unavailable.
- **Types:**
  - **Application-Layer Attacks:** Target specific applications (e.g., HTTP flood).
  - **Network-Layer Attacks:** Overload network resources (e.g., SYN flood).
- **Defense:** DDoS protection services, rate limiting, and firewalls.

### **6. Zero-Day Exploits**
- **Definition:** Exploits for vulnerabilities unknown to the vendor or unpatched.
- **Defense:** Use behavioral detection tools, EDR, and stay updated on new patches.

### **7. Insider Threats**
- **Definition:** Threats from employees or individuals with authorized access.
- **Types:** Data theft, sabotage, or unintentional mistakes.
- **Defense:** Implement strict access controls, monitoring, and insider threat training.

### **8. Credential Theft**
- **Definition:** Theft of user credentials, often through phishing or brute-force attacks.
- **Common Techniques:**
  - **Keyloggers:** Capture keystrokes to record credentials.
  - **Brute-force Attacks:** Attempt multiple passwords until successful.
- **Defense:** Enforce MFA, use strong password policies, and monitor for suspicious login activity.

---

## 5. Cybersecurity Best Practices Summary

- **Strong Passwords and MFA:** Enforce complex passwords and multi-factor authentication.
- **User Awareness Training:** Train employees to recognize phishing and social engineering.
- **Regular Patching:** Keep software and hardware up to date to prevent exploitation of vulnerabilities.
- **Backups:** Regularly back up data and test the restoration process.
- **Network Security:** Segment networks, monitor traffic, and secure endpoints.
- **Logging and Monitoring:** Enable logging on critical systems and set up alerts for anomalies.
- **Access Control:** Use least privilege, review permissions regularly, and disable inactive accounts.
