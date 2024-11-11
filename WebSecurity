# Web Application Security Cheat Sheet

## 1. Core Web Application Security Concepts

### Authentication and Authorization
  - **Authentication**: Verifies the identity of users (e.g., via usernames, passwords, multi-factor authentication).
  - **Authorization**: Determines if an authenticated user has permission to access specific resources (e.g., role-based access control).

### Session Management
  - **Sessions**: Mechanisms to maintain user state across HTTP requests, typically using session cookies or tokens.
  - **Best Practices**:
    - Use secure, HTTP-only, and SameSite cookies.
    - Set session expiration and enforce session timeouts.
    - Regenerate session IDs after login and other sensitive actions to prevent session fixation.

### Input Validation
  - **Goal**: Ensure only expected input is processed to prevent injection attacks.
  - **Methods**:
    - Use allow-lists to enforce input formats.
    - Avoid parsing untrusted input without validation.
    - Implement strong validation for fields, e.g., email, password, phone numbers.

---

## 2. OWASP Top 10 Vulnerabilities

The OWASP Top 10 list is a standard awareness document that highlights the most critical web application security risks.

### A01: Broken Access Control
  - **Impact**: Unauthorized users gain access to restricted functions or data.
  - **Examples**: URL manipulation, missing access controls, insecure object references.
  - **Mitigations**:
    - Enforce role-based access control (RBAC) and verify permissions server-side.
    - Use least privilege for all actions.
    - Implement secure access checks at each resource endpoint.

### A02: Cryptographic Failures
  - **Impact**: Sensitive data exposure due to weak encryption practices.
  - **Examples**: Using outdated algorithms, weak keys, or storing sensitive data in plaintext.
  - **Mitigations**:
    - Use strong encryption (e.g., AES-256 for data at rest, TLS 1.2/1.3 for data in transit).
    - Avoid custom cryptographic implementations.
    - Enforce secure transport (e.g., HTTPS) and use certificates for SSL/TLS.

### A03: Injection
  - **Impact**: Attacker inserts malicious code into the application (e.g., SQL injection, command injection).
  - **Examples**: SQL injection, NoSQL injection, OS command injection.
  - **Mitigations**:
    - Use parameterized queries or prepared statements for database operations.
    - Avoid concatenating user input in SQL queries or commands.
    - Validate and sanitize all inputs.

### A04: Insecure Design
  - **Impact**: Flawed application logic and insecure patterns expose systems to attacks.
  - **Mitigations**:
    - Conduct threat modeling early in the design phase.
    - Apply secure design principles, like “secure by default.”
    - Regularly update design patterns to follow security best practices.

### A05: Security Misconfiguration
  - **Impact**: Misconfigured systems (e.g., default settings, open ports) expose applications to attacks.
  - **Mitigations**:
    - Apply secure configurations for servers, databases, and frameworks.
    - Regularly patch and update software components.
    - Disable unused features and remove default accounts.

### A06: Vulnerable and Outdated Components
  - **Impact**: Outdated libraries or modules introduce vulnerabilities.
  - **Mitigations**:
    - Regularly update third-party components and libraries.
    - Use dependency-checking tools (e.g., OWASP Dependency-Check, Snyk).
    - Verify components against known vulnerability databases (e.g., CVE database).

### A07: Identification and Authentication Failures
  - **Impact**: Weak authentication exposes the app to unauthorized access.
  - **Mitigations**:
    - Use multi-factor authentication (MFA).
    - Implement strong password policies and secure storage (e.g., bcrypt for password hashing).
    - Prevent brute-force attacks by limiting login attempts.

### A08: Software and Data Integrity Failures
  - **Impact**: Compromised software components or updates lead to application takeover.
  - **Mitigations**:
    - Use code signing and verify the integrity of updates.
    - Enable Content Security Policy (CSP) to prevent data manipulation.
    - Secure APIs and third-party integrations with proper validation and access controls.

### A09: Security Logging and Monitoring Failures
  - **Impact**: Lack of proper logging and monitoring allows attacks to go unnoticed.
  - **Mitigations**:
    - Log security events and keep track of user activities.
    - Use centralized logging and monitor logs for suspicious activity.
    - Set up alerts for potential security incidents.

### A10: Server-Side Request Forgery (SSRF)
  - **Impact**: Allows attackers to force the server to make requests to unintended locations.
  - **Mitigations**:
    - Restrict outbound connections and validate requested URLs.
    - Use allow-lists for internal services and APIs.
    - Block access to sensitive or internal addresses (e.g., 127.0.0.1, AWS metadata IP).

---

## 3. Secure Coding Practices

### Input Validation and Output Encoding
  - Validate and sanitize user inputs to ensure they meet expected formats and types.
  - Encode output based on context (e.g., HTML encode user input before rendering in HTML).

### Use HTTPS and Secure Cookies
  - Ensure all communications occur over HTTPS to protect data in transit.
  - Mark cookies as Secure, HttpOnly, and use the SameSite attribute to protect against CSRF.

### Error Handling and Logging
  - Avoid revealing sensitive information in error messages (e.g., stack traces).
  - Log errors and security events but sanitize logs to prevent sensitive data exposure.

### Secure API Development
  - Require authentication for all API endpoints and use tokens (e.g., JWT).
  - Rate-limit API requests to prevent abuse (e.g., brute-force attacks).
  - Validate and sanitize all API inputs to prevent injection vulnerabilities.

### Avoid Hardcoded Secrets
  - Store sensitive data (e.g., API keys, passwords) in environment variables or secure vaults.
  - Use key management solutions and rotate secrets regularly.

---

## 4. Web Application Security Testing

### Manual Testing Techniques
  - **Fuzz Testing**: Test inputs with various unexpected values (e.g., SQL syntax, JavaScript code).
  - **Parameter Tampering**: Modify URL or form parameters to test for unauthorized access or changes.
  - **Cookie Manipulation**: Edit cookies to test session management and security.
  - **CSRF Testing**: Test for Cross-Site Request Forgery by sending requests without proper CSRF tokens.

### Automated Testing Tools
  - **Burp Suite**: Web application testing tool for intercepting and modifying requests, scanning for vulnerabilities.
  - **OWASP ZAP**: Free, open-source web application security scanner.
  - **Nikto**: Web server scanner to detect outdated software, misconfigurations, and common vulnerabilities.
  - **SQLMap**: Automated tool for detecting and exploiting SQL injection vulnerabilities.
  - **Nmap**: Network mapping tool to discover open ports and running services.

---

## 5. Security Best Practices for Web Applications

### Implement Strong Access Controls
  - Use Role-Based Access Control (RBAC) to restrict users to only necessary permissions.
  - Implement access control checks server-side to prevent client-side bypass.

### Use Secure Development Practices
  - Adopt a Secure Development Lifecycle (SDLC) and integrate security at every development stage.
  - Perform regular code reviews, static analysis, and dynamic testing.

### Apply Content Security Policy (CSP)
  - CSP mitigates XSS attacks by restricting resources that can be loaded by the web application.
  - Define allowed sources for scripts, styles, images, and frames.

### Monitor and Respond to Threats
  - Use Web Application Firewalls (WAF) to filter and monitor HTTP requests.
  - Enable centralized logging and monitor for suspicious activity (e.g., failed login attempts, unusual traffic).

### Regularly Update Dependencies and Libraries
  - Use dependency scanning tools (e.g., Dependabot, Snyk) to identify and update vulnerable libraries.
  - Remove unused libraries or code to reduce the attack surface.
