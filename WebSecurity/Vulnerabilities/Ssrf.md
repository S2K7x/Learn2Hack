# SSRF (Server-Side Request Forgery) Vulnerability

### 1. **Definition**

Server-Side Request Forgery (SSRF) is a vulnerability that occurs when a web application allows an attacker to send HTTP requests or other types of network requests from the vulnerable server to internal or external resources without proper input validation. This vulnerability often allows attackers to bypass access controls, access sensitive resources, scan internal networks, exfiltrate data, or even interact with internal services.

### 2. **How SSRF Works**

1. **Request Submission**: The web application accepts a URL, IP address, or other types of inputs that can be used to generate a network request.
2. **Server-Side Processing**: The server sends a request to the provided URL or address without checking whether it is internal, external, or on a blacklist.
3. **Unauthorized Access**: If the request targets an internal or sensitive service, the attacker can access resources that would normally be inaccessible from the outside.

### 3. **Examples of SSRF Scenarios**

- **File Uploads**: Forms that allow users to upload files or images from URLs they provide.
- **API Services**: API calls that accept URLs or IP addresses as parameters.
- **Webhook Integrations**: Integration points that accept URLs to send data to.
- **Modifiable HTTP Headers**: Manipulating HTTP headers such as `Host`, `Referer`, or `X-Forwarded-For` to redirect requests.
- **Configuration Interfaces**: Admin interfaces that accept URLs for configuring services.

### 4. **Impact of SSRF Vulnerability**

- **Access to Internal Resources**: SSRF can allow access to internal admin interfaces, databases, private APIs, and other services that are not publicly exposed.
- **Exploitation of Internal Services**: It may allow exploitation of internal services such as cloud metadata servers (e.g., AWS EC2 Metadata service via `http://169.254.169.254/`), databases, or internal REST APIs.
- **Leakage of Sensitive Information**: SSRF can provide access to configuration data, credentials, or internal infrastructure details.
- **Remote Code Execution**: In some cases, SSRF can lead to remote code execution (RCE) if internal services are vulnerable.

### 5. **Detection Techniques with Burp Suite**

1. **Configure Burp Suite**: Ensure Burp Suite is configured as a proxy to capture HTTP/HTTPS requests.
2. **Explore the Application**: Navigate through the application to identify input points for URLs, IP addresses, or suspicious parameters.
3. **Intercept Request**: Use Burp Suite's interception to capture requests containing URLs.
4. **Modify Requests**: Inject internal URLs such as `http://localhost`, `http://127.0.0.1`, or `http://169.254.169.254/` (for AWS). Also, try common internal service ports (e.g., 22 for SSH, 3306 for MySQL).
5. **Analyze Responses**: Look for responses indicating access to internal services, such as specific HTTP error codes, unexpected content, or error messages revealing internal information.
6. **Automation**: Use extensions like "Burp Collaborator" to detect non-interactive SSRF and scanners like "Burp Suite Scanner" for automated SSRF detection.

### 6. **Advanced Techniques and Workarounds**

- **Bypassing Filters**: If basic filters block terms like `http`, try variations such as `hTtp`, `HTTP`, or URL encoding.
- **DNS Rebinding**: Exploit DNS rebinding to bypass security filters and redirect SSRF traffic to internal services.
- **Gopher Protocol**: If supported, use the Gopher protocol (`gopher://`) to interact with internal services via SSRF payloads.
- **URL Fragments**: Use fragments (`#`) to mask parts of the URL and bypass filtering restrictions.

### 7. **Preventive Measures**

- **Input Validation**: Implement strict validation for URLs, blocking private and internal IPs, and verifying the legitimacy of URLs.
- **Whitelisting**: Use whitelists to restrict request destinations to specific domains or IPs.
- **Disable Unnecessary Protocols**: Disable unnecessary protocols in libraries used for requests (e.g., gopher, file).
- **Network Isolation**: Isolate production environments and sensitive internal networks to minimize the potential impact of SSRF attacks.
- **Access Controls**: Strengthen access controls for internal services, ensuring they are only accessible from trusted sources.
- **Security Audits**: Regularly conduct security audits to identify and fix potential SSRF entry points.

### 8. **Conclusion**

SSRF is a powerful vulnerability that can provide unauthorized access to sensitive internal resources, bypass firewalls, and even lead to remote code execution.
