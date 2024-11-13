# Port 80 - HTTP Cheatsheet

## Overview

- **Port Number**: 80
- **Protocol**: TCP
- **Service**: HTTP (Hypertext Transfer Protocol)
- **Purpose**: The primary protocol for delivering web pages and resources over the internet.
- **Standard**: Defined in RFC 2616 (HTTP/1.1), RFC 7540 (HTTP/2), RFC 9110 (HTTP/1.1 updates).

## Key HTTP Characteristics

- **Stateless**: Each HTTP request is independent and does not retain session state.
- **Unencrypted by Default**: HTTP communication on Port 80 is not encrypted, leaving it vulnerable to eavesdropping and Man-in-the-Middle (MitM) attacks.
- **Request-Response Model**: Clients (e.g., browsers) send requests to servers, which return responses containing requested resources.

## Common Uses

- **Web Browsing**: Accessing websites and web applications.
- **API Communication**: HTTP-based APIs use JSON or XML over Port 80.
- **Resource Delivery**: Loading images, stylesheets, scripts, and other web assets.
- **Web Application Management**: HTTP is used for managing web servers and configuring services.

## HTTP Methods Overview

### Basic HTTP Methods

- **GET**: Retrieve information from the server.
  ```http
  GET /index.html HTTP/1.1
  Host: example.com

	•	POST: Submit data to the server (often used in forms).

POST /form_submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=user&password=pass


	•	PUT: Update or replace a resource on the server.

PUT /api/item/123 HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 59

{
  "id": 123,
  "name": "New Item Name",
  "description": "Updated description"
}


	•	DELETE: Remove a resource from the server.

DELETE /api/item/123 HTTP/1.1
Host: example.com


	•	HEAD: Retrieve headers for a resource without the body.

HEAD /index.html HTTP/1.1
Host: example.com



Less Common HTTP Methods

	•	OPTIONS: Retrieve the HTTP methods supported by the server.
	•	PATCH: Partially modify a resource.
	•	TRACE: Echoes back the received request; can be used for debugging.
	•	CONNECT: Establishes a tunnel to the server (used in proxies).

HTTP Response Status Codes

	•	1xx Informational:
	•	100 Continue, 101 Switching Protocols
	•	2xx Success:
	•	200 OK, 201 Created, 204 No Content
	•	3xx Redirection:
	•	301 Moved Permanently, 302 Found, 304 Not Modified
	•	4xx Client Error:
	•	400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found
	•	5xx Server Error:
	•	500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable

Common Attack Vectors and Vulnerabilities

1. SQL Injection (SQLi)

	•	Attack: Inserting or manipulating SQL queries via HTTP requests to interact with the database.
	•	Example: A vulnerable login form might allow:

POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything


	•	Mitigation:
	•	Use parameterized queries.
	•	Implement input validation.
	•	Use WAFs (Web Application Firewalls).

2. Cross-Site Scripting (XSS)

	•	Attack: Injecting malicious scripts that execute in the victim’s browser.
	•	Example: Inserting a malicious <script> tag in a search box.

GET /search?q=<script>alert('XSS');</script> HTTP/1.1


	•	Mitigation:
	•	Sanitize and validate all inputs.
	•	Use security headers like Content-Security-Policy.
	•	Escape user data in HTML contexts.

3. Cross-Site Request Forgery (CSRF)

	•	Attack: Tricks a user into executing unintended actions by exploiting their authenticated session.
	•	Example: A hidden image tag causing an unwanted request:

<img src="http://example.com/delete_account?id=1234" />


	•	Mitigation:
	•	Use CSRF tokens for state-changing operations.
	•	Implement SameSite cookies.
	•	Verify referer headers.

4. Directory Traversal

	•	Attack: Accessing files and directories outside the web root using ../.
	•	Example Attack String:

GET /../../../../etc/passwd HTTP/1.1
Host: example.com


	•	Mitigation:
	•	Sanitize file paths.
	•	Use realpath() functions in the backend to resolve paths securely.
	•	Restrict web server permissions.

5. Command Injection

	•	Attack: Executing arbitrary commands on the server via web inputs.
	•	Example:

POST /execute_command HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

cmd=; ls -la /etc;


	•	Mitigation:
	•	Use parameterized queries.
	•	Validate and sanitize user inputs.
	•	Use least privilege for web server user accounts.

6. Man-in-the-Middle (MitM)

	•	Attack: Intercepting or altering HTTP traffic because HTTP is unencrypted.
	•	Mitigation:
	•	Switch to HTTPS using SSL/TLS (Port 443).
	•	Implement HSTS (HTTP Strict Transport Security).

Example of an SQL Injection Exploit Using SQLMap

	•	Basic SQLMap command to test an HTTP GET endpoint for SQLi:

sqlmap -u "http://example.com/product?id=1" --dbs



Common HTTP Vulnerabilities

	•	CVE-2017-5638: Apache Struts remote code execution via HTTP headers.
	•	CVE-2015-1635: HTTP.sys Remote Code Execution in Windows.
	•	CVE-2020-1938: Apache Tomcat AJP File Inclusion vulnerability.

HTTP Security Hardening and Best Practices

Security Headers

	•	Example of adding security headers in an HTTP response:

Content-Security-Policy: default-src 'self';
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block



Use HTTPS Instead of HTTP

	•	Use SSL/TLS certificates to encrypt traffic.
	•	Redirect all HTTP traffic to HTTPS.
	•	Use Let’s Encrypt for free SSL certificates.

Web Application Firewall (WAF)

	•	Implement a WAF like ModSecurity to filter and block malicious HTTP traffic.
	•	Use rulesets to detect SQLi, XSS, and other common attacks.

Input Validation and Sanitization

	•	Sanitize all inputs from user forms, URLs, and headers.
	•	Use allow-lists (positive validation) rather than deny-lists.
	•	Use libraries like OWASP ESAPI for input handling.

Secure Cookie Management

	•	Example of setting secure cookies in HTTP responses:

Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Strict



Firewall Rules

	•	Linux iptables example to restrict Port 80 to specific IPs:

iptables -A INPUT -p tcp --dport 80 -s trusted_ip_address -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP



Logging and Monitoring HTTP Traffic

Enable HTTP Server Logs

	•	Enable access and error logs for web servers like Apache or Nginx.
	•	Apache access log (example for Debian/Ubuntu):

sudo tail -f /var/log/apache2/access.log


	•	Nginx error log (example for CentOS):

sudo tail -f /var/log/nginx/error.log



Monitor with Tools

	•	Wireshark: Capture and analyze HTTP packets. Use filter: tcp.port == 80.
	•	Splunk/ELK Stack: Log aggregation, search, and analysis.
	•	Fail2ban: Block IP addresses that show malicious behavior.

Using curl to Test HTTP Security Headers

	•	Check HTTP headers of a website:

curl -I http://example.com


	•	Test if a website redirects from HTTP to HTTPS:

curl -I http://example.com --max-redirs 10



Scripting HTTP Automation and Exploits

Bash Script to Fetch HTTP Response

#!/bin/bash
URL="http://example.com"
curl -v $URL

Python Script to Send GET Request

import requests

url = "http://example.com"
response = requests.get(url)
print(response.status_code)
