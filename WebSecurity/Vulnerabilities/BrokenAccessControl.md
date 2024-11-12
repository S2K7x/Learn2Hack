**Broken Access Control** refers to a security flaw where an attacker is able to access parts of a web application, API, or service that they should not have access to. This often results from improper enforcement of permissions or restrictions on resources.

### Key Concepts and Terms

- **Access Control**: Mechanisms or policies that restrict access to resources based on user privileges (e.g., admin, user, guest).
- **Horizontal Privilege Escalation**: Accessing resources or data of another user with the same privilege level (e.g., user A accessing user B's data).
- **Vertical Privilege Escalation**: Gaining higher privileges than what is authorized (e.g., user gaining admin rights).
- **Insecure Direct Object Reference (IDOR)**: Directly accessing objects by manipulating parameters (e.g., changing a user ID in a URL).

---

## 1. Common Vulnerabilities in Broken Access Control

### 1.1. **Horizontal Privilege Escalation**

Occurs when a user can access data or functionality of another user with the same privilege level.

### Example:

- A user changes the `user_id` in a request and gains access to another user's data.

### Attack Scenario:

```
GET /account/details?user_id=123 HTTP/1.1
Host: victim.com

Modify `user_id` to `124`:
GET /account/details?user_id=124 HTTP/1.1
Host: victim.com

```

If the system does not verify ownership of the `user_id`, user 123 can view the data of user 124.

### How to Test:

1. **Identify user-specific parameters** (e.g., `user_id`, `account_number`) in HTTP requests.
2. **Manipulate the parameter** to another valid user’s identifier.
3. Check if you can access the other user’s data.

### 1.2. **Vertical Privilege Escalation**

Occurs when a user with lower privileges can access restricted resources meant for higher-privileged users.

### Example:

- A regular user accessing admin-only features by altering role or privileges in a request.

### Attack Scenario:

```
POST /admin/delete_user HTTP/1.1
Host: victim.com
Cookie: role=user

Modify the role:
POST /admin/delete_user HTTP/1.1
Host: victim.com
Cookie: role=admin

```

If the system fails to check if the user is actually an admin, this request could succeed.

### How to Test:

1. **Identify role-based access control logic** (e.g., roles stored in cookies, JWTs, session).
2. **Change the role/privilege level** directly (e.g., `user` -> `admin`) or try accessing admin endpoints.
3. **Observe the response** for successful escalation (e.g., gaining access to sensitive pages, actions like user management).

---

## 2. Testing for Access Control Vulnerabilities

### 2.1. **URL Manipulation**

Attackers can manipulate URL parameters to access unauthorized data.

### Attack Scenario:

```
Original request:
GET /order/view?order_id=101 HTTP/1.1

Try changing the `order_id`:
GET /order/view?order_id=102 HTTP/1.1

```

If the system doesn’t verify that the `order_id` belongs to the logged-in user, an attacker may view other users' orders.

### How to Test:

- **Identify all parameterized URLs** and **modify** values (especially `id`, `account`, `user_id`, `order_id`).
- Check if **other user’s resources** are displayed.

### 2.2. **Forced Browsing**

This happens when sensitive pages are accessible without proper authentication or authorization. It involves guessing or brute-forcing URLs.

### Attack Scenario:

```
Regular user access:
GET /user/dashboard HTTP/1.1

Try accessing admin pages:
GET /admin/panel HTTP/1.1

```

If the admin panel is accessible to a regular user without any authentication check, this is a **forced browsing** issue.

### How to Test:

1. **Manually enter URLs** that you suspect are admin or sensitive pages (e.g., `/admin`, `/settings`, `/config`).
2. **Observe responses** for any unintended access (e.g., accessing a panel you shouldn’t see).

---

## 3. Attack Techniques and Payloads

### 3.1. **Insecure Direct Object Reference (IDOR)**

IDOR occurs when an application uses user-supplied input to access objects without verifying if the user is authorized.

### Example:

```
GET /documents/view?doc_id=123 HTTP/1.1

Change `doc_id` to another document ID:
GET /documents/view?doc_id=124 HTTP/1.1

```

If user 123 can view user 124's document without authorization, this is an IDOR vulnerability.

### How to Test:

- Identify all user-controllable IDs in requests.
- Change the values and see if access is granted to other users’ resources.

### 3.2. **Parameter Tampering**

By modifying parameters (e.g., role, permissions) in cookies, headers, or forms, attackers can elevate privileges.

### Example:

```
POST /change_role HTTP/1.1
Host: victim.com
Cookie: role=user

Change the role to admin:
POST /change_role HTTP/1.1
Host: victim.com
Cookie: role=admin

```

If the application doesn’t validate the change of role, this can allow privilege escalation.

### How to Test:

- Modify `role` or `permissions` parameters.
- Look for hidden input fields in forms that define roles or privileges.
- Tamper with `cookies` or `JWTs` containing roles or permissions.

### 3.3. **Accessing Unlinked Resources**

Sometimes, sensitive resources (like files, APIs) are not linked but still accessible if an attacker knows the exact URL.

### Example:

```
GET /uploads/private/user123-report.pdf HTTP/1.1

Try accessing a different report:
GET /uploads/private/user124-report.pdf HTTP/1.1

```

### How to Test:

- Use **directory brute-forcing tools** like **Dirbuster**, **Gobuster**, or **FFUF** to discover hidden directories and files.
- **Guess URLs** of sensitive resources based on naming conventions.

---

## 4. Common Mistakes that Lead to Broken Access Control

### 4.1. **Relying Only on Frontend Controls**

- Access controls should never be enforced **only in the frontend (e.g., JavaScript)**, as they can be bypassed by modifying requests.
- Example: Relying on hidden form fields or disabled buttons to restrict actions.

### 4.2. **Missing Server-Side Authorization**

- Failing to **validate user roles or permissions** in backend code before granting access to resources.
- Example: Not checking if the user is allowed to access an endpoint or manipulate a resource.

### 4.3. **Exposed Sensitive Endpoints**

- Sensitive endpoints (e.g., `/admin`, `/config`) are left exposed without authentication or authorization checks.
- Example: If any user can access `/admin/dashboard` without an admin role check.

---

## 5. Real-World Examples of Exploits

### 5.1. **GitHub Issue - Lack of Access Control on Pull Requests**

- GitHub had a vulnerability where any user could interact with a restricted pull request even if they were not authorized.

### 5.2. **Uber - Horizontal Privilege Escalation**

- A user was able to update the phone number of another account due to improper validation of user ID ownership.

---

## 6. Mitigation Strategies

### 6.1. **Enforce Server-Side Authorization**

- Implement access control checks **on the server** for every resource request.
- Ensure that the user’s session is checked for the right **roles and permissions**.

### 6.2. **Use UUIDs Instead of Sequential IDs**

- Replace predictable `user_id` or `order_id` with **UUIDs** to prevent guessing attacks.
- Example:
    
    ```
    /order/view?order_id=550e8400-e29b-41d4-a716-446655440000
    
    ```
    

### 6.3. **Implement Proper Role-Based Access Control (RBAC)**

- Assign roles (e.g., user, admin) and enforce **RBAC checks** before accessing resources.
- Example of RBAC logic in code:
    
    ```python
    if not current_user.is_admin:
        return "Access Denied", 403
    
    ```
    

### 6.4. **Disable Forced Browsing**

- Disable access to sensitive endpoints by users without proper roles. Use access control middleware to check permissions.

---

## 7. Tools for Finding Broken Access Control

- **Burp Suite**: Use **Intruder** to brute-force and manipulate parameters (e.g., `user_id`, `role`).
- **OWASP ZAP**: Use the **Forced Browse** plugin to discover unprotected URLs.
- **FFUF / Gobuster**: Directory brute-forcing tools for uncovering unprotected directories and files.
- **Postman**: Manually test API access control by modifying request parameters.

---

## 8. OWASP Reference

### OWASP Top 10

Broken Access Control is ranked **#1** in the [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/).

### OWASP ASVS

Refer to **Section 4** (Access Control) of the OWASP Application Security Verification Standard (ASVS) for detailed guidance

on access control testing.

---
