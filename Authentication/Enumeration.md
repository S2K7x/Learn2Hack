## 🔍 **Enumeration of Authentication Mechanisms**

### **Goals**
- Discover authentication points.
- Understand the mechanism and protocols used.
- Gather potential attack surface details.

### **Techniques**
#### **1. Analyze HTTP Responses**
- Look for headers related to authentication:
  - `WWW-Authenticate`: Indicates Basic, Digest, or NTLM authentication.
  - `Set-Cookie`: May store session tokens or authentication states.
  - `Content-Type`: Could suggest specific API authentication (e.g., JSON Web Tokens, XML).
  
#### **2. Analyze Login Pages**
- Inspect the login form:
  - Identify the **request method** (e.g., POST or GET).
  - Locate fields for username, password, and hidden inputs (e.g., CSRF tokens).
  - Look for rate-limiting mechanisms.
- Check JavaScript for hidden routes or API endpoints.

#### **3. Search for Default Credentials**
- Common defaults: `admin:admin`, `admin:password`, etc.
- Tools like **cewl** or **commonspeak** can generate wordlists for weak default passwords.

#### **4. Directory and Endpoint Enumeration**
- Use tools like **ffuf**, **dirb**, or **gobuster** to identify:
  - `/login`
  - `/admin`
  - `/auth`
  - `/api/authenticate`
  - `/forgot-password`
  - `/signup`

#### **5. Monitor Responses for Clues**
- HTTP status codes can reveal:
  - `200 OK`: Successful login.
  - `403 Forbidden`: Valid user, wrong password.
  - `401 Unauthorized`: Invalid credentials.
- Check error messages for hints like:
  - “User does not exist.”
  - “Invalid password.”

#### **6. User Enumeration**
- Registration forms: Look for messages indicating an existing username or email.
- Login responses: Different messages for valid vs. invalid usernames.
- Password reset: Identifies valid accounts by error/success responses.

#### **7. Social Engineering**
- Inspect public information (emails, usernames, or password reset Q&A).
- Leverage OSINT tools like **Sherlock** to find matching usernames.

---

## 💥 **Brute Force Authentication**

### **Best Practices for Brute Force**
- Use **targeted wordlists** (e.g., known users, leaked password databases).
- Rotate IPs to avoid detection/rate-limiting (tools like **ProxyChains**).
- Automate using tools such as **Hydra**, **Medusa**, or **Burp Suite Intruder**.

### **Common Brute Force Scenarios**
#### **1. Online Brute Force**
- Exploit poorly implemented protections (rate-limiting, lockout, CAPTCHA).
- Example: Weak admin login page.
  
#### **2. Offline Brute Force**
- Attack hashed or encrypted password files (dumped credentials).
- Tools: **John the Ripper**, **Hashcat**.

---

### **Tools and Usage**

#### **Hydra**
```bash
hydra -L usernames.txt -P passwords.txt <protocol>://<target> -V
# Example: HTTP Basic Authentication
hydra -L users.txt -P passwords.txt http-get://example.com/login
```

#### **Burp Suite**
- Load the login request into **Intruder**.
- Set payload positions (e.g., username and password fields).
- Use **payloads** for brute-forcing.
- Monitor responses (e.g., status codes, error messages).

#### **Medusa**
```bash
medusa -h <host> -U usernames.txt -P passwords.txt -M http -m DIR:/login
```

#### **Nmap**
```bash
nmap --script http-brute -p 80 <target>
```

---

## 🚩 **Defensive Measures to Test For**
- Rate-limiting:
  - Is there a limit on login attempts? (e.g., IP bans or CAPTCHA after 5 attempts).
- Account lockout:
  - Does the account get locked after repeated failed attempts?
- Strong password policies:
  - Are users required to use long, complex passwords?
- MFA (Multi-Factor Authentication):
  - Test for bypass techniques (e.g., brute-forcing backup codes).
- Session Management:
  - Look for weak JWTs or exposed session IDs.

---

## 🔨 **Sample Attack Scenarios**

### **Attack 1: Brute Forcing Login**
1. Monitor login requests:
   - Username: `admin`
   - Password: `password123`
   - POST Data:
     ```http
     POST /login HTTP/1.1
     Host: example.com
     Content-Type: application/x-www-form-urlencoded

     username=admin&password=password123
     ```
2. Automate password guessing:
   ```bash
   hydra -l admin -P common-passwords.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid password"
   ```

### **Attack 2: User Enumeration**
- Input a valid username and invalid password:
  ```http
  POST /login HTTP/1.1
  Host: example.com

  username=johndoe&password=wrongpassword
  ```
- Analyze the error message:
  - If different from invalid user error, the account exists.

---

## 🛠 **Sample Tools**

| **Tool**       | **Purpose**                         |
|-----------------|-------------------------------------|
| `Hydra`         | Online brute-forcing authentication. |
| `Burp Suite`    | Manual and automated enumeration.  |
| `Medusa`        | Parallel brute-forcing across services. |
| `CeWL`          | Create custom wordlists for targeted attacks. |
| `Gobuster`      | Directory brute-forcing endpoints. |

---

## ⚠️ **Ethical Considerations**
- Only test on systems you have explicit permission to test.
- Avoid disrupting services or violating user privacy.
- Follow responsible disclosure processes for discovered vulnerabilities.
