Password attacks aim to compromise authentication mechanisms, allowing unauthorized access to systems. This guide provides an introduction to password profiling, attack techniques, and online attack methods, along with best practices for securing passwords.

---

### **1. What is a Password?**

- **Definition**: A string of characters used to authenticate users to systems, applications, or devices.
- **Components**:
    - Letters (uppercase and lowercase).
    - Numbers.
    - Symbols (`!@#$%^&*`).
- **Strong Passwords**:
    - At least 8 characters (preferably more).
    - A mix of letters, numbers, and symbols.
    - Avoid common phrases, dictionary words, or predictable patterns.

---

### **2. Password Profiling**

Password profiling involves creating custom password lists tailored to a specific target.

### **a. Techniques**

- **Information Gathering**:
    - Collect data about the target (names, birthdays, hobbies, pets, etc.).
    - Sources: Social media, leaked databases, corporate websites.
- **Profiling Tools**:
    - **CUPP (Common User Password Profiler)**:
        
        ```bash
        cupp -i
        
        ```
        
        - Interactive mode to input details and generate a wordlist.
    - **Mentalist**: GUI tool for crafting wordlists based on patterns.

### **b. Enhancing Wordlists**

- Combine basic profiles with permutations:
    - Add numbers, special characters, or dates.
    - Use tools like **Crunch**:
        
        ```bash
        crunch 8 12 abcdefgh -o wordlist.txt
        
        ```
        

---

### **3. Types of Password Attacks**

### **a. Brute Force**

- Exhaustive trial of all possible combinations.
- Tools: **Hydra**, **Medusa**, **John the Ripper**.
- **Example**:
    
    ```bash
    hydra -l admin -P wordlist.txt ssh://192.168.1.100
    
    ```
    

### **b. Dictionary Attack**

- Uses a predefined list of passwords (dictionary or wordlist).
- Tools: **Hashcat**, **John the Ripper**.
- Example with John:
    
    ```bash
    john --wordlist=wordlist.txt hash.txt
    
    ```
    

### **c. Hybrid Attack**

- Combines dictionary words with mutations (e.g., appending numbers, symbols).
- Example with Hashcat:
    
    ```bash
    hashcat -a 6 -m 0 hashes.txt dictionary.txt ?d?d
    
    ```
    

### **d. Rainbow Table Attack**

- Uses precomputed hash tables to crack passwords.
- Tools: **RainbowCrack**.

### **e. Credential Stuffing**

- Reuses credentials from data breaches against other services.
- Tools: **SentryMBA**, **STORM**.

### **f. Password Spraying**

- Tests a single password across multiple accounts to avoid lockout.
- Tools: **CrackMapExec**:
    
    ```bash
    crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123!'
    
    ```
    

### **g. Online vs. Offline Attacks**

- **Online**:
    - Directly interacts with the target service.
    - Example: SSH brute-forcing.
- **Offline**:
    - Cracks hashed passwords obtained from database breaches or dumps.

---

### **4. Online Password Attacks**

### **a. Enumeration Techniques**

- Before attacking, enumerate usernames or email addresses:
    - Email verification tools.
    - Username enumeration via error messages on login pages.

### **b. Tools**

1. **Hydra**:
    - Supports many protocols (SSH, HTTP, FTP, etc.).
    
    ```bash
    hydra -L users.txt -P passwords.txt <ftp://192.168.1.1>
    
    ```
    
2. **Medusa**:
    - Highly parallel brute-forcing tool.
    
    ```bash
    medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh
    
    ```
    
3. **Burp Suite** (For HTTP/HTTPS):
    - Use Intruder to automate brute-forcing.
    - Example: Login forms with custom payloads.

---

### **5. Generating Custom Wordlists**

### **a. Prebuilt Wordlists**

- Popular options:
    - **rockyou.txt**: Large list of common passwords (default in Kali Linux).
    - **SecLists**: Comprehensive repository of wordlists.
    
    ```bash
    git clone <https://github.com/danielmiessler/SecLists.git>
    
    ```
    

### **b. Custom Wordlist Tools**

- **CUPP**: Automates wordlist generation.
- **Mentalist**: GUI for creating patterns.

### **c. Markov Chains**

- Tools like **John the Ripper** use probabilistic techniques to generate likely passwords based on patterns:
    
    ```bash
    john --incremental hash.txt
    
    ```
    

---

### **6. Hash Cracking**

### **a. Understanding Password Hashes**

- Common algorithms: MD5, SHA1, SHA256, bcrypt.
- Example hash: `$6$wExAhdRQ$ZcBMQiTPa/j5EYl8.Zgmh6ywgJcfKw6vK7GpZKw7uMg/7A2Q.SGg`.

### **b. Cracking Tools**

1. **Hashcat**:
    - GPU-accelerated password cracking.
    
    ```bash
    hashcat -m 0 hashes.txt wordlist.txt
    
    ```
    
2. **John the Ripper**:
    - Versatile cracking tool with advanced modes.
    
    ```bash
    john hash.txt --wordlist=rockyou.txt
    
    ```
    

### **c. Salts**

- Salts add randomness to hashes, making precomputed attacks harder.
- Example:
    - Original Password: `password123`.
    - Salted Hash: `salt + password123`.

---

### **7. Defense Against Password Attacks**

### **a. Strong Password Policy**

- Minimum 12 characters, mixed case, numbers, and symbols.
- Prohibit common and breached passwords.

### **b. Multi-Factor Authentication (MFA)**

- Adds an extra layer of security (e.g., OTP, biometrics).

### **c. Account Lockout**

- Temporarily lock accounts after multiple failed login attempts.

### **d. Hashing Best Practices**

- Use strong algorithms (e.g., bcrypt, Argon2).
- Add random salts to every password.

### **e. Monitor and Respond**

- Monitor logs for brute-forcing or spraying attempts.
- Respond with automated IP blocking or CAPTCHA.

---

### **8. Example Workflow for a Password Attack**

1. **Gather Information**:
    - Extract potential usernames/emails.
    - Identify services to target (e.g., SSH, RDP, HTTP login).
2. **Generate Wordlists**:
    - Use tools like CUPP or Mentalist.
    - Enhance with common wordlists (e.g., rockyou.txt).
3. **Attack**:
    - Test passwords with Hydra or Burp Suite.
    - Crack offline hashes using Hashcat or John.
4. **Analyze Results**:
    - Verify cracked passwords.
    - Assess impact and document findings.

---

### **9. Tools Comparison**

| Tool | Purpose | Strengths |
| --- | --- | --- |
| **Hydra** | Online brute-forcing | Protocol versatility |
| **John the Ripper** | Offline hash cracking | Custom modes, flexibility |
| **Hashcat** | GPU-based hash cracking | High performance |
| **CUPP** | Password profiling | Target-specific wordlists |
| **Mentalist** | Wordlist creation | Pattern-based generation |

---

### **10. Tips for Ethical Password Testing**

- **Authorization**: Ensure explicit permission before testing.
- **Rate Limiting**: Avoid overwhelming systems; stay within acceptable limits.
- **Documentation**: Record all findings and methods for reporting.
