# Exploiting Multi-Factor Authentication (MFA)

Multi-Factor Authentication (MFA) enhances security by requiring users to present multiple forms of verification (e.g., password + OTP). Despite its advantages, misconfigurations or flawed implementations can expose MFA to exploitation. This guide outlines common weaknesses in MFA systems and techniques for exploiting them.

---

## 🔑 **How MFA Works**

MFA requires two or more of the following factors for authentication:

1. **Something you know**: Password or PIN.
2. **Something you have**: One-time password (OTP), hardware token, or push notification.
3. **Something you are**: Biometric data (fingerprint, facial recognition).

---

## 🚩 **Common MFA Vulnerabilities**

### 1. **Bypassing MFA via Password Reset**
- **What it is**: Many systems allow password resets to bypass MFA entirely.
- **Exploitation**:
  1. Request a password reset on a victim's account.
  2. Reset the password without requiring MFA.
  3. Log in with the new password.

#### **Mitigation**:
- Enforce MFA during password reset workflows.
- Notify users via email/SMS about password reset requests.

---

### 2. **Exploiting Weak Backup Mechanisms**
- **What it is**: Backup or fallback options (e.g., security questions, recovery codes) are often less secure than MFA.
- **Exploitation**:
  - Social engineering to guess security question answers.
  - Obtain recovery codes via phishing or shoulder surfing.

#### **Mitigation**:
- Require MFA to access recovery options.
- Use stronger backup methods, such as secondary OTPs.

---

### 3. **Session Hijacking**
- **What it is**: Once MFA is completed, the session token is vulnerable to hijacking.
- **Exploitation**:
  - Intercept session cookies using MITM attacks or XSS.
  - Replay the stolen session cookie to bypass MFA.

#### **Mitigation**:
- Bind session tokens to user/device or IP.
- Use secure cookies (`HttpOnly`, `Secure`, `SameSite`).

---

### 4. **Brute Forcing OTPs**
- **What it is**: Exploiting weak or predictable OTPs to brute force authentication.
- **Exploitation**:
  - Exploit OTP systems with no rate-limiting.
  - Guess common 6-digit codes (e.g., 123456, 000000).

#### **Mitigation**:
- Implement rate-limiting for OTP input attempts.
- Use randomized, cryptographically secure OTPs.

---

### 5. **Exploiting Push Notification Fatigue**
- **What it is**: Spamming the victim with push notifications until they accidentally approve access.
- **Exploitation**:
  1. Flood the victim’s MFA app with login requests.
  2. Wait for the victim to approve the request out of frustration.

#### **Mitigation**:
- Limit failed MFA attempts per user.
- Notify users of unusual authentication attempts.

---

### 6. **Phishing MFA Credentials**
- **What it is**: Trick the user into providing both primary credentials and MFA codes.
- **Exploitation**:
  - Use a phishing page that mimics the login portal and requests an OTP.
  - Relay the credentials and OTP in real-time to log in.

#### **Mitigation**:
- Use phishing-resistant authentication (e.g., FIDO2).
- Educate users about phishing techniques.

---

### 7. **SIM Swapping**
- **What it is**: Attacker gains control of the victim's phone number to receive MFA codes.
- **Exploitation**:
  1. Social engineer the victim’s mobile carrier to port their number.
  2. Receive SMS-based OTPs meant for the victim.

#### **Mitigation**:
- Avoid SMS-based MFA; prefer app-based OTPs or hardware tokens.
- Use carrier PINs and alerts for SIM changes.

---

### 8. **Replay Attacks on OTPs**
- **What it is**: Reusing a valid OTP that has not yet expired.
- **Exploitation**:
  - Capture an OTP during a session and replay it before expiration.

#### **Mitigation**:
- Enforce single-use OTPs.
- Implement strict expiration for OTPs (e.g., <30 seconds).

---

### 9. **Biometric Spoofing**
- **What it is**: Exploiting flaws in biometric systems to spoof authentication.
- **Exploitation**:
  - Use high-resolution images or 3D-printed molds to replicate fingerprints or faces.

#### **Mitigation**:
- Use anti-spoofing mechanisms (e.g., liveness detection).
- Combine biometrics with another MFA factor.

---

## 🔧 **Tools and Techniques for MFA Exploitation**

| **Tool**             | **Purpose**                                              |
|-----------------------|----------------------------------------------------------|
| **Evilginx2**         | Phish credentials and bypass MFA using reverse proxies.  |
| **Modlishka**         | Real-time credential and OTP harvesting.                 |
| **Hydra**             | Brute force OTP inputs (if rate-limiting is absent).     |
| **MFA Fatigue Scripts** | Automate push notification spamming.                   |
| **Wireshark**         | Capture and analyze network traffic for OTP leakage.     |

---

## 🛡️ **Defensive Best Practices for MFA**

1. **Enforce Strong MFA Mechanisms**:
   - Use app-based OTPs (e.g., Google Authenticator, Authy) or hardware tokens (e.g., YubiKey).
   - Avoid SMS-based authentication due to SIM swap risks.

2. **Secure Backup Methods**:
   - Protect recovery codes and enforce MFA for account recovery.

3. **Rate-Limit and Monitor**:
   - Apply rate-limiting for failed login and OTP attempts.
   - Monitor for unusual authentication patterns (e.g., multiple MFA requests).

4. **Use Phishing-Resistant Authentication**:
   - Implement FIDO2 or WebAuthn protocols for strong MFA.

5. **Educate Users**:
   - Train users to recognize phishing attempts and suspicious activity.
   - Encourage reporting of unauthorized MFA requests.

---

## 🔨 **Example Exploits**

### **1. MFA Phishing with Evilginx2**
- Clone the target login page and proxy authentication requests:
  1. Deploy Evilginx2 and configure it for the target domain.
  2. Send the victim a phishing link.
  3. Harvest credentials and OTPs in real time.

### **2. OTP Brute Forcing**
- Script a brute-force attack on a vulnerable OTP system:
  ```bash
  hydra -l victim -P otp_list.txt -s 443 -f https-post-form \
  "/login:username=^USER^&otp=^PASS^:Invalid OTP"
  ```

### **3. Exploiting Push Fatigue**
- Spam push notifications using automation tools:
  ```bash
  while true; do
      curl -X POST -d "user=victim" https://target.com/mfa/push
  done
  ```

