# JWT Security : Understanding and Securing JSON Web Tokens

JSON Web Tokens (JWTs) are widely used for authentication, authorization, and information exchange in modern web applications. While JWTs are efficient and versatile, improper implementation can lead to severe security vulnerabilities.

---

## 🔑 **What is a JWT?**

### **Structure**
JWTs are compact, URL-safe tokens consisting of three parts:
1. **Header**:
   - Specifies the token type (`JWT`) and signing algorithm (e.g., `HS256`, `RS256`).
   ```json
   {
       "alg": "HS256",
       "typ": "JWT"
   }
   ```
2. **Payload**:
   - Contains the claims (data). Examples:
     - `iss` (issuer), `sub` (subject), `exp` (expiration), `iat` (issued at), `aud` (audience).
   ```json
   {
       "sub": "1234567890",
       "name": "John Doe",
       "admin": true
   }
   ```
3. **Signature**:
   - Ensures the integrity and authenticity of the token. It's calculated as:
     ```
     HMACSHA256(
       base64UrlEncode(header) + "." + base64UrlEncode(payload),
       secret
     )
     ```

### **Example JWT**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

---

## 🚀 **Where JWTs Are Used**

1. **Authentication**:
   - Used as access tokens to verify user identity (e.g., OAuth2 flows).
   - Example: Bearer tokens in `Authorization` headers.
   ```http
   Authorization: Bearer <JWT>
   ```

2. **Authorization**:
   - Used to define and enforce access control policies.

3. **Session Management**:
   - Replaces traditional server-side sessions by storing user state client-side.

4. **Information Exchange**:
   - Encodes and transmits claims securely between parties.

---

## 🛠️ **Common JWT Vulnerabilities**

### 1. **Lack of Signature Validation**
- **Issue**: Applications fail to validate JWT signatures properly.
- **Example Attack**: Send a token with a manipulated payload.
  ```bash
  # Original Token
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  # Forged Token (role=admin)
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  ```

#### **Mitigation**:
- Always verify JWT signatures using the correct algorithm and secret key.

---

### 2. **None Algorithm Attack**
- **Issue**: Some libraries allow the `alg` field to be set to `none`, disabling signature validation.
- **Example Attack**:
  ```bash
  # Set "alg" to "none" in the header
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
  ```
  - Forge payload without a valid signature.

#### **Mitigation**:
- Explicitly block or reject the `none` algorithm on the server.
- Ensure the `alg` value is enforced as expected (`HS256`, `RS256`, etc.).

---

### 3. **Weak Secret Key**
- **Issue**: Using short, predictable, or hardcoded secrets for HMAC-based JWTs.
- **Example Attack**:
  - Brute force the secret using tools like **jwt-cracker** or **John the Ripper**.

#### **Mitigation**:
- Use long, randomly generated keys for HMAC algorithms.
- Rotate keys periodically and revoke compromised tokens.

---

### 4. **Key Confusion in RS256 and HS256**
- **Issue**: Confusion between HMAC (symmetric) and RSA (asymmetric) algorithms.
- **Example Attack**:
  - Submit a token using `HS256` instead of `RS256` with the public key as the secret.
  - If the server incorrectly uses the public key for HMAC verification, the signature is valid.

#### **Mitigation**:
- Validate the `alg` field and enforce the correct signing algorithm.
- Avoid accepting public keys as secrets for symmetric algorithms.

---

### 5. **Token Replay**
- **Issue**: JWTs, once issued, can be reused until they expire.
- **Example Attack**:
  - An attacker intercepts a valid JWT and replays it later to impersonate the user.

#### **Mitigation**:
- Implement token revocation lists or short expiration times (`exp` claim).
- Combine JWTs with other security measures like device IDs or IP verification.

---

### 6. **Exposed Tokens**
- **Issue**: Tokens stored in insecure locations (e.g., localStorage or URLs).
- **Example Attack**:
  - An attacker accesses stored tokens via XSS or intercepts tokens in URLs.

#### **Mitigation**:
- Store tokens in **HttpOnly** cookies instead of localStorage.
- Avoid including tokens in URLs or query strings.

---

### 7. **Missing Claims Validation**
- **Issue**: Applications fail to validate critical claims (e.g., `iss`, `exp`, `aud`).
- **Example Attack**:
  - Use a token issued for a different service (`aud` mismatch).
  - Use expired tokens (`exp` bypass).

#### **Mitigation**:
- Validate all relevant claims:
  - `exp`: Ensure the token has not expired.
  - `aud`: Confirm the audience matches the intended application.
  - `iss`: Verify the token was issued by a trusted source.

---

## 🛡️ **Best Practices for JWT Security**

### **Token Construction**
1. Use strong, modern algorithms:
   - Prefer `RS256` (asymmetric) over `HS256` (symmetric) for better security.
2. Generate secure secrets for HMAC and private keys for RSA.
3. Rotate secrets and keys periodically.

### **Token Storage**
1. Store tokens securely:
   - Use **HttpOnly** and **Secure** flags for cookies.
   - Avoid storing tokens in `localStorage` or `sessionStorage` to prevent XSS.
2. Never expose tokens in URLs or query parameters.

### **Token Lifecycle**
1. Enforce short-lived tokens with the `exp` claim.
2. Use refresh tokens to issue new access tokens when necessary.
3. Invalidate tokens upon logout or server-side revocation.

### **Token Validation**
1. Validate the `alg` field and enforce the expected signing algorithm.
2. Verify critical claims (`iss`, `aud`, `exp`, etc.).
3. Use token introspection (e.g., via OAuth2) for additional checks.

### **Logging and Monitoring**
1. Log suspicious token usage, such as:
   - Tokens used from different IPs or devices.
   - Repeated use of expired tokens.
2. Monitor for brute force attacks on token secrets.

---

## 🔧 **Tools for JWT Security**

| **Tool**           | **Purpose**                                       |
|---------------------|---------------------------------------------------|
| **jwt.io**          | Decode and inspect JWTs.                         |
| **jwt-tool**        | Test JWT vulnerabilities (`none`, key confusion). |
| **Burp Suite**      | Manipulate and replay JWTs.                       |
| **JOSEPH**          | Test JWT signing and validation flaws.            |
| **jwt-cracker**     | Brute force weak secrets for HMAC-signed tokens.  |

---

## 🔨 **Example of Secure JWT Handling**

### **Token Creation (Node.js)**
```javascript
const jwt = require('jsonwebtoken');

const payload = { sub: "1234567890", name: "John Doe", admin: true };
const secret = process.env.JWT_SECRET;

const token = jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "1h" });
console.log(token);
```

### **Token Verification (Node.js)**
```javascript
const jwt = require('jsonwebtoken');

const token = "eyJhbGciOiJIUzI1NiIsInR...";
const secret = process.env.JWT_SECRET;

try {
    const decoded = jwt.verify(token, secret);
    console.log(decoded);
} catch (err) {
    console.error("Token validation failed:", err.message);
}
```
