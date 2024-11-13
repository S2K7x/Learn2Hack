# Cryptography Cheat Sheets 🔐

### Purpose
These cheat sheets cover SSL/TLS configuration and testing, PGP/GPG commands for secure message encryption, and certificate management techniques, including OpenSSL and Java Keystore management. Ideal for security engineers, developers, and network administrators.

---

## 📖 Table of Contents

1. [SSL/TLS Configuration Cheat Sheet](#ssl-tls-configuration-cheat-sheet)
2. [PGP/GPG Cheat Sheet](#pgp-gpg-cheat-sheet)
3. [Certificate Management Cheat Sheet](#certificate-management-cheat-sheet)

---

## 1. SSL/TLS Configuration Cheat Sheet

### 🔑 Command Examples for Setting Up and Testing TLS

1. **Generate a Private Key**:
   ```bash
   openssl genpkey -algorithm RSA -out private.key -aes256  # Generates an encrypted RSA private key
   ```

2. **Generate a Certificate Signing Request (CSR)**:
   - This CSR is sent to a Certificate Authority (CA) to obtain a signed certificate.
   ```bash
   openssl req -new -key private.key -out request.csr
   ```

3. **Generate a Self-Signed Certificate**:
   ```bash
   openssl req -x509 -new -nodes -key private.key -sha256 -days 365 -out certificate.crt
   ```

4. **Test SSL/TLS Connection with `openssl`**:
   ```bash
   openssl s_client -connect <domain>:443
   ```
   - Add `-showcerts` to view all certificates in the chain, and `-tls1_2` to specify a specific TLS version.

5. **TLS Cipher Suite Testing**:
   - Test the ciphers supported by a server.
   ```bash
   openssl s_client -connect <domain>:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'
   ```

6. **SSL/TLS Scan with `sslyze`**:
   ```bash
   sslyze --regular <domain>
   ```
   - `sslyze` performs a deep SSL/TLS scan, testing for vulnerabilities like weak ciphers, SSLv3, and more.

### 🌐 Best Practices for HTTPS Configuration

1. **Use Strong Cipher Suites**:
   - Avoid older and weaker ciphers like `DES` and `RC4`.
   - Preferred Ciphers: `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`.

2. **Enable Perfect Forward Secrecy (PFS)**:
   - Prioritize cipher suites that use `ECDHE` (Elliptic Curve Diffie-Hellman) for key exchange.

3. **Set HSTS (HTTP Strict Transport Security)**:
   - Enforce HTTPS by adding this header:
     ```http
     Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
     ```

4. **Disable SSL and Older TLS Versions**:
   - Only enable TLSv1.2 and TLSv1.3, and disable SSLv2, SSLv3, and TLSv1.0/1.1 in server configuration.

5. **Enable OCSP Stapling**:
   - Reduces latency by allowing the server to provide certificate revocation status directly to clients.

---

## 2. PGP/GPG Cheat Sheet

### 🔐 Commands for Key Generation, Encryption, and Decryption

1. **Generate a New GPG Key Pair**:
   ```bash
   gpg --gen-key
   ```
   - Follow prompts to set key type, size (2048-bit or larger), and expiration.

2. **List Existing GPG Keys**:
   - **Public Keys**:
     ```bash
     gpg --list-keys
     ```
   - **Private Keys**:
     ```bash
     gpg --list-secret-keys
     ```

3. **Export and Import GPG Keys**:
   - **Export Public Key**:
     ```bash
     gpg --export -a <email> > public.key
     ```
   - **Export Private Key**:
     ```bash
     gpg --export-secret-key -a <email> > private.key
     ```
   - **Import a Key**:
     ```bash
     gpg --import <path_to_key>
     ```

4. **Encrypt a File**:
   - Encrypt a file for a specific recipient.
   ```bash
   gpg --output encrypted_file.gpg --encrypt --recipient <email> file.txt
   ```

5. **Decrypt a File**:
   - Decrypts a file and outputs the result to a specified file.
   ```bash
   gpg --output decrypted_file.txt --decrypt encrypted_file.gpg
   ```

6. **Sign and Verify Files**:
   - **Sign a File**:
     ```bash
     gpg --output file.sig --sign file.txt
     ```
   - **Verify a Signature**:
     ```bash
     gpg --verify file.sig file.txt
     ```

7. **Clearsign a Text File**:
   - Creates a plain text signature (useful for signing emails).
   ```bash
   gpg --clearsign file.txt
   ```

---

## 3. Certificate Management Cheat Sheet

### 🔑 Commands for Certificate Management with OpenSSL

1. **Generate a Private Key**:
   ```bash
   openssl genpkey -algorithm RSA -out private.key -aes256
   ```

2. **Create a CSR (Certificate Signing Request)**:
   - Required for obtaining a certificate from a CA.
   ```bash
   openssl req -new -key private.key -out request.csr
   ```

3. **Generate a Self-Signed Certificate**:
   - Useful for internal or testing purposes.
   ```bash
   openssl req -x509 -key private.key -in request.csr -out certificate.crt -days 365
   ```

4. **Convert Certificate Formats**:
   - **Convert PEM to DER**:
     ```bash
     openssl x509 -outform der -in certificate.pem -out certificate.der
     ```
   - **Convert PEM to PKCS#12 (for importing to Windows)**:
     ```bash
     openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.pem
     ```

5. **View Certificate Details**:
   - **View Contents of a PEM Certificate**:
     ```bash
     openssl x509 -in certificate.pem -text -noout
     ```
   - **Check a Certificate and Private Key Match**:
     ```bash
     openssl x509 -noout -modulus -in certificate.crt | openssl md5
     openssl rsa -noout -modulus -in private.key | openssl md5
     ```

### 🛠 Commands for Java Keystore (JKS) Management with `keytool`

1. **Generate a Key Pair**:
   - **Self-Signed Certificate**:
     ```bash
     keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -validity 365 -keystore keystore.jks
     ```

2. **Create a CSR**:
   - Generate a CSR for the key in a keystore.
   ```bash
   keytool -certreq -alias mykey -keystore keystore.jks -file request.csr
   ```

3. **Import a Certificate**:
   - **Import a Signed Certificate** into the keystore.
   ```bash
   keytool -import -trustcacerts -alias mykey -file certificate.crt -keystore keystore.jks
   ```

4. **List Certificates in a Keystore**:
   - View all entries in a Java Keystore.
   ```bash
   keytool -list -keystore keystore.jks
   ```

5. **Export a Certificate from a Keystore**:
   - Export the public certificate associated with an alias.
   ```bash
   keytool -exportcert -alias mykey -keystore keystore.jks -file exported_certificate.crt
   ```

6. **Delete an Entry from a Keystore**:
   ```bash
   keytool -delete -alias mykey -keystore keystore.jks
   ```

---

### 📘 Resources

- **OpenSSL Documentation**: [OpenSSL Manual](https://www.openssl.org/docs/)
- **GPG Manual**: [GNU Privacy Guard](https://gnupg.org/documentation/)
- **Java Keytool Documentation**: [Oracle Java Keytool Guide](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html)
- **SSL Labs SSL Test**: [SSL Labs](https://www.ssllabs.com/ssltest/) - Free SSL configuration and vulnerability scanner for public websites.
