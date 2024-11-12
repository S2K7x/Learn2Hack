### Stored XSS (Persistent XSS) Overview

Stored Cross-Site Scripting (XSS), or **Persistent XSS**, occurs when an attacker injects malicious scripts into a website's data storage (e.g., database, file system, or session storage), and these scripts are later executed when the data is rendered on a webpage. Unlike **Reflected XSS**, where the attack is only triggered by visiting a specially crafted URL, **Stored XSS** persists in the system and can affect all users who view the infected page.

### Key Differences Between Stored and Reflected XSS:

- **Reflected XSS**: The malicious input is reflected immediately in the response without being stored.
- **Stored XSS**: The malicious input is stored (typically in a database) and later displayed to users who view the affected page.

### Why Stored XSS is More Dangerous:
- It affects **multiple users** rather than just the attacker.
- The payload can be **persistent** until it is manually cleaned by an administrator or developer.
- Attackers can compromise a website’s **reputation** and **security** by injecting persistent malicious scripts that affect the whole user base.

---

### Step-by-Step Methodology for Finding Stored XSS

### 1. **Understand the Basics of Stored XSS**

In **Stored XSS**, malicious scripts are injected and stored in a data source like a database. When a user views content that contains this stored malicious script, it is executed in the context of their browser.

#### Example Scenario:

1. A user submits a comment on a blog.
2. The comment is stored in a database.
3. When another user views the comment, the stored script is executed because it is embedded in the webpage without proper sanitization or escaping.

#### Code Example:

```php
<form action="/post_comment" method="POST">
    <textarea name="comment"></textarea>
    <input type="submit" />
</form>

<!-- When rendering comments -->
<p><?php echo $comment; ?></p>
```

If the comment input is not sanitized, an attacker can inject the following malicious payload:

```html
<script>alert('Stored XSS')</script>
```

### 2. **Identify User-Input Fields that Get Stored**

Look for places where user-generated data is stored and later rendered back to users. Common examples include:

- **Comment sections**: Blogs, forums, and product reviews.
- **Message boards**: Post submissions, direct messages.
- **User profiles**: Username, status messages, and other inputs displayed publicly.
- **Feedback forms**: Contact forms, surveys, and other forms that users submit.

**Examples of potential targets:**
- A comment field on a blog.
- A user feedback form.
- Profile update forms.

### 3. **Inspect How User Input is Stored and Rendered**

Check where user input is stored and later rendered to ensure it's sanitized correctly. Pay attention to:

- **Form inputs**: Look for areas where user input is received, such as text boxes, textareas, and other fields.
- **Pages that display user input**: For example, when displaying comments or reviews, or when showing a user’s profile.

#### Example of user input handling:

```html
<form action="/submit_feedback" method="POST">
    <textarea name="feedback"></textarea>
    <input type="submit" value="Submit">
</form>

<!-- Rendering the feedback -->
<p>Feedback: <?php echo $feedback; ?></p>
```

If the `feedback` input is not sanitized, it may lead to a Stored XSS vulnerability.

### 4. **Inject Malicious Payloads into Input Fields**

To test for **Stored XSS**, inject various payloads into the user input fields and submit them. When the input is stored and later rendered, the payloads will trigger execution if not sanitized properly.

#### Basic Test Payloads:

- **Script tag payload**:

    ```html
    <script>alert('Stored XSS')</script>
    ```

- **Event handler-based payload**:

    ```html
    <img src="invalidimage" onerror="alert(1)">
    ```

- **SVG-based payload** (to bypass some filters):

    ```html
    <svg onload=alert(1)>
    ```

#### Test Steps:

1. Find an input field such as a comment box, profile form, or feedback form.
2. Inject the payload into the input field and submit the form.
3. Navigate to the page where the input is displayed (e.g., a comments section, profile page).
4. Observe whether the script executes (e.g., by displaying an alert box or inspecting the page source).

#### Example Payload for Stored XSS:

```html
<script>alert('XSS')</script>
```

### 5. **Observe the Output on the Page**

After submitting your payload, check the page where the data is rendered to see if the malicious script executes. 

#### Key Indicators of Stored XSS:

- **Script execution**: If the injected script is executed when the page loads (e.g., an alert box shows), you have identified a **Stored XSS** vulnerability.
- **Unsafe HTML output**: Check the HTML source or use browser developer tools to look for the injected payload in the rendered page.

#### Example of Unsafe Rendering:

```html
<p>Feedback: <script>alert(1)</script></p>
```

When viewed in the browser, this will trigger the JavaScript alert.

### 6. **Inspect Using Browser Developer Tools**

- **Open Developer Tools** (F12 or right-click -> Inspect) to check the page’s HTML source.
- In the **Elements** tab, look for the injected payload in the rendered HTML.
- In the **Console** tab, check for errors or any outputs that result from script execution.

**Network Tab**: Use this to check the response from the server. If the server returns unsanitized input, it indicates the vulnerability.

### 7. **Use Automated Tools to Aid in Detecting Stored XSS**

Automated tools can speed up the process of identifying stored XSS vulnerabilities. These tools can automatically inject payloads and check responses for unsafe behavior.

- **Burp Suite**: Use the **Intruder** or **Scanner** tools to test input fields for XSS.
- **OWASP ZAP**: Automatically scans web applications for security flaws, including XSS vulnerabilities.
- **XSStrike**: A specialized tool for detecting XSS by testing multiple payloads.

#### Burp Suite Testing:

1. Intercept a request that includes a form submission (e.g., a comment).
2. Send the request to **Intruder** and select the positions to inject the payloads.
3. Set a list of common XSS payloads.
4. Analyze the responses for any payloads that are reflected in the HTML without sanitization.

### 8. **Examine Common Storage Points for User Input**

**Stored XSS** usually happens when user data is stored and displayed back to the user. Common storage points include:

- **Databases**: Where data such as comments, posts, and reviews are stored.
- **File Systems**: Logs or other stored data.
- **Session Storage**: Data stored in the session that is rendered on a page.
- **Content Management Systems**: These systems often store user-generated content that might not be sanitized properly.

### 9. **Dangerous Functions to Watch for in Code**

Certain server-side functions may be dangerous if they do not properly sanitize user input:

- In **PHP**: Functions like `echo`, `print`, `printf`, and template rendering functions (e.g., `include()`, `require()`).
- In **Node.js**: Functions like `res.send()`, `res.render()`, or any template rendering functions that do not escape data properly.
- In other web frameworks: Be aware of rendering functions that directly output unsanitized data into HTML.

### 10. **Validate the Vulnerability**

Once you find a stored XSS vulnerability, validate it by:

1. Submitting the payload (e.g., `<script>alert(1)</script>`).
2. Ensuring it is stored and retrieved from the database or file.
3. Visiting the page that displays the input, and confirming that the payload is executed.

#### Testing with Advanced Payloads:

- **Testing for bypass**: Check if certain characters are blocked and try URL encoding or using different event handlers (e.g., `onload`, `onerror`).

---

### Example: Full Testing Process for Stored XSS

Let’s assume you have a blog with a comment section:

1. **Find the comment form**:

    ```html
    <form action="/submit_comment" method="POST">
        <textarea name="comment"></textarea>
        <input type="submit" value="Submit">
    </form>
    ```

2. **Inject a payload** (e.g., `<script>alert('XSS')</script>`).
3. **Submit the comment** and check the page where the comment is displayed.
4. **Observe whether the script executes**: If the payload is reflected and executed, it confirms a stored XSS vulnerability.

---

### Summary of Key Steps:

1. **Understand Stored XSS**: Malicious input is stored and executed when rendered to users.
2. **Identify input fields**: Focus on comment sections, user profiles, and any other stored user input.
3. **Inject payloads**: Use common XSS payloads and test for execution.
4. **Inspect output**: Check the HTML source and observe if the payload executes.
5. **Use automated tools**: Use Burp Suite, OWASP ZAP, or XSStrike for faster testing.
6. **Validate the vulnerability**: Confirm by viewing the page and checking for script execution.
