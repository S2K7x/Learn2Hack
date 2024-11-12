# DOM-Based XSS Cheat Sheet

**DOM-based XSS** occurs when a web page’s client-side JavaScript processes untrusted data (usually from the URL, cookies, or other user-controlled sources) and writes that data back into the DOM (Document Object Model) without proper sanitization or validation. This bypasses server-side protection mechanisms because the entire issue is contained in the client-side code (JavaScript).

## 1. Understanding the Basics of DOM XSS

### What is DOM?

The DOM is an object-oriented representation of the HTML on a web page. It allows JavaScript to dynamically interact with, manipulate, and modify the web page’s structure.

### Difference between Stored/Reflected and DOM XSS

- **Reflected and Stored XSS** involve server-side interaction.
- **DOM-based XSS** occurs entirely in the browser (client-side), making it more complex and harder to detect using traditional scanning tools.

### Example:

```html
<script>
    var input = location.hash;
    document.write(input);
</script>
```

In this example, `location.hash` (the URL fragment) is inserted into the DOM using `document.write()` without sanitization, leading to potential DOM XSS.

## 2. Understand User Input Entry Points in JavaScript

DOM-based XSS typically originates from data read from:

- `location` (URL parameters)
- `document.cookie` (cookies)
- `localStorage/sessionStorage` (browser storage)
- `window.name`
- `history` object
- HTML5 APIs such as `postMessage()`

An attacker can modify these sources to inject malicious data.

## 3. Inspect the Web Page's Client-Side JavaScript

Look at the JavaScript code running in the browser. Inspect for:

- Functions that read data from the URL, cookies, or other input points (e.g., `location.search`, `document.cookie`).
- Functions that write data back into the DOM, like:
    - `document.write()`
    - `innerHTML`
    - `outerHTML`
    - `eval()` (or similar functions like `setTimeout()` with code)
    - `appendChild()` or any DOM manipulation method

### Example of dangerous code:

```jsx
var userInput = location.search;
document.getElementById('output').innerHTML = userInput; // Potential DOM XSS
```

## 4. Analyze How Data is Handled in the DOM

Check how user-controlled data is processed:

- **No input validation/sanitization**: If the user input is directly inserted into the DOM without being filtered or sanitized.
- **Unsafe DOM APIs**: Functions like `document.write()`, `innerHTML`, `outerHTML`, or `eval()` are dangerous when they process user input.

## 5. Inject Malicious Payloads to Test the Vulnerability

Start by manipulating the URL parameters to inject potential XSS payloads. For example, if the page reads from `location.search` (query string), inject common payloads in the query string like:

- **Test Payload 1 (Simple alert)**:

    ```
    ?name=<script>alert(1)</script>
    ```

- **Test Payload 2 (Bypassing filters)**:

    ```
    ?name=<svg/onload=alert(1)>
    ```

### Steps to test:

1. Look for any part of the web page that interacts with URL parameters (e.g., URLs like `example.com?name=John`).
2. Append your payloads to the URL parameters or fragment (`#`) to see if the input is reflected directly in the page without proper encoding or sanitization.

### Example of URL testing:

```
http://example.com/page?input=><script>alert(1)</script>
```

## 6. Use Browser Developer Tools

Most browsers have built-in developer tools. Use the following features:

- **Inspect Element**: Right-click on the web page and select "Inspect". Look at the elements in the DOM to see if user inputs are placed unsafely in the HTML structure.
- **Console Tab**: Use the console to interact with the page’s JavaScript directly. You can manually test if inputs are processed safely.
- **Network Tab**: Monitor the network requests to see if any input gets processed client-side or server-side.

### Example:
In Chrome, open Developer Tools (F12 or right-click -> Inspect), and navigate to the **Console** tab. If you find suspicious code like `document.write(location.search)`, you can manipulate the URL parameters and see the direct impact in real-time.

## 7. Automated Tools to Help Detect DOM XSS

- **Burp Suite**: Use the **DOM Invader** extension (available in Burp Suite Pro or Burp Suite Community Edition with extensions). It can analyze web pages for DOM XSS.
- **XSStrike**: A command-line tool that can fuzz for DOM XSS by sending payloads into all potential vectors like URL fragments, cookies, etc.
- **Chrome DevTools Snippets**: Write custom scripts in the browser to scan the DOM for insecure JavaScript functions automatically.

### Sample Burp Suite test process:

1. Open Burp and intercept the web page traffic.
2. Analyze the web page’s structure and detect whether any reflected data from the URL is handled insecurely.
3. Use the DOM Invader extension to automatically find potential injection points.

## 8. Common Dangerous Functions and Safer Alternatives

### Dangerous functions:

- `document.write()`
- `innerHTML`
- `outerHTML`
- `eval()`
- `setTimeout()`/`setInterval()` with strings
- `window.location.href` (when used unsafely)
- `window.open()`

### Safer Alternatives:

- Use `textContent` or `innerText` instead of `innerHTML` to insert untrusted data.
- Avoid `eval()`, use `JSON.parse()` for JSON data.
- Instead of `document.write()`, use DOM manipulation methods like `createElement()` and append elements safely to the DOM.

## 9. Validating a Found Vulnerability

Once you believe you've found a vulnerability:

- Craft a **proof of concept (PoC)** payload that successfully executes a JavaScript function (such as `alert()`) when injected into the DOM.
- Check for edge cases where the application might be vulnerable only under certain conditions (like different browsers or specific input lengths).
- Ensure that your payload executes without any server-side involvement (since DOM XSS is purely client-side).

## Final Example: Full Testing Process

Let’s assume the following JavaScript code exists on a web page:

```html
<script>
   var name = location.search.split('name=')[1];
   document.getElementById('welcome').innerHTML = "Welcome " + name;
</script>
```

### Steps:

1. Look at how the `location.search` parameter is used (in this case, directly inserted into the DOM without sanitization).
2. Inject a payload like `?name=<script>alert(1)</script>` in the URL.
3. If the payload executes and the alert pops up, you’ve found a DOM-based XSS vulnerability.
```
