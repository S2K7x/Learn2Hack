# Python Cheat Sheet for Developers and Security Researchers

A comprehensive Python cheat sheet covering fundamental concepts, useful modules, and security practices. This guide is ideal for general development, scripting, automation, data analysis, and security-focused tasks.

---

## 1. Python Basics

### Syntax

| **Syntax**                     | **Description**                                          |
|---------------------------------|----------------------------------------------------------|
| `print("Hello, World!")`        | Display output to the console.                           |
| `# This is a comment`           | Commenting (ignored by Python).                          |
| `variable_name = value`         | Variable assignment.                                     |
| `type(variable_name)`           | Get the data type of a variable.                         |
| `len(string_or_list)`           | Get length of a string or list.                          |
| `input("Enter value: ")`        | Get user input from console.                             |

### Basic Data Types

| **Data Type**  | **Example**          |
|----------------|----------------------|
| Integer        | `num = 10`           |
| Float          | `num = 10.5`         |
| String         | `text = "Hello"`     |
| Boolean        | `flag = True`        |
| List           | `items = [1, 2, 3]`  |
| Dictionary     | `data = {"key": "value"}` |

---

## 2. Control Flow

### Conditional Statements

```python
if condition:
    # Code to execute if condition is true
elif another_condition:
    # Code for another condition
else:
    # Code if all conditions are false
```

### Loops

| **Loop**      | **Example**                                            |
|---------------|--------------------------------------------------------|
| For loop      | `for item in iterable:`<br> `# Code to execute`       |
| While loop    | `while condition:`<br> `# Code to execute`            |

#### Example:

```python
# For loop example
for i in range(5):
    print(i)

# While loop example
i = 0
while i < 5:
    print(i)
    i += 1
```

---

## 3. Functions

### Defining Functions

```python
def function_name(parameters):
    # Function code
    return result
```

#### Example:

```python
def add(a, b):
    return a + b

print(add(3, 4))  # Output: 7
```

### Lambda Functions

```python
# Anonymous functions useful for small, single-use functions
square = lambda x: x * x
print(square(5))  # Output: 25
```

---

## 4. Exception Handling

Handle errors gracefully with `try`, `except`, `finally`.

```python
try:
    # Code that may raise an exception
    result = 10 / 0
except ZeroDivisionError as e:
    print("Error:", e)
finally:
    print("This always runs")
```

---

## 5. Useful Modules and Libraries

### OS Module (System Operations)

| **Command**              | **Description**                                |
|--------------------------|------------------------------------------------|
| `import os`              | Import OS module.                             |
| `os.getcwd()`            | Get current working directory.                |
| `os.chdir('path')`       | Change directory.                              |
| `os.listdir('path')`     | List files and directories.                   |
| `os.mkdir('dir')`        | Create a new directory.                       |
| `os.remove('file')`      | Remove a file.                                |
| `os.system('command')`   | Execute a system command (caution: may have security risks). |

### Sys Module (System Information)

| **Command**              | **Description**                                |
|--------------------------|------------------------------------------------|
| `import sys`             | Import sys module.                            |
| `sys.argv`               | List of command-line arguments passed to script. |
| `sys.exit()`             | Exit the program.                              |
| `sys.platform`           | Get platform information.                     |
| `sys.version`            | Display Python version.                       |

### JSON Module (Data Parsing)

| **Command**              | **Description**                                |
|--------------------------|------------------------------------------------|
| `import json`            | Import JSON module.                           |
| `json.loads(json_string)`| Parse JSON string.                            |
| `json.dumps(dictionary)` | Convert dictionary to JSON string.            |
| `json.load(file_object)` | Read JSON data from a file.                   |
| `json.dump(data, file_object)` | Write JSON data to a file.               |

---

## 6. File I/O (Input/Output)

| **Operation**            | **Description**                                |
|--------------------------|------------------------------------------------|
| `open("file.txt", "r")`   | Open a file for reading.                      |
| `open("file.txt", "w")`   | Open a file for writing (creates or overwrites). |
| `open("file.txt", "a")`   | Open a file for appending.                    |
| `file.read()`             | Read the entire file.                         |
| `file.readline()`         | Read a single line.                           |
| `file.readlines()`        | Read all lines into a list.                   |
| `file.write("text")`      | Write text to file.                           |
| `file.close()`            | Close the file.                               |

#### Example:

```python
with open("file.txt", "w") as file:
    file.write("Hello, World!")
```

---

## 7. Regular Expressions (re Module)

Regular expressions are used for pattern matching and text processing.

```python
import re

# Match pattern
match = re.search(r"pattern", "string to search")

# Replace pattern
result = re.sub(r"pattern", "replacement", "string to search")

# Find all matches
matches = re.findall(r"pattern", "string to search")
```

#### Example:

```python
if re.match(r'\d+', '123abc'):
    print("Starts with digits")
```

---

## 8. Network Programming (sockets)

Python’s `socket` module allows for low-level network interactions.

```python
import socket

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a server
s.connect(("example.com", 80))

# Send data
s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

# Receive data
data = s.recv(1024)
print(data)

# Close the connection
s.close()
```

---

## 9. Data Encryption (cryptography Library)

Using `cryptography` library for encryption (install with `pip install cryptography`).

```python
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data
encrypted_data = cipher.encrypt(b"Sensitive data")

# Decrypt data
decrypted_data = cipher.decrypt(encrypted_data)
print(decrypted_data)
```

---

## 10. Python Security Practices

### 1. Avoid Command Injection
- Avoid using `os.system()` and subprocess calls with user input.
- Use `shlex.quote()` for sanitizing shell commands if needed.

### 2. Securely Handle Sensitive Data
- Avoid hardcoding sensitive data (e.g., passwords, API keys) in code.
- Use environment variables or a configuration management tool.

### 3. Validate User Input
- Use regex or specific validation functions to sanitize and validate user input, especially for web apps and API development.

### 4. Use Parameterized SQL Queries
- Avoid SQL injection by using parameterized queries with libraries like `sqlite3`, `psycopg2` for PostgreSQL.

#### Example of Parameterized Query:

```python
import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

## Summary

This cheat sheet provides a solid overview of Python essentials, from basic syntax and file operations to network programming and security practices. Whether you're working on general development or security-focused tasks, this guide serves as a quick reference for useful commands, modules, and secure coding practices.

Feel free to add this cheat sheet to your GitHub for easy access and ongoing learning.
```

### Key Features:
- **Headings and Subheadings:** The cheat sheet is divided into logical sections, making it easy to navigate.
- **Tables:** Tools and commands are presented in tables for better readability.
- **Code Blocks:** Python code snippets are displayed in clear code blocks for quick reference.
- **Examples:** Practical examples help illustrate each concept.
