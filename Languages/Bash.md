# Bash Scripting and Command Line Cheat Sheet

This cheat sheet covers essential commands, scripting basics, automation techniques, and best practices for tasks commonly used in system administration, automation, and penetration testing.

---

## 1. Basic Command Line Operations

| Command                        | Description                                |
|---------------------------------|--------------------------------------------|
| `pwd`                           | Print the current working directory.       |
| `ls`                            | List files and directories (-la for detailed view). |
| `cd <directory>`                | Change directory.                          |
| `cp <source> <destination>`     | Copy files or directories (-r for recursive). |
| `mv <source> <destination>`     | Move or rename files/directories.          |
| `rm <file>`                     | Remove files (-r for directories).        |
| `cat <file>`                    | Display the contents of a file.            |
| `less <file>`                   | View file contents with pagination.        |
| `head -n <number> <file>`       | Display the first N lines of a file.       |
| `tail -n <number> <file>`       | Display the last N lines of a file.        |
| `find <directory> -name <filename>` | Search for files by name.               |
| `grep '<pattern>' <file>`       | Search for a pattern in a file.            |
| `chmod <permissions> <file>`    | Change file permissions (e.g., `chmod 755 file`). |
| `chown <user>:<group> <file>`   | Change file ownership.                     |
| `echo "text"`                   | Print text to the terminal.                |
| `date`                          | Display current date and time.             |

---

## 2. File Manipulation

### Text Manipulation Commands

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `grep 'pattern' <file>`          | Search for a specific pattern in a file.  |
| `sed 's/old/new/g' <file>`       | Replace all occurrences of “old” with “new” in a file. |
| `awk '{print $1}' <file>`        | Print specific columns of text (e.g., first column). |
| `sort <file>`                    | Sort lines in a file.                     |
| `uniq`                           | Filter out duplicate lines in a file.     |
| `cut -d '<delimiter>' -f <field>` | Extract specific fields from a file.     |
| `tr 'a-z' 'A-Z'`                 | Translate lowercase to uppercase.        |

### File Compression and Archiving

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `tar -cvf archive.tar <files>`   | Create a `.tar` archive.                  |
| `tar -xvf archive.tar`           | Extract a `.tar` archive.                |
| `gzip <file>`                    | Compress a file with gzip.                |
| `gunzip <file>.gz`               | Decompress a `.gz` file.                  |
| `zip archive.zip <files>`        | Create a `.zip` archive.                  |
| `unzip archive.zip`              | Extract files from a `.zip` archive.     |

---

## 3. Network Commands

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `ping <host>`                    | Test connectivity to a host.              |
| `ifconfig` or `ip addr`          | Display network interface configuration.  |
| `traceroute <host>`              | Trace the route to a host.                |
| `nslookup <domain>`              | DNS lookup for a domain.                 |
| `netstat -tuln`                  | List network connections and listening ports. |
| `curl <URL>`                     | Fetch data from a URL.                   |
| `wget <URL>`                     | Download files from a URL.               |
| `ssh <user>@<host>`              | SSH into a remote machine.                |
| `scp <source> <user>@<host>:<destination>` | Secure copy files to/from a remote machine. |

---

## 4. Process Management

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `ps aux`                         | Display a list of running processes.      |
| `top`                            | View real-time system resource usage.     |
| `htop`                           | Interactive process viewer (requires installation). |
| `kill <PID>`                     | Terminate a process by its PID.           |
| `killall <process_name>`         | Terminate all processes with the given name. |
| `pkill <process_name>`           | Kill processes by name (similar to `killall`). |
| `jobs`                           | List background jobs in the current session. |
| `bg <job_id>`                    | Move a job to the background.             |
| `fg <job_id>`                    | Bring a background job to the foreground. |
| `nohup <command> &`              | Run a command in the background, immune to hangups. |

---

## 5. Scripting Basics

### Variables

Define variables without spaces around the equals sign.

```bash
name="John Doe"
echo "Hello, $name!"
```

### Conditionals

```bash
if [ "$var" == "value" ]; then
    echo "Match"
else
    echo "No match"
fi
```

### Loops

**For Loop:**

```bash
for i in {1..5}; do
    echo "Number $i"
done
```

**While Loop:**

```bash
count=1
while [ $count -le 5 ]; do
    echo "Count is $count"
    ((count++))
done
```

### Functions

Define reusable code blocks with functions.

```bash
function greet {
    echo "Hello, $1!"
}
greet "Alice"
```

### Reading User Input

```bash
echo "Enter your name:"
read name
echo "Hello, $name"
```

### Exit Codes

Every command in Bash returns an exit code (0 for success, non-zero for failure).

```bash
echo "Hello"
echo $?  # Prints the exit code of the last command
```

---

## 6. File and Directory Tests

Bash provides options for testing file types and properties.

| Test                              | Description                                 |
|-----------------------------------|---------------------------------------------|
| `[ -f <file> ]`                   | True if the file exists and is a regular file. |
| `[ -d <directory> ]`              | True if the directory exists.               |
| `[ -e <file_or_directory> ]`      | True if the file or directory exists.      |
| `[ -s <file> ]`                   | True if the file exists and is not empty.   |
| `[ -r <file> ]`                   | True if the file exists and is readable.    |
| `[ -w <file> ]`                   | True if the file exists and is writable.    |
| `[ -x <file> ]`                   | True if the file exists and is executable.  |

Example:

```bash
if [ -f /etc/passwd ]; then
    echo "/etc/passwd exists"
fi
```

---

## 7. Regular Expressions and Pattern Matching

Use `grep`, `sed`, and `awk` for pattern matching and text processing.

### `grep` Examples

```bash
grep "pattern" file.txt         # Find lines matching "pattern" in file.txt
grep -i "pattern" file.txt      # Case-insensitive search
grep -r "pattern" /path         # Recursive search in directory
```

### `sed` Examples

```bash
sed 's/old/new/g' file.txt      # Replace "old" with "new" in file.txt
sed -n '2,5p' file.txt          # Print lines 2 to 5
```

### `awk` Examples

```bash
awk '{print $1, $3}' file.txt   # Print the first and third columns
awk '/pattern/ {print $0}' file.txt  # Print lines containing "pattern"
```

---

## 8. System Information

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `uname -a`                       | Display system information.               |
| `df -h`                          | Show filesystem disk usage.               |
| `du -sh <directory>`             | Display the size of a directory.          |
| `free -h`                        | Show memory usage.                        |
| `top`                            | Display real-time resource usage.         |
| `uptime`                         | Show system uptime.                       |
| `whoami`                         | Display the current username.             |
| `history`                        | Show command history.                     |

---

## 9. Networking Utilities

| Command                         | Description                               |
|----------------------------------|-------------------------------------------|
| `ifconfig` or `ip addr`          | Display network interfaces and IP addresses. |
| `netstat -tulnp`                 | Show listening ports and associated programs. |
| `ping <host>`                    | Check connectivity to a host.             |
| `traceroute <host>`              | Trace the route to a host.                |
| `dig <domain>`                   | DNS lookup for a domain.                 |
| `curl -I <URL>`                  | Fetch HTTP headers from a URL.            |

---

## 10. Automation and Task Scheduling with Cron

### Cron Jobs

Cron jobs are scheduled tasks in Unix-based systems. Edit the crontab file with:

```bash
cr

ontab -e
```

### Cron Syntax

```
* * * * * <command>
| | | | |
| | | | ----- Day of week (0 - 7) (Sunday = 0 or 7)
| | | ----- Month (1 - 12)
| | ----- Day of month (1 - 31)
| ----- Hour (0 - 23)
----- Minute (0 - 59)
```
