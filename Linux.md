# Kali Linux Cheat Sheet for Penetration Testers

## 1. Basic System Commands

| Command                  | Description                                             |
|--------------------------|---------------------------------------------------------|
| `uname -a`                | Display system information.                            |
| `cat /etc/os-release`     | Show OS release info (useful to confirm Kali version). |
| `whoami`                  | Show current user.                                     |
| `hostname`                | Show system’s hostname.                                |
| `uptime`                  | Display how long the system has been running.          |
| `history`                 | View command history (useful in pentests for auditing). |

### User Management
  - **Add a user**: `useradd <username> && passwd <username>`
  - **Switch user**: `su <username>`
  - **List sudoers**: `cat /etc/sudoers` or `sudo -l`
  - **Check current user privileges**: `id`

---

## 2. File System Navigation

| Command                             | Description                                      |
|-------------------------------------|--------------------------------------------------|
| `pwd`                               | Print current working directory.                |
| `ls`                                | List directory contents (use `-la` for detailed view). |
| `cd <directory>`                    | Change directory.                               |
| `cp <source> <destination>`         | Copy files or directories.                     |
| `mv <source> <destination>`         | Move or rename files/directories.               |
| `rm <file>`                         | Delete files (`-r` for directories).            |
| `find <directory> -name <file>`     | Search for files.                               |
| `locate <filename>`                 | Locate files (requires `updatedb` database).    |
| `du -sh <directory/file>`           | Display disk usage.                             |
| `df -h`                             | Show filesystem space.                          |
| `chmod <permissions> <file>`        | Change file permissions (e.g., `chmod 755 file`). |
| `chown <user>:<group> <file>`       | Change file owner/group.                        |

---

## 3. Text Manipulation

| Command                           | Description                                        |
|-----------------------------------|----------------------------------------------------|
| `cat <file>`                      | View file contents.                               |
| `less <file>`                     | Paginate through a file.                          |
| `head -n <number> <file>`         | Show the first lines of a file.                   |
| `tail -n <number> <file>`         | Show the last lines of a file.                    |
| `grep '<pattern>' <file>`         | Search for a pattern within a file.               |
| `cut -d '<delimiter>' -f <field>` | Cut specific fields from lines.                   |
| `awk '{print $1}'`                | Process text fields (e.g., print the first field).|
| `sed 's/<old>/<new>/g'`           | Stream editor for text substitution.              |
| `nano <file>`                     | Open a file in nano editor.                       |

---

## 4. Networking

| Command                            | Description                                             |
|------------------------------------|---------------------------------------------------------|
| `ifconfig`                         | Show or configure network interfaces.                   |
| `ip addr`                          | Display IP addresses of interfaces.                    |
| `ping <host>`                      | Test connectivity to a host.                           |
| `traceroute <host>`                | Trace the path packets take to a network host.         |
| `netstat -tulnp`                   | Display listening ports and services.                  |
| `ss -tulnp`                        | Newer alternative to `netstat` for socket stats.        |
| `nmap <IP>`                        | Network scanning with Nmap (variety of flags for intensity, `-A` for full scan). |
| `whois <domain>`                   | Fetch WHOIS information for a domain.                  |
| `dig <domain>`                     | DNS lookup.                                            |
| `curl -I <URL>`                    | Get HTTP headers from a URL.                           |
| `wget <URL>`                       | Download files from a URL.                            |
| `ftp <host>`                       | Connect to an FTP server.                             |
| `ssh <user>@<host>`                | SSH into a remote machine.                            |

---

## 5. Process Management

| Command                            | Description                                             |
|------------------------------------|---------------------------------------------------------|
| `ps aux`                           | List all running processes.                            |
| `top`                              | Interactive process viewer.                            |
| `htop`                             | Enhanced version of `top` (Kali comes with this by default). |
| `kill <PID>`                       | Terminate a process by PID.                            |
| `killall <process>`                | Kill all processes with a given name.                  |
| `pkill <process>`                  | Kill processes by name (similar to `killall`).         |
| `service <service> start/stop`     | Start or stop a service (e.g., `service apache2 start`). |
| `systemctl start/stop <service>`   | Control systemd services.                              |
| `journalctl -u <service>`          | View logs for a specific service.                      |

---

## 6. File Compression & Archiving

| Command                            | Description                                             |
|------------------------------------|---------------------------------------------------------|
| `tar -cf archive.tar <file(s)>`    | Create a `.tar` archive.                               |
| `tar -xf archive.tar`              | Extract a `.tar` archive.                              |
| `gzip <file>`                      | Compress a file with gzip.                             |
| `gunzip <file>.gz`                 | Decompress a `.gz` file.                               |
| `zip <archive.zip> <file(s)>`      | Compress files to `.zip` format.                       |
| `unzip <archive.zip>`              | Extract files from a `.zip` archive.                   |

---

## 7. Permissions & Ownership

| Command                            | Description                                             |
|------------------------------------|---------------------------------------------------------|
| `chmod <mode> <file>`              | Change file permissions (e.g., `chmod 755 file`).       |
| `chown <user>:<group> <file>`      | Change file ownership.                                 |
| `ls -l`                            | List file permissions and ownership.                   |

### Common Permission Modes:
  - `777`: Read, write, execute for all.
  - `755`: Full for owner, read/execute for others.
  - `644`: Owner read/write, others read-only.

---

## 8. Kali-Specific Tools & Commands

### Enumeration
  - **Nmap**: Network mapper for port scanning and network discovery.
    ```bash
    nmap -A -T4 <target>
    ```

  - **Recon-ng**: A full-featured web reconnaissance framework.
    ```bash
    recon-ng
    ```

### Web Exploitation
  - **Nikto**: Web server scanner.
    ```bash
    nikto -h <host>
    ```

  - **Burp Suite**: Proxy tool for web application testing.
    ```bash
    burpsuite
    ```

### Exploitation Frameworks
  - **Metasploit**: Popular exploitation framework.
    ```bash
    msfconsole
    ```

  - **Exploitdb**: Local database of known exploits.
    ```bash
    searchsploit <term>
    ```

### Password Cracking
  - **John the Ripper**: Password cracker.
    ```bash
    john --wordlist=<path_to_wordlist> <hashfile>
    ```

  - **Hydra**: Password cracker for network protocols.
    ```bash
    hydra -l <username> -P <passwordlist> <target IP> ssh
    ```

### Post-Exploitation
  - **Privilege Escalation Scripts**: Tools like LinPEAS for Linux privilege escalation.
    ```bash
    ./linpeas.sh
    ```

### Wireless Hacking
  - **Aircrack-ng Suite**: Wireless network auditing tools.
    ```bash
    airmon-ng start wlan0     # Enable monitor mode
    airodump-ng wlan0mon      # Capture packets
    ```

---

## 9. Useful File Locations in Kali Linux

| Path                              | Description                                              |
|-----------------------------------|----------------------------------------------------------|
| `/etc/`                           | System configurations.                                   |
| `/etc/passwd`                     | User account information.                                |
| `/etc/shadow`                     | Encrypted passwords.                                     |
| `/etc/network/interfaces`         | Network interfaces config.                               |
| `/var/log/`                       | System log files.                                        |
| `/home/`                          | Home directories for users.                              |
| `/opt/`                           | Optional/additional software.                            |
| `/usr/share/`                     | Shared data, including exploits (like `/usr/share/exploitdb`). |
