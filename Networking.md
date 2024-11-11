# Networking Fundamentals Cheatsheet

## 1. OSI Model

The OSI (Open Systems Interconnection) model is a conceptual framework used to understand network interactions in seven layers:

| Layer          | Number | Description                            | Protocols/Examples     |
|----------------|--------|----------------------------------------|------------------------|
| Physical      | 1      | Hardware, cables, connectors           | Ethernet, USB          |
| Data Link     | 2      | MAC addressing, error detection        | Ethernet (MAC), PPP    |
| Network       | 3      | Routing, IP addressing                 | IP, ICMP               |
| Transport     | 4      | End-to-end connections, reliability    | TCP, UDP               |
| Session       | 5      | Dialog control, session management     | NetBIOS, RPC           |
| Presentation  | 6      | Data format translation, encryption    | SSL/TLS, ASCII         |
| Application   | 7      | User interfaces, application protocols | HTTP, FTP, SMTP        |

**Key Points:**
  - **Encapsulation**: Data is encapsulated as it moves down the layers and decapsulated when moving up.
  - **Flow**: Application to Physical (sending), Physical to Application (receiving).

---

## 2. TCP/IP Model

The TCP/IP model is a simpler, four-layer version of the OSI model:

| TCP/IP Layer   | Corresponding OSI Layers | Protocols                      |
|----------------|--------------------------|--------------------------------|
| Application    | 5, 6, 7                   | HTTP, FTP, DNS, SMTP           |
| Transport      | 4                        | TCP, UDP                       |
| Internet       | 3                        | IP, ICMP, ARP                  |
| Network Access | 1, 2                      | Ethernet, Wi-Fi                |

**Key Protocols:**
  - **TCP (Transmission Control Protocol)**: Reliable, connection-oriented.
  - **UDP (User Datagram Protocol)**: Unreliable, connectionless, faster.

---

## 3. IP Addressing

### IPv4 Basics:
  - **Format**: 32-bit numeric address written as four decimal numbers (e.g., 192.168.1.1).
  - **Classes**:
    - **Class A**: 1.0.0.0 to 126.255.255.255 (Large networks)
    - **Class B**: 128.0.0.0 to 191.255.255.255 (Medium-sized networks)
    - **Class C**: 192.0.0.0 to 223.255.255.255 (Small networks)
  - **Private IP Ranges**:
    - **Class A**: 10.0.0.0 to 10.255.255.255
    - **Class B**: 172.16.0.0 to 172.31.255.255
    - **Class C**: 192.168.0.0 to 192.168.255.255

### IPv6 Basics:
  - **Format**: 128-bit hexadecimal address (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334).
  - **Advantages**: Larger address space, built-in security features (IPSec).

---

## 4. Subnetting

### CIDR Notation:
  - **CIDR (Classless Inter-Domain Routing)**: Specifies the number of bits in the subnet mask (e.g., 192.168.1.0/24).
  - **Subnet Masks**:
    - /24 → 255.255.255.0
    - /16 → 255.255.0.0
    - /8  → 255.0.0.0

### Subnet Calculation:
  1. **Network bits**: Define the network.
  2. **Host bits**: Used for devices (e.g., /28 means 4 bits for hosts, so 2^4 - 2 = 14 usable addresses).

### Example:
  - **192.168.1.0/28** → Network size = 16 addresses, 14 usable.

---

## 5. Ports and Protocols

### Common Port Numbers:

| Protocol | Port Number | Description                |
|----------|-------------|----------------------------|
| HTTP     | 80          | Web traffic (unencrypted)  |
| HTTPS    | 443         | Secure web traffic         |
| FTP      | 21          | File Transfer Protocol     |
| SSH      | 22          | Secure Shell               |
| SMTP     | 25          | Email sending              |
| DNS      | 53          | Domain Name System queries |
| Telnet   | 23          | Unsecured remote login     |

### Port Ranges:
  - **Well-known ports**: 0-1023
  - **Registered ports**: 1024-49151
  - **Dynamic/Private ports**: 49152-65535

---

## 6. Protocol Overview

- **HTTP (Hypertext Transfer Protocol)**:
  - **Port**: 80
  - Stateless and unencrypted.
  - Uses GET, POST, PUT, DELETE methods.
  
- **HTTPS (Hypertext Transfer Protocol Secure)**:
  - **Port**: 443
  - Encrypted using TLS/SSL.
  - Same methods as HTTP, secure transmission.
  
- **FTP (File Transfer Protocol)**:
  - **Port**: 21
  - Unencrypted, can use secure alternatives like SFTP (port 22).

---

## 7. Basic Firewall Concepts

  - **Definition**: A firewall controls incoming and outgoing network traffic based on predetermined security rules.
  - **Types**:
    - **Packet Filtering**: Basic, checks source/destination IPs and ports.
    - **Stateful Inspection**: Keeps track of active connections.
    - **Application Layer Firewalls**: Filters based on specific application data.
  - **Rules**:
    - **Allow**: Permits specific traffic.
    - **Deny**: Blocks traffic.
  - **Best Practices**:
    - Use least privilege principle for access.
    - Implement logging for monitoring.
    - Update rules regularly to address new threats.

### Example Rule:
 - ALLOW TCP FROM 192.168.1.0/24 TO ANY PORT 80,443 DENY ALL 
