# Port 53 - DNS (Domain Name System) Cheatsheet

## Overview

- **Port Number**: 53
- **Protocol**: UDP/TCP
- **Service**: DNS (Domain Name System)
- **Purpose**: Translates human-readable domain names (e.g., example.com) into IP addresses (e.g., 192.168.1.1).
- **Standard**: Defined in multiple RFCs (1034, 1035, 2181, 4033, 4034, 4035, etc.).

## Key DNS Characteristics

- **UDP/TCP Dual Protocol**:
  - **UDP (Default)**: Lightweight and faster, used for most DNS queries.
  - **TCP**: Used for zone transfers (AXFR), DNSSEC, and large queries/responses.
- **Hierarchical**: DNS uses a tree structure with root, top-level domains (TLDs), and subdomains.
- **Caching**: DNS servers cache responses to speed up resolution.

## Common Uses

- **Domain Name Resolution**: Converts domains into IP addresses.
- **Reverse DNS Lookups**: Converts IP addresses back into domain names.
- **Email Delivery**: DNS MX (Mail Exchange) records direct email delivery.
- **Service Location**: SRV records identify services in a domain.

## DNS Record Types Overview

### Common DNS Record Types

- **A**: Maps a domain to an IPv4 address.
  ```plaintext
  example.com.        3600    IN  A     192.0.2.1

	•	AAAA: Maps a domain to an IPv6 address.

example.com.        3600    IN  AAAA  2001:db8::1


	•	CNAME: Alias of one domain to another.

www.example.com.    3600    IN  CNAME example.com.


	•	MX: Mail exchange record, directs email to a mail server.

example.com.        3600    IN  MX    10 mail.example.com.


	•	NS: Name server record, defines the DNS servers for a domain.

example.com.        3600    IN  NS    ns1.example.com.


	•	PTR: Pointer record for reverse DNS lookups.

1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.


	•	SRV: Service locator for services (e.g., SIP, LDAP).

_sip._tcp.example.com. 3600 IN SRV 10 5 5060 sipserver.example.com.


	•	TXT: Text record, often used for verification and security (e.g., SPF, DKIM).

example.com.        3600    IN  TXT   "v=spf1 include:_spf.google.com ~all"



DNS Query Types

	•	Standard Query: Basic name-to-IP lookup.
	•	Recursive Query: A client asks a DNS server to resolve a name completely, contacting multiple DNS servers if necessary.
	•	Iterative Query: A client asks a DNS server for the best answer it has; if the server doesn’t know, it returns a referral.
	•	Zone Transfer: (AXFR) Request for a full copy of a DNS zone (TCP).

Attack Vectors and Common Vulnerabilities

1. DNS Spoofing / Cache Poisoning

	•	Attack: Attacker inserts false DNS responses into a DNS cache, redirecting traffic.
	•	Example: User types example.com, but the cached IP is a malicious server.
	•	Mitigation:
	•	Implement DNSSEC to validate DNS responses.
	•	Set short TTL (Time To Live) values to limit cache duration.
	•	Use secure DNS resolvers (e.g., Cloudflare 1.1.1.1, Google 8.8.8.8).

2. DNS Amplification DDoS

	•	Attack: Exploits open DNS resolvers to flood a target with amplified traffic.
	•	Example: An attacker sends a small DNS query with a spoofed source IP (victim’s IP); the response is significantly larger.
	•	Mitigation:
	•	Disable recursive queries on authoritative DNS servers.
	•	Use rate limiting to manage DNS queries.
	•	Implement Response Rate Limiting (RRL) on DNS servers.

3. Zone Transfer Attack

	•	Attack: An attacker performs a zone transfer (AXFR) to download the entire DNS zone, revealing internal network structure.
	•	Mitigation:
	•	Restrict zone transfers to authorized IPs using allow-transfer.
	•	Use TSIG (Transaction SIGnature) for signed zone transfers.

4. DNS Tunneling

	•	Attack: Encapsulating data within DNS queries to bypass firewalls (e.g., for C2 communication in malware).
	•	Example: A client sends encoded data via DNS queries to a malicious domain.
	•	Mitigation:
	•	Monitor and inspect DNS traffic for unusual patterns.
	•	Block known malicious domains using threat intelligence.
	•	Use DNS filtering solutions to detect DNS tunnels.

5. Subdomain Takeover

	•	Attack: An attacker gains control over an abandoned subdomain that points to an external service.
	•	Example: A CNAME record points to a service (e.g., GitHub Pages) that is no longer controlled by the legitimate owner.
	•	Mitigation:
	•	Regularly audit DNS records for dangling references.
	•	Remove or update stale DNS entries.

Example of a Zone Transfer Attack Using dig

# Perform a zone transfer (AXFR) using dig
dig axfr @ns1.example.com example.com

Common DNS Vulnerabilities

	•	CVE-2020-8616: BIND vulnerable to DoS attack via crafted TCP payload.
	•	CVE-2018-5740: Improper handling of trusted key files in BIND.
	•	CVE-2017-3145: DNS query processing vulnerabilities in BIND leading to crashes.

DNS Security Hardening and Best Practices

Disable Recursion on Authoritative DNS Servers

	•	Recursive queries should be handled only by dedicated resolvers, not public DNS servers.

# Example in BIND configuration (named.conf)
options {
    recursion no;
    allow-recursion { none; };
};

Restrict Zone Transfers

# Restrict zone transfers in BIND (named.conf)
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { 192.168.1.100; 192.168.1.101; };
};

Implement DNSSEC

	•	DNSSEC provides data integrity by signing DNS records with digital signatures.

# BIND configuration snippet for enabling DNSSEC
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    auto-dnssec maintain;
    inline-signing yes;
};

Log and Monitor DNS Queries

	•	Enable query logging to detect abnormal patterns.

# Enable query logging in BIND
logging {
    channel default_log {
        file "/var/log/named.log";
        severity info;
        print-time yes;
    };
    category queries { default_log; };
};

Use DNS Filtering Solutions

	•	Use services like OpenDNS, Quad9, or Cloudflare DNS to block known malicious domains.
	•	Implement Pi-hole for DNS-level ad-blocking and filtering.

Firewall Rules

# Allow DNS traffic only from trusted sources (iptables example)
iptables -A INPUT -p tcp --dport 53 -s trusted_ip_address -j ACCEPT
iptables -A INPUT -p udp --dport 53 -s trusted_ip_address -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j DROP
iptables -A INPUT -p udp --dport 53 -j DROP

Monitoring DNS Traffic

Network Monitoring Tools

	•	Wireshark: Capture DNS traffic using filter: udp.port == 53.
	•	Suricata: Network IDS/IPS with DNS anomaly detection.
	•	Zeek (Bro): Network security monitoring tool, great for DNS analysis.

Analyze DNS Logs

# Tail DNS logs for suspicious activity (BIND example)
sudo tail -f /var/log/named.log

# Search for failed DNS resolution attempts
grep "SERVFAIL" /var/log/named.log

Detect DNS Tunneling

	•	Look for:
	•	Unusually long domain names (used to encode data).
	•	High frequency of TXT record requests.
	•	Abnormal query patterns to specific domains.
	•	Use tools like dnstop or Dnstwist to analyze DNS traffic.

Scripting and Automation for DNS

Query DNS Records Using dig (Command-Line Tool)

# Query A record
dig example.com A

# Query MX record
dig example.com MX

# Perform a reverse DNS lookup
dig -x 192.0.2.1

# Query with a specific DNS server
dig @8.8.8.8 example.com A

Python Script to Query DNS Records Using dnspython

import dns.resolver

# Basic DNS query for A record
domain = "example

.com"
result = dns.resolver.resolve(domain, 'A')
for ipval in result:
    print(f'IP Address: {ipval.to_text()}')

Final Notes

	•	Always secure DNS with DNSSEC and zone transfer restrictions.
	•	Implement logging and monitoring for DNS anomalies to detect potential attacks early.
	•	Use DNS filtering and trusted DNS providers to enhance security.

For more resources on DNS, refer to the following:
	•	BIND DNS Server Documentation
	•	DNSSEC Deployment Guide
	•	OWASP DNS Security
