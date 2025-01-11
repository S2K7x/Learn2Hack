Reconnaissance is the first and one of the most critical phases of a Red Team engagement. It involves collecting information about your target to identify potential attack vectors. This guide will break down essential tools, techniques, and workflows for Red Team recon.

---

### **1. Recon Overview**

- **Objective**: Gather intelligence on the target (organization, infrastructure, individuals) without alerting the defenders.
- **Types of Recon**:
    - **Passive Recon**: Collect publicly available information without interacting directly with the target (e.g., WHOIS, DNS lookups).
    - **Active Recon**: Interact with the target’s systems to gather more precise data (e.g., port scans, subdomain enumeration).

---

### **2. DNS Recon**

Domain Name System (DNS) recon is critical for uncovering infrastructure details. Key techniques include:

### **a. DNS Queries**

- Use **dig** or **nslookup**:
    
    ```bash
    dig target.com ANY
    nslookup -type=any target.com
    
    ```
    
- Collect information like mail servers, name servers, and TXT records.

### **b. Zone Transfers**

- Exploit improperly configured DNS servers:
    
    ```bash
    dig axfr @<name-server> target.com
    
    ```
    
- If successful, this dumps all DNS records (rare but valuable).

### **c. Subdomain Enumeration**

- Identify additional subdomains to expand the attack surface:
    - Tools: **Sublist3r**, **amass**, **dnsrecon**, [**crt.sh**](http://crt.sh/).
    - Example with amass:
        
        ```bash
        amass enum -d target.com
        
        ```
        

### **d. DNS Tunneling Indicators**

- Look for encoded data in DNS traffic to understand potential C2 channels.

---

### **3. Advanced Searching**

Search engines and databases provide significant intelligence:

### **a. Google Dorking**

- Use advanced search queries to uncover sensitive data:
    
    ```
    site:target.com filetype:pdf
    site:target.com inurl:admin
    intitle:"index of" "confidential"
    
    ```
    
- Example: Find employee email patterns:
    
    ```
    site:linkedin.com "@target.com"
    
    ```
    

### **b. Public Data Sources**

- WHOIS: Retrieve domain registration data.
    - Tools: **whois**, **whoxy** API.
    - Example:
        
        ```bash
        whois target.com
        
        ```
        
- Shodan: Identify exposed services and devices.
    - Query Example:
        
        ```
        org:"Target Organization" port:22
        
        ```
        

### **c. Breach Data**

- Search for breached credentials:
    - Tools: **HaveIBeenPwned**, **Dehashed**, [**Hunter.io**](http://hunter.io/).

---

### **4. Recon-ng**

A powerful, modular framework for recon automation.

### **a. Getting Started**

- Install Recon-ng:
    
    ```bash
    pip install recon-ng
    recon-ng
    
    ```
    
- Load workspaces for project separation:
    
    ```
    workspace create target
    
    ```
    

### **b. Key Modules**

- **Domain Info**:
    
    ```
    use recon/domains-hosts/bing_domain_web
    set source target.com
    run
    
    ```
    
- **Contacts**: Find emails.
    
    ```
    use recon/contacts-hosts/bing_contacts
    set source target.com
    run
    
    ```
    

### **c. Output Reports**

- Generate and export collected data:
    
    ```
    use reporting/csv
    set output target_recon.csv
    run
    
    ```
    

---

### **5. Maltego**

A visual information-gathering and relationship-mapping tool.

### **a. Installation**

- Download from the [Maltego website](https://www.maltego.com/).
- Free version: Maltego CE (Community Edition).

### **b. Key Features**

- **Transforms**:
    - Automated intelligence gathering using predefined actions.
    - Examples:
        - Transform domain to subdomains.
        - Discover linked email addresses or phone numbers.

### **c. Example Workflow**

1. **Seed Information**: Start with a domain (e.g., `target.com`).
2. **Transform Selection**:
    - Transform: To DNS records, subdomains, or related email addresses.
3. **Graph Visualization**: Map relationships visually for clarity.
4. **Export Data**: Save the graph or raw data for further analysis.

---

### **6. Recon Automation**

### **a. Tools for Automation**

- **OSINT Framework**: Centralized resource for OSINT tools.
- **TheHarvester**: Quick email, subdomain, and service discovery.
    
    ```bash
    theharvester -d target.com -b google
    
    ```
    
- **SpiderFoot**: Automated recon and vulnerability assessment.
    
    ```bash
    spiderfoot -s target.com
    
    ```
    

### **b. Combine Tools**

- Use a recon automation suite like **ReconFTW** to streamline:
    
    ```bash
    git clone <https://github.com/six2dez/reconftw>
    ./reconftw.sh -d target.com
    
    ```
    

---

### **7. Ethical Recon Practices**

- Avoid **active recon** on targets without explicit authorization.
- Log and document all activities for report generation.
- Use VPNs or proxy chains for anonymized scanning.

---

### **8. Example Recon Workflow**

1. **Passive Recon**:
    - Google Dorking: Search for exposed data.
    - WHOIS Lookup: Get registrar and contact information.
    - Breach Search: Check for leaked credentials.
2. **DNS Recon**:
    - Enumerate subdomains using amass.
    - Perform zone transfers if DNS servers are misconfigured.
3. **Active Recon** (authorized only):
    - Port scan with **nmap**.
    - Use Maltego to map relationships.
4. **Data Aggregation**:
    - Store findings in **Recon-ng** or a spreadsheet.

---

### **9. Tools Comparison**

| Tool | Purpose | Strengths |
| --- | --- | --- |
| **Recon-ng** | Modular recon framework | Automation and flexibility |
| **Maltego** | Visual relationship mapping | Intuitive UI, powerful transforms |
| **TheHarvester** | Quick OSINT discovery | Easy to use, fast results |
| **SpiderFoot** | Full recon automation | Versatile and detailed |
| **Amass** | Subdomain enumeration | Comprehensive results |

---

### **10. Tips for Red Team Recon**

- Use multiple tools to cross-validate results.
- Keep recon stealthy—limit active techniques unless authorized.
- Prioritize open-source and publicly available information.
- Document findings in a clear, actionable format.

This cheat sheet equips you with essential techniques and tools to gather and organize intel effectively during Red Team assessments. For best results, combine these strategies with hands-on practice in simulated environments.
