# **Blue Team Cheat Sheet: Threat Intelligence & Open-Source Tools**  

This cheat sheet provides an overview of key threat intelligence concepts and practical use of various open-source tools to identify and analyze threats.  

---

## **1. Threat Intelligence Basics**  

### **What is Threat Intelligence?**  
Threat Intelligence (TI) is the process of collecting, analyzing, and applying information about cyber threats to improve an organization's security posture.  

### **Types of Threat Intelligence**  
- **Strategic Intelligence** – High-level analysis for decision-makers (e.g., geopolitical threats, industry trends).  
- **Tactical Intelligence** – Focuses on attacker tactics, techniques, and procedures (TTPs).  
- **Operational Intelligence** – Real-time insights into active threats (e.g., attack campaigns).  
- **Technical Intelligence** – Indicators of Compromise (IOCs) such as malicious IPs, domains, hashes, and signatures.  

### **Key Threat Intelligence Sources**  
- **OSINT (Open-Source Intelligence)** – Publicly available threat data from forums, blogs, news, and social media.  
- **SIGINT (Signals Intelligence)** – Network and communications monitoring (e.g., packet analysis).  
- **HUMINT (Human Intelligence)** – Insider reports, human-driven intelligence.  
- **Dark Web & Deep Web** – Intelligence from hacker forums, markets, and underground sources.  

---

## **2. Using UrlScan.io for Malicious URL Analysis**  

**UrlScan.io** allows users to scan and analyze URLs for malicious behavior.  

### **How to Use UrlScan.io**  
1. Visit **[https://urlscan.io](https://urlscan.io/)**.  
2. Enter the suspicious URL in the search bar and click "Scan."  
3. Review the scan results:  
   - **Requests & Responses:** Check where the URL communicates.  
   - **Screenshots:** Visual representation of the webpage.  
   - **Detected Threats:** Identifies phishing/malware indicators.  
4. Investigate linked domains, JavaScript behavior, and embedded resources.  

### **Command-Line Alternative** (Using API)  
```bash
curl -X POST "https://urlscan.io/api/v1/scan/" \
-H "API-Key: YOUR_API_KEY" \
-H "Content-Type: application/json" \
-d '{"url": "http://suspicious-website.com", "visibility": "public"}'
```

---

## **3. Using Abuse.ch for Malware & Botnet Tracking**  

**Abuse.ch** provides intelligence on malware, botnets, and C2 servers.  

### **Useful Abuse.ch Projects**
- **URLhaus** – Tracks malicious URLs distributing malware.  
- **ThreatFox** – Database of IOCs (IP addresses, domains, hashes).  
- **Feodo Tracker** – Identifies active botnet C2 servers.  

### **How to Search for IOCs**
1. Visit **[https://abuse.ch](https://abuse.ch/)**.  
2. Use the search bar to enter:  
   - IP address  
   - Domain  
   - Hash  
3. Analyze results for malicious activity, reputation, and associations.  

### **API Lookup for Automated Threat Hunting**
Retrieve information on an IP address:  
```bash
curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" | grep "192.168.1.1"
```
Retrieve malware hash details:  
```bash
curl -s "https://threatfox-api.abuse.ch/api/v1/" -H "Content-Type: application/json" -d '{
  "query": "search_hash",
  "hash": "malwarehashhere"
}'
```

---

## **4. Investigating Phishing Emails with PhishTool**  

**PhishTool** helps analyze phishing emails, headers, and attachments.  

### **Steps to Analyze a Phishing Email**  
1. **Extract Email Headers**  
   - In Gmail: Click **More (⋮) > Show Original**  
   - In Outlook: **File > Properties > Internet Headers**  

2. **Use PhishTool to Analyze Email Headers**  
   - Visit **[https://phishtool.com](https://phishtool.com/)**.  
   - Copy and paste email headers.  
   - Identify suspicious indicators like:  
     - **SPF, DKIM, DMARC failures**  
     - **Unusual sender domains**  
     - **Encoded payloads**  

3. **Extract and Scan Attachments & Links**  
   - Use **VirusTotal**: [https://www.virustotal.com](https://www.virustotal.com/)  
   - Use **Hybrid Analysis**: [https://www.hybrid-analysis.com](https://www.hybrid-analysis.com/)  

### **Common Phishing Indicators**
🚩 **Sender address mismatches the domain**  
🚩 **Urgent or threatening language**  
🚩 **Unexpected attachments or links**  
🚩 **Look-alike domains (e.g., paypa1.com instead of paypal.com)**  

---

## **5. Using Cisco Talos Intelligence for Threat Research**  

Cisco Talos provides comprehensive threat intelligence on IPs, domains, and files.  

### **How to Use Talos Intelligence**
1. Visit **[https://talosintelligence.com](https://talosintelligence.com/)**.  
2. Enter an IP address, domain, or file hash in the search bar.  
3. Analyze:  
   - **IP Reputation:** Malicious, suspicious, or clean.  
   - **Domains:** Blacklist status and category.  
   - **Malware Hashes:** Detection history and malware family.  

### **Example Lookups**
- Checking a suspicious IP:  
  - **Result:** "This IP is associated with a botnet (e.g., Mirai)."  
- Analyzing a domain:  
  - **Result:** "This domain was used in phishing campaigns."  

### **Talos API for Automated Queries**  
```bash
curl -X GET "https://talosintelligence.com/api/v1/details/ip/8.8.8.8"
```

---

## **Quick IOC Lookup Cheat Sheet**  

| Tool         | Purpose                          | URL |
|-------------|----------------------------------|--------------------------------|
| **UrlScan.io** | Analyze & scan suspicious URLs | [https://urlscan.io](https://urlscan.io/) |
| **Abuse.ch** | Track malware, botnets & C2 servers | [https://abuse.ch](https://abuse.ch/) |
| **PhishTool** | Analyze phishing emails | [https://phishtool.com](https://phishtool.com/) |
| **Talos Intelligence** | Investigate IPs, domains, and hashes | [https://talosintelligence.com](https://talosintelligence.com/) |
| **VirusTotal** | Scan files & URLs for malware | [https://www.virustotal.com](https://www.virustotal.com/) |
| **Hybrid Analysis** | Sandbox malware analysis | [https://www.hybrid-analysis.com](https://www.hybrid-analysis.com/) |

---

## **Conclusion**  
Threat Intelligence is critical for proactively identifying and mitigating cyber threats. By leveraging open-source tools like **UrlScan.io, Abuse.ch, PhishTool, and Talos Intelligence**, blue teams can detect malicious activity, investigate phishing campaigns, and track emerging threats effectively.  

🔹 **Best Practice:** Automate IOC lookups and integrate threat feeds into SIEMs for continuous monitoring.  
🔹 **Stay Updated:** Follow threat intelligence reports from vendors like Cisco Talos, FireEye, and Recorded Future.  
