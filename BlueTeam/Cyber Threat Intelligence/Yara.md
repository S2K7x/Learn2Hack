# **YARA Cheat Sheet – Threat Hunting, Malware Analysis & Forensics**  

YARA is a powerful tool for identifying and classifying malware through pattern matching. It is widely used in **threat intelligence, digital forensics, and malware hunting** to detect and categorize malware families based on shared characteristics.

---

## **1. What is YARA?**  

🔹 **YARA** (Yet Another Recursive Acronym) is a rule-based pattern matching tool for malware classification.  
🔹 It helps **identify malware families** by searching for specific byte patterns, strings, or behaviors in files, memory, and network traffic.  
🔹 Developed by **VirusTotal** and used in **threat intelligence, DFIR, SOC, and malware analysis**.  

### **Common Use Cases:**  
✔ **Threat Intelligence** – Detect IOCs (Indicators of Compromise)  
✔ **Malware Detection** – Classify known and unknown threats  
✔ **Memory Forensics** – Scan live system memory for malware  
✔ **Incident Response** – Identify malicious files or persistence mechanisms  

---

## **2. YARA Rule Structure**  

A **YARA rule** consists of three main sections:  
```yara
rule RuleName {
    meta:
        author = "JohnDoe"
        description = "Detects a specific malware family"
        date = "2025-01-17"
    
    strings:
        $string1 = "malicious_payload"
        $hex1 = { 6A 40 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }
    
    condition:
        any of them
}
```

### **Key Components:**  
- **meta** – Metadata describing the rule (author, date, description).  
- **strings** – Strings or hexadecimal patterns to detect.  
- **condition** – Defines when the rule should trigger (e.g., any of them, all of them, a combination).  

---

## **3. Running YARA Rules**  

### **Basic YARA Command**
```bash
yara rule.yara target_file
```
**Example:** Scan a malware sample:
```bash
yara my_rule.yara sample.exe
```

### **Scanning an Entire Directory**
```bash
yara my_rule.yara /path/to/files/
```

### **Scan a Process in Memory**
```bash
yara -p <PID> my_rule.yara
```

### **Recursive Scanning**
```bash
yara -r my_rule.yara /path/to/directory
```

### **Using YARA with VirusTotal**
Search for YARA rule matches in VirusTotal:
```bash
curl --request POST \
  --url https://www.virustotal.com/api/v3/intelligence/search \
  --header 'x-apikey: YOUR_API_KEY' \
  --header 'content-type: application/json' \
  --data '{"query":"rule:my_yara_rule"}'
```

---

## **4. YARA String Matching Techniques**  

### **Text String Matching**  
```yara
strings:
    $malicious_str1 = "malware.exe"
    $malicious_str2 = "This program cannot be run in DOS mode."
condition:
    any of them
```

### **Hexadecimal Byte Pattern Matching**  
```yara
strings:
    $hex_pattern = { 6A 40 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }
condition:
    any of them
```
🔹 **Wildcards (`??`)** match **any byte** in a sequence.  

### **Regular Expressions**  
```yara
strings:
    $regex = /Trojan\.\d{3,4}/
condition:
    any of them
```
🔹 **Regex (`/pattern/`)** can match **variable malware signatures**.  

---

## **5. YARA Conditions**  

Conditions define when a rule should match.

### **Basic Conditions**
```yara
condition:
    $string1 or $string2
```
✔ Matches if **either** `$string1` or `$string2` is found.  

```yara
condition:
    all of them
```
✔ Matches **only if all** string patterns are found.  

```yara
condition:
    #string1 >= 5
```
✔ Matches **if `$string1` appears at least 5 times**.  

---

## **6. Advanced YARA Rule Techniques**  

### **File Size-Based Matching**
```yara
condition:
    filesize < 100KB
```
✔ Only matches if the file size is **less than 100KB**.  

### **Matching at Specific Offsets**
```yara
condition:
    $string1 at 0x200
```
✔ `$string1` **must appear at byte offset `0x200`** in the file.  

### **Checking File Types (PE, ELF, Mach-O)**
```yara
import "pe"
condition:
    pe.number_of_sections > 5
```
✔ Matches **PE files with more than 5 sections**.  

```yara
import "elf"
condition:
    elf.machine == elf.EM_X86_64
```
✔ Matches **64-bit ELF executables**.  

---

## **7. YARA for Memory Forensics**  

🔹 **Use YARA to scan RAM dumps & live processes for malware**.  
🔹 Works with **Volatility, Rekall**, and raw memory images.  

### **Scanning a Memory Dump**
```bash
yara my_rule.yara memdump.raw
```

### **Scanning a Process in Memory (Linux)**
```bash
sudo yara -p $(pgrep -f target_process) my_rule.yara
```

---

## **8. YARA and MITRE ATT&CK**  

✔ Map YARA rules to **MITRE ATT&CK TTPs** for better threat intelligence.  

**Example: Detecting Process Injection (T1055)**
```yara
import "pe"

rule ProcessInjection {
    meta:
        author = "Blue Team"
        description = "Detects process injection techniques"
        mitre_attack_id = "T1055"
    
    strings:
        $virtual_alloc = "VirtualAllocEx"
        $write_process_mem = "WriteProcessMemory"
        $create_thread = "CreateRemoteThread"
    
    condition:
        all of ($virtual_alloc, $write_process_mem, $create_thread)
}
```
✔ Detects **remote process injection APIs** used by malware.  

---

## **9. YARA Integration with Security Tools**  

### **YARA + VirusTotal**  
✔ Use YARA rules for **threat intelligence searches**.  
✔ Upload custom rules for automated detection.  

### **YARA + SIEM (Splunk, ELK, Graylog)**  
✔ Automate **threat detection** across logs and event data.  

### **YARA + EDR (CrowdStrike, SentinelOne, Velociraptor)**  
✔ Hunt for **malware and persistence techniques** in real time.  

### **YARA + Volatility for Memory Forensics**
✔ Scan memory dumps for **hidden malware and rootkits**.  

```bash
vol.py -f memory.dmp yarascan --yara-rules=my_rule.yara
```

---

## **10. YARA Resources & Learning**  

✔ **YARA Documentation**: [https://yara.readthedocs.io/](https://yara.readthedocs.io/)  
✔ **GitHub YARA Rules Repo**: [https://github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules)  
✔ **MITRE ATT&CK Framework**: [https://attack.mitre.org/](https://attack.mitre.org/)  
✔ **Threat Intelligence Feeds**: [https://otx.alienvault.com/](https://otx.alienvault.com/)  

---

## **Conclusion**  
🔹 **YARA is a must-have tool** for malware analysts, threat hunters, and SOC teams.  
🔹 Use YARA rules to **detect, classify, and hunt** malware efficiently.  
🔹 Integrate YARA with **SIEM, EDR, and memory forensics tools** for deeper visibility.  

🚀 **Mastering YARA = Stronger Threat Detection & Response!** 🚀  

