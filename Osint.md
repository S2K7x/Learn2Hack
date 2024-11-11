# OSINT Cheat Sheet

A comprehensive guide focused on **Open Source Intelligence (OSINT)**, covering core concepts, tools, techniques, and ethical considerations for gathering publicly available information on individuals, organizations, and other targets. OSINT is commonly used in **security assessments**, **penetration testing**, and **threat intelligence gathering**.

---

## 1. Core Concepts of OSINT

**OSINT** involves collecting and analyzing publicly available information from a variety of sources to gain insights on a target. OSINT is commonly used in **cybersecurity**, **threat intelligence**, and **investigations**.

### **OSINT Workflow**
1. **Define Objectives:** Identify what information is needed and why.
2. **Identify Sources:** Decide which sources will likely contain the required information (social media, websites, public records, etc.).
3. **Collect Data:** Gather data from various OSINT sources.
4. **Analyze Data:** Assess the data for relevance, accuracy, and insights.
5. **Report Findings:** Document results, drawing conclusions and recommendations if needed.

### **Ethical and Legal Considerations**
- Only gather data from public sources.
- Respect privacy laws and avoid unauthorized access.
- Avoid information misuse and follow ethical guidelines, especially when OSINT is applied to cybersecurity or investigations.

---

## 2. Common OSINT Techniques

| **Technique**            | **Description**                                                                 |
|--------------------------|---------------------------------------------------------------------------------|
| **Passive Reconnaissance** | Collect information without direct engagement with the target (e.g., social media scraping, WHOIS data). |
| **Active Reconnaissance**  | Interact with the target directly (e.g., port scanning, sending test requests). |
| **Social Media Profiling** | Analyze social media accounts for patterns, locations, connections, and activities. |
| **Metadata Analysis**      | Extract metadata from documents, images, and files to find information about authors, locations, and timestamps. |
| **Search Engine Dorking**  | Use advanced search operators to uncover hidden information on websites (e.g., Google Dorking). |
| **Public Record Search**   | Retrieve data from government and public records like business registrations, property records, and court filings. |
| **Geolocation and Mapping**| Use geographic data to determine physical locations of individuals or organizations. |

---

## 3. Popular OSINT Tools and Resources

### **General OSINT Tools**
- **Maltego:** Visualization and link analysis tool for mapping connections between entities.
- **SpiderFoot:** Automated OSINT tool for threat intelligence gathering.
- **theHarvester:** Tool for collecting emails, subdomains, and other data from public sources.
- **Recon-ng:** A modular web reconnaissance framework that integrates with APIs for data gathering.

### **Domain and Website Information**
- **WHOIS Lookup:** Get domain ownership information.
  - Websites: Whois.com, DomainTools.
  - CLI Tool: `whois domain.com`
- **DNS Enumeration:** Gather DNS records (A, MX, NS) and subdomains.
  - Tools: `nslookup`, `dig`, `dnsrecon`, `Sublist3r`.
- **Web Archive Search:** View historical snapshots of websites.
  - Website: [Wayback Machine](https://archive.org/web/)

### **Social Media OSINT**
- **Sherlock:** Find usernames across various social networks.
- **Social-Searcher:** Real-time social media search engine.
- **Tinfoleak:** Tool to analyze Twitter accounts (location data, hashtags, device info).

### **Email OSINT**
- **Hunter.io:** Search for email addresses associated with a domain.
- **EmailRep:** Tool to analyze email reputation and associated data.
- **OSINT Email Lookup Services:** Tools like **EmailRecon** and **HaveIBeenPwned** to check email breaches.

### **People Search and Background Checks**
- **Pipl:** People search engine that aggregates data from various public sources.
- **Intelius:** Public records and background search tool.
- **Spokeo:** Aggregates information from social profiles, public records, and more.
- **LinkedIn and Facebook:** Use profiles and social connections for professional and personal data.

### **Image and Video Analysis**
- **ExifTool:** Extract metadata from images and videos.
- **Google Reverse Image Search:** Find similar images or track where an image appears online.
- **TinEye:** Reverse image search to locate the source or modified versions of an image.

### **Geolocation Tools**
- **Google Earth and Google Maps:** View geographic information and satellite images.
- **GeoSocial Footprint:** Tool to map the social media footprint of users.
- **EXIF GPS Data:** Check images for GPS metadata with ExifTool or Jeffrey’s EXIF Viewer.
- **OpenStreetMap (OSM):** Community-based mapping tool for public map data.

### **Dark Web OSINT**
- **Ahmia:** Search engine for Tor hidden services.
- **Onion Search Engine:** Indexes .onion sites on the Tor network.
- **Dark Web Monitoring Tools:** Services like **DarkOwl** and **Recorded Future** monitor dark web activity (useful for organizations).

---

## 4. OSINT Techniques by Data Type

### **Domain and IP Information**
1. **WHOIS Data:** Obtain information on domain ownership and registration.
   - Example CLI: `whois example.com`
2. **DNS Records:** Retrieve DNS information, including subdomains and IP addresses.
   - Example CLI: `nslookup example.com`, `dig example.com`
3. **Reverse IP Lookup:** Identify all domains associated with a specific IP.
   - Tools: Reverse IP Lookup (online), **Shodan**.

### **Email and Username Information**
1. **Email Enumeration:** Search for email patterns or email addresses tied to domains.
   - Example Tool: **Hunter.io**
2. **Email Breach Check:** Check if an email address has been exposed in a data breach.
   - Example Tool: **HaveIBeenPwned**
3. **Username Search:** Locate profiles associated with a username across various platforms.
   - Example Tool: **Sherlock (CLI)**, **Namechk** (web-based).

### **Social Media Analysis**
1. **Profile Analysis:** Review posts, comments, and metadata to gather information on activities, patterns, and connections.
   - Tools: **Tinfoleak** (Twitter), **Social-Searcher**.
2. **Geolocation of Posts:** Extract location-based data from social media posts.
   - Example: **Tinfoleak** can show the geographic location of Twitter posts with geotags.

### **Image and Video Metadata**
1. **EXIF Data:** Extract metadata such as GPS coordinates, camera settings, and timestamps.
   - Example Tool: `exiftool image.jpg`
2. **Reverse Image Search:** Use to find where an image has been published or if it has been modified.
   - Tools: **Google Reverse Image Search**, **TinEye**.

### **Geolocation**
1. **Analyze Social Media Posts:** Many posts may include geolocation data if users share location.
2. **Image Metadata for GPS Data:** Extract GPS data from photos to locate where they were taken.
3. **Public Mapping Services:** Use services like **Google Earth** or **OpenStreetMap** to investigate locations.

---

## 5. Advanced OSINT Techniques

### **Google Dorking**
Using specific search operators to locate hidden or sensitive information indexed by search engines.

- **Basic Operators:**
  - `site:example.com`: Search within a specific site.
  - `filetype:pdf`: Search for specific file types.
  - `"text"`: Search for exact phrases.

- **Example Dorking Queries:**
  - `site:example.com filetype:pdf confidential`
  - `intitle:"index of" "password"`

### **Metadata Analysis**
- **Document Metadata:** Extract metadata from documents to find author names, modification dates, and software used.
  - Tools: **ExifTool**, **FOCA** (document metadata extraction).
- **File System Metadata:** When analyzing files from web servers, metadata may reveal sensitive information.

### **Dark Web Intelligence**
- **Hidden Services Monitoring:** Track .onion sites on the dark web for stolen credentials or leaked information.
- **Dark Web Search Engines:** Use search engines like **Ahmia** to locate .onion sites.
- **Threat Intelligence Platforms:** Platforms like **Recorded Future** provide insights and alerts on dark web activities.

---

## 6. OSINT Best Practices

- **Use VPNs and Anonymity Tools:** When conducting OSINT, use a **VPN** and consider tools like **Tor** to protect your identity.
- **Document Findings:** Keep detailed notes on findings, sources, and analysis to ensure data is organized.
- **Cross-Reference Information:** Verify findings from multiple sources to ensure data accuracy.
- **Stay Ethical and Legal:** Ensure all collected information is from public or authorized sources. Avoid social engineering or other intrusive tactics.
- **Automate OSINT Where Possible:** Use tools and scripts to speed up repetitive tasks (e.g., **Recon-ng**, **SpiderFoot**).
