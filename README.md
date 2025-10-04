<div align="center">
  <img alt="Evilwaf Logo" src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/img/evilwaf.jpg" height="160" />
  <br />
  <img alt="Evilwaf Title" src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/img/evilwaf.jpg" height="60" />
</div>

#Evilwaf 2.0


# EvilWAF - Web Application Firewall Bypass Toolkit

**EvilWAF** is an advanced firewall bypass and fingerprinting tool designed to detect and bypass Web Application Firewalls (WAF). It supports multiple evasion techniques for comprehensive security assessment.

## Key Features
- **WAF Fingerprinting**: Identify and detect specific WAF solutions
- **Multiple Bypass Techniques**:
  - Header Manipulation
  - DNS History Analysis  
  - Subdomain Enumeration
- **Firewall Evasion**: Advanced methods to bypass security controls
- **Comprehensive Scanning**: Multi-technique approach for maximum effectiveness

## Supported WAF Detection and bypass
- Cloudflare, Akamai, Imperva, ModSecurity, and more
- 


## WAF Bypass Techniques

### 1. **Header Manipulation**
Advanced HTTP header manipulation to evade WAF detection:
- **User-Agent Rotation**: Cycle through different browser signatures
- **X-Forwarded-For Spoofing**: Fake originating IP addresses
- **Accept-Encoding Manipulation**: Alter compression headers
- **Cookie Parameter Pollution**: Overload cookie parameters

### 2. **DNS History Analysis**
Leverage DNS records to discover hidden entry points:
- **Historical DNS Lookups**: Find old IP addresses and subdomains
- **CNAME Chain Analysis**: Trace domain aliases and redirects
- **Passive DNS Replication**: Gather intelligence from DNS databases
- **Expired Domain Detection**: Identify forgotten subdomains
- **IP History Reconstruction**: Map historical server locations

### 3. **Subdomain Enumeration**
Comprehensive subdomain discovery for alternative access:
- **Brute-force Discovery**: Dictionary attacks on subdomains
- **Certificate Transparency Logs**: Extract domains from SSL certificates
- **Search Engine Scraping**: Harvest subdomains from public indexes
- **DNS Zone Transfer Attempts**: Exploit misconfigured DNS servers
- **Reverse IP Lookup**: Find all domains on shared hosting

### 4. **HTTP Request Smuggling**
Advanced protocol-level attacks to bypass WAF inspection:
- **CL.TE Attacks**: Content-Length vs Transfer-Encoding conflicts
- **TE.CL Attacks**: Transfer-Encoding vs Content-Length confusion
- **Header Obfuscation**: Space and tab variations in headers
- **Chunk Size Manipulation**: Large and malformed chunk sizes
- **Method Override**: Smuggled GET, POST, PUT, DELETE requests
- **Endpoint Diversification**: Target admin panels, APIs, and internal endpoints

### 5. **JWT Algorithm Confusion**
Authentication bypass through token manipulation:
- **Algorithm "none" Attack**: Remove signature verification
- **Weak Secret Testing**: Common and default JWT secrets
- **Key Confusion**: Use public keys as HMAC secrets
- **Header Injection**: KID, JKU, and X5U header attacks
- **Timestamp Manipulation**: Future expirations and fixed timestamps
- **Role Escalation**: Admin and superuser claim injection

### 6. **GraphQL Query Batching**
Exploit GraphQL features to evade detection:
- **Query Batching**: Multiple queries in single request
- **Array Batching**: ID arrays with injection payloads
- **Mutation Batching**: Combined login and privilege escalation
- **Introspection Abuse**: Schema discovery with injection
- **Alias Attacks**: Multiple query aliases with different parameters
- **Variable Manipulation**: SQL injection through GraphQL variables

### 7. **gRPC/Protobuf Bypass**
Binary protocol attacks to evade content inspection:
- **Protocol Confusion**: Mix gRPC, Protobuf, and REST content types
- **Binary Encoding**: SQL injection in binary payloads
- **Content-Type Manipulation**: Various gRPC content type headers
- **Cloud Provider Mimicry**: AWS, Google, and Azure gRPC headers
- **WebSocket Protocol**: gRPC-Web and WebSocket protocol attacks
- **Proxy Header Injection**: Combine gRPC with proxy headers








<p align="center">
  <img alt="Screenshot"
  src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/img/screen.jpg" height="320" />
</p>

<p align="center">
  <img alt="Screenshot"
  src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/img/screenshot.jpg" height="320" />
</p>


## Disclaimer

**Important: Read This Before Using EvilWAF**
- This tool is designed for **authorized security testing only**
- You must have **explicit permission** to test the target systems
- Intended for **educational purposes**, **security research**, and **authorized penetration testing**
- **Not for malicious or illegal activities**

### Legal Compliance:
- Users are solely responsible for how they use this tool
- The developers are **not liable** for any misuse or damage caused
- Ensure compliance with local, state, and federal laws


[Website](https://securitytrails.com/)
**Features:**
- Historical DNS records
- IP history for domains
- Subdomain enumeration
- Free tier available
**Usage:** Search for domain → View DNS History



[Website](https://viewdns.info/)
**Features:**
- IP History lookup
- DNS record history
- Reverse IP lookup
- Completely free
**Tools:**
- IP History: https://viewdns.info/iphistory/
- Reverse IP: https://viewdns.info/reverseip/


[Website]( https://dnslytics.com/)
**Features:**
- Historical DNS data
- Reverse IP lookup
- Domain history
- Free limited queries
- 

[Website]( https://www.whoxy.com/)
**Features:**
- Reverse IP lookup
- Historical WHOIS
- Free API limited.


##support 
I DO NOT offer support for privide elligal issue but I  will help you to  reach your goal


[linkedin](https://www.linkedin.com/in/matrix-leons-77793a340)


**evilwaf** is made by matrix leons



<p align="center">
  <a href="https://github.com/matrixleons/evilwaf">
    <img src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/img/Image.jpg" height="60" />
  </a>
</p>





##  Installation

### Method 1: Clone from GitHub (Recommended)
```bash
git clone https://github.com/matrixleons/evilwaf.git

cd evilwaf

pip3 install -r requirements.txt

python3 evilwaf.py -d https://site.com -o results.json(Recommended)

python3 evilwaf.py -d site.com -o results.json 

python3 evilwaf.py -d site.com / https://site.com

            [ Tool output example]



[+] PHASE 2: DNS History Bypass
[*] Testing 14 IP variants
[-] 35.187.93.140                            Bypass Success
[-] 35.187.93.1                              Bypass Failed
[-] 35.187.93.2                              Bypass Failed
[-] 35.187.93.10                             Bypass Failed
[-] 35.187.93.50                             Bypass Failed
[-] 35.187.93.100                            Bypass Failed
[-] 35.187.93.200                            Bypass Failed
[-] 35.187.93.254                            Bypass Failed
[-] 35.187.93.255                            Bypass Failed
[-] 35.187.93.101                            Bypass Failed
[-] 35.187.93.102                            Bypass Failed
[-] 35.187.93.103                            Bypass Failed
[-] 35.187.93.253                            Bypass Failed
[-] 35.187.93.252                            Bypass Failed







Docker Installation

docker build -t evilwaf .
docker run -it evilwaf -d example.com

*****done*****
