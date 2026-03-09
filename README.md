<p align="center">
  <img alt="Evilwaf Logo"
  src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/evilwaf.png"
  style="width:100%;max-width:800px;" />
</p>
  

# Evilwaf 2.4.1


# EvilWAF - Web Application Firewall Testing and Bypass toolkit 

**EvilWAF** is an advanced transparent MITM proxy designed for WAF bypass and detect common  Web Application Firewalls (WAF). It supports multiple  techniques for comprehensive security assessment.



## Features

- **Transparent MITM Proxy** — Works with any tool that supports `--proxy`. Zero configuration on tool side.
- **TCP Fingerprint Rotation** — Rotates TCP stack options per request to avoid behavioral detection.
- **TLS Fingerprint Rotation** — Rotates TLS fingerprint (JA3/JA4 style) paired with TCP profiles.
- **Tor IP Rotation** — Routes traffic through Tor and rotates exit IP every request automatically.

- **Proxy pool IP Rotation** - rotates IP every request automatically through external proxy's 

- **Origin IP Hunter** — Discovers the real server IP behind the WAF using 10 parallel scanners:
  - DNS history, SSL certificate analysis, subdomain enumeration
  - DNS misconfiguration, cloud leak detection, GitHub leak search
  - HTTP header leak, favicon hash, ASN range scan, Censys
- **Auto WAF Detection** — Detects WAF vendor automatically before bypass starts.
- **Direct Origin Bypass** — Once real IP is found, routes all traffic directly to the server, skipping the WAF entirely.
- **Full HTTPS MITM** — Intercepts and inspects HTTPS traffic with dynamic certificate generation per host.
- **HTTP/2 & HTTP/1.1 Support** — Negotiates ALPN automatically and handles both protocols.
- **TUI Dashboard** — Real-time terminal UI showing traffic, techniques, Tor IPs, and bypass results.
- **Headless Mode** — `--no-tui` flag for scripting and CI/CD pipelines.
- **Response Advisor** — Automatically retries on WAF blocks (403, 429, 503) with different techniques.


<p align="center">
  <img alt="Screenshot"
  src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/screen.jpg"
  style="width:100%;max-width:800px;" />
</p>




<p align="center">
  <img alt="Screenshot"
  src="https://raw.githubusercontent.com/matrixleons/evilwaf/main/media/screenshot.jpg"
  style="width:100%;max-width:800px;" />
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
I DO NOT offer support for provide illigal issue but I  will help you to  reach your goal


[linkedin](https://www.linkedin.com/in/matrix-leons-77793a340)


**evilwaf** is made by matrix leons





##  💥Show Your Support
If this program  has been helpful to you and see the problems please consider giving us the feedback




## CA Certificate Setup (Required for HTTPS)

```bash
EvilWAF generates a local CA to intercept HTTPS traffic. You need to trust it once.

# Run EvilWAF first — CA is auto-generated at startup
# Then find the cert:
ls /tmp/evilwaf_ca_*/evilwaf-ca.pem

# Linux — trust system-wide
sudo cp /tmp/evilwaf_ca_*/evilwaf-ca.pem /usr/local/share/ca-certificates/evilwaf-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/evilwaf_ca_*/evilwaf-ca.pem

For tools like sqlmap, pass --verify-ssl=false or use the --no-check-certificate equivalent for your tool.
```



##  Installation


```bash

# 1. Create virtual environment
python3 -m venv myenv

# 2. Activate virtual environment
source myenv/bin/activate


git clone https://github.com/matrixleons/evilwaf.git

cd evilwaf

pip3 install -r requirements.txt

python3 evilwaf.py -h


Docker Installation

docker build -t evilwaf .
docker run -it evilwaf -t example.com
```

## Usage

```bash
Basic — Standard Proxy Mode
python3 evilwaf.py -t https://target.com

Auto-Hunt Origin IP Behind WAF
python3 evilwaf.py -t https://target.com --auto-hunt

EvilWAF will run 10 scanners in parallel, rank candidates by confidence, then ask:
  [?] Use 1.2.3.4 as origin IP for bypass? [y/n]:If you confirm, all traffic goes directly to the real server IP, bypassing the WAF completely

Manual Origin IP (If You Already Know It)
python3 evilwaf.py -t https://target.com --server-ip 1.2.3.4

With Tor IP Rotation when tor is running

python3 evilwaf.py -t https://target.com --enable-tor 

Headless Mode (No TUI)
python3 evilwaf.py -t https://target.com --no-tui

Upstream Proxy (route through external proxy)
python3 evilwaf.py -t https://target.com --upstream-proxy socks5://127.0.0.1:1080
python3 evilwaf.py -t https://target.com --upstream-proxy http://user:pass@proxy.com:8080
python3 evilwaf.py -t https://target.com --proxy-file proxies.txt

Custom Listen Address and Port
python3 evilwaf.py -t https://target.com --listen-host 0.0.0.0 --listen-port 9090


Connecting Your ToolOnce EvilWAF is running, point any tool to it via proxy:
  
  # sqlmap
sqlmap -u "https://target.com/page?id=1" --proxy=http://127.0.0.1:8080 --ignore-proxy=False

# ffuf
ffuf -u https://target.com/FUZZ -x http://127.0.0.1:8080

# nuclei
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# curl (for testing)
curl -x http://127.0.0.1:8080 https://target.com

API Keys (Optional)
Set these as environment variables to unlock more origin IP scanners:

export SHODAN_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

Without API keys, EvilWAF still runs using free sources (DNS history, SSL certs, HTTP headers, favicon hash, subdomain enum).
```

## Contributing

Contributions are welcome. EvilWAF is growing and there are many areas to improve.
How to Contribute

# Clone your fork
git clone https://github.com/matrixleons/evilwaf/fork
* Create your feature branch: ``git checkout -b my-new-feature``
* Commit your changes: ``git commit -am 'Add some feature'``
* Push to the branch: ``git push origin my-new-feature``
* Submit a pull request!

# Guidelines
Keep code clean and consistent with existing style
Test your changes before submitting a PR

Do not create technique which modify the body include headers, payloads and cookies 

Open an issue first for large changes so we can discuss

# License
Licensed under the Apache License, Version 2.0




