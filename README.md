

<p align="center">
  <a href="https://github.com/matrixleons/evilwaf/stargazers">
    <img src="https://img.shields.io/github/stars/matrixleons/evilwaf?style=flat-square" alt="Stars">
  </a>
  <a href="https://github.com/matrixleons/evilwaf/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

**EvilWAF** is an advanced transparent MITM Firewall bypass proxy and deep WAF vulnerability scanner designed for authorized security testing. It operates at the transport layer — it does not touch payloads, cookies, or headers from your tools. Works with any tool like(`ffuz`, `sqlmap`, `nuclei` and etc) that supports `--proxy`.

---

## Features

### Proxy & Bypass
- **Transparent MITM Proxy** — Works with any tool that supports `--proxy`. Zero configuration on tool side.
- **TCP Fingerprint Rotation** — Rotates TCP stack options per request to avoid behavioral detection.
- **TLS Fingerprint Rotation** — Rotates TLS fingerprint (JA3/JA4 style) paired with TCP profiles.
- **HTTP/2 Fingerprint Rotation** — Per-request H2 SETTINGS and HEADERS frame profile rotation cycling through Chrome, Firefox, Safari, and Edge profiles to prevent WAF behavioral fingerprinting.
- **Source Port Manipulation** — Rotates source port per request, breaking WAF session tracking and rate-limit counters that rely on source port consistency.
- **Cloudflare Header Injection** — Injects Cloudflare-specific internal headers (`CF-Connecting-IP`, `CF-Ray`, `True-Client-IP`) with crafted values to test WAF header trust and attempt IP allowlist bypass.
- **Tor IP Rotation** — Routes traffic through Tor and rotates exit IP every request automatically.
- **Proxy Pool IP Rotation** — Rotates IP every request through external proxy pool.
- **Origin IP Hunter** — Discovers the real server IP behind the WAF using 10 parallel scanners:
  - DNS history, SSL certificate analysis, subdomain enumeration
  - DNS misconfiguration, cloud leak detection, GitHub leak search
  - HTTP header leak, favicon hash, ASN range scan, Censys
- **Auto WAF Detection** — Detects WAF vendor automatically before bypass starts.
- **Direct Origin Bypass** — Once real IP is found, routes all traffic directly to the server, skipping the WAF entirely.
- **Full HTTPS MITM** — Intercepts and inspects HTTPS traffic with dynamic certificate generation per host.
- **HTTP/2 & HTTP/1.1 Support** — Negotiates ALPN automatically and handles both protocols.
- **Response Advisor** — Automatically retries on WAF blocks (403, 429, 503) with different techniques.

### WAF Vulnerability Scanner
- **Deep Multi-Layer WAF Scanner** — Treats the firewall itself as the target. Analyses all WAF defensive layers simultaneously across 10 independent scanning layers:
  - `Layer 1  Network` — Virtual host bypass, sensitive path probing, Host header manipulation
  - `Layer 2  RuleEngine` — Payload-based rule-gap detection: SQLi, XSS, RCE, LFI
  - `Layer 3  RateLimit` — Burst and sustained rate-limit enforcement testing
  - `Layer 4  Evasion` — Encoding and normalisation bypass with 10 encoding variants per payload
  - `Layer 5  Behavioural` — Timing analysis: tarpit, JS challenge delay, back-off detection
  - `Layer 6  Header` — HTTP header injection and IP spoofing bypass
  - `Layer 7  TLS` — TLS version probing, SNI bypass, certificate fingerprinting
  - `Layer 8  MethodVerb` — HTTP method bypass including WebDAV methods
  - `Layer 9  Session` — Cookie manipulation, auth bypass, session fixation probes
  - `Layer 10 Misconfig` — WAF misconfiguration and information leak detection
- **Persistent Session** — Each scan merges with historical JSON data from previous scans. Confidence grows over time — the longer you scan, the more accurate the results.
- **Statistical Confidence Engine** — Per-layer confidence scores computed using mean, standard deviation, and stability analysis. A finding at 86% confidence after 15 verified passes is a real vulnerability, not noise.
- **False Positive Verification** — Every finding is replayed against a clean baseline before reporting. Findings that do not reproduce are automatically excluded.
- **C Extension** (`_fast_scanner.c`) — High-performance Python C extension for classification, entropy analysis, timing anomaly detection, and statistics hot paths.

### Interface
- **TUI Dashboard** — Real-time terminal UI showing live traffic, active techniques, Tor IPs, source ports, proxy pool, and scanner findings per layer.
- **Headless Mode** — `--no-tui` flag for scripting and CI/CD pipelines.
- **Scan-Only Mode** — `--scan-only` to run the WAF vulnerability scanner standalone without starting the proxy.

---

<details>
<summary><strong>About Cloudflare & Research</strong></summary>

<br>

### Why Cloudflare?

Cloudflare is widely regarded as the most sophisticated Web Application Firewall in the world today. It is not simply a set of rules — it is a multi-layered defence system that combines several technologies working simultaneously to protect web applications.

At the network level, Cloudflare operates across hundreds of data centres globally, meaning every request passes through infrastructure that has visibility into traffic patterns from millions of websites at once. This global visibility is one of its most powerful advantages — it can detect attack patterns emerging anywhere in the world and deploy mitigations across all protected properties within seconds.

At the inspection level, Cloudflare analyses requests across multiple dimensions simultaneously: TCP/IP fingerprint, TLS fingerprint, HTTP/2 frame structure, header ordering, request timing, behavioural patterns across sessions, and payload content. Any single one of these signals alone is not enough to block a request, but Cloudflare correlates all of them together to build a risk score per request.

The machine learning component is what makes Cloudflare fundamentally different from traditional WAFs. Where rule-based WAFs look for known bad patterns, Cloudflare's ML models are trained on petabytes of real attack traffic. They learn what legitimate browser traffic looks like at the transport layer — the exact sequence of TCP options, the precise structure of a TLS ClientHello, the ordering of HTTP/2 SETTINGS frames — and flag anything that deviates from that baseline, even if the payload itself appears clean. This is why simply encoding a payload or rotating headers is not enough against Cloudflare. The bypass has to happen at the transport layer, not the application layer.

### Why Is Cloudflare Hard to Bypass?

Most WAF bypass techniques target the rule engine — obfuscating payloads, using encoding variants, splitting attack strings across parameters. These techniques work against signature-based WAFs because those WAFs only look at payload content.

Cloudflare's defence operates before the payload is even inspected. A request from a Python HTTP library, even sending a completely benign payload, can be challenged or blocked because the TLS fingerprint does not match any known browser. This means the tool making the request is identified before the content is analysed. Cloudflare calls this behavioural fingerprinting, and it is the primary reason standard penetration testing tools fail against it even when the underlying payloads are correct.

Rate limiting on Cloudflare is also intelligent — it is not simply a counter of requests per IP per second. It tracks request patterns across sessions, correlates behaviour across IPs sharing the same ASN, and applies progressive challenges rather than hard blocks, making it difficult to detect the threshold through automated testing.

### The Developer's Research Approach

The developer of EvilWAF approaches Cloudflare not as a target to attack but as a subject of study. The research methodology is systematic: observe how Cloudflare responds to different transport-layer identities, measure which signals trigger challenges versus blocks versus silent passes, and build statistical models of its behaviour from live data.

This is fundamentally different from reading documentation or studying CVEs. Cloudflare's behaviour cannot be fully understood from external sources because it changes continuously — models are retrained, thresholds are adjusted, new signals are added. The only reliable way to understand it is through live, controlled, authorised experimentation and careful analysis of the data collected.

The goal of this research is to produce tools and knowledge that help the security research community understand what WAF bypass actually looks like at a technical level in 2026 — not to cause harm, but to ensure that defenders understand the real capabilities and limitations of the technologies they rely on. A security researcher who understands how Cloudflare detects and blocks requests is better equipped to test whether applications behind it are truly protected.

EvilWAF's scanner architecture — persistent sessions, statistical confidence, multi-layer analysis, timing anomaly detection — exists because this kind of research requires long observation periods and rigorous data collection, not quick scans. Real WAF research takes time, and the tools should reflect that.

</details>

---









## Disclaimer

**Important: Read This Before Using EvilWAF**
- This tool is designed for **authorized security testing only**
- You must have **explicit permission** to test the target systems
- Intended for **educational purposes**, **security research**, and **authorized penetration testing**
- **Not for malicious or illegal activities**

### Legal Compliance
- Users are solely responsible for how they use this tool
- The developers are **not liable** for any misuse or damage caused
- Ensure compliance with local, state, and federal laws

---

## Support

I do not offer support for illegal use cases, but I will help you reach your goal in authorized testing.

[LinkedIn](https://www.linkedin.com/in/matrix-leons-77793a340)

**EvilWAF** is made by Matrix Leons.

---

## Support The Project

If EvilWAF has been useful to you, consider supporting its development. Your contribution helps keep this project maintained and growing.

<p align="center">
  <a href="https://store.pesapal.com/supportmywork">
    <img src="https://img.shields.io/badge/Donate-Support%20the%20Project-brightgreen?style=for-the-badge" alt="Donate">
  </a>
</p>

**[Donate](https://store.pesapal.com/supportmywork)**

I appreciate Thank you. 

---

## CA Certificate Setup (Required for HTTPS)

```bash
# EvilWAF generates a local CA to intercept HTTPS traffic. Trust it once.

# Run EvilWAF first — CA is auto-generated at startup
# Then find the cert:
ls /tmp/evilwaf_ca_*/evilwaf-ca.pem

# Linux — trust system-wide
sudo cp /tmp/evilwaf_ca_*/evilwaf-ca.pem /usr/local/share/ca-certificates/evilwaf-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  /tmp/evilwaf_ca_*/evilwaf-ca.pem

# For tools like sqlmap, pass --ignore-proxy=False or equivalent for your tool.
```

---

## Installation

```bash
# 1. Create virtual environment
python3 -m venv myenv

# 2. Activate virtual environment
source myenv/bin/activate

# 3. Clone and install
git clone https://github.com/matrixleons/evilwaf.git
cd evilwaf
pip3 install -r requirements.txt

# 4. Build C extension (optional, improves scanner performance)
python setup_fast_scanner.py build_ext --inplace

python3 evilwaf.py -h
```

### Docker Installation

```bash
docker build -t evilwaf .
docker run -it evilwaf -t https://example.com
```

---

## Usage

```bash
# Basic — Standard Proxy Mode
python3 evilwaf.py -t https://target.com

# Auto-Hunt Origin IP Behind WAF
python3 evilwaf.py -t https://target.com --auto-hunt

# EvilWAF runs 10 scanners in parallel, ranks candidates by confidence, then asks:
#   [?] Use 1.2.3.4 as origin IP for bypass? [y/n]:
# If confirmed, all traffic goes directly to the real server, bypassing WAF completely.

# Manual Origin IP (if already known)
python3 evilwaf.py -t https://target.com --server-ip 1.2.3.4

# With Tor IP Rotation
python3 evilwaf.py -t https://target.com --enable-tor

# Headless Mode (No TUI)
python3 evilwaf.py -t https://target.com --no-tui

# WAF Vulnerability Scanner — alongside proxy
python3 evilwaf.py -t https://target.com --scan-vulns

# WAF Vulnerability Scanner — standalone, no proxy
python3 evilwaf.py -t https://target.com --scan-only

# WAF Vulnerability Scanner — custom rate and output
python3 evilwaf.py -t https://target.com --scan-only --scan-rps 5.0 --scan-output ./results

# Upstream Proxy
python3 evilwaf.py -t https://target.com --upstream-proxy socks5://127.0.0.1:1080
python3 evilwaf.py -t https://target.com --upstream-proxy http://user:pass@proxy.com:8080
python3 evilwaf.py -t https://target.com --proxy-file proxies.txt

# Custom Listen Address and Port
python3 evilwaf.py -t https://target.com --listen-host 0.0.0.0 --listen-port 9090
```

### Connecting Your Tool

Once EvilWAF is running, point any tool to it via proxy:

```bash
# sqlmap
sqlmap -u "https://target.com/page?id=1" --proxy=http://127.0.0.1:8080 --ignore-proxy=False

# ffuf
ffuf -u https://target.com/FUZZ -x http://127.0.0.1:8080

# nuclei
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# curl (for testing)
curl -x http://127.0.0.1:8080 https://target.com
```

### API Keys (Optional)

```bash
export SHODAN_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
```

Without API keys, EvilWAF still runs using free sources (DNS history, SSL certs, HTTP headers, favicon hash, subdomain enum).

---

## Contributing

Contributions are welcome. EvilWAF is growing and there are many areas to improve.

```bash
# Fork and clone
git clone https://github.com/matrixleons/evilwaf/fork
git checkout -b my-new-feature
git commit -am 'Add some feature'
git push origin my-new-feature
# Submit a pull request
```

### Guidelines
- Keep code clean and consistent with existing style
- Test your changes before submitting a PR
- Do not create techniques which modify the body, headers, payloads, or cookies of proxied requests
- Open an issue first for large changes so we can discuss

---

## License

Licensed under the Apache License, Version 2.0
