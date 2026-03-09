# EVILWAF - Changelog

All notable changes to the EVILWAF project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.4.1] - 2026-03-07

### Added
- **Proxy pool IP rotation** -
use external proxies  IPs  for IP rotation 
---

## [2.4.0] - 2026-03-05

### Added
- **Transparent MITM Proxy Architecture** — EvilWAF now sits between any tool and target as a fully transparent proxy. No tool-side configuration needed beyond `--proxy`.
- **TCP Fingerprint Rotation** — Per-request TCP stack option manipulation to avoid behavioral detection by WAF engines.
- **TLS Fingerprint Rotation** — Per-request TLS fingerprint rotation (JA3/JA4 style) paired with TCP profiles for consistent transport-layer identity.
- **Tor IP Rotation** — Full Tor integration via stem. Rotates exit node IP automatically every request or every N requests via `--tor-rotate-every`.
- **Origin IP Hunter** — Automated real server IP discovery behind WAF using 10 parallel scanners:
  - DNS history analysis
  - SSL certificate inspection
  - Subdomain enumeration
  - DNS misconfiguration detection
  - Cloud provider leak detection
  - GitHub leak search
  - HTTP header leak analysis
  - Favicon hash matching
  - ASN range scanning
  - Censys integration
- **Direct Origin Bypass Mode** — Once real IP is discovered, all traffic is routed directly to the origin server, skipping the WAF layer entirely.
- **Auto WAF Detection** — Automatically detects and identifies WAF vendor before bypass starts.
- **MITM HTTPS Interception** — Dynamic per-host certificate generation via local CA. Full HTTPS traffic inspection without touching payload.
- **HTTP/2 and HTTP/1.1 Support** — Automatic ALPN negotiation. Handles both H2 and H1 sessions transparently.
- **Response Advisor** — Intelligent retry engine. Automatically retries blocked requests (403, 429, 503) with rotated techniques without user intervention.
- **TUI Dashboard** — Real-time terminal UI built with urwid showing live traffic, active techniques, Tor IP rotation log, and bypass results.
- **Headless Mode** — `--no-tui` flag for scripted and CI/CD usage with stdout traffic table.
- **`--auto-hunt` flag** — Single flag to trigger full origin IP discovery workflow with interactive confirmation.
- **`--server-ip` flag** — Manual origin IP override for direct bypass when IP is already known.
- **CA Certificate Export** — Auto-exports CA in PEM, CER, and P12 formats for browser and system trust installation.
- **Docker support** — Full Dockerfile and entrypoint script with Tor service management included.
- **Optional API key support** — Shodan, SecurityTrails, VirusTotal, Censys via environment variables.

### Removed
- **HTTP/3 bypass technique** — Removed as primary bypass method. QUIC/HTTP3 now used only as ALPN protocol negotiation where server supports it, not as evasion technique.
- **HTTP/2 downgrade bypass technique** — Removed as standalone bypass. H2 handled transparently via ALPN, not as evasion layer.
- **IP rotation via proxy pool** — Replaced entirely by Tor-based rotation with stem control for cleaner, more reliable IP switching.
- **Payload manipulation techniques** — All payload-level bypass logic removed. EvilWAF no longer touches request body, cookies, headers, or query parameters from the proxied tool.
- **WAF-specific tamper logic** — Removed per-WAF tamper scripts. Bypass now operates purely at transport layer.
- **Static bypass technique list** — Removed fixed technique sequences. All techniques now rotate dynamically per request.

### Changed
- **Core architecture rewritten** — From standalone bypass scanner to transparent MITM proxy messenger. EvilWAF is now an orchestration layer, not a payload modifier.
- **Bypass philosophy** — Shifted from "modify what the tool sends" to "change how traffic travels". Payload integrity is now guaranteed.
- **WAF detection** — Moved from scan-time detection to pre-proxy detection. WAF is identified once at startup before any tool traffic flows.
- **Tool integration** — Any tool supporting `--proxy` now works with EvilWAF out of the box. No per-tool configuration required.

### Fixed
- Memory leaks during long proxy sessions with many concurrent connections
- Unicode handling in host headers during MITM handshake
- Certificate cache overflow causing stale cert errors on high-volume scans
- H2 stream ID collision during concurrent request handling
- Tor rotation race condition under high request frequency

---

## [2.3.0] - 2025-12-10

### Added
- Early transparent proxy prototype — initial MITM architecture experiment
- Basic TCP option manipulation module
- Proof of concept Tor rotation via stem

### Changed
- Began migration away from payload-based bypass toward transport-layer approach
- Refactored WAF detector into standalone module

### Fixed
- Proxy tunnel stability issues under sustained load
- SSL handshake failures on TLS 1.3 targets

---

## [2.2.0] - 2025-09-20

### Added
- Advanced firewall bypass techniques
- DNS history bypass techniques
- Cloudflare WAF detection improvements
- DataDome firewall bypass methods
- ModSecurity rule evasion techniques
- Sucuri WAF detection patterns
- Incapsula/Imperva bypass methods
- Fastly CDN detection
- Google Cloud Armor patterns
- StackPath WAF detection
- Docker support with Dockerfile
- Comprehensive .gitignore file
- EditorConfig for code consistency

### Improved
- Banner design with multiple style options
- WAF detection accuracy
- Performance optimization
- Error handling and logging
- Code documentation
- User interface and experience

### Fixed
- DNS history outdated data issues
- False positive WAF detections
- Memory leaks in large-scale scans
- Unicode handling in payloads
- Cross-platform compatibility issues

---

## [2.1.0] - 2024-08-15

### Added
- Basic WAF detection capabilities
- Simple firewall bypass methods
- Initial project structure

### Improved
- Codebase organization
- Basic error handling

---

## [2.0.0] - 2024-07-01

### Added
- Initial project release
- Basic functionality
- Core architecture

---

## Unreleased

### Planned Features
- [ ] AI-powered WAF behavior analysis
- [ ] Machine learning TLS/TCP profile generation
- [ ] Real-time threat intelligence integration
- [ ] Advanced behavioral timing analysis
- [ ] Plugin system for custom scanner modules
- [ ] GUI interface option
- [ ] Cloud deployment support
- [ ] Windows platform support

---

## Versioning Scheme

- **Major version** (X.0.0): Breaking changes, major rewrites
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, minor improvements

## Release Types

- **Stable**: Production-ready releases
- **Beta**: Feature-complete, testing phase
- **Alpha**: Early access, unstable features

---

## Compatibility

| EvilWAF Version | Python Version | OS Support |
|---|---|---|
| 2.4.x | 3.8+ | Linux, macOS |
| 2.3.x | 3.8+ | Linux, macOS |
| 2.2.x | 3.8+ | Linux, Windows, macOS |
| 2.1.x | 3.7+ | Linux, Windows |
| 2.0.x | 3.6+ | Linux |

---

## Contributing

To contribute to this changelog:
1. Add changes under the appropriate version section
2. Use the format: `- **Component**: Description of change`
3. Categorize changes as Added, Changed, Removed, Fixed, or Security
4. Include issue numbers where applicable: `(#123)`

---

## Links

- [GitHub Repository](https://github.com/matrixleons/evilwaf)
- [Issue Tracker](https://github.com/matrixleons/evilwaf/issues)

---

*This changelog is maintained according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).*