# EvilWAF

EvilWAF is a transparent MITM proxy for authorized WAF testing and response analysis.
It supports HTTP/1.1 and HTTP/2, TLS interception, request mutation, and optional origin-IP reconnaissance.

## Authorized Use Only
Use this project only on systems where you have explicit, written permission to test.

## Quickstart (60s)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
python3 evilwaf.py -t https://example.com --no-tui
python3 evilwaf.py -t https://example.com --no-tui --record-limit 5000
```

## Core Features
- Transparent proxy for tools that support `--proxy`
- HTTPS MITM with on-the-fly certificates
- TCP/TLS fingerprint rotation
- Optional Tor/proxy rotation
- WAF signature-based detection
- Origin IP hunting (multiple scanners with confidence ranking)

## Project Layout
- `evilwaf.py` - CLI entrypoint and app wiring
- `core/` - interception engine, protocol handling, WAF detector
- `chemistry/` - rotation and origin-recon modules
- `tests/` - `unittest` suite
- `.github/workflows/` - CI, CodeQL, release automation

## Development
```bash
python3 -m unittest discover -s tests -v
coverage run --source=core,chemistry -m unittest discover -s tests -v
coverage report -m --fail-under=100
python3 benchmarks/proxy_benchmark.py --proxy http://127.0.0.1:8080 --target http://127.0.0.1:18080
```

Quality/security checks run in CI:
- Ruff (`F`, `E9`)
- Black formatting check (selected modules)
- Mypy strict check (selected modules)
- `pip-audit` on locked dependencies
- performance budget checks (`.github/workflows/performance.yml`)

Memory safety:
- `--record-limit` bounds in-memory traffic records (minimum enforced value: `1000`).
- `--record-spool-file /path/to/records.jsonl` writes evicted records to JSONL once the in-memory cap is reached.
- `--record-spool-max-mb` rotates and compresses spool archives (`.1.gz`) after size threshold.

## Architecture (High Level)
1. Client connects to local proxy.
2. HTTP traffic is forwarded and normalized by `core/interceptor.py`.
3. HTTPS `CONNECT` can be tunneled or intercepted with generated certificates.
4. Request/response records are scored for pass/block behavior.
5. Optional chemistry modules apply TCP/TLS/Tor/proxy rotation and origin discovery.

## Troubleshooting
- TLS certificate errors: trust the generated CA certificate.
- Tor rotation not active: verify Tor control port/password configuration.
- Coverage/CI mismatch: regenerate lockfile and run tests from a clean virtualenv.

## Contributing
Open PRs against `dev`. Include test evidence and risk notes for networking/TLS changes.
