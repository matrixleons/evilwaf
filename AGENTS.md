# Repository Guidelines

## Project Structure & Module Organization
- `evilwaf.py`: main CLI entrypoint and TUI orchestration.
- `core/`: proxy engine and protocol handling (`interceptor.py`, `waf_detector.py`, `proxy_file.py`).
- `chemistry/`: traffic mutation and recon modules (`tor_rotator.py`, `tls_rotator.py`, `tcp_options.py`, `origin_server_ip.py`).
- `chemistry/data/`: static datasets and source lists used by recon scanners.
- `media/`: screenshots and project images.
- `tests/`: unit tests (`test_*.py`).

Keep new logic in `core/` or `chemistry/` modules, and keep `evilwaf.py` focused on argument parsing and app wiring.

## Build, Test, and Development Commands
- `python3 -m venv .venv && source .venv/bin/activate`: create and activate a virtual environment.
- `pip install -r requirements.txt`: install runtime dependencies.
- `python3 evilwaf.py -t https://example.com --no-tui`: run in headless mode.
- `python3 -m unittest discover -s tests -v`: run unit tests.
- `python3 -m py_compile evilwaf.py core/*.py chemistry/*.py`: quick syntax validation.

## Coding Style & Naming Conventions
- Language: Python 3, 4-space indentation, UTF-8 files.
- Naming: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- Prefer small, single-purpose methods and explicit dataclasses for structured records.
- Preserve existing style: type hints where practical, minimal comments, and no broad refactors in unrelated files.

## Testing Guidelines
- Framework: built-in `unittest` (no pytest requirement in repo).
- Place tests in `tests/` and name files `test_*.py`; methods should start with `test_`.
- Cover behavior changes with focused unit tests (mock network/socket-heavy paths).
- For new flags/options, add at least one regression test for parsing and one for runtime wiring.

## Commit & Pull Request Guidelines
- Commit style in history is concise, imperative, and scoped (e.g., `Fix override IP and TOR rotation wiring; add regression tests`).
- Keep commits focused; avoid mixing feature work and unrelated cleanup.
- PRs should include:
  - What changed and why.
  - Risk/impact notes (networking, TLS, TOR, proxy behavior).
  - Test evidence (`unittest` output or exact command run).
  - Linked issue(s) when applicable.

## Security & Configuration Tips
- Never commit secrets (API keys, TOR control passwords). Use environment variables.
- Treat generated cert material as sensitive; do not add runtime CA artifacts to version control.
- Validate proxy targets and recon sources before adding new defaults.
