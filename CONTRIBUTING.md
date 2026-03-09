# Contributing

Thanks for improving EvilWAF.

## Before You Open a PR

- Keep changes focused and small (one concern per PR).
- Describe risk/impact, especially for networking, TLS, proxy, and scanner logic.
- Prefer additive changes over broad refactors.

## Local Validation

Run the following before pushing:

```bash
python -m pip install -r requirements.txt
python -m py_compile evilwaf.py core/*.py chemistry/*.py
python evilwaf.py -h
```

If you changed runtime behavior, include a short reproducible test or command output in the PR description.

## Commit Guidelines

- Use concise, imperative commit messages.
- Include scope when useful, for example: `core: ...`, `chemistry: ...`, `docs: ...`, `ci: ...`.
- Avoid mixing unrelated cleanup with behavioral changes.

## Pull Request Checklist

- What changed and why.
- Any user-facing behavior changes.
- Security impact and mitigation notes (if applicable).
- Manual validation steps.
- Linked issue(s), if available.

## Security Reports

Please do not disclose vulnerabilities in public issues. Use the repository Security tab and private advisory flow.
