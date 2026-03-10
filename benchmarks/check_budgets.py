#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def _parse_result(path: Path) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        k, v = line.strip().split("=", 1)
        try:
            out[k] = float(v)
        except ValueError:
            pass
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_budgets.py <result-file> <budget-file>")
        return 2
    result = _parse_result(Path(sys.argv[1]))
    budget = json.loads(Path(sys.argv[2]).read_text())

    failures = []
    if result.get("latency_p95_ms", 0.0) > budget["latency_p95_ms_max"]:
        failures.append("latency_p95_ms")
    if result.get("success_rate", 0.0) < budget["success_rate_min"]:
        failures.append("success_rate")
    if result.get("rps", 0.0) < budget["rps_min"]:
        failures.append("rps")

    if failures:
        print("budget check failed:", ", ".join(failures))
        print(result)
        return 1
    print("budget check passed")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
