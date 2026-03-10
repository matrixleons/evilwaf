from __future__ import annotations

from typing import List


def load_proxy_file(path: str) -> List[str]:
    proxies: List[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean and not clean.startswith("#"):
                proxies.append(clean)
    return proxies
