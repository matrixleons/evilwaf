#!/usr/bin/env python3
from __future__ import annotations

import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests


@dataclass
class Sample:
    status_code: int
    latency_ms: float
    ok: bool


def _single_request(proxy_url: str, target_url: str, timeout: float) -> Sample:
    start = time.perf_counter()
    try:
        resp = requests.get(
            target_url,
            timeout=timeout,
            proxies={"http": proxy_url, "https": proxy_url},
            verify=False,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0
        return Sample(status_code=resp.status_code, latency_ms=latency_ms, ok=True)
    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return Sample(status_code=0, latency_ms=latency_ms, ok=False)


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int((pct / 100.0) * (len(ordered) - 1))
    return ordered[idx]


def run_benchmark(
    proxy_url: str,
    target_url: str,
    requests_count: int,
    concurrency: int,
    timeout: float,
) -> Dict[str, float]:
    latencies: List[float] = []
    success = 0
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(_single_request, proxy_url, target_url, timeout)
            for _ in range(requests_count)
        ]
        for f in as_completed(futures):
            sample = f.result()
            latencies.append(sample.latency_ms)
            if sample.ok:
                success += 1
    elapsed = time.perf_counter() - started
    rps = (requests_count / elapsed) if elapsed > 0 else 0.0
    return {
        "requests": float(requests_count),
        "success_rate": (success / requests_count) if requests_count else 0.0,
        "rps": rps,
        "latency_p50_ms": percentile(latencies, 50.0),
        "latency_p95_ms": percentile(latencies, 95.0),
        "latency_mean_ms": statistics.mean(latencies) if latencies else 0.0,
        "duration_s": elapsed,
    }


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Proxy benchmark harness")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080")
    parser.add_argument("--target", default="https://example.com")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=8.0)
    return parser.parse_args()


def main() -> int:
    args = _args()
    parsed = urlparse(args.proxy)
    if not parsed.scheme or not parsed.netloc:
        raise SystemExit(f"Invalid proxy URL: {args.proxy}")
    result = run_benchmark(
        proxy_url=args.proxy,
        target_url=args.target,
        requests_count=args.requests,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )
    print("benchmark_result")
    for k, v in result.items():
        print(f"{k}={v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
