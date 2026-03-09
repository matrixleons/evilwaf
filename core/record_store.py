from __future__ import annotations

import contextlib
import gzip
import json
import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from core.models import ProxyRecord


class RecordStore:
    def __init__(
        self,
        record_limit: int = 20000,
        spool_path: Optional[str] = None,
        spool_max_bytes: int = 50 * 1024 * 1024,
    ):
        self.buffer: Deque[ProxyRecord] = deque(maxlen=max(1000, record_limit))
        self.buffer_lock = threading.Lock()
        self.metrics_lock = threading.Lock()
        self.started_at = time.time()
        self.total_records = 0
        self.total_passed = 0
        self.total_blocked = 0

        self.spool_path = spool_path
        self.spool_max_bytes = max(1024, spool_max_bytes)
        self.spool_lock = threading.Lock()
        self.spool_fp = None
        if self.spool_path:
            spool_dir = os.path.dirname(self.spool_path)
            if spool_dir:
                os.makedirs(spool_dir, exist_ok=True)
            self.spool_fp = open(self.spool_path, "a", encoding="utf-8")

    @staticmethod
    def serialize_record(record: ProxyRecord) -> Dict[str, Any]:
        return {
            "timestamp": record.request.timestamp,
            "method": record.request.method,
            "host": record.request.host,
            "path": record.request.path,
            "status_code": record.response.status_code,
            "passed": record.passed,
            "blocked": record.blocked,
            "technique": record.technique_applied,
            "is_https": record.request.is_https,
            "response_time": record.response.response_time,
        }

    def _rotate_spool_if_needed_unlocked(self):
        if not self.spool_path or not self.spool_fp:
            return
        try:
            size = os.path.getsize(self.spool_path)
        except OSError:
            return
        if size < self.spool_max_bytes:
            return
        self.spool_fp.close()
        rotated = f"{self.spool_path}.1"
        gz_path = f"{rotated}.gz"
        with contextlib.suppress(OSError):
            os.remove(gz_path)
        with contextlib.suppress(OSError):
            os.remove(rotated)
        os.replace(self.spool_path, rotated)
        with open(rotated, "rb") as src, gzip.open(gz_path, "wb", compresslevel=6) as dst:
            dst.write(src.read())
        with contextlib.suppress(OSError):
            os.remove(rotated)
        self.spool_fp = open(self.spool_path, "a", encoding="utf-8")

    def spill_record(self, record: ProxyRecord):
        if not self.spool_fp:
            return
        payload = json.dumps(self.serialize_record(record), separators=(",", ":"))
        with self.spool_lock:
            self._rotate_spool_if_needed_unlocked()
            self.spool_fp.write(payload + "\n")
            self.spool_fp.flush()

    def append(self, record: ProxyRecord):
        with self.metrics_lock:
            self.total_records += 1
            if record.passed:
                self.total_passed += 1
            if record.blocked:
                self.total_blocked += 1
        with self.buffer_lock:
            if self.buffer.maxlen and len(self.buffer) >= self.buffer.maxlen:
                self.spill_record(self.buffer[0])
            self.buffer.append(record)

    def get_records(self) -> List[ProxyRecord]:
        with self.buffer_lock:
            return list(self.buffer)

    def clear(self):
        with self.buffer_lock:
            self.buffer.clear()

    def get_spooled_records(self, limit: int = 200) -> List[Dict[str, Any]]:
        if not self.spool_path:
            return []
        entries: List[Dict[str, Any]] = []
        paths = [f"{self.spool_path}.1.gz", self.spool_path]
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                opener = gzip.open if path.endswith(".gz") else open
                with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln:
                            continue
                        with contextlib.suppress(Exception):
                            entries.append(json.loads(ln))
            except Exception:
                continue
        return entries[-max(1, limit):]

    def get_metrics(self) -> Dict[str, Any]:
        now = time.time()
        uptime = max(0.001, now - self.started_at)
        with self.metrics_lock:
            total = self.total_records
            passed = self.total_passed
            blocked = self.total_blocked
        with self.buffer_lock:
            in_memory = len(self.buffer)
            memory_cap = self.buffer.maxlen or 0
        spool_size = 0
        if self.spool_path and os.path.exists(self.spool_path):
            with contextlib.suppress(OSError):
                spool_size = os.path.getsize(self.spool_path)
        return {
            "uptime_seconds": uptime,
            "total_records": total,
            "passed_records": passed,
            "blocked_records": blocked,
            "pass_rate": (passed / total) if total else 0.0,
            "block_rate": (blocked / total) if total else 0.0,
            "records_per_second": (total / uptime),
            "in_memory_records": in_memory,
            "in_memory_capacity": memory_cap,
            "spool_file": self.spool_path,
            "spool_size_bytes": spool_size,
        }

    def close(self):
        if self.spool_fp:
            with self.spool_lock:
                self.spool_fp.close()
                self.spool_fp = None
