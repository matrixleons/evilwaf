from __future__ import annotations

import ctypes
import ipaddress
import os
import queue
import random
import socket
import ssl
import struct
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_FASTER_LIB: Optional[ctypes.CDLL] = None
_LIB_PATH = os.path.join(os.path.dirname(__file__), "_evil_faster.so")

if os.path.exists(_LIB_PATH):
    try:
        _FASTER_LIB = ctypes.CDLL(_LIB_PATH)
        _FASTER_LIB.tcp_connect_test.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        _FASTER_LIB.tcp_connect_test.restype = ctypes.c_int
        _FASTER_LIB.batch_tcp_test.argtypes = [
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
        ]
        _FASTER_LIB.batch_tcp_test.restype = ctypes.c_int
    except Exception:
        _FASTER_LIB = None

_DATACENTER_RANGES = [
    ipaddress.ip_network("52.0.0.0/11"),
    ipaddress.ip_network("54.0.0.0/8"),
    ipaddress.ip_network("34.0.0.0/9"),
    ipaddress.ip_network("35.0.0.0/8"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

_RESIDENTIAL_CIDRS = [
    "41.0.0.0/8",
    "41.80.0.0/13",
    "41.215.0.0/17",
    "102.0.0.0/8",
    "102.68.0.0/15",
    "196.200.0.0/13",
    "197.136.0.0/13",
    "197.155.0.0/16",
    "105.0.0.0/8",
    "197.0.0.0/8",
    "41.90.0.0/15",
    "196.0.0.0/8",
    "41.33.0.0/16",
    "196.202.0.0/15",
    "41.139.0.0/16",
    "41.57.0.0/16",
    "41.60.0.0/13",
    "41.72.0.0/13",
    "41.184.0.0/13",
    "41.191.0.0/16",
    "41.206.0.0/15",
    "41.210.0.0/15",
    "41.220.0.0/14",
    "41.226.0.0/15",
    "41.232.0.0/13",
    "41.248.0.0/13",
    "196.192.0.0/13",
    "196.210.0.0/15",
    "196.220.0.0/14",
    "196.47.0.0/16",
    "102.130.0.0/15",
    "102.140.0.0/14",
    "102.176.0.0/13",
    "102.200.0.0/13",
    "102.216.0.0/13",
    "105.16.0.0/12",
    "105.64.0.0/11",
    "105.96.0.0/11",
    "105.128.0.0/11",
    "105.160.0.0/11",
    "105.192.0.0/11",
    "105.224.0.0/12",
]

_PROXY_PORTS = [8080, 3128, 1080, 8888, 80, 8118, 3129, 8081, 8000, 9090]

_PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://proxylist.geonode.com/api/proxy-list?limit=200&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https",
    "https://api.openproxylist.xyz/http.txt",
]

_VERIFY_URLS = [
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://checkip.amazonaws.com",
]

_TOR_EXIT_NODE_PREFIXES = [
    "185.220.", "199.249.", "204.8.", "66.220.", "176.10.",
    "46.165.", "77.109.", "192.42.", "162.247.", "171.25.",
    "193.11.", "131.188.", "213.141.", "212.21.", "109.70.",
]


@dataclass
class ProxyEntry:
    host: str
    port: int
    latency: float = 9999.0
    alive: bool = False
    anonymous: bool = False
    https_ok: bool = False
    last_checked: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    source: str = ""

    def score(self) -> float:
        if not self.alive:
            return 0.0
        base = 1.0 / max(self.latency, 0.01)
        bonus = 0.3 if self.anonymous else 0.0
        https_bonus = 0.2 if self.https_ok else 0.0
        reliability = self.success_count / max(self.success_count + self.fail_count, 1)
        return base + bonus + https_bonus + reliability

    def address(self) -> str:
        return f"{self.host}:{self.port}"


def _is_datacenter_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _DATACENTER_RANGES:
            if addr in net:
                return True
    except ValueError:
        return True
    return False


def _is_tor_exit(ip_str: str) -> bool:
    for prefix in _TOR_EXIT_NODE_PREFIXES:
        if ip_str.startswith(prefix):
            return True
    return False


def _tcp_connect(host: str, port: int, timeout: float = 3.0) -> float:
    if _FASTER_LIB is not None:
        t_ms = int(timeout * 1000)
        result = _FASTER_LIB.tcp_connect_test(
            host.encode(), port, t_ms
        )
        if result < 0:
            return -1.0
        return result / 1000.0
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return time.monotonic() - start
    except Exception:
        return -1.0


def _batch_tcp_connect(entries: List[Tuple[str, int]], timeout: float = 3.0) -> List[float]:
    if _FASTER_LIB is not None and entries:
        n = len(entries)
        hosts_arr = (ctypes.c_char_p * n)(*(e[0].encode() for e in entries))
        ports_arr = (ctypes.c_int * n)(*(e[1] for e in entries))
        results_arr = (ctypes.c_int * n)(*([0] * n))
        t_ms = int(timeout * 1000)
        _FASTER_LIB.batch_tcp_test(hosts_arr, ports_arr, n, t_ms, results_arr)
        return [r / 1000.0 if r >= 0 else -1.0 for r in results_arr]
    results = []
    for host, port in entries:
        results.append(_tcp_connect(host, port, timeout))
    return results


def _http_probe(host: str, port: int, timeout: float = 5.0) -> Tuple[bool, bool, float]:
    url = random.choice(_VERIFY_URLS)
    proxy_url = f"http://{host}:{port}"
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(proxy_handler)
    opener.addheaders = [("User-Agent", "Mozilla/5.0")]
    start = time.monotonic()
    try:
        with opener.open(url, timeout=timeout) as resp:
            body = resp.read(512).decode("utf-8", errors="ignore")
            latency = time.monotonic() - start
            anonymous = "x-forwarded-for" not in str(resp.headers).lower()
            return True, anonymous, latency
    except Exception:
        return False, False, 9999.0


def _https_probe(host: str, port: int, timeout: float = 6.0) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        connect_req = f"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n"
        raw.sendall(connect_req.encode())
        raw.settimeout(timeout)
        resp = raw.recv(256).decode("utf-8", errors="ignore")
        raw.close()
        return "200" in resp
    except Exception:
        return False


def _full_verify(entry: ProxyEntry) -> ProxyEntry:
    latency = _tcp_connect(entry.host, entry.port, timeout=3.0)
    if latency < 0:
        entry.alive = False
        entry.last_checked = time.monotonic()
        return entry

    alive, anonymous, http_latency = _http_probe(entry.host, entry.port, timeout=6.0)
    entry.alive = alive
    entry.anonymous = anonymous
    entry.latency = http_latency if alive else 9999.0
    entry.last_checked = time.monotonic()

    if alive:
        entry.https_ok = _https_probe(entry.host, entry.port, timeout=6.0)
        entry.success_count += 1
    else:
        entry.fail_count += 1

    return entry


def _generate_residential_ip() -> str:
    cidr = random.choice(_RESIDENTIAL_CIDRS)
    net = ipaddress.ip_network(cidr, strict=False)
    host_bits = net.max_prefixlen - net.prefixlen
    rand_host = random.randint(1, (1 << host_bits) - 2)
    ip = net.network_address + rand_host
    return str(ip)


def _scrape_proxy_source(url: str, timeout: float = 10.0) -> List[Tuple[str, int]]:
    results: List[Tuple[str, int]] = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1024 * 512).decode("utf-8", errors="ignore")
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                parts = line.split(":")
                host = parts[0].strip()
                try:
                    port = int(parts[1].strip().split()[0])
                except Exception:
                    continue
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    continue
                if not _is_datacenter_ip(host) and not _is_tor_exit(host):
                    results.append((host, port))
    except Exception:
        pass
    return results


class EvilProxyPool:
    def __init__(
        self,
        min_pool_size: int = 10,
        max_pool_size: int = 200,
        harvest_workers: int = 8,
        verify_workers: int = 50,
        recheck_interval: float = 120.0,
        max_latency: float = 8.0,
        require_anonymous: bool = False,
        require_https: bool = False,
        scan_residential: bool = True,
        residential_batch: int = 500,
    ):
        self._min_pool = min_pool_size
        self._max_pool = max_pool_size
        self._harvest_workers = harvest_workers
        self._verify_workers = verify_workers
        self._recheck_interval = recheck_interval
        self._max_latency = max_latency
        self._require_anonymous = require_anonymous
        self._require_https = require_https
        self._scan_residential = scan_residential
        self._residential_batch = residential_batch

        self._pool: Dict[str, ProxyEntry] = {}
        self._pool_lock = threading.RLock()

        self._verify_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._ready_entries: List[ProxyEntry] = []
        self._ready_lock = threading.Lock()

        self._seen_addresses: Set[str] = set()
        self._seen_lock = threading.Lock()

        self._request_counter = 0
        self._counter_lock = threading.Lock()
        self._assigned: Dict[int, ProxyEntry] = {}
        self._assigned_lock = threading.Lock()

        self._running = False
        self._threads: List[threading.Thread] = []

        self._stats = {
            "harvested": 0,
            "verified_ok": 0,
            "verified_fail": 0,
            "requests_served": 0,
        }
        self._stats_lock = threading.Lock()

    def start(self):
        self._running = True
        for _ in range(self._verify_workers):
            t = threading.Thread(target=self._verify_worker, daemon=True)
            t.start()
            self._threads.append(t)

        t = threading.Thread(target=self._harvest_loop, daemon=True)
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self._recheck_loop, daemon=True)
        t.start()
        self._threads.append(t)

        t = threading.Thread(target=self._pool_guardian, daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        self._running = False

    def _add_to_verify(self, host: str, port: int, source: str = ""):
        addr = f"{host}:{port}"
        with self._seen_lock:
            if addr in self._seen_addresses:
                return
            self._seen_addresses.add(addr)
        entry = ProxyEntry(host=host, port=port, source=source)
        try:
            self._verify_queue.put_nowait(entry)
        except queue.Full:
            pass

    def _verify_worker(self):
        while self._running:
            try:
                entry = self._verify_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            entry = _full_verify(entry)
            if entry.alive and entry.latency <= self._max_latency:
                if self._require_anonymous and not entry.anonymous:
                    with self._stats_lock:
                        self._stats["verified_fail"] += 1
                    continue
                if self._require_https and not entry.https_ok:
                    with self._stats_lock:
                        self._stats["verified_fail"] += 1
                    continue
                with self._pool_lock:
                    if len(self._pool) < self._max_pool:
                        self._pool[entry.address()] = entry
                with self._ready_lock:
                    self._ready_entries.append(entry)
                    self._ready_entries.sort(key=lambda e: e.score(), reverse=True)
                with self._stats_lock:
                    self._stats["verified_ok"] += 1
            else:
                with self._stats_lock:
                    self._stats["verified_fail"] += 1

    def _harvest_from_sources(self):
        for url in _PROXY_SOURCES:
            if not self._running:
                break
            pairs = _scrape_proxy_source(url)
            with self._stats_lock:
                self._stats["harvested"] += len(pairs)
            for host, port in pairs:
                self._add_to_verify(host, port, source="scrape")

    def _harvest_residential_scan(self):
        batch_size = 100
        candidates = []
        for _ in range(self._residential_batch):
            ip = _generate_residential_ip()
            port = random.choice(_PROXY_PORTS)
            candidates.append((ip, port))

        pairs = [(h, p) for h, p in candidates]
        latencies = _batch_tcp_connect(pairs, timeout=2.0)

        for i, latency in enumerate(latencies):
            if latency > 0:
                host, port = pairs[i]
                self._add_to_verify(host, port, source="residential_scan")

    def _harvest_loop(self):
        while self._running:
            with self._ready_lock:
                current_size = len(self._ready_entries)

            if current_size < self._min_pool * 3:
                threads = []
                t = threading.Thread(target=self._harvest_from_sources, daemon=True)
                threads.append(t)
                t.start()

                if self._scan_residential:
                    t2 = threading.Thread(target=self._harvest_residential_scan, daemon=True)
                    threads.append(t2)
                    t2.start()

                for t in threads:
                    t.join(timeout=60)

            time.sleep(5.0)

    def _recheck_loop(self):
        while self._running:
            time.sleep(self._recheck_interval)
            if not self._running:
                break
            with self._ready_lock:
                entries = list(self._ready_entries)

            def recheck(entry: ProxyEntry):
                updated = _full_verify(entry)
                if not updated.alive or updated.latency > self._max_latency:
                    with self._pool_lock:
                        self._pool.pop(updated.address(), None)
                    with self._ready_lock:
                        try:
                            self._ready_entries.remove(entry)
                        except ValueError:
                            pass
                else:
                    with self._pool_lock:
                        self._pool[updated.address()] = updated
                    with self._ready_lock:
                        for i, e in enumerate(self._ready_entries):
                            if e.address() == updated.address():
                                self._ready_entries[i] = updated
                                break
                    with self._ready_lock:
                        self._ready_entries.sort(key=lambda e: e.score(), reverse=True)

            workers = []
            for entry in entries:
                t = threading.Thread(target=recheck, args=(entry,), daemon=True)
                workers.append(t)
                t.start()
                if len(workers) >= self._verify_workers:
                    for w in workers:
                        w.join(timeout=15)
                    workers = []
            for w in workers:
                w.join(timeout=15)

    def _pool_guardian(self):
        while self._running:
            time.sleep(3.0)
            with self._ready_lock:
                size = len(self._ready_entries)
            if size < self._min_pool:
                t = threading.Thread(target=self._harvest_from_sources, daemon=True)
                t.start()
                if self._scan_residential:
                    t2 = threading.Thread(target=self._harvest_residential_scan, daemon=True)
                    t2.start()

    def _pick_entry(self) -> Optional[ProxyEntry]:
        with self._ready_lock:
            alive = [e for e in self._ready_entries if e.alive and e.latency <= self._max_latency]
            if not alive:
                return None
            top = alive[:max(10, len(alive) // 3)]
            return random.choice(top)

    def get_proxy_for_request(self, request_id: Optional[int] = None) -> Optional[ProxyEntry]:
        if request_id is None:
            with self._counter_lock:
                self._request_counter += 1
                request_id = self._request_counter

        with self._assigned_lock:
            if request_id in self._assigned:
                return self._assigned[request_id]

        entry = self._pick_entry()
        if entry is None:
            return None

        with self._assigned_lock:
            self._assigned[request_id] = entry
            if len(self._assigned) > 10000:
                oldest = sorted(self._assigned.keys())[:5000]
                for k in oldest:
                    del self._assigned[k]

        with self._stats_lock:
            self._stats["requests_served"] += 1

        return entry

    def release_request(self, request_id: int, success: bool = True):
        with self._assigned_lock:
            entry = self._assigned.pop(request_id, None)
        if entry is None:
            return
        addr = entry.address()
        with self._pool_lock:
            stored = self._pool.get(addr)
            if stored:
                if success:
                    stored.success_count += 1
                else:
                    stored.fail_count += 1
                    if stored.fail_count >= 3 and stored.fail_count > stored.success_count:
                        del self._pool[addr]
                        with self._ready_lock:
                            try:
                                self._ready_entries.remove(stored)
                            except ValueError:
                                pass
                        with self._seen_lock:
                            self._seen_addresses.discard(addr)

    def create_connection(self, host: str, port: int, request_id: Optional[int] = None, timeout: float = 15.0) -> socket.socket:
        if request_id is None:
            with self._counter_lock:
                self._request_counter += 1
                request_id = self._request_counter

        entry = self.get_proxy_for_request(request_id)
        if entry is None:
            raise ConnectionError("No alive proxy available in pool")

        try:
            sock = socket.create_connection((entry.host, entry.port), timeout=timeout)
            connect_req = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Proxy-Connection: keep-alive\r\n\r\n"
            )
            sock.sendall(connect_req.encode())
            sock.settimeout(timeout)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(256)
                if not chunk:
                    break
                resp += chunk
            if b"200" not in resp:
                sock.close()
                self.release_request(request_id, success=False)
                raise ConnectionError(f"Proxy CONNECT failed: {resp[:64]}")
            self.release_request(request_id, success=True)
            return sock
        except Exception as exc:
            self.release_request(request_id, success=False)
            raise ConnectionError(f"Proxy connection error: {exc}")

    def get_proxy_dict(self, request_id: Optional[int] = None) -> Optional[Dict[str, str]]:
        entry = self.get_proxy_for_request(request_id)
        if entry is None:
            return None
        url = f"http://{entry.host}:{entry.port}"
        return {"http": url, "https": url}

    def pool_size(self) -> int:
        with self._ready_lock:
            return len([e for e in self._ready_entries if e.alive])

    def stats(self) -> Dict:
        with self._stats_lock:
            s = dict(self._stats)
        s["pool_size"] = self.pool_size()
        s["queue_size"] = self._verify_queue.qsize()
        return s

    def wait_until_ready(self, min_proxies: int = 5, timeout: float = 120.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.pool_size() >= min_proxies:
                return True
            time.sleep(0.5)
        return False