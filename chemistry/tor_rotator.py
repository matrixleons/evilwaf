import random
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

import requests
from stem import Signal
from stem.control import Controller


TOR_PROXIES: List[Dict[str, str]] = [
    {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"},
    {"http": "socks5://127.0.0.1:9052", "https": "socks5://127.0.0.1:9052"},
    {"http": "socks5://127.0.0.1:9054", "https": "socks5://127.0.0.1:9054"},
    {"http": "socks5://127.0.0.1:9056", "https": "socks5://127.0.0.1:9056"},
    {"http": "socks5://127.0.0.1:9058", "https": "socks5://127.0.0.1:9058"},
    {"http": "socks5://tor1:9050",       "https": "socks5://tor1:9050"},
    {"http": "socks5://tor2:9050",       "https": "socks5://tor2:9050"},
    {"http": "socks5://tor3:9050",       "https": "socks5://tor3:9050"},
    {"http": "socks5://tor4:9050",       "https": "socks5://tor4:9050"},
    {"http": "socks5://tor5:9050",       "https": "socks5://tor5:9050"},
    {"http": "socks5://tor6:9050",       "https": "socks5://tor6:9050"},
    {"http": "socks5://tor7:9050",       "https": "socks5://tor7:9050"},
    {"http": "socks5://tor8:9050",       "https": "socks5://tor8:9050"},
    {"http": "socks5://tor9:9050",       "https": "socks5://tor9:9050"},
    {"http": "socks5://tor10:9050",      "https": "socks5://tor10:9050"},
]

TOR_CONTROL_PORTS: List[int] = [
    9051, 9053, 9055, 9057, 9059,
    9061, 9063, 9065, 9067, 9069,
]


@dataclass
class TorRotator:
    tor_proxy: str = field(default="socks5://127.0.0.1:9050")
    control_port: int = field(default=9051)
    control_password: str = field(default="")
    min_rotate_interval: int = field(default=1)

    _rotation_counter: int = field(default=0, init=False, repr=False)
    _last_rotation_time: float = field(default=0.0, init=False, repr=False)
    _current_ip: Optional[str] = field(default=None, init=False, repr=False)
    _current_proxy_index: int = field(default=0, init=False, repr=False)
    _available_proxies: List[Dict[str, str]] = field(default_factory=list, init=False, repr=False)
    _available_control_ports: List[int] = field(default_factory=list, init=False, repr=False)
    _lock: object = field(default=None, init=False, repr=False)

    def __post_init__(self):
        import threading
        self._lock = threading.Lock()
        self._available_proxies = self._probe_proxies()
        self._available_control_ports = self._probe_control_ports()
        if not self._available_proxies:
            self._available_proxies = [{"http": self.tor_proxy, "https": self.tor_proxy}]
        if not self._available_control_ports:
            self._available_control_ports = [self.control_port]

    def _probe_proxies(self) -> List[Dict[str, str]]:
        alive = []
        for proxy in TOR_PROXIES:
            try:
                r = requests.get(
                    "https://check.torproject.org/api/ip",
                    proxies=proxy,
                    timeout=5,
                )
                if r.json().get("IsTor", False):
                    alive.append(proxy)
            except Exception:
                continue
        return alive

    def _probe_control_ports(self) -> List[int]:
        alive = []
        for port in TOR_CONTROL_PORTS:
            try:
                with Controller.from_port(port=port) as ctrl:
                    ctrl.authenticate(password=self.control_password)
                    alive.append(port)
            except Exception:
                continue
        return alive

    def _next_proxy(self) -> Dict[str, str]:
        with self._lock:
            if not self._available_proxies:
                return {"http": self.tor_proxy, "https": self.tor_proxy}
            proxy = self._available_proxies[self._current_proxy_index % len(self._available_proxies)]
            self._current_proxy_index += 1
            return proxy

    def _rotate_all_circuits(self) -> bool:
        rotated = False
        for port in self._available_control_ports:
            try:
                with Controller.from_port(port=port) as ctrl:
                    ctrl.authenticate(password=self.control_password)
                    ctrl.signal(Signal.NEWNYM)
                    rotated = True
            except Exception:
                continue
        return rotated

    def _controller(self) -> Controller:
        for port in self._available_control_ports:
            try:
                return Controller.from_port(port=port)
            except Exception:
                continue
        return Controller.from_port(port=self.control_port)

    def rotate_circuit(self) -> bool:
        now = time.time()
        elapsed = now - self._last_rotation_time
        if elapsed < self.min_rotate_interval:
            time.sleep(self.min_rotate_interval - elapsed)
        ok = self._rotate_all_circuits()
        if ok:
            with self._lock:
                self._rotation_counter += 1
                self._last_rotation_time = time.time()
                self._current_ip = None
        return ok

    def get_proxy_dict(self) -> Dict[str, str]:
        return self._next_proxy()

    def get_current_ip(self) -> Optional[str]:
        proxy = self._next_proxy()
        try:
            resp = requests.get(
                "https://api.ipify.org?format=json",
                proxies=proxy,
                timeout=10,
            )
            ip = resp.json().get("ip")
            with self._lock:
                self._current_ip = ip
            return ip
        except Exception:
            return None

    def is_tor_alive(self) -> bool:
        for proxy in self._available_proxies:
            try:
                resp = requests.get(
                    "https://check.torproject.org/api/ip",
                    proxies=proxy,
                    timeout=8,
                )
                if resp.json().get("IsTor", False):
                    return True
            except Exception:
                continue
        return False

    def rotate_and_verify(self, max_attempts: int = 3) -> Tuple[bool, Optional[str]]:
        prev_ip = self._current_ip
        for _ in range(max_attempts):
            ok = self.rotate_circuit()
            if not ok:
                continue
            time.sleep(random.uniform(1.0, 2.5))
            ip = self.get_current_ip()
            if ip and ip != prev_ip:
                with self._lock:
                    self._current_ip = ip
                return True, ip
        return False, self._current_ip

    def per_request_proxy(self) -> Dict:
        return {
            "proxies": self._next_proxy(),
            "rotation_count": self._rotation_counter,
            "current_ip": self._current_ip,
        }

    def should_rotate(self, request_count: int, rotate_every: int = 1) -> bool:
        return request_count % max(rotate_every, 1) == 0

    def get_stats(self) -> Dict:
        return {
            "available_proxies": len(self._available_proxies),
            "available_control_ports": len(self._available_control_ports),
            "rotation_count": self._rotation_counter,
            "current_ip": self._current_ip,
            "current_proxy_index": self._current_proxy_index,
        }