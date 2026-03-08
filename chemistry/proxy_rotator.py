import socket
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

import socks


@dataclass
class ProxyRotator:
    proxy_urls: List[str] = field(default_factory=list)

    _proxies: List[Dict] = field(default_factory=list, init=False, repr=False)
    _current_index: int = field(default=0, init=False, repr=False)
    _lock: object = field(default=None, init=False, repr=False)
    _rotation_counter: int = field(default=0, init=False, repr=False)

    SCHEME_MAP = {
        "socks5": socks.SOCKS5,
        "socks5h": socks.SOCKS5,
        "socks4": socks.SOCKS4,
        "socks4a": socks.SOCKS4,
        "http": socks.HTTP,
        "https": socks.HTTP,
    }

    def __post_init__(self):
        self._lock = threading.Lock()
        parsed = [self._parse_proxy_url(u) for u in self.proxy_urls]
        self._proxies = [p for p in parsed if p is not None]
        alive = self._probe_proxies()
        if alive:
            self._proxies = alive

    def _parse_proxy_url(self, url: str) -> Optional[Dict]:
        try:
            p = urlparse(url)
            scheme = (p.scheme or "socks5").lower()
            proxy_type = self.SCHEME_MAP.get(scheme)
            if proxy_type is None:
                return None
            port = p.port or (1080 if scheme.startswith("socks") else 8080)
            return {
                "type": proxy_type,
                "addr": p.hostname,
                "port": port,
                "username": p.username,
                "password": p.password,
                "url": url,
                "scheme": scheme,
            }
        except Exception:
            return None

    def _probe_proxies(self) -> List[Dict]:
        alive = []
        for proxy in self._proxies:
            try:
                s = socks.create_connection(
                    dest_pair=("check.torproject.org", 443),
                    timeout=10,
                    proxy_type=proxy["type"],
                    proxy_addr=proxy["addr"],
                    proxy_port=proxy["port"],
                    proxy_username=proxy.get("username"),
                    proxy_password=proxy.get("password"),
                )
                s.close()
                alive.append(proxy)
            except Exception:
                continue
        return alive

    def _next_proxy(self) -> Optional[Dict]:
        with self._lock:
            if not self._proxies:
                return None
            proxy = self._proxies[self._current_index % len(self._proxies)]
            self._current_index += 1
            self._rotation_counter += 1
            return proxy

    def create_connection(self, dest_host: str, dest_port: int, timeout: int = 15) -> socket.socket:
        proxy = self._next_proxy()
        if proxy is None:
            sock = socket.create_connection((dest_host, dest_port), timeout=timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        sock = socks.create_connection(
            dest_pair=(dest_host, dest_port),
            timeout=timeout,
            proxy_type=proxy["type"],
            proxy_addr=proxy["addr"],
            proxy_port=proxy["port"],
            proxy_username=proxy.get("username"),
            proxy_password=proxy.get("password"),
            socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
        )
        return sock

    def get_proxy_dict(self) -> Dict[str, str]:
        proxy = self._next_proxy()
        if proxy is None:
            return {}
        url = proxy["url"]
        return {"http": url, "https": url}

    def per_request_proxy(self) -> Dict:
        proxy = self._next_proxy()
        if proxy is None:
            return {"proxies": {}, "rotation_count": self._rotation_counter}
        url = proxy["url"]
        return {
            "proxies": {"http": url, "https": url},
            "rotation_count": self._rotation_counter,
        }

    def get_stats(self) -> Dict:
        return {
            "available_proxies": len(self._proxies),
            "rotation_count": self._rotation_counter,
            "current_index": self._current_index,
        }
