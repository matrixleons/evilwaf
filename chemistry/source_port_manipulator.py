# chemistry/source_port_manipulator.py

from __future__ import annotations

import random
import socket
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict

try:
    import _sport_fast
    _C_EXT_AVAILABLE = True
except ImportError:
    _C_EXT_AVAILABLE = False


_TRUSTED_PORTS = [80, 443, 53, 8080, 8443]

_PROFILES: Dict[str, Dict] = {
    "trusted": {
        "description": "Ports that appear as internal/trusted traffic",
        "ports":       _TRUSTED_PORTS,
        "randomize":   False,
    },
    "browser_linux": {
        "description": "Linux browser ephemeral range",
        "ports":       [],
        "range":       (32768, 60999),
        "randomize":   True,
    },
    "browser_windows": {
        "description": "Windows browser ephemeral range",
        "ports":       [],
        "range":       (49152, 65535),
        "randomize":   True,
    },
    "scanner_evasion": {
        "description": "Ports that appear as  legitimate scanner traffic",
        "ports":       [1024, 1025, 1026, 2048, 4096, 8192],
        "randomize":   True,
    },
    "rotating": {
        "description": "Rotate between trusted and  ephemeral — maximum evasion",
        "ports":       _TRUSTED_PORTS,
        "range":       (32768, 60999),
        "randomize":   True,
        "mix":         True,
    },
}


@dataclass
class PortManipulationResult:
    source_port:   int
    profile:       str
    success:       bool
    error:         Optional[str] = None
    bind_attempts: int           = 0


class SourcePortManipulator:
    """
    Manipulates TCP source port before each connection.
    """

    MAX_BIND_ATTEMPTS = 5

    def __init__(
        self,
        profile:         str           = "rotating",
        fixed_port:      Optional[int] = None,
        rotate_every:    int           = 1,
        fallback_random: bool          = True,
    ):
        if profile not in _PROFILES:
            raise ValueError(
                f"Unknown profile: {profile}. Choose: {list(_PROFILES)}"
            )

        self._profile_name    = profile
        self._profile         = _PROFILES[profile]
        self._fixed_port      = fixed_port
        self._rotate_every    = max(1, rotate_every)
        self._fallback_random = fallback_random

        self._request_count   = 0
        self._current_port    = 0
        self._last_port       = 0
        self._lock            = threading.Lock()
        self._used_ports: List[int] = []



    def next_port(self) -> int:
        """return the next source port according to the profile  ."""
        with self._lock:
            self._request_count += 1
            if self._fixed_port:
                self._current_port = self._fixed_port
                return self._current_port
            if (self._request_count % self._rotate_every == 0
                    or self._current_port == 0):
                self._current_port = self._select_port()
            return self._current_port

    def create_connection(
        self,
        host:    str,
        port:    int,
        timeout: int = 15,
    ) -> socket.socket:
        """
        create chosen TCP connection and source port 

        we use C extension automatically if present
        """
        src_port = self.next_port()

        if _C_EXT_AVAILABLE:
            return self._c_connect(host, port, src_port, timeout)

        return self._py_connect(host, port, src_port, timeout)

    def per_request_options(self) -> Dict:
        """TCPOptionsManipulator.per_request_options()."""
        port = self.next_port()
        return {
            "source_port": port,
            "profile":     self._profile_name,
            "c_ext":       _C_EXT_AVAILABLE,
        }

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "profile":       self._profile_name,
                "c_ext":         _C_EXT_AVAILABLE,
                "request_count": self._request_count,
                "current_port":  self._current_port,
                "last_port":     self._last_port,
                "used_ports":    list(self._used_ports[-10:]),
            }

    def rotate(self):
        """Force port rotation and use Magic.error_solver()."""
        with self._lock:
            self._current_port = 0



    def _c_connect(
        self,
        host:     str,
        port:     int,
        src_port: int,
        timeout:  int,
    ) -> socket.socket:
        """
        use  _sport_fast.connect() 

        _sport_fast.connect() return raw file descriptor (int).
        """
        try:
            fd = _sport_fast.connect(
                host,
                port,
                src_port,
                float(timeout),
                self.MAX_BIND_ATTEMPTS,
            )

            sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            # close original fd  — socket.fromfd() 
            try:
                import os
                os.close(fd)
            except OSError:
                pass

            with self._lock:
                self._last_port = src_port
                if src_port and src_port not in self._used_ports:
                    self._used_ports.append(src_port)
                if len(self._used_ports) > 200:
                    self._used_ports.pop(0)

            return sock

        except (ConnectionError, OSError):
            # C extension is failed  try  Python fallback
            if self._fallback_random:
                return self._py_connect(host, port, 0, timeout)
            raise



    def _py_connect(
        self,
        host:     str,
        port:     int,
        src_port: int,
        timeout:  int,
    ) -> socket.socket:
        """
        use Python fallback when C extension failed or not present 
        """
        result = self._bind_and_connect(host, port, src_port, timeout)

        if not result.success and self._fallback_random:
            result = self._bind_and_connect(host, port, 0, timeout)

        if not result.success:
            raise ConnectionError(
                f"SourcePortManipulator: connection failed — {result.error}"
            )

        return self._make_socket(host, port, result.source_port, timeout)

    def _bind_and_connect(
        self,
        host:     str,
        port:     int,
        src_port: int,
        timeout:  int,
    ) -> PortManipulationResult:
        attempts    = 0
        current     = src_port
        last_error  = ""

        while attempts < self.MAX_BIND_ATTEMPTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET,  socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,  1)
                sock.settimeout(timeout)

                if current:
                    sock.bind(("", current))
                sock.connect((host, port))
                sock.close()

                with self._lock:
                    self._last_port = current
                    if current and current not in self._used_ports:
                        self._used_ports.append(current)
                    if len(self._used_ports) > 200:
                        self._used_ports.pop(0)

                return PortManipulationResult(
                    source_port=current,
                    profile=self._profile_name,
                    success=True,
                    bind_attempts=attempts + 1,
                )

            except OSError as e:
                last_error = str(e)
                # Port is busy
                if e.errno in (98, 48, 10048):
                    attempts += 1
                    current = self._random_port_in_range(32768, 60999)
                    continue
                return PortManipulationResult(
                    source_port=current,
                    profile=self._profile_name,
                    success=False,
                    error=last_error,
                    bind_attempts=attempts + 1,
                )
            except Exception as e:
                return PortManipulationResult(
                    source_port=current,
                    profile=self._profile_name,
                    success=False,
                    error=str(e),
                    bind_attempts=attempts + 1,
                )

        return PortManipulationResult(
            source_port=current,
            profile=self._profile_name,
            success=False,
            error=f"Max attempts reached — last: {last_error}",
            bind_attempts=attempts,
        )

    def _make_socket(
        self,
        host:     str,
        port:     int,
        src_port: int,
        timeout:  int,
    ) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,  socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,  1)
        sock.settimeout(timeout)
        if src_port:
            sock.bind(("", src_port))
        sock.connect((host, port))
        return sock



    def _select_port(self) -> int:
        prof = self._profile

        if prof.get("mix"):
            if self._request_count % 2 == 0:
                return random.choice(_TRUSTED_PORTS)
            lo, hi = prof.get("range", (32768, 60999))
            return self._random_port_in_range(lo, hi)


        if prof["ports"] and not prof.get("randomize"):
            idx = self._request_count % len(prof["ports"])
            return prof["ports"][idx]


        if prof["ports"] and prof.get("randomize"):
            return random.choice(prof["ports"])


        if "range" in prof:
            lo, hi = prof["range"]
            return self._random_port_in_range(lo, hi)

        return 0

    def _random_port_in_range(self, lo: int, hi: int) -> int:
        attempts = 0
        while attempts < 20:
            port = random.randint(lo, hi)
            if port not in self._used_ports[-50:]:
                return port
            attempts += 1
        return random.randint(lo, hi)