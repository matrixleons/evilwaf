from __future__ import annotations

import random
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import h2.config
    import h2.connection
    import h2.settings
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


@dataclass
class H2Profile:
    name: str
    user_agent: str
    settings: Dict[int, int]
    window_update_increment: int
    header_order: List[str]
    pseudo_header_order: List[str]
    initial_stream_window: int
    enable_push: int
    header_table_size: int
    max_frame_size: int
    max_header_list_size: Optional[int]
    priority_weight: int
    priority_depends_on: int
    priority_exclusive: bool
    padding: bool


_SETTINGS_HEADER_TABLE_SIZE    = 0x1
_SETTINGS_ENABLE_PUSH          = 0x2
_SETTINGS_INITIAL_WINDOW_SIZE  = 0x4
_SETTINGS_MAX_FRAME_SIZE       = 0x5
_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

_PROFILES: Dict[str, H2Profile] = {
    "chrome120": H2Profile(
        name="chrome120",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  6291456,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=[
            ":method", ":authority", ":scheme", ":path",
            "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "upgrade-insecure-requests",
            "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
            "accept-language",
        ],
        pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
        initial_stream_window=6291456,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=262144,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "chrome119": H2Profile(
        name="chrome119",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  6291456,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=[
            ":method", ":authority", ":scheme", ":path",
            "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "upgrade-insecure-requests",
            "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
            "accept-language",
        ],
        pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
        initial_stream_window=6291456,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=262144,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "firefox121": H2Profile(
        name="firefox121",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  131072,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 65536,
        },
        window_update_increment=12517377,
        header_order=[
            ":method", ":path", ":authority", ":scheme",
            "user-agent", "accept", "accept-language",
            "accept-encoding", "connection",
        ],
        pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
        initial_stream_window=131072,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=65536,
        priority_weight=42,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "firefox120": H2Profile(
        name="firefox120",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  131072,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 65536,
        },
        window_update_increment=12517377,
        header_order=[
            ":method", ":path", ":authority", ":scheme",
            "user-agent", "accept", "accept-language",
            "accept-encoding", "connection",
        ],
        pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
        initial_stream_window=131072,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=65536,
        priority_weight=42,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "safari17": H2Profile(
        name="safari17",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    4096,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  2097152,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
        },
        window_update_increment=10485760,
        header_order=[
            ":method", ":scheme", ":path", ":authority",
            "accept", "user-agent", "accept-language",
            "accept-encoding",
        ],
        pseudo_header_order=[":method", ":scheme", ":path", ":authority"],
        initial_stream_window=2097152,
        enable_push=0,
        header_table_size=4096,
        max_frame_size=16384,
        max_header_list_size=None,
        priority_weight=16,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "safari16": H2Profile(
        name="safari16",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    4096,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  2097152,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
        },
        window_update_increment=10485760,
        header_order=[
            ":method", ":scheme", ":path", ":authority",
            "accept", "user-agent", "accept-language",
            "accept-encoding",
        ],
        pseudo_header_order=[":method", ":scheme", ":path", ":authority"],
        initial_stream_window=2097152,
        enable_push=0,
        header_table_size=4096,
        max_frame_size=16384,
        max_header_list_size=None,
        priority_weight=16,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "edge120": H2Profile(
        name="edge120",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  6291456,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=[
            ":method", ":authority", ":scheme", ":path",
            "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "upgrade-insecure-requests",
            "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
            "accept-language",
        ],
        pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
        initial_stream_window=6291456,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=262144,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
    "chrome_android120": H2Profile(
        name="chrome_android120",
        user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        settings={
            _SETTINGS_HEADER_TABLE_SIZE:    65536,
            _SETTINGS_ENABLE_PUSH:          0,
            _SETTINGS_INITIAL_WINDOW_SIZE:  6291456,
            _SETTINGS_MAX_FRAME_SIZE:       16384,
            _SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=[
            ":method", ":authority", ":scheme", ":path",
            "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "upgrade-insecure-requests",
            "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-dest", "accept-encoding", "accept-language",
        ],
        pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
        initial_stream_window=6291456,
        enable_push=0,
        header_table_size=65536,
        max_frame_size=16384,
        max_header_list_size=262144,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=False,
    ),
}

_PROFILE_GROUPS = {
    "chrome":  ["chrome120", "chrome119", "edge120", "chrome_android120"],
    "firefox": ["firefox121", "firefox120"],
    "safari":  ["safari17", "safari16"],
    "all":     list(_PROFILES.keys()),
}


def get_profile(name: str) -> Optional[H2Profile]:
    return _PROFILES.get(name)


def list_profiles() -> List[str]:
    return list(_PROFILES.keys())


class H2FingerprintRotator:
    def __init__(
        self,
        profiles: Optional[List[str]] = None,
        strategy: str = "weighted_random",
        lock_per_host: bool = True,
    ):
        if profiles:
            self._profiles = [_PROFILES[p] for p in profiles if p in _PROFILES]
        else:
            self._profiles = list(_PROFILES.values())

        if not self._profiles:
            self._profiles = list(_PROFILES.values())

        self._strategy = strategy
        self._lock_per_host = lock_per_host

        self._host_map: Dict[str, H2Profile] = {}
        self._host_lock = threading.Lock()

        self._round_robin_idx = 0
        self._rr_lock = threading.Lock()

        self._request_count = 0
        self._count_lock = threading.Lock()

        self._last_profile: Optional[H2Profile] = None

    def _pick(self) -> H2Profile:
        if self._strategy == "round_robin":
            with self._rr_lock:
                p = self._profiles[self._round_robin_idx % len(self._profiles)]
                self._round_robin_idx += 1
                return p
        if self._strategy == "weighted_random":
            weights = []
            for p in self._profiles:
                if p.name.startswith("chrome"):
                    weights.append(50)
                elif p.name.startswith("firefox"):
                    weights.append(30)
                elif p.name.startswith("safari"):
                    weights.append(15)
                else:
                    weights.append(5)
            return random.choices(self._profiles, weights=weights, k=1)[0]
        return random.choice(self._profiles)

    def get_profile_for_host(self, host: str) -> H2Profile:
        if self._lock_per_host:
            with self._host_lock:
                if host not in self._host_map:
                    self._host_map[host] = self._pick()
                return self._host_map[host]
        return self._pick()

    def rotate_host(self, host: str) -> H2Profile:
        with self._host_lock:
            profile = self._pick()
            self._host_map[host] = profile
            return profile

    def get_profile_for_request(self) -> H2Profile:
        with self._count_lock:
            self._request_count += 1
        profile = self._pick()
        self._last_profile = profile
        return profile

    def clear_host(self, host: str):
        with self._host_lock:
            self._host_map.pop(host, None)

    def identifier(self) -> str:
        if self._last_profile:
            return self._last_profile.name
        return "none"


def build_h2_settings(profile: H2Profile) -> Dict[int, int]:
    s = {
        _SETTINGS_HEADER_TABLE_SIZE:   profile.header_table_size,
        _SETTINGS_ENABLE_PUSH:         profile.enable_push,
        _SETTINGS_INITIAL_WINDOW_SIZE: profile.initial_stream_window,
        _SETTINGS_MAX_FRAME_SIZE:      profile.max_frame_size,
    }
    if profile.max_header_list_size is not None:
        s[_SETTINGS_MAX_HEADER_LIST_SIZE] = profile.max_header_list_size
    return s


def reorder_headers(
    headers: List[Tuple[str, str]],
    profile: H2Profile,
) -> List[Tuple[str, str]]:
    pseudo = {k: v for k, v in headers if k.startswith(":")}
    regular = {k: v for k, v in headers if not k.startswith(":")}

    ordered: List[Tuple[str, str]] = []

    for key in profile.pseudo_header_order:
        if key in pseudo:
            ordered.append((key, pseudo[key]))

    for pseudo_key in pseudo:
        if pseudo_key not in profile.pseudo_header_order:
            ordered.append((pseudo_key, pseudo[pseudo_key]))

    added_regular = set()
    for key in profile.header_order:
        if key in regular and key not in added_regular:
            ordered.append((key, regular[key]))
            added_regular.add(key)

    for key, val in regular.items():
        if key not in added_regular:
            ordered.append((key, val))

    return ordered


def inject_browser_headers(
    headers: List[Tuple[str, str]],
    profile: H2Profile,
    host: str,
    path: str,
    scheme: str = "https",
) -> List[Tuple[str, str]]:
    existing = {k.lower() for k, _ in headers}
    extra: List[Tuple[str, str]] = []

    if "user-agent" not in existing:
        extra.append(("user-agent", profile.user_agent))

    if "accept" not in existing:
        if profile.name.startswith("firefox"):
            extra.append(("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"))
        elif profile.name.startswith("safari"):
            extra.append(("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
        else:
            extra.append(("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"))

    if "accept-encoding" not in existing:
        extra.append(("accept-encoding", "gzip, deflate, br"))

    if "accept-language" not in existing:
        extra.append(("accept-language", "en-US,en;q=0.9"))

    if profile.name.startswith(("chrome", "edge")):
        if "sec-ch-ua" not in existing:
            if "chrome120" in profile.name or "edge120" in profile.name:
                extra.append(("sec-ch-ua", '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'))
            else:
                extra.append(("sec-ch-ua", '"Not_A Brand";v="8", "Chromium";v="119", "Google Chrome";v="119"'))
        if "sec-ch-ua-mobile" not in existing:
            mobile = "?1" if "android" in profile.name else "?0"
            extra.append(("sec-ch-ua-mobile", mobile))
        if "sec-ch-ua-platform" not in existing:
            platform = '"Android"' if "android" in profile.name else '"Windows"'
            extra.append(("sec-ch-ua-platform", platform))
        if "sec-fetch-site" not in existing:
            extra.append(("sec-fetch-site", "none"))
        if "sec-fetch-mode" not in existing:
            extra.append(("sec-fetch-mode", "navigate"))
        if "sec-fetch-user" not in existing:
            extra.append(("sec-fetch-user", "?1"))
        if "sec-fetch-dest" not in existing:
            extra.append(("sec-fetch-dest", "document"))
        if "upgrade-insecure-requests" not in existing:
            extra.append(("upgrade-insecure-requests", "1"))

    combined = list(headers) + extra
    return reorder_headers(combined, profile)


def patch_h2_connection(conn: "h2.connection.H2Connection", profile: H2Profile):
    if not H2_AVAILABLE:
        return
    try:
        conn.local_settings.header_table_size   = profile.header_table_size
        conn.local_settings.enable_push         = profile.enable_push
        conn.local_settings.initial_window_size = profile.initial_stream_window
        conn.local_settings.max_frame_size      = profile.max_frame_size
        if profile.max_header_list_size is not None:
            conn.local_settings.max_header_list_size = profile.max_header_list_size
    except Exception:
        pass


def make_h2_config(profile: H2Profile, client_side: bool = True) -> "h2.config.H2Configuration":
    if not H2_AVAILABLE:
        raise RuntimeError("h2 library not available")
    cfg = h2.config.H2Configuration(
        client_side=client_side,
        header_encoding="utf-8",
    )
    return cfg


def apply_window_update(conn: "h2.connection.H2Connection", profile: H2Profile, flush_fn=None):
    if not H2_AVAILABLE:
        return
    try:
        conn.increment_flow_control_window(profile.window_update_increment)
        if flush_fn:
            flush_fn()
    except Exception:
        pass


@dataclass
class FingerprintResult:
    profile_name: str
    settings: Dict[int, int]
    window_update: int
    pseudo_header_order: List[str]
    user_agent: str
    headers_applied: List[Tuple[str, str]] = field(default_factory=list)


def fingerprint_request(
    rotator: H2FingerprintRotator,
    host: str,
    method: str,
    path: str,
    scheme: str,
    raw_headers: List[Tuple[str, str]],
    per_host: bool = True,
) -> FingerprintResult:
    if per_host:
        profile = rotator.get_profile_for_host(host)
    else:
        profile = rotator.get_profile_for_request()

    base = [
        (":method",    method),
        (":authority", host),
        (":scheme",    scheme),
        (":path",      path),
    ]
    for k, v in raw_headers:
        if not k.startswith(":"):
            base.append((k, v))

    final_headers = inject_browser_headers(base, profile, host, path, scheme)

    return FingerprintResult(
        profile_name=profile.name,
        settings=build_h2_settings(profile),
        window_update=profile.window_update_increment,
        pseudo_header_order=profile.pseudo_header_order,
        user_agent=profile.user_agent,
        headers_applied=final_headers,
    )