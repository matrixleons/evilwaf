from scapy.all import IP, TCP, sr1
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Union

@dataclass
class TCPOptionsManipulator:

    mss_values: List[int] = field(default_factory=lambda: [
        1460,
        1440,
        1360,
        1380,
        1452,
        8960,
        9000,
        1412,
        1500,
        1492
    ])

    window_scales: List[int] = field(default_factory=lambda: [
        8,
        7,
        6,
        5,
        4,
        3,
        2,
        1,
        0
    ])

    window_sizes: List[int] = field(default_factory=lambda: [
        65535,
        65392,
        64240,
        29200,
        43690,
        26883,
        32768,
        16384,
        8192
    ])

    _last_profile: Optional[str] = field(default=None, init=False, repr=False)
    _rotation_counter: int = field(default=0, init=False, repr=False)

    def _build_profile(
        self,
        mss: int,
        sack: bool,
        wscale: Optional[int],
        ts: Optional[Tuple[int, int]],
        nop_count: int,
        window: int
    ) -> Dict:
        opts = []
        opts.append(('MSS', mss))
        if sack:
            opts.append(('SAckOK', b''))
        if ts:
            opts.append(('Timestamp', ts))
        if wscale is not None:
            opts.append(('WScale', wscale))
        for _ in range(nop_count):
            opts.append(('NOP', None))
        return {
            "options": opts,
            "window": window
        }

    def chrome_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=8,
            ts=(random.randint(100000, 999999), 0),
            nop_count=1,
            window=65535
        )

    def firefox_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=7,
            ts=(random.randint(100000, 999999), 0),
            nop_count=1,
            window=65535
        )

    def safari_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=6,
            ts=(random.randint(50000, 500000), 0),
            nop_count=0,
            window=65392
        )

    def edge_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=8,
            ts=(random.randint(100000, 999999), 0),
            nop_count=1,
            window=64240
        )

    def linux_kernel_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=7,
            ts=(random.randint(1000000, 9999999), 0),
            nop_count=0,
            window=29200
        )

    def windows_11_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=8,
            ts=None,
            nop_count=1,
            window=64240
        )

    def macos_ventura_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=6,
            ts=(random.randint(50000, 500000), 0),
            nop_count=0,
            window=65392
        )

    def android_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=8,
            ts=(random.randint(100000, 999999), 0),
            nop_count=0,
            window=65535
        )

    def ios_profile(self) -> Dict:
        return self._build_profile(
            mss=1460,
            sack=True,
            wscale=6,
            ts=(random.randint(50000, 500000), 0),
            nop_count=0,
            window=65535
        )

    def _all_profiles(self) -> Dict[str, callable]:
        return {
            "chrome": self.chrome_profile,
            "firefox": self.firefox_profile,
            "safari": self.safari_profile,
            "edge": self.edge_profile,
            "linux": self.linux_kernel_profile,
            "windows11": self.windows_11_profile,
            "macos": self.macos_ventura_profile,
            "android": self.android_profile,
            "ios": self.ios_profile
        }

    def get_profile(self, name: Optional[str] = None) -> Dict:
        profiles = self._all_profiles()
        if name and name in profiles:
            self._last_profile = name
            return profiles[name]()
        chosen = random.choice(list(profiles.keys()))
        self._last_profile = chosen
        return profiles[chosen]()

    def rotate(self) -> Dict:
        profiles = self._all_profiles()
        keys = list(profiles.keys())
        if self._last_profile in keys:
            keys.remove(self._last_profile)
        chosen = random.choice(keys)
        self._last_profile = chosen
        self._rotation_counter += 1
        return profiles[chosen]()

    def send_syn(
        self,
        dst_ip: str,
        dst_port: int,
        profile_name: Optional[str] = None
    ) -> Optional[object]:
        profile = self.get_profile(profile_name)
        pkt = IP(dst=dst_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=dst_port,
            flags="S",
            seq=random.randint(0, 2**32 - 1),
            window=profile["window"],
            options=profile["options"]
        )
        resp = sr1(pkt, timeout=3, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == "SA":
            return resp
        return None

    def per_request_options(self) -> Dict:
        profile = self.rotate()
        return {
            "options": profile["options"],
            "window": profile["window"],
            "profile": self._last_profile,
            "rotation_count": self._rotation_counter
        }