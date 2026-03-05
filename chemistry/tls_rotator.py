import random
import tls_client
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, List

@dataclass
class TLSFingerprinter:

    _session_counter: int = field(default=0, init=False, repr=False)
    _last_identifier: Optional[str] = field(default=None, init=False, repr=False)

    identifiers: List[str] = field(default_factory=lambda: [
        "chrome_120",
        "chrome_117",
        "chrome_116",
        "firefox_121",
        "firefox_120",
        "firefox_117",
        "safari_17_0",
        "safari_16_5",
        "edge_120",
        "edge_117",
        "opera_90",
        "opera_89",
    ])

    custom_profiles: List[Dict] = field(default_factory=lambda: [
        {
            "name": "chrome_android",
            "client_identifier": "chrome_120",
            "random_tls_extension_order": True,
            "force_http1": False,
            "alpn_protocols": [
                "h2",
                "http/1.1"
            ],
            "signature_algorithms": [
                "ECDSAWithP256AndSHA256",
                "PSSWithSHA256",
                "PKCS1WithSHA256",
                "ECDSAWithP384AndSHA384",
                "PSSWithSHA384",
                "PKCS1WithSHA384",
                "PSSWithSHA512",
                "PKCS1WithSHA512",
            ]
        },
        {
            "name": "firefox_linux",
            "client_identifier": "firefox_121",
            "random_tls_extension_order": False,
            "force_http1": False,
            "alpn_protocols": [
                "h2",
                "http/1.1"
            ],
            "signature_algorithms": [
                "ECDSAWithP256AndSHA256",
                "PSSWithSHA256",
                "PKCS1WithSHA256",
                "ECDSAWithP384AndSHA384",
                "PSSWithSHA384",
                "PKCS1WithSHA384",
                "PSSWithSHA512",
                "PKCS1WithSHA512",
            ]
        },
        {
            "name": "safari_ios",
            "client_identifier": "safari_17_0",
            "random_tls_extension_order": False,
            "force_http1": False,
            "alpn_protocols": [
                "h2",
                "h2c",
                "http/1.1"
            ],
            "signature_algorithms": [
                "ECDSAWithP256AndSHA256",
                "PSSWithSHA256",
                "PKCS1WithSHA256",
                "ECDSAWithP384AndSHA384",
                "ECDSAWithP521AndSHA512",
                "PSSWithSHA384",
                "PSSWithSHA512",
                "PKCS1WithSHA384",
                "PKCS1WithSHA512",
            ]
        },
        {
            "name": "edge_windows",
            "client_identifier": "edge_120",
            "random_tls_extension_order": True,
            "force_http1": False,
            "alpn_protocols": [
                "h2",
                "http/1.1"
            ],
            "signature_algorithms": [
                "ECDSAWithP256AndSHA256",
                "PSSWithSHA256",
                "PKCS1WithSHA256",
                "ECDSAWithP384AndSHA384",
                "PSSWithSHA384",
                "PKCS1WithSHA384",
                "PSSWithSHA512",
                "PKCS1WithSHA512",
            ]
        },
    ])

    def _make_session(
        self,
        identifier: str,
        random_ext_order: bool = True
    ) -> tls_client.Session:
        self._session_counter += 1
        return tls_client.Session(
            client_identifier=identifier,
            random_tls_extension_order=random_ext_order
        )

    def get_session(
        self,
        identifier: Optional[str] = None
    ) -> Tuple[tls_client.Session, str]:
        if identifier and identifier in self.identifiers:
            self._last_identifier = identifier
            return self._make_session(identifier), identifier
        chosen = random.choice(self.identifiers)
        self._last_identifier = chosen
        return self._make_session(chosen), chosen

    def rotate(self) -> Tuple[tls_client.Session, str]:
        pool = self.identifiers.copy()
        if self._last_identifier in pool:
            pool.remove(self._last_identifier)
        chosen = random.choice(pool)
        self._last_identifier = chosen
        self._session_counter += 1
        return self._make_session(chosen), chosen

    def get_custom_session(
        self,
        profile_name: Optional[str] = None
    ) -> Tuple[tls_client.Session, str]:
        if profile_name:
            match = next(
                (p for p in self.custom_profiles if p["name"] == profile_name),
                None
            )
        else:
            match = random.choice(self.custom_profiles)

        if not match:
            return self.rotate()

        session = tls_client.Session(
            client_identifier=match["client_identifier"],
            random_tls_extension_order=match["random_tls_extension_order"]
        )
        self._last_identifier = match["name"]
        self._session_counter += 1
        return session, match["name"]

    def paired_with_tcp(self, tcp_profile_name: str) -> Tuple[tls_client.Session, str]:
        mapping = {
            "chrome": "chrome_120",
            "firefox": "firefox_121",
            "safari": "safari_17_0",
            "edge": "edge_120",
            "windows11": "edge_120",
            "macos": "safari_17_0",
            "linux": "firefox_121",
            "android": "chrome_120",
            "ios": "safari_17_0",
        }
        identifier = mapping.get(tcp_profile_name)
        if not identifier:
            return self.rotate()
        self._last_identifier = identifier
        return self._make_session(identifier, random_ext_order=True), identifier

    def per_request_session(self) -> Dict:
        session, identifier = self.rotate()
        return {
            "session": session,
            "identifier": identifier,
            "session_count": self._session_counter
        }