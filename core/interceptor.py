from __future__ import annotations

import contextlib
import datetime
import ipaddress
import os
import random
import re
import select
import socket
import ssl
import string
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

try:
    import aioquic.quic.configuration
    import aioquic.quic.connection
    import aioquic.quic.events
    import asyncio
    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False

from chemistry.tcp_options import TCPOptionsManipulator
from chemistry.tls_rotator import TLSFingerprinter
from chemistry.tor_rotator import TorRotator
from chemistry.proxy_rotator import ProxyRotator
from chemistry.source_port_manipulator import SourcePortManipulator
from chemistry.http2_fingerprinter import H2FingerprintRotator, patch_h2_connection, apply_window_update, fingerprint_request
from chemistry.evil_proxy import EvilProxyPool




_CF_AIRPORTS = ["NBO", "LHR", "JFK", "LAX", "SIN", "DXB", "FRA", "CDG", "AMS", "SYD"]

_CF_IP_RANGES = [
    "103.21.244", "103.22.200", "103.31.4", "104.16.0", "104.17.0",
    "108.162.192", "131.0.72", "141.101.64", "162.158.0", "172.64.0",
    "173.245.48", "188.114.96", "190.93.240", "197.234.240", "198.41.128",
]


def _generate_cf_ray() -> str:
    chars = string.digits + "abcdef"
    ray_id = "".join(random.choices(chars, k=16))
    return f"{ray_id}-{random.choice(_CF_AIRPORTS)}"


def _generate_cf_connecting_ip() -> str:
    prefix = random.choice(_CF_IP_RANGES)
    return f"{prefix}.{random.randint(1, 254)}"


def _inject_cf_headers(hdrs: dict, visitor_ip: Optional[str] = None) -> dict:
    ip = visitor_ip or _generate_cf_connecting_ip()
    hdrs["CF-Connecting-IP"] = ip
    hdrs["X-Forwarded-For"] = ip
    hdrs["X-Forwarded-Proto"] = "https"
    hdrs["CF-RAY"] = _generate_cf_ray()
    hdrs["CF-Visitor"] = '{"scheme":"https"}'
    hdrs["CF-IPCountry"] = random.choice(["US", "GB", "DE", "FR", "SG", "AU", "JP"])
    hdrs["X-Real-IP"] = ip
    return hdrs


@dataclass
class InterceptedRequest:
    method: str = "GET"
    url: str = ""
    path: str = ""
    host: str = ""
    port: int = 80
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    cookies: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    timestamp: float = 0.0
    source_pid: Optional[int] = None
    source_tool: Optional[str] = None
    is_tunnel: bool = False
    is_https: bool = False
    sni_hostname: Optional[str] = None
    tls_version: Optional[str] = None
    http_version: str = "1.1"
    inject_cf_headers: bool = False


@dataclass
class InterceptedResponse:
    status_code: int = 0
    status_text: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    cookies: dict = field(default_factory=dict)
    response_time: float = 0.0
    timestamp: float = 0.0
    is_https: bool = False
    tls_version: Optional[str] = None
    http_version: str = "1.1"


@dataclass
class ProxyRecord:
    request: InterceptedRequest = field(default_factory=InterceptedRequest)
    response: InterceptedResponse = field(default_factory=InterceptedResponse)
    technique_applied: str = ""
    passed: bool = False
    blocked: bool = False
    total_time: float = 0.0
    intercepted_https: bool = False
    decryption_successful: bool = False


@dataclass
class AdvisorDecision:
    action: str = "forward"
    technique: str = ""
    delay: float = 0.0
    rotate_ip: bool = False
    reason: str = ""
    forward_response: bool = True
    next_protocol: Optional[str] = None


class CertificateAuthority:
    STORE_CAP = 150
    CA_EXPIRY = datetime.timedelta(days=10 * 365)
    CERT_EXPIRY = datetime.timedelta(days=365)

    def __init__(self, ca_dir: Optional[str] = None):
        self.ca_dir = ca_dir or tempfile.mkdtemp(prefix="evilwaf_ca_")
        self.ca_cert_path = os.path.join(self.ca_dir, "evilwaf-ca.pem")
        self.ca_key_path = os.path.join(self.ca_dir, "evilwaf-ca-key.pem")
        self.cert_cache: Dict[str, Tuple[str, str]] = {}
        self.expire_queue: List[str] = []
        self.cache_lock = threading.Lock()
        if not os.path.exists(self.ca_cert_path):
            self._create_ca()

    @staticmethod
    @contextlib.contextmanager
    def _umask_secret():
        original = os.umask(0)
        os.umask(original | 0o77)
        try:
            yield
        finally:
            os.umask(original)

    def _create_ca(self):
        ca_key = rsa.generate_private_key(65537, 4096, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EvilWAF MITM Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "evilwaf-ca"),
        ])
        now = datetime.datetime.utcnow()
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + self.CA_EXPIRY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        with self._umask_secret():
            with open(self.ca_cert_path, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(self.ca_key_path, "wb") as f:
                f.write(ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))

    def export_ca_certificates(self, export_dir: Optional[str] = None) -> Dict[str, str]:
        export_dir = export_dir or self.ca_dir
        export_path = os.path.join(export_dir, "evilwaf-ca-cert.pem")
        p12_path = os.path.join(export_dir, "evilwaf-ca.p12")
        cer_path = os.path.join(export_dir, "evilwaf-ca.cer")
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
        for p in [export_path, cer_path]:
            with open(p, "wb") as f:
                f.write(ca_cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
        with open(self.ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), None, default_backend())
        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"EvilWAF CA", key=ca_key, cert=ca_cert,
            cas=None, encryption_algorithm=serialization.NoEncryption()
        )
        with open(p12_path, "wb") as f:
            f.write(p12_data)
        return {"pem": export_path, "p12": p12_path, "cer": cer_path}

    @staticmethod
    def _asterisk_forms(hostname: str) -> List[str]:
        if not hostname:
            return ["*"]
        parts = hostname.split(".")
        forms = [hostname]
        for i in range(1, len(parts)):
            forms.append("*." + ".".join(parts[i:]))
        forms.append("*")
        return forms

    def _create_san_extension(self, hostname: str) -> x509.SubjectAlternativeName:
        sans = []
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            try:
                idn = hostname.encode("idna").decode("ascii")
            except Exception:
                idn = hostname
            sans.append(x509.DNSName(idn))
            if hostname.count(".") > 1:
                wc = "*." + ".".join(hostname.split(".")[1:])
                try:
                    sans.append(x509.DNSName(wc.encode("idna").decode("ascii")))
                except Exception:
                    pass
        return x509.SubjectAlternativeName(sans)

    def get_certificate_for_host(self, hostname: str) -> Tuple[str, str]:
        with self.cache_lock:
            for form in self._asterisk_forms(hostname):
                if form in self.cert_cache:
                    return self.cert_cache[form]
            cert_path, key_path = self._generate_host_certificate(hostname)
            self.cert_cache[hostname] = (cert_path, key_path)
            self.expire_queue.append(hostname)
            if len(self.expire_queue) > self.STORE_CAP:
                expired = self.expire_queue.pop(0)
                if expired in self.cert_cache:
                    old_cert, _ = self.cert_cache.pop(expired)
                    try:
                        import shutil
                        shutil.rmtree(os.path.dirname(old_cert), ignore_errors=True)
                    except Exception:
                        pass
            return cert_path, key_path

    def _generate_host_certificate(self, hostname: str) -> Tuple[str, str]:
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(self.ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), None, default_backend())
        host_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject_attrs = []
        is_valid_cn = bool(hostname) and len(hostname) < 64
        if is_valid_cn:
            try:
                subject_attrs.append(x509.NameAttribute(
                    NameOID.COMMON_NAME, hostname.encode("idna").decode("ascii")
                ))
            except Exception:
                pass
        subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EvilWAF Proxy"))
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(subject_attrs))
            .issuer_name(ca_cert.subject)
            .public_key(host_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + self.CERT_EXPIRY)
            .add_extension(self._create_san_extension(hostname), critical=not is_valid_cn)
            .add_extension(x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        tmp = tempfile.mkdtemp(prefix="evilwaf_cert_")
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        with self._umask_secret():
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(host_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
        return cert_path, key_path

    def cleanup(self):
        import shutil
        for cert_path, _ in list(self.cert_cache.values()):
            try:
                shutil.rmtree(os.path.dirname(cert_path), ignore_errors=True)
            except Exception:
                pass
        try:
            shutil.rmtree(self.ca_dir, ignore_errors=True)
        except Exception:
            pass


class H2Connection:
    def __init__(self, sock, is_server: bool, hostname: str = ""):
        self.sock = sock
        self.is_server = is_server
        self.hostname = hostname
        cfg = h2.config.H2Configuration(
            client_side=not is_server,
            header_encoding="utf-8",
        )
        self.conn = h2.connection.H2Connection(config=cfg)
        self._lock = threading.Lock()

    def initiate(self):
        self.conn.initiate_connection()
        self._flush()

    def _flush(self):
        data = self.conn.data_to_send(65535)
        if data:
            self.sock.sendall(data)

    def recv_events(self, timeout: float = 10.0) -> List:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65535)
            if not data:
                return []
            with self._lock:
                events = self.conn.receive_data(data)
                self._flush()
            return events
        except (socket.timeout, ssl.SSLError, OSError):
            return []

    def send_headers(self, stream_id: int, headers: list, end_stream: bool = False):
        with self._lock:
            self.conn.send_headers(stream_id, headers, end_stream=end_stream)
            self._flush()

    def send_data(self, stream_id: int, data: bytes, end_stream: bool = True):
        with self._lock:
            chunk = 16384
            for i in range(0, len(data), chunk):
                end = end_stream and (i + chunk >= len(data))
                self.conn.send_data(stream_id, data[i:i + chunk], end_stream=end)
            self._flush()

    def reset_stream(self, stream_id: int, error_code: int = 0):
        with self._lock:
            try:
                self.conn.reset_stream(stream_id, error_code=error_code)
                self._flush()
            except Exception:
                pass

    def close(self):
        with self._lock:
            try:
                self.conn.close_connection()
                self._flush()
            except Exception:
                pass


class H1Parser:
    REQ_RE = re.compile(
        rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+(\S+)\s+HTTP/(\d\.\d)\r?\n",
        re.IGNORECASE,
    )
    RESP_RE = re.compile(
        rb"^HTTP/(\d\.\d)\s+(\d{3})\s*(.*?)\r?\n",
        re.IGNORECASE,
    )

    @classmethod
    def read_message(cls, sock, timeout: float = 30.0) -> Tuple[bytes, bytes]:
        sock.settimeout(timeout)
        raw = b""
        try:
            while b"\r\n\r\n" not in raw:
                try:
                    chunk = sock.recv(4096)
                except ssl.SSLWantReadError:
                    time.sleep(0.01)
                    continue
                if not chunk:
                    break
                if not raw and chunk[0] in (0x16, 0x14, 0x15, 0x17):
                    return b"", b""
                if not raw and chunk[:3] == b"PRI":
                    return b"", b""
                raw += chunk
                if len(raw) > 131072:
                    break
        except (socket.timeout, ssl.SSLError, OSError):
            return b"", b""

        if not raw or b"\r\n\r\n" not in raw:
            return raw, b""

        header_end = raw.index(b"\r\n\r\n") + 4
        headers_raw = raw[:header_end]
        body = raw[header_end:]

        hdrs = cls.extract_headers(headers_raw)
        cl_str = hdrs.get("content-length", "")
        te = hdrs.get("transfer-encoding", "").lower()

        if cl_str.strip().isdigit():
            total = int(cl_str.strip())
            remaining = total - len(body)
            while remaining > 0:
                try:
                    chunk = sock.recv(min(remaining, 8192))
                    if not chunk:
                        break
                    body += chunk
                    remaining -= len(chunk)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
        elif "chunked" in te:
            body = cls._read_chunked(sock, body)

        return headers_raw, body

    @classmethod
    def _read_chunked(cls, sock, already_read: bytes) -> bytes:
        buf = already_read
        body = b""
        sock.settimeout(15.0)
        while True:
            while b"\r\n" not in buf:
                try:
                    more = sock.recv(512)
                    if not more:
                        return body
                    buf += more
                except (socket.timeout, OSError):
                    return body
            nl = buf.index(b"\r\n")
            size_line = buf[:nl].split(b";")[0].strip()
            buf = buf[nl + 2:]
            try:
                sz = int(size_line, 16)
            except ValueError:
                return body
            if sz == 0:
                return body
            if sz > 50 * 1024 * 1024:
                return body
            while len(buf) < sz + 2:
                try:
                    more = sock.recv(min(sz - len(buf) + 2, 8192))
                    if not more:
                        return body
                    buf += more
                except (socket.timeout, OSError):
                    return body
            body += buf[:sz]
            buf = buf[sz + 2:]

    @classmethod
    def extract_headers(cls, raw: bytes) -> Dict[str, str]:
        hdrs: Dict[str, str] = {}
        end = raw.find(b"\r\n\r\n")
        section = raw[:end] if end != -1 else raw
        lines = section.split(b"\r\n")[1:]
        for line in lines:
            if b":" in line:
                k, _, v = line.partition(b":")
                hdrs[k.decode("utf-8", errors="ignore").strip().lower()] = \
                    v.decode("utf-8", errors="ignore").strip()
        return hdrs

    @classmethod
    def parse_request_line(cls, raw: bytes) -> Optional[Tuple[str, str, str]]:
        m = cls.REQ_RE.search(raw)
        if not m:
            return None
        return (
            m.group(1).decode("utf-8", errors="ignore"),
            m.group(2).decode("utf-8", errors="ignore"),
            m.group(3).decode("utf-8", errors="ignore"),
        )

    @classmethod
    def parse_response_line(cls, raw: bytes) -> Optional[Tuple[str, int, str]]:
        m = cls.RESP_RE.search(raw)
        if not m:
            return None
        return (
            m.group(1).decode("utf-8", errors="ignore"),
            int(m.group(2)),
            m.group(3).decode("utf-8", errors="ignore").strip(),
        )

    @classmethod
    def build_request(cls, req: InterceptedRequest, inject_cf: bool = False) -> bytes:
        path = req.path or "/"
        hdrs = {k: v for k, v in req.headers.items()}
        hdrs.pop("proxy-connection", None)
        hdrs.pop("proxy-authorization", None)
        hdrs.pop("transfer-encoding", None)
        hdrs["host"] = req.host if req.port in (80, 443) else f"{req.host}:{req.port}"
        hdrs["connection"] = "close"
        if not hdrs.get("content-type") and req.body:
            hdrs["content-type"] = "application/x-www-form-urlencoded"
        if req.body:
            hdrs["content-length"] = str(len(req.body))
        if inject_cf or req.inject_cf_headers:
            visitor_ip = hdrs.get("x-forwarded-for")
            hdrs = _inject_cf_headers(hdrs, visitor_ip)
        lines = [f"{req.method} {path} HTTP/1.1".encode()]
        for k, v in hdrs.items():
            lines.append(f"{k}: {v}".encode())
        lines += [b"", b""]
        return b"\r\n".join(lines) + req.body

    @classmethod
    def build_response(cls, resp: InterceptedResponse) -> bytes:
        status_text = resp.status_text or "OK"
        lines = [f"HTTP/1.1 {resp.status_code} {status_text}".encode()]
        skip = {"transfer-encoding", "connection", "keep-alive"}
        for k, v in resp.headers.items():
            if k.lower() not in skip:
                lines.append(f"{k}: {v}".encode())
        lines.append(b"connection: close")
        if resp.body:
            lines.append(f"content-length: {len(resp.body)}".encode())
        lines += [b"", b""]
        return b"\r\n".join(lines) + resp.body


class TLSContextFactory:
    CIPHERS = (
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384"
    )

    @classmethod
    def client_context(cls, alpn: List[str] = None) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers(cls.CIPHERS)
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        protos = alpn if alpn else ["h2", "http/1.1"]
        ctx.set_alpn_protocols(protos)
        return ctx

    @classmethod
    def server_context(cls, cert_path: str, key_path: str, alpn: List[str] = None) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers(cls.CIPHERS)
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        protos = alpn if alpn else ["h2", "http/1.1"]
        ctx.set_alpn_protocols(protos)
        return ctx


class MITMHandshaker:
    def __init__(
        self,
        ca: CertificateAuthority,
        override_ip: Optional[str] = None,
        proxy_rotator: Optional[ProxyRotator] = None,
        sport_manip: Optional[SourcePortManipulator] = None,
    ):
        self.ca = ca
        self.override_ip = override_ip
        self._proxy_rotator = proxy_rotator
        self._sport = sport_manip

    def perform(self, client_sock: socket.socket, hostname: str, port: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "client_tls": None,
            "server_tls": None,
            "alpn": "http/1.1",
            "error": None,
            "via_override_ip": False,
        }
        server_raw = None
        client_tls = None

        try:
            connect_host = self.override_ip if self.override_ip else hostname
            via_override = bool(self.override_ip)

            if self._proxy_rotator:
                server_raw = self._proxy_rotator.create_connection(connect_host, port, timeout=15)
                server_raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
                server_raw = socket.create_connection((connect_host, port), timeout=15)
                server_raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            cert_path, key_path = self.ca.get_certificate_for_host(hostname)
            server_ctx = TLSContextFactory.server_context(cert_path, key_path)
            client_tls = server_ctx.wrap_socket(client_sock, server_side=True)

            client_alpn = client_tls.selected_alpn_protocol() or "http/1.1"
            upstream_alpn = ["h2", "http/1.1"] if client_alpn == "h2" and H2_AVAILABLE else ["http/1.1"]

            client_ctx = TLSContextFactory.client_context(alpn=upstream_alpn)
            server_tls = client_ctx.wrap_socket(server_raw, server_hostname=hostname)

            negotiated = server_tls.selected_alpn_protocol() or "http/1.1"

            result.update({
                "success": True,
                "client_tls": client_tls,
                "server_tls": server_tls,
                "alpn": negotiated,
                "via_override_ip": via_override,
            })

        except ssl.SSLError as e:
            result["error"] = f"SSL: {e}"
            for s in [client_tls, server_raw]:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        except Exception as e:
            result["error"] = str(e)
            for s in [client_tls, server_raw]:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

        return result


class H2SessionHandler:
    def __init__(
        self,
        client_tls,
        server_tls,
        host: str,
        port: int,
        server_alpn: str,
        callbacks: Dict,
        magic: "Magic",
        advisor: "ResponseAdvisor",
        records_list: List,
        records_lock: threading.Lock,
        is_waf_block: Callable,
        inject_cf: bool = False,
        h2_rotator: Optional["H2FingerprintRotator"] = None,
    ):
        self.client_tls = client_tls
        self.server_tls = server_tls
        self.host = host
        self.port = port
        self.server_alpn = server_alpn
        self.callbacks = callbacks
        self.magic = magic
        self.advisor = advisor
        self.records_list = records_list
        self.records_lock = records_lock
        self.is_waf_block = is_waf_block
        self.inject_cf = inject_cf
        self._h2_rotator = h2_rotator or magic.get_h2_rotator()

    def _make_client_h2(self) -> Optional[H2Connection]:
        if not H2_AVAILABLE:
            return None
        try:
            c = H2Connection(self.client_tls, is_server=True, hostname=self.host)
            c.initiate()
            return c
        except Exception:
            return None

    def _make_server_h2(self) -> Optional[H2Connection]:
        if not H2_AVAILABLE:
            return None
        try:
            profile = self._h2_rotator.get_profile_for_host(self.host)
            cfg = make_h2_config(profile, client_side=True)
            c = H2Connection(self.server_tls, is_server=False, hostname=self.host)
            patch_h2_connection(c.conn, profile)
            c.conn.initiate_connection()
            apply_window_update(c.conn, profile, c._flush)
            c._flush()
            return c
        except Exception:
            return None

    def handle(self) -> List[ProxyRecord]:
        if self.server_alpn == "h2" and H2_AVAILABLE:
            return self._handle_h2_to_h2()
        elif self.server_alpn == "h2" and not H2_AVAILABLE:
            return self._relay_raw()
        else:
            return self._handle_h1_to_h1()

    def _handle_h2_to_h2(self) -> List[ProxyRecord]:
        records = []
        client_h2 = self._make_client_h2()
        server_h2 = self._make_server_h2()
        if not client_h2 or not server_h2:
            return self._relay_raw()

        profile = self._h2_rotator.get_profile_for_host(self.host)
        pending: Dict[int, Dict] = {}

        def pump_client():
            while True:
                events = client_h2.recv_events(timeout=30)
                if not events:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        raw_headers = list(ev.headers)
                        pending[ev.stream_id] = {
                            "headers": dict(raw_headers),
                            "body": b"",
                            "done": False,
                            "profile": profile.name,
                        }

                        method = dict(raw_headers).get(":method", "GET")
                        path = dict(raw_headers).get(":path", "/")
                        scheme = dict(raw_headers).get(":scheme", "https")

                        fp_result = fingerprint_request(
                            rotator=self._h2_rotator,
                            host=self.host,
                            method=method,
                            path=path,
                            scheme=scheme,
                            raw_headers=[(k, v) for k, v in raw_headers if not k.startswith(":")],
                            per_host=True,
                        )
                        fwd_headers = fp_result.headers_applied

                        if self.inject_cf:
                            cf_ip = _generate_cf_connecting_ip()
                            cf_extras = [
                                ("cf-connecting-ip", cf_ip),
                                ("x-forwarded-for", cf_ip),
                                ("x-forwarded-proto", "https"),
                                ("cf-ray", _generate_cf_ray()),
                                ("cf-visitor", '{"scheme":"https"}'),
                                ("cf-ipcountry", random.choice(["US", "GB", "DE", "SG"])),
                            ]
                            existing_keys = {k for k, _ in fwd_headers}
                            for hk, hv in cf_extras:
                                if hk not in existing_keys:
                                    fwd_headers.append((hk, hv))

                        try:
                            server_h2.send_headers(
                                ev.stream_id,
                                fwd_headers,
                                end_stream=ev.stream_ended is not None,
                            )
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.DataReceived):
                        sid = ev.stream_id
                        if sid in pending:
                            pending[sid]["body"] += ev.data
                        try:
                            client_h2.conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                            client_h2._flush()
                        except Exception:
                            pass
                        try:
                            server_h2.send_data(ev.stream_id, ev.data, end_stream=False)
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.StreamEnded):
                        sid = ev.stream_id
                        if sid in pending:
                            pending[sid]["done"] = True
                        try:
                            server_h2.conn.end_stream(sid)
                            server_h2._flush()
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return

        def pump_server():
            response_store: Dict[int, Dict] = {}
            while True:
                events = server_h2.recv_events(timeout=30)
                if not events:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.ResponseReceived):
                        sid = ev.stream_id
                        response_store[sid] = {"headers": dict(ev.headers), "body": b""}
                        try:
                            client_h2.send_headers(
                                sid,
                                [(k, v) for k, v in ev.headers],
                                end_stream=ev.stream_ended is not None,
                            )
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.DataReceived):
                        sid = ev.stream_id
                        if sid in response_store:
                            response_store[sid]["body"] += ev.data
                        try:
                            server_h2.conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                            server_h2._flush()
                        except Exception:
                            pass
                        try:
                            client_h2.send_data(sid, ev.data, end_stream=False)
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.StreamEnded):
                        sid = ev.stream_id
                        if sid in response_store and sid in pending:
                            req_info = pending[sid]
                            resp_info = response_store[sid]
                            status = int(resp_info["headers"].get(":status", 0))
                            used_profile = req_info.get("profile", profile.name)

                            req = InterceptedRequest(
                                timestamp=time.time(),
                                method=req_info["headers"].get(":method", "GET"),
                                path=req_info["headers"].get(":path", "/"),
                                host=self.host,
                                port=self.port,
                                url=f"https://{self.host}:{self.port}{req_info['headers'].get(':path', '/')}",
                                headers={k: v for k, v in req_info["headers"].items() if not k.startswith(":")},
                                body=req_info["body"],
                                is_https=True,
                                http_version="2",
                                inject_cf_headers=self.inject_cf,
                            )
                            resp = InterceptedResponse(
                                timestamp=time.time(),
                                status_code=status,
                                headers={k: v for k, v in resp_info["headers"].items() if not k.startswith(":")},
                                body=resp_info["body"],
                                is_https=True,
                                http_version="2",
                            )

                            techs = [f"h2:{used_profile}", "tcp_fp"]
                            if self.inject_cf:
                                techs.append("cf_spoof")
                            if self.magic.get_evil_proxy() and self.magic.get_evil_proxy().pool_size() > 0:
                                techs.append("evil_proxy")

                            record = ProxyRecord(
                                request=req,
                                response=resp,
                                technique_applied=",".join(techs),
                                passed=200 <= status < 400,
                                blocked=self.is_waf_block(status),
                                intercepted_https=True,
                                decryption_successful=True,
                            )
                            records.append(record)
                            with self.records_lock:
                                self.records_list.append(record)
                            if self.callbacks.get("record"):
                                self.callbacks["record"](record)

                            if self.is_waf_block(status):
                                self._h2_rotator.rotate_host(self.host)

                        try:
                            client_h2.conn.end_stream(sid)
                            client_h2._flush()
                        except Exception:
                            pass

                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return

        t_client = threading.Thread(target=pump_client, daemon=True)
        t_server = threading.Thread(target=pump_server, daemon=True)
        t_client.start()
        t_server.start()
        t_client.join(timeout=120)
        t_server.join(timeout=120)

        try:
            client_h2.close()
        except Exception:
            pass
        try:
            server_h2.close()
        except Exception:
            pass
        return records

    def _handle_h1_to_h1(self) -> List[ProxyRecord]:
        records = []
        while True:
            req_headers_raw, req_body = H1Parser.read_message(self.client_tls, timeout=30)
            if not req_headers_raw:
                break
            if req_headers_raw[:3] == b"PRI":
                records.extend(self._relay_raw())
                break

            parsed = H1Parser.parse_request_line(req_headers_raw)
            if not parsed:
                break
            method, path, version = parsed
            hdrs = H1Parser.extract_headers(req_headers_raw)

            req = InterceptedRequest(
                timestamp=time.time(),
                method=method,
                path=path,
                host=self.host,
                port=self.port,
                url=f"https://{self.host}:{self.port}{path}",
                headers=hdrs,
                body=req_body,
                is_https=True,
                http_version="1.1",
                inject_cf_headers=self.inject_cf,
            )

            if self.callbacks.get("request"):
                self.callbacks["request"](req)

            magic_state = self.magic.apply(host=self.host)

            raw_to_send = H1Parser.build_request(req, inject_cf=self.inject_cf)
            try:
                self.server_tls.sendall(raw_to_send)
            except Exception:
                break

            resp_headers_raw, resp_body = H1Parser.read_message(self.server_tls, timeout=30)
            if not resp_headers_raw:
                break

            pr = H1Parser.parse_response_line(resp_headers_raw)
            resp = InterceptedResponse(timestamp=time.time(), is_https=True, http_version="1.1")
            if pr:
                resp.status_code = pr[1]
                resp.status_text = pr[2]
            resp.headers = H1Parser.extract_headers(resp_headers_raw)
            resp.body = resp_body

            if self.callbacks.get("response"):
                self.callbacks["response"](resp)

            decision = self.advisor.advise(resp, req, ProxyRecord())
            if decision.action in ("retry", "rotate_and_retry"):
                if decision.rotate_ip:
                    self.magic._bind_to_tor()
                if decision.delay > 0:
                    time.sleep(decision.delay)
                try:
                    self.server_tls.sendall(raw_to_send)
                    rh2, rb2 = H1Parser.read_message(self.server_tls, timeout=30)
                    if rh2:
                        pr2 = H1Parser.parse_response_line(rh2)
                        if pr2:
                            resp.status_code = pr2[1]
                            resp.status_text = pr2[2]
                        resp.headers = H1Parser.extract_headers(rh2)
                        resp.body = rb2
                except Exception:
                    pass

            out = H1Parser.build_response(resp)
            try:
                self.client_tls.sendall(out)
            except Exception:
                break

            techs = ["http/1.1"]
            if magic_state.get("tcp", {}).get("profile"):
                techs.append("tcp_fp")
            if magic_state.get("tls", {}).get("identifier"):
                techs.append("tls_fp")
            if magic_state.get("tor", {}).get("active"):
                techs.append("tor")
            if magic_state.get("sport"):
                techs.append("sport")
            if magic_state.get("h2", {}).get("profile"):
                techs.append(f"h2_ua:{magic_state['h2']['profile']}")
            if magic_state.get("evil_proxy", {}).get("active"):
                techs.append("evil_proxy")
            if self.inject_cf:
                techs.append("cf_spoof")

            record = ProxyRecord(
                request=req,
                response=resp,
                technique_applied=",".join(techs),
                passed=200 <= resp.status_code < 400,
                blocked=self.is_waf_block(resp.status_code),
                intercepted_https=True,
                decryption_successful=True,
            )
            records.append(record)
            with self.records_lock:
                self.records_list.append(record)
            if self.callbacks.get("record"):
                self.callbacks["record"](record)

            if self.is_waf_block(resp.status_code):
                self._h2_rotator.rotate_host(self.host)

            if hdrs.get("connection", "").lower() == "close":
                break

        return records

    def _relay_raw(self) -> List[ProxyRecord]:
        try:
            self.client_tls.setblocking(False)
            self.server_tls.setblocking(False)
            socks = [self.client_tls, self.server_tls]
            while True:
                try:
                    readable, _, exc = select.select(socks, [], socks, 2.0)
                    if exc:
                        break
                    if self.client_tls in readable:
                        try:
                            d = self.client_tls.read(8192)
                            if not d:
                                break
                            self.server_tls.sendall(d)
                        except ssl.SSLWantReadError:
                            pass
                        except Exception:
                            break
                    if self.server_tls in readable:
                        try:
                            d = self.server_tls.read(8192)
                            if not d:
                                break
                            self.client_tls.sendall(d)
                        except ssl.SSLWantReadError:
                            pass
                        except Exception:
                            break
                except Exception:
                    break
        except Exception:
            pass
        return []


class ResponseAdvisor:
    ROTATE_ON = (429, 503, 509)
    RETRY_TECH = (403, 406, 418)
    PASS = (200, 201, 204, 301, 302, 304)

    def __init__(self, magic: "Magic", max_retries: int = 3, retry_delay: float = 1.5):
        self._magic = magic
        self._max = max_retries
        self._delay = retry_delay
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def advise(self, response: InterceptedResponse, request: InterceptedRequest, record: ProxyRecord) -> AdvisorDecision:
        code = response.status_code
        if code in self.PASS:
            self._reset(request.host)
            return AdvisorDecision(action="forward", reason=f"{code} pass")
        if code in self.RETRY_TECH:
            return self._retry(request, record, reason=f"{code} waf block")
        if code in self.ROTATE_ON:
            return self._rotate_and_retry(response, request, record)
        return AdvisorDecision(action="forward", reason=f"{code} default")

    def _retry(self, request: InterceptedRequest, record: ProxyRecord, reason: str) -> AdvisorDecision:
        if not self._has_left(request.host):
            return AdvisorDecision(action="forward", reason="max retries")
        self._inc(request.host)
        return AdvisorDecision(action="retry", delay=self._delay, reason=reason, forward_response=False)

    def _rotate_and_retry(self, response: InterceptedResponse, request: InterceptedRequest, record: ProxyRecord) -> AdvisorDecision:
        if not self._has_left(request.host):
            return AdvisorDecision(action="forward", reason="max retries")
        delay = self._get_delay(response)
        self._inc(request.host)
        return AdvisorDecision(action="rotate_and_retry", delay=delay, rotate_ip=True, reason="rate limited", forward_response=False)

    def _has_left(self, host: str) -> bool:
        with self._lock:
            return self._counts.get(host, 0) < self._max

    def _inc(self, host: str):
        with self._lock:
            self._counts[host] = self._counts.get(host, 0) + 1

    def _reset(self, host: str):
        with self._lock:
            self._counts.pop(host, None)

    def _get_delay(self, response: InterceptedResponse) -> float:
        ra = response.headers.get("retry-after", "").strip()
        if ra.isdigit():
            return min(float(ra), 60.0)
        return self._delay









class Forwarder:
    def forward(self, response: InterceptedResponse, handler: BaseHTTPRequestHandler) -> bool:
        try:
            if response.status_code == 0:
                response.status_code = 502
                response.status_text = "Bad Gateway"
            handler.send_response(response.status_code, response.status_text)
            skip = {"transfer-encoding", "connection", "keep-alive"}
            for k, v in response.headers.items():
                if k.lower() not in skip:
                    handler.send_header(k, v)
            handler.send_header("Connection", "close")
            if response.body:
                handler.send_header("Content-Length", str(len(response.body)))
            handler.end_headers()
            if response.body and handler.command != "HEAD":
                handler.wfile.write(response.body)
            return True
        except Exception:
            return False


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True





class Magic:
    def __init__(
        self,
        tcp: Optional[TCPOptionsManipulator] = None,
        tls: Optional[TLSFingerprinter] = None,
        tor: Optional[TorRotator] = None,
        sport: Optional[SourcePortManipulator] = None,
        h2_rotator: Optional[H2FingerprintRotator] = None,
        evil_proxy: Optional[EvilProxyPool] = None,
    ):
        self._tcp = tcp or TCPOptionsManipulator()
        self._tls = tls or TLSFingerprinter()
        self._tor = tor or TorRotator()
        self._sport = sport or SourcePortManipulator()
        self._h2 = h2_rotator or H2FingerprintRotator(strategy="weighted_random")
        self._evil_proxy = evil_proxy
        self._lock = threading.Lock()
        self._request_count = 0
        self._last_h2_profile: str = ""

    def apply(self, technique: str = "", host: str = "") -> Dict[str, Any]:
        with self._lock:
            self._request_count += 1
            count = self._request_count

        tcp_opts = self._tcp.per_request_options()
        tls_sess, tls_id = self._tls.paired_with_tcp(tcp_opts.get("profile", ""))
        sport_opts = self._sport.per_request_options()

        h2_profile = self._h2.get_profile_for_host(host) if host else self._h2.get_profile_for_request()
        self._last_h2_profile = h2_profile.name

        result: Dict[str, Any] = {
            "tcp": tcp_opts,
            "tls": {"session": tls_sess, "identifier": tls_id},
            "tor": {},
            "sport": sport_opts,
            "h2": {
                "profile": h2_profile.name,
                "user_agent": h2_profile.user_agent,
                "window_update": h2_profile.window_update_increment,
                "pseudo_order": h2_profile.pseudo_header_order,
            },
            "evil_proxy": {},
        }

        if technique == "ip_rotation" or self._tor.should_rotate(count):
            if self._tor.is_tor_alive():
                ok, ip = self._tor.rotate_and_verify()
                result["tor"] = {"active": ok, "ip": ip, "proxies": self._tor.get_proxy_dict()}

        if self._evil_proxy is not None:
            entry = self._evil_proxy.get_proxy_for_request(count)
            if entry:
                result["evil_proxy"] = {
                    "active": True,
                    "host": entry.host,
                    "port": entry.port,
                    "latency": entry.latency,
                    "anonymous": entry.anonymous,
                    "request_id": count,
                }

        self._tcp._last_profile = tcp_opts.get("profile", "")
        self._tls._last_identifier = tls_id
        return result

    def get_h2_rotator(self) -> H2FingerprintRotator:
        return self._h2

    def get_evil_proxy(self) -> Optional[EvilProxyPool]:
        return self._evil_proxy

    def create_connection_via_evil_proxy(
        self,
        host: str,
        port: int,
        request_id: Optional[int] = None,
        timeout: float = 15.0,
    ) -> socket.socket:
        if self._evil_proxy is None:
            raise ConnectionError("EvilProxyPool not configured")
        return self._evil_proxy.create_connection(host, port, request_id=request_id, timeout=timeout)

    def _bind_to_tor(self) -> Dict[str, Any]:
        if not self._tor.is_tor_alive():
            return {"active": False}
        ok, ip = self._tor.rotate_and_verify()
        return {"active": ok, "ip": ip, "proxies": self._tor.get_proxy_dict()}

    def error_solver(self, error: Exception, context: str = "") -> bool:
        if isinstance(error, ssl.SSLError):
            try:
                self._tls.rotate()
            except Exception:
                pass
        if isinstance(error, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            try:
                self._tcp.rotate()
            except Exception:
                pass
            try:
                self._sport.rotate()
            except Exception:
                pass
        if self._evil_proxy is not None:
            try:
                self._h2.rotate_host(context)
            except Exception:
                pass
        return True


class Interceptor:
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        intercept_https: bool = True,
        tor_control_port: int = 9051,
        tor_password: str = "",
        tor_rotate_every: int = 5,
        override_ip: Optional[str] = None,
        target_host: Optional[str] = None,
        upstream_proxies: Optional[List[str]] = None,
        use_evil_proxy: bool = False,
        evil_proxy_min_pool: int = 10,
        evil_proxy_max_pool: int = 200,
        evil_proxy_require_anonymous: bool = False,
        evil_proxy_require_https: bool = False,
        h2_profiles: Optional[List[str]] = None,
        h2_strategy: str = "weighted_random",
    ):
        self._host = listen_host
        self._port = listen_port
        self._override_ip = override_ip
        self._target_host = target_host
        self._running = False
        self._server: Optional[ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._records: List[ProxyRecord] = []
        self._records_lock = threading.Lock()

        self._proxy_rotator = ProxyRotator(proxy_urls=upstream_proxies) if upstream_proxies else None

        self._evil_proxy: Optional[EvilProxyPool] = None
        if use_evil_proxy:
            self._evil_proxy = EvilProxyPool(
                min_pool_size=evil_proxy_min_pool,
                max_pool_size=evil_proxy_max_pool,
                require_anonymous=evil_proxy_require_anonymous,
                require_https=evil_proxy_require_https,
            )
            self._evil_proxy.start()

        self._h2_rotator = H2FingerprintRotator(
            profiles=h2_profiles,
            strategy=h2_strategy,
            lock_per_host=True,
        )

        self.ca = CertificateAuthority()
        self._sport_manip = SourcePortManipulator(profile="rotating")
        self._handshaker = MITMHandshaker(
            self.ca,
            override_ip=override_ip,
            proxy_rotator=self._proxy_rotator,
            sport_manip=self._sport_manip,
        )
        self._forwarder = Forwarder()

        self._tor = TorRotator(
            control_port=tor_control_port,
            control_password=tor_password,
            min_rotate_interval=10,
        )
        self._tcp_manip = TCPOptionsManipulator()
        self._tls_fp = TLSFingerprinter()
        self._magic = Magic(
            tcp=self._tcp_manip,
            tls=self._tls_fp,
            tor=self._tor,
            sport=self._sport_manip,
            h2_rotator=self._h2_rotator,
            evil_proxy=self._evil_proxy,
        )
        self._advisor = ResponseAdvisor(self._magic)

        self.intercept_https = intercept_https
        self.https_intercepted = 0
        self.https_tunneled = 0
        self.https_errors = 0

        self._callbacks: Dict[str, Optional[Callable]] = {
            "request": None,
            "response": None,
            "record": None,
        }

    def set_on_request(self, cb: Callable): self._callbacks["request"] = cb
    def set_on_response(self, cb: Callable): self._callbacks["response"] = cb
    def set_on_record(self, cb: Callable): self._callbacks["record"] = cb

    def _is_waf_block(self, code: int) -> bool:
        return code in {403, 406, 407, 409, 418, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526}

    def _create_upstream_connection(self, host: str, port: int, timeout: int = 15, request_id: Optional[int] = None) -> socket.socket:
        if self._evil_proxy is not None and self._evil_proxy.pool_size() > 0:
            try:
                sock = self._evil_proxy.create_connection(host, port, request_id=request_id, timeout=float(timeout))
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return sock
            except Exception:
                pass

        connect_host = self._override_ip if self._override_ip else host
        if self._proxy_rotator:
            sock = self._proxy_rotator.create_connection(connect_host, port, timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock

        sock = socket.create_connection((connect_host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def _process_http_request(self, req: InterceptedRequest, request_id: Optional[int] = None) -> InterceptedResponse:
        resp = InterceptedResponse(timestamp=time.time())
        start = time.time()
        sock = None
        try:
            parsed = urlparse(req.url)
            host = parsed.hostname or req.host
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            req.path = path
            req.host = host
            req.port = port

            sock = self._create_upstream_connection(host, port, timeout=30, request_id=request_id)

            if parsed.scheme == "https":
                ctx = TLSContextFactory.client_context(alpn=["http/1.1"])
                sock = ctx.wrap_socket(sock, server_hostname=host)

            inject = bool(self._override_ip)
            sock.sendall(H1Parser.build_request(req, inject_cf=inject))
            resp_headers_raw, resp_body = H1Parser.read_message(sock, timeout=30)

            if resp_headers_raw:
                pr = H1Parser.parse_response_line(resp_headers_raw)
                if pr:
                    resp.status_code = pr[1]
                    resp.status_text = pr[2]
                resp.headers = H1Parser.extract_headers(resp_headers_raw)
                resp.body = resp_body
                resp.is_https = parsed.scheme == "https"
            resp.response_time = time.time() - start

        except Exception as e:
            resp.status_code = 502
            resp.status_text = "Bad Gateway"
            resp.body = f"Proxy Error: {e}".encode()
            resp.response_time = time.time() - start
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return resp

    def _handle_tunnel(self, client_sock: socket.socket, server_sock: socket.socket):
        client_sock.setblocking(False)
        server_sock.setblocking(False)
        socks = [client_sock, server_sock]
        try:
            while True:
                readable, _, exc = select.select(socks, [], socks, 1.0)
                if exc:
                    break
                for s in readable:
                    other = server_sock if s is client_sock else client_sock
                    try:
                        data = s.recv(8192)
                        if not data:
                            return
                        other.sendall(data)
                    except Exception:
                        return
        except Exception:
            pass

    def get_records(self) -> List[ProxyRecord]:
        with self._records_lock:
            return list(self._records)

    def clear_records(self):
        with self._records_lock:
            self._records.clear()

    def export_ca_certificates(self, export_dir: Optional[str] = None) -> Dict[str, str]:
        return self.ca.export_ca_certificates(export_dir)

    def start(self):
        self._running = True
        interceptor_ref = self

        class ProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 60

            def log_message(self, fmt, *args):
                pass

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (OSError, ConnectionResetError, BrokenPipeError):
                    pass

            def handle(self):
                try:
                    super().handle()
                except (OSError, ConnectionResetError, BrokenPipeError):
                    pass

            def _parse_request(self) -> InterceptedRequest:
                req = InterceptedRequest(timestamp=time.time())
                req.method = self.command
                req.path = self.path
                req.headers = {k.lower(): v for k, v in self.headers.items()}
                req.host = self.headers.get("Host", "")
                parsed = urlparse(self.path)
                if parsed.scheme and parsed.netloc:
                    req.url = self.path
                    req.host = parsed.netloc
                else:
                    req.url = f"http://{req.host}{self.path}"
                req.port = 80
                if ":" in req.host and not req.host.startswith("["):
                    h, _, p = req.host.rpartition(":")
                    req.host = h
                    try:
                        req.port = int(p)
                    except Exception:
                        pass
                cookie_hdr = self.headers.get("Cookie", "")
                if cookie_hdr:
                    for part in cookie_hdr.split(";"):
                        if "=" in part:
                            ck, _, cv = part.strip().partition("=")
                            req.cookies[ck.strip()] = cv.strip()
                if parsed.query:
                    req.query_params = parse_qs(parsed.query)
                cl = int(self.headers.get("Content-Length", 0) or 0)
                if cl > 0:
                    try:
                        req.body = self.rfile.read(cl)
                    except Exception:
                        req.body = b""
                req.inject_cf_headers = bool(interceptor_ref._override_ip)
                return req

            def _dispatch(self):
                try:
                    req = self._parse_request()
                    if interceptor_ref._callbacks["request"]:
                        interceptor_ref._callbacks["request"](req)

                    magic_state = interceptor_ref._magic.apply(host=req.host)
                    request_id = magic_state.get("evil_proxy", {}).get("request_id")

                    resp = interceptor_ref._process_http_request(req, request_id=request_id)

                    techs = ["tcp_fp", "tls_fp", "sport"]
                    h2_info = magic_state.get("h2", {})
                    if h2_info.get("profile"):
                        techs.append(f"h2:{h2_info['profile']}")
                    if magic_state.get("tor", {}).get("active"):
                        techs.append("tor")
                    if magic_state.get("evil_proxy", {}).get("active"):
                        techs.append("evil_proxy")
                    if req.inject_cf_headers:
                        techs.append("cf_spoof")

                    record = ProxyRecord(
                        request=req,
                        response=resp,
                        technique_applied=",".join(techs),
                        passed=200 <= resp.status_code < 400,
                        blocked=interceptor_ref._is_waf_block(resp.status_code),
                    )
                    with interceptor_ref._records_lock:
                        interceptor_ref._records.append(record)
                    if interceptor_ref._callbacks["record"]:
                        interceptor_ref._callbacks["record"](record)
                    interceptor_ref._forwarder.forward(resp, self)
                except Exception as e:
                    try:
                        self.send_error(502, str(e))
                    except Exception:
                        pass

            def do_GET(self): self._dispatch()
            def do_POST(self): self._dispatch()
            def do_PUT(self): self._dispatch()
            def do_DELETE(self): self._dispatch()
            def do_PATCH(self): self._dispatch()
            def do_HEAD(self): self._dispatch()
            def do_OPTIONS(self): self._dispatch()

            def do_CONNECT(self):
                parts = self.path.split(":")
                remote_host = parts[0]
                remote_port = int(parts[1]) if len(parts) > 1 else 443

                if interceptor_ref.intercept_https:
                    self.send_response(200, "Connection Established")
                    self.send_header("Proxy-Agent", "EvilWAF")
                    self.end_headers()
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass

                    result = interceptor_ref._handshaker.perform(
                        self.request, remote_host, remote_port
                    )

                    if result["success"]:
                        interceptor_ref.https_intercepted += 1
                        inject_cf = bool(interceptor_ref._override_ip)
                        handler = H2SessionHandler(
                            client_tls=result["client_tls"],
                            server_tls=result["server_tls"],
                            host=remote_host,
                            port=remote_port,
                            server_alpn=result["alpn"],
                            callbacks=interceptor_ref._callbacks,
                            magic=interceptor_ref._magic,
                            advisor=interceptor_ref._advisor,
                            records_list=interceptor_ref._records,
                            records_lock=interceptor_ref._records_lock,
                            is_waf_block=interceptor_ref._is_waf_block,
                            inject_cf=inject_cf,
                            h2_rotator=interceptor_ref._h2_rotator,
                        )
                        handler.handle()
                        try:
                            result["client_tls"].close()
                        except Exception:
                            pass
                        try:
                            result["server_tls"].close()
                        except Exception:
                            pass
                        return
                    else:
                        interceptor_ref.https_errors += 1
                        try:
                            remote_sock = interceptor_ref._create_upstream_connection(remote_host, remote_port, timeout=15)
                            interceptor_ref.https_tunneled += 1
                            interceptor_ref._handle_tunnel(self.request, remote_sock)
                            try:
                                remote_sock.close()
                            except Exception:
                                pass
                        except Exception as e:
                            try:
                                self.send_error(502, str(e))
                            except Exception:
                                pass
                        return

                try:
                    remote_sock = interceptor_ref._create_upstream_connection(remote_host, remote_port, timeout=15)
                    self.send_response(200, "Connection Established")
                    self.send_header("Proxy-Agent", "EvilWAF")
                    self.end_headers()
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass
                    interceptor_ref.https_tunneled += 1
                    interceptor_ref._handle_tunnel(self.request, remote_sock)
                    try:
                        remote_sock.close()
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        self.send_error(502, str(e))
                    except Exception:
                        pass

        try:
            self._server = ThreadedHTTPServer((self._host, self._port), ProxyHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            time.sleep(0.3)
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.settimeout(2)
            try:
                if test.connect_ex((self._host, self._port)) != 0:
                    raise RuntimeError(f"Failed to bind on {self._host}:{self._port}")
            finally:
                test.close()
        except Exception as e:
            self._running = False
            raise RuntimeError(f"Failed to start proxy: {e}")

    def stop(self):
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._evil_proxy:
            self._evil_proxy.stop()
        self.ca.cleanup()

    def is_running(self) -> bool:
        return self._running

    def get_listen_address(self) -> str:
        return f"{self._host}:{self._port}"


def create_interceptor(
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
    intercept_https: bool = True,
    tor_control_port: int = 9051,
    tor_password: str = "",
    tor_rotate_every: int = 5,
    override_ip: Optional[str] = None,
    target_host: Optional[str] = None,
    upstream_proxies: Optional[List[str]] = None,
    use_evil_proxy: bool = False,
    evil_proxy_min_pool: int = 10,
    evil_proxy_max_pool: int = 200,
    evil_proxy_require_anonymous: bool = False,
    evil_proxy_require_https: bool = False,
    h2_profiles: Optional[List[str]] = None,
    h2_strategy: str = "weighted_random",
) -> Interceptor:
    return Interceptor(
        listen_host=listen_host,
        listen_port=listen_port,
        intercept_https=intercept_https,
        tor_control_port=tor_control_port,
        tor_password=tor_password,
        tor_rotate_every=tor_rotate_every,
        override_ip=override_ip,
        target_host=target_host,
        upstream_proxies=upstream_proxies,
        use_evil_proxy=use_evil_proxy,
        evil_proxy_min_pool=evil_proxy_min_pool,
        evil_proxy_max_pool=evil_proxy_max_pool,
        evil_proxy_require_anonymous=evil_proxy_require_anonymous,
        evil_proxy_require_https=evil_proxy_require_https,
        h2_profiles=h2_profiles,
        h2_strategy=h2_strategy,
    )