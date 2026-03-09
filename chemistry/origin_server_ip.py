from __future__ import annotations

import asyncio
import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

import dns.query
import dns.resolver
import dns.zone

from core.waf_detector import WAFDetector as WAFSignatureDetector

SHODAN_API_KEY         = os.getenv("SHODAN_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
VIRUSTOTAL_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY")
CENSYS_API_ID          = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET      = os.getenv("CENSYS_API_SECRET")

_DATA_DIR = Path(__file__).parent / "data"


def _load_json(filename: str) -> dict | list:
    with open(_DATA_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_lines(filename: str) -> list[str]:
    with open(_DATA_DIR / filename, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


_WAF_IP_RANGES_RAW: dict        = _load_json("waf_ip_ranges.json")
_CLOUD_ASN_PATTERNS: dict       = _load_json("cloud_patterns.json")
_SUBDOMAIN_WORDLIST: list[str]  = _load_lines("wordlist.txt")
_CODE_LEAK_PATTERNS: list[str]  = _load_lines("code_leak_patterns.txt")
_DNS_HISTORY_SOURCES: list[str] = _load_lines("dns_history.txt")
_PASSIVE_SUBDOMAIN_SOURCES: list[str] = _load_lines("sources.txt")
_CODE_SEARCH_SOURCES: list[str] = _load_lines("code_search.txt")
_CT_LOG_SOURCES: list[str]      = _load_lines("ct_log_sources.txt")
_HTTP_PROBE_PATHS: list[str]    = _load_lines("http_probe_paths.txt")
_HTTP_LEAK_HEADERS: list[str]   = _load_lines("http_leak_headers.txt")


class ConfidenceLevel(Enum):
    LOW      = 0.40
    MEDIUM   = 0.60
    HIGH     = 0.80
    CRITICAL = 0.95


class WAFVendor(Enum):
    CLOUDFLARE = "cloudflare"
    CLOUDFLARE_IPV6 = "cloudflare_ipv6"
    AKAMAI = "akamai"
    AKAMAI_IPV6 = "akamai_ipv6"
    FASTLY = "fastly"
    FASTLY_IPV6 = "fastly_ipv6"
    SUCURI = "sucuri"
    INCAPSULA = "incapsula"
    IMPERVA = "imperva"
    AWS_WAF = "aws_waf"
    AWS_CLOUDFRONT = "cloudfront"
    AZURE_CDN = "azure_cdn"
    GOOGLE_CLOUD_CDN = "google_cloud_cdn"
    ALIBABA = "alibaba"
    ORACLE_CLOUD = "oracle_cloud"
    HETZNER = "hetzner"
    OVH_CDN = "ovh_cdn"
    STACKPATH = "stackpath"
    BUNNYCDN = "bunnycdn"
    KEYCDN = "keycdn"
    DDOS_GUARD = "ddos_guard"
    WORDFENCE = "wordfence"
    SITEGROUND = "siteground"
    CLOUDWAYS = "cloudways"
    F5_BIGIP = "f5_bigip"
    FORTIWEB = "fortiweb"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    CITRIX = "citrix"
    PALO_ALTO = "palo_alto"
    RADWARE = "radware"
    SONICWALL = "sonicwall"
    WATCHGUARD = "watchguard"
    COMODO = "comodo" 
    MODSECURITY = "modsecurity"
    OPENAPPSEC = "openappsec"
    NGINX = "nginx"
    APACHE = "apache"
    OPENRESTY = "openresty"
    LITESPEED = "litespeed"
    OPENLITESPEED = "openlitespeed"
    VARNISH = "varnish"
    KUBERNETES = "kubernetes"
    SHIELD = "shield"
    LIQUID = "liquid"
    UNKNOWN = "unknown"


WAF_IP_RANGES: dict[WAFVendor, list[str]] = {
    WAFVendor(vendor): ranges
    for vendor, ranges in _WAF_IP_RANGES_RAW.items()
}

_VENDOR_NAME_MAP: dict[str, WAFVendor] = {v.value: v for v in WAFVendor}


@dataclass
class OriginResult:
    ip: str
    source: str
    confidence: float
    details: dict            = field(default_factory=dict)
    timestamp: float         = field(default_factory=time.monotonic)
    waf_vendor: WAFVendor    = WAFVendor.UNKNOWN
    verified: bool           = False
    cert_verified: bool      = False
    http_verified: bool      = False
    cross_source_count: int  = 1
    asn: Optional[str]       = None
    org: Optional[str]       = None
    country: Optional[str]   = None
    ports: list[int]         = field(default_factory=list)
    hostnames: list[str]     = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.ip)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OriginResult) and self.ip == other.ip


@dataclass
class ReconReport:
    target: str
    origin_candidates: list[OriginResult] = field(default_factory=list)
    best_candidate: Optional[OriginResult] = None
    waf_vendor: WAFVendor                  = WAFVendor.UNKNOWN
    waf_names: list[str]                   = field(default_factory=list)
    total_sources_checked: int             = 0
    duration: float                        = 0.0
    source_stats: dict                     = field(default_factory=lambda: defaultdict(int))
    verified_ips: list[str]                = field(default_factory=list)

    def add(self, result: OriginResult) -> None:
        existing = {r.ip: r for r in self.origin_candidates}
        if result.ip not in existing:
            self.origin_candidates.append(result)
        else:
            ex = existing[result.ip]
            ex.cross_source_count += 1
            if result.confidence > ex.confidence:
                ex.confidence = result.confidence
            ex.details.update(result.details)
            if result.verified:
                ex.verified = True
            if result.cert_verified:
                ex.cert_verified = True
            if result.http_verified:
                ex.http_verified = True
            if result.asn and not ex.asn:
                ex.asn = result.asn
            if result.org and not ex.org:
                ex.org = result.org
            sources = ex.details.get("sources", [])
            if result.source not in sources:
                sources.append(result.source)
            ex.details["sources"] = sources
        self.source_stats[result.source.split(":")[0]] += 1
        self._update_best()

    def _update_best(self) -> None:
        if self.origin_candidates:
            pool = [r for r in self.origin_candidates if r.verified] or self.origin_candidates
            self.best_candidate = max(pool, key=lambda r: (r.confidence, r.cross_source_count))

    def get_cross_source_ips(self, min_sources: int = 2) -> list[OriginResult]:
        return [r for r in self.origin_candidates if r.cross_source_count >= min_sources]

    @property
    def sorted_candidates(self) -> list[OriginResult]:
        return sorted(
            self.origin_candidates,
            key=lambda r: (r.confidence, r.cross_source_count),
            reverse=True,
        )

    @property
    def high_confidence_candidates(self) -> list[OriginResult]:
        return [r for r in self.origin_candidates if r.confidence >= ConfidenceLevel.HIGH.value]


def _is_waf_ip(ip: str, extra_ranges: Optional[list[str]] = None) -> tuple[bool, WAFVendor]:
    try:
        addr = ipaddress.ip_address(ip)
        for vendor, ranges in WAF_IP_RANGES.items():
            if any(addr in ipaddress.ip_network(r) for r in ranges):
                return True, vendor
        if extra_ranges:
            for r in extra_ranges:
                if addr in ipaddress.ip_network(r):
                    return True, WAFVendor.UNKNOWN
        return False, WAFVendor.UNKNOWN
    except ValueError:
        return False, WAFVendor.UNKNOWN


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _extract_ips(text: str) -> list[str]:
    pat = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    return [ip for ip in set(re.findall(pat, text)) if not _is_private_ip(ip)]


def _fetch_url(
    url: str,
    timeout: int = 10,
    headers: Optional[dict] = None,
    auth: Optional[Tuple[str, str]] = None,
) -> Optional[str]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        hdrs.update(headers)
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {token}"
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore")
    except Exception:
        return None


def _resolve_hostname(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


class IPEnricher:
    _IPINFO     = "https://ipinfo.io/{ip}/json"
    _INTERNETDB = "https://internetdb.shodan.io/{ip}"

    def enrich(self, result: OriginResult) -> OriginResult:
        data = _fetch_url(self._IPINFO.format(ip=result.ip), timeout=5)
        if data:
            try:
                p = json.loads(data)
                result.org     = p.get("org")
                result.country = p.get("country")
                result.asn     = (p.get("org") or "").split(" ")[0] or None
                h = p.get("hostname")
                if h and h not in result.hostnames:
                    result.hostnames.append(h)
            except Exception:
                pass

        sdata = _fetch_url(self._INTERNETDB.format(ip=result.ip), timeout=5)
        if sdata:
            try:
                p = json.loads(sdata)
                result.ports = p.get("ports", [])
                for h in p.get("hostnames", []):
                    if h not in result.hostnames:
                        result.hostnames.append(h)
            except Exception:
                pass
        return result


class OriginVerifier:
    def __init__(self, domain: str):
        self.domain = domain

    def verify_cert(self, ip: str) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((ip, 443), timeout=5),
                server_hostname=self.domain,
            ) as sock:
                cert = sock.getpeercert()
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        clean = san_value.lstrip("*.")
                        if self.domain.endswith(clean) or self.domain == clean:
                            return True
        except Exception:
            pass
        return False

    def verify_http(self, ip: str) -> bool:
        for port, use_ssl in [(443, True), (80, False)]:
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    raw  = socket.create_connection((ip, port), timeout=5)
                    conn = ssl.wrap_socket(raw, server_hostname=self.domain)
                else:
                    conn = socket.create_connection((ip, port), timeout=5)

                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.domain}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                conn.sendall(req.encode())
                resp = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 32768:
                        break
                conn.close()
                if resp:
                    status_line = resp.split(b"\r\n")[0].decode(errors="ignore")
                    if re.match(r"HTTP/\d\.\d \d{3}", status_line):
                        code = int(status_line.split()[1])
                        if code < 500:
                            return True
            except Exception:
                continue
        return False

    def verify(self, ip: str) -> Tuple[bool, bool, bool]:
        cert_ok = self.verify_cert(ip)
        http_ok = self.verify_http(ip)
        return (cert_ok or http_ok), cert_ok, http_ok


class _WAFVendorResolver:
    def __init__(self, domain: str):
        self.domain = domain
        self._sig   = WAFSignatureDetector()

    def detect(self) -> tuple[WAFVendor, list[str]]:
        try:
            ip = socket.gethostbyname(self.domain)
            is_waf, vendor = _is_waf_ip(ip)
            if is_waf and vendor != WAFVendor.UNKNOWN:
                return vendor, [vendor.value]
        except socket.gaierror:
            pass

        names: list[str] = []
        data = _fetch_url(f"https://{self.domain}", timeout=8)
        if data:
            try:
                names = self._sig.detect_from_response(data, {})
            except Exception:
                pass

        vendor = WAFVendor.UNKNOWN
        for name in names:
            key = name.lower().replace(" ", "_")
            if key in _VENDOR_NAME_MAP:
                vendor = _VENDOR_NAME_MAP[key]
                break
            for v in WAFVendor:
                if v.value in key:
                    vendor = v
                    break

        return vendor, names


class DNSHistoryScanner:
    _ST_API  = "https://api.securitytrails.com/v1/history/{domain}/dns/a"
    _VT_API  = "https://www.virustotal.com/api/v3/domains/{domain}/resolutions"

    def __init__(self, domain: str):
        self.domain = domain

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []
        sources = list(_DNS_HISTORY_SOURCES)

        with ThreadPoolExecutor(max_workers=max(1, len(sources) + 2)) as ex:
            futs = [loop.run_in_executor(ex, _fetch_url, u.format(domain=self.domain))
                    for u in sources]

            if SECURITYTRAILS_API_KEY:
                st_fut = loop.run_in_executor(
                    ex,
                    _fetch_url,
                    self._ST_API.format(domain=self.domain),
                    10,
                    {"APIKEY": SECURITYTRAILS_API_KEY},
                    None,
                )
                futs.append(st_fut)
                sources.append("securitytrails_api")

            if VIRUSTOTAL_API_KEY:
                vt_fut = loop.run_in_executor(
                    ex,
                    _fetch_url,
                    self._VT_API.format(domain=self.domain),
                    10,
                    {"x-apikey": VIRUSTOTAL_API_KEY},
                    None,
                )
                futs.append(vt_fut)
                sources.append("virustotal_api")

            responses = await asyncio.gather(*futs, return_exceptions=True)

        for i, resp in enumerate(responses):
            if not isinstance(resp, str):
                continue
            src_label = (
                sources[i].split("/")[2]
                if i < len(_DNS_HISTORY_SOURCES)
                else sources[i]
            )
            ips = self._parse(resp, sources[i] if i < len(sources) else "")
            for ip in ips:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append(OriginResult(
                        ip=ip,
                        source=f"dns_history:{src_label}",
                        confidence=ConfidenceLevel.MEDIUM.value,
                        details={"method": "dns_history", "source": src_label},
                    ))
        return results

    def _parse(self, text: str, source: str) -> list[str]:
        ips: list[str] = []
        if "securitytrails" in source or "virustotal" in source:
            try:
                data = json.loads(text)
                records = (
                    data.get("records", []) or
                    data.get("data", []) or
                    []
                )
                for rec in records:
                    for val in rec.get("values", [rec]):
                        ip = val.get("ip") or val.get("address") or ""
                        if ip and not _is_private_ip(ip):
                            ips.append(ip)
            except Exception:
                ips.extend(_extract_ips(text))
        else:
            ips.extend(_extract_ips(text))
        return list(set(ips))


class SSLCertificateScanner:
    def __init__(self, domain: str):
        self.domain = domain

    def _parse_ct(self, response: str) -> list[str]:
        subs: list[str] = []
        try:
            data = json.loads(response)
            if isinstance(data, list):
                for entry in data:
                    names = entry.get("name_value") or entry.get("dns_names", [])
                    if isinstance(names, str):
                        names = names.splitlines()
                    for n in names:
                        n = n.strip().lstrip("*.")
                        if self.domain in n:
                            subs.append(n)
        except Exception:
            subs.extend(re.findall(rf"([a-zA-Z0-9_\-\.]+\.{re.escape(self.domain)})", response))
        return list(set(subs))

    def _probe_cert_san(self, ip: str) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((ip, 443), timeout=3),
                server_hostname=self.domain,
            ) as s:
                cert = s.getpeercert()
                for _, san_val in cert.get("subjectAltName", []):
                    clean = san_val.lstrip("*.")
                    if self.domain.endswith(clean) or self.domain == clean:
                        return True
        except Exception:
            pass
        return False

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []

        with ThreadPoolExecutor(max_workers=max(1, len(_CT_LOG_SOURCES))) as ex:
            responses = await asyncio.gather(
                *[loop.run_in_executor(ex, _fetch_url, u.format(domain=self.domain))
                  for u in _CT_LOG_SOURCES],
                return_exceptions=True,
            )

        subs: list[str] = []
        for resp in responses:
            if isinstance(resp, str):
                subs.extend(self._parse_ct(resp))
        subs = list(set(subs))

        with ThreadPoolExecutor(max_workers=30) as ex:
            resolved = await asyncio.gather(
                *[loop.run_in_executor(ex, _resolve_hostname, s) for s in subs],
                return_exceptions=True,
            )

        candidate_ips: list[str] = []
        for ip in resolved:
            if isinstance(ip, str) and ip:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    candidate_ips.append(ip)

        with ThreadPoolExecutor(max_workers=20) as ex:
            cert_checks = await asyncio.gather(
                *[loop.run_in_executor(ex, self._probe_cert_san, ip)
                  for ip in candidate_ips],
                return_exceptions=True,
            )

        for i, ip in enumerate(candidate_ips):
            cert_ok = isinstance(cert_checks[i], bool) and cert_checks[i]
            conf    = ConfidenceLevel.HIGH.value if cert_ok else ConfidenceLevel.HIGH.value - 0.05
            results.append(OriginResult(
                ip=ip,
                source="ssl_certificate:ct_logs",
                confidence=conf,
                cert_verified=cert_ok,
                details={"method": "ct_log_resolution", "cert_san_verified": cert_ok},
            ))
        return results


class SubdomainEnumerator:
    def __init__(self, domain: str):
        self.domain = domain

    def _resolve(self, subdomain: str) -> Optional[OriginResult]:
        fqdn = f"{subdomain}.{self.domain}" if not subdomain.endswith(self.domain) else subdomain
        try:
            ip = socket.gethostbyname(fqdn)
            is_waf, _ = _is_waf_ip(ip)
            if not is_waf and not _is_private_ip(ip):
                return OriginResult(
                    ip=ip,
                    source=f"subdomain_enum:{fqdn}",
                    confidence=ConfidenceLevel.MEDIUM.value + 0.1,
                    details={"subdomain": fqdn, "method": "bruteforce"},
                )
        except socket.gaierror:
            pass
        return None

    def _parse_passive(self, response: str) -> list[str]:
        subs: list[str] = []
        try:
            data = json.loads(response)
            if isinstance(data, list):
                for entry in data:
                    name = (entry.get("name_value") or entry.get("subdomain")
                            or entry.get("hostname") or "")
                    if isinstance(name, str) and self.domain in name:
                        clean  = name.strip().lstrip("*.")
                        prefix = clean.replace(f".{self.domain}", "").replace(self.domain, "")
                        if prefix:
                            subs.append(prefix)
            elif isinstance(data, dict):
                for key in ("subdomains", "passive_dns", "data"):
                    for entry in data.get(key, []):
                        hostname = (entry.get("hostname") or entry.get("domain") or
                                    (entry if isinstance(entry, str) else ""))
                        if self.domain in hostname:
                            subs.append(hostname.replace(f".{self.domain}", ""))
        except Exception:
            subs.extend(re.findall(rf"([a-zA-Z0-9_\-]+)\.{re.escape(self.domain)}", response))
        return subs

    async def _passive_enum(self) -> list[str]:
        loop = asyncio.get_event_loop()
        subs: list[str] = []
        with ThreadPoolExecutor(max_workers=max(1, len(_PASSIVE_SUBDOMAIN_SOURCES))) as ex:
            responses = await asyncio.gather(
                *[loop.run_in_executor(ex, _fetch_url, u.format(domain=self.domain))
                  for u in _PASSIVE_SUBDOMAIN_SOURCES],
                return_exceptions=True,
            )
        for resp in responses:
            if isinstance(resp, str):
                subs.extend(self._parse_passive(resp))
        return list(set(subs))

    async def scan(self) -> list[OriginResult]:
        passive  = await self._passive_enum()
        all_subs = list(set(_SUBDOMAIN_WORDLIST + passive))
        loop     = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=100) as ex:
            resolved = await asyncio.gather(
                *[loop.run_in_executor(ex, self._resolve, s) for s in all_subs],
                return_exceptions=True,
            )
        return [r for r in resolved if isinstance(r, OriginResult)]


class DNSMisconfigurationScanner:
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV"]

    def __init__(self, domain: str):
        self.domain   = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = 5
        self.resolver.lifetime = 10

    def _query_record(self, record_type: str) -> list[str]:
        ips: list[str] = []
        targets = [self.domain]
        if record_type == "DMARC":
            targets = [f"_dmarc.{self.domain}"]
        elif record_type == "SRV":
            targets = [f"_http._tcp.{self.domain}", f"_https._tcp.{self.domain}",
                       f"_ftp._tcp.{self.domain}"]
        for target in targets:
            try:
                rt = "TXT" if record_type in ("SPF", "DMARC") else record_type
                for rdata in self.resolver.resolve(target, rt):
                    text = rdata.to_text()
                    ips.extend(_extract_ips(text))
                    if record_type in ("MX", "NS", "SRV"):
                        for part in text.split():
                            try:
                                resolved_ip = socket.gethostbyname(part.rstrip("."))
                                if not _is_private_ip(resolved_ip):
                                    ips.append(resolved_ip)
                            except socket.gaierror:
                                pass
            except Exception:
                pass
        return list(set(ips))

    def _check_zone_transfer(self) -> list[str]:
        ips: list[str] = []
        try:
            for ns in self.resolver.resolve(self.domain, "NS"):
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(str(ns.target), self.domain, timeout=5)
                    )
                    for _, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                ips.extend(_extract_ips(rdata.to_text()))
                except Exception:
                    pass
        except Exception:
            pass
        return ips

    def _check_wildcard_dns(self) -> list[str]:
        try:
            ip = socket.gethostbyname(f"nonexistent-{int(time.time())}.{self.domain}")
            return [ip] if not _is_private_ip(ip) else []
        except socket.gaierror:
            return []

    async def scan(self) -> list[OriginResult]:
        loop      = asyncio.get_event_loop()
        results: list[OriginResult] = []
        all_types = self.RECORD_TYPES + ["DMARC", "SPF"]

        with ThreadPoolExecutor(max_workers=len(all_types) + 2) as ex:
            all_results = await asyncio.gather(
                *[loop.run_in_executor(ex, self._query_record, rt) for rt in all_types],
                loop.run_in_executor(ex, self._check_zone_transfer),
                loop.run_in_executor(ex, self._check_wildcard_dns),
                return_exceptions=True,
            )

        for i, ip_list in enumerate(all_results):
            if not isinstance(ip_list, list):
                continue
            if i < len(all_types):
                source     = f"dns_record:{all_types[i]}"
                confidence = ConfidenceLevel.MEDIUM.value
            elif i == len(all_types):
                source     = "dns_misconfiguration:zone_transfer"
                confidence = ConfidenceLevel.CRITICAL.value - 0.05
            else:
                source     = "dns_misconfiguration:wildcard"
                confidence = ConfidenceLevel.MEDIUM.value - 0.1

            for ip in ip_list:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append(OriginResult(
                        ip=ip, source=source, confidence=confidence,
                        details={"method": source},
                    ))
        return results


class CloudProviderLeakScanner:
    def __init__(self, domain: str):
        self.domain   = domain
        self.resolver = dns.resolver.Resolver()

    def _follow_cname_chain(self, hostname: str, depth: int = 0) -> list[OriginResult]:
        if depth > 10:
            return []
        results: list[OriginResult] = []
        try:
            for rdata in self.resolver.resolve(hostname, "CNAME"):
                cname = str(rdata.target).rstrip(".")
                for provider, patterns in _CLOUD_ASN_PATTERNS.items():
                    for pat in patterns:
                        if pat in cname:
                            try:
                                ip = socket.gethostbyname(cname)
                                is_waf, _ = _is_waf_ip(ip)
                                if not is_waf:
                                    results.append(OriginResult(
                                        ip=ip,
                                        source=f"cloud_leak:cname:{provider}",
                                        confidence=ConfidenceLevel.HIGH.value,
                                        details={"cname": cname, "provider": provider,
                                                 "method": "cname_chain", "depth": depth},
                                    ))
                            except socket.gaierror:
                                pass
                results.extend(self._follow_cname_chain(cname, depth + 1))
        except Exception:
            pass
        return results

    def _check_txt_spf_includes(self) -> list[OriginResult]:
        results: list[OriginResult] = []
        try:
            for rdata in self.resolver.resolve(self.domain, "TXT"):
                txt = rdata.to_text()
                if "spf" in txt.lower() or "include" in txt.lower():
                    for inc in re.findall(r"include:([^\s]+)", txt):
                        try:
                            ip = socket.gethostbyname(inc)
                            is_waf, _ = _is_waf_ip(ip)
                            if not is_waf:
                                results.append(OriginResult(
                                    ip=ip,
                                    source="cloud_leak:spf_include",
                                    confidence=ConfidenceLevel.MEDIUM.value + 0.05,
                                    details={"include": inc, "method": "spf_include_resolution"},
                                ))
                        except socket.gaierror:
                            pass
        except Exception:
            pass
        return results

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []
        with ThreadPoolExecutor(max_workers=2) as ex:
            all_results = await asyncio.gather(
                loop.run_in_executor(ex, self._follow_cname_chain, self.domain),
                loop.run_in_executor(ex, self._check_txt_spf_includes),
                return_exceptions=True,
            )
        for r in all_results:
            if isinstance(r, list):
                results.extend(r)
        return results


class GitHubLeakScanner:
    def __init__(self, domain: str):
        self.domain = domain

    def _extract_from_code(self, text: str) -> list[str]:
        ips: list[str] = []
        for pat in _CODE_LEAK_PATTERNS:
            ips.extend(re.findall(pat, text, re.IGNORECASE | re.MULTILINE))
        ips.extend(_extract_ips(text))
        return list(set(ips))

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []
        with ThreadPoolExecutor(max_workers=max(1, len(_CODE_SEARCH_SOURCES))) as ex:
            responses = await asyncio.gather(
                *[loop.run_in_executor(ex, _fetch_url, u.format(domain=self.domain))
                  for u in _CODE_SEARCH_SOURCES],
                return_exceptions=True,
            )
        for i, resp in enumerate(responses):
            if not isinstance(resp, str):
                continue
            for ip in self._extract_from_code(resp):
                try:
                    addr = ipaddress.ip_address(ip)
                    is_waf, _ = _is_waf_ip(ip)
                    if not addr.is_private and not is_waf:
                        results.append(OriginResult(
                            ip=ip,
                            source="github_leak:code_search",
                            confidence=ConfidenceLevel.HIGH.value - 0.08,
                            details={"method": "code_search",
                                     "source_url": _CODE_SEARCH_SOURCES[i]},
                        ))
                except ValueError:
                    pass
        return results


class HTTPHeaderLeakScanner:
    def __init__(self, domain: str):
        self.domain = domain

    def _probe_path(self, path: str) -> list[str]:
        ips: list[str] = []
        try:
            conn = http.client.HTTPSConnection(self.domain, timeout=5)
            conn.request("GET", path, headers={"Host": self.domain, "User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            for hdr in _HTTP_LEAK_HEADERS:
                val = resp.getheader(hdr, "")
                if val:
                    ips.extend(_extract_ips(val))
                    for h in re.findall(r"([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})", val):
                        try:
                            resolved = socket.gethostbyname(h)
                            if not _is_private_ip(resolved):
                                ips.append(resolved)
                        except socket.gaierror:
                            pass
        except Exception:
            pass
        return list(set(ips))

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []
        with ThreadPoolExecutor(max_workers=max(1, len(_HTTP_PROBE_PATHS))) as ex:
            all_results = await asyncio.gather(
                *[loop.run_in_executor(ex, self._probe_path, p) for p in _HTTP_PROBE_PATHS],
                return_exceptions=True,
            )
        for i, ip_list in enumerate(all_results):
            if not isinstance(ip_list, list):
                continue
            for ip in ip_list:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append(OriginResult(
                        ip=ip,
                        source=f"http_header_leak:{_HTTP_PROBE_PATHS[i]}",
                        confidence=ConfidenceLevel.HIGH.value,
                        details={"method": "header_leak", "path": _HTTP_PROBE_PATHS[i]},
                    ))
        return results


class FaviconHashScanner:
    _SHODAN_FREE  = "https://www.shodan.io/search?query=http.favicon.hash:{hash}"
    _SHODAN_API   = "https://api.shodan.io/shodan/host/search?key={key}&query=http.favicon.hash:{hash}"
    _FAVICON_PATHS = ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]

    def __init__(self, domain: str):
        self.domain = domain

    def _fetch_favicon(self, path: str) -> Optional[bytes]:
        try:
            req = Request(
                f"https://{self.domain}{path}",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urlopen(req, timeout=5) as resp:
                return resp.read()
        except Exception:
            return None

    @staticmethod
    def _mmh3_hash(data: bytes) -> int:
        h, length = 0, len(data)
        nblocks = length // 4
        for block in range(nblocks):
            k = struct.unpack_from("<I", data, block * 4)[0]
            k = ((k * 0xCC9E2D51) & 0xFFFFFFFF)
            k = (((k << 15) | (k >> 17)) & 0xFFFFFFFF)
            k = ((k * 0x1B873593) & 0xFFFFFFFF)
            h ^= k
            h = (((h << 13) | (h >> 19)) & 0xFFFFFFFF)
            h = ((h * 5 + 0xE6546B64) & 0xFFFFFFFF)
        tail_idx = nblocks * 4
        k, tail  = 0, length & 3
        if tail >= 3: k ^= data[tail_idx + 2] << 16
        if tail >= 2: k ^= data[tail_idx + 1] << 8
        if tail >= 1:
            k ^= data[tail_idx]
            k  = ((k * 0xCC9E2D51) & 0xFFFFFFFF)
            k  = (((k << 15) | (k >> 17)) & 0xFFFFFFFF)
            k  = ((k * 0x1B873593) & 0xFFFFFFFF)
            h ^= k
        h ^= length
        h ^= h >> 16; h = ((h * 0x85EBCA6B) & 0xFFFFFFFF)
        h ^= h >> 13; h = ((h * 0xC2B2AE35) & 0xFFFFFFFF)
        h ^= h >> 16
        return h if h <= 0x7FFFFFFF else h - 0x100000000

    def _search_shodan(self, fhash: int) -> list[str]:
        if SHODAN_API_KEY:
            url  = self._SHODAN_API.format(key=SHODAN_API_KEY, hash=fhash)
            resp = _fetch_url(url, timeout=10)
            if resp:
                try:
                    data = json.loads(resp)
                    return [m.get("ip_str", "") for m in data.get("matches", []) if m.get("ip_str")]
                except Exception:
                    pass
        resp = _fetch_url(self._SHODAN_FREE.format(hash=fhash), timeout=10)
        return _extract_ips(resp) if resp else []

    async def scan(self) -> list[OriginResult]:
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []
        with ThreadPoolExecutor(max_workers=len(self._FAVICON_PATHS)) as ex:
            favicons = await asyncio.gather(
                *[loop.run_in_executor(ex, self._fetch_favicon, p)
                  for p in self._FAVICON_PATHS],
                return_exceptions=True,
            )
        for i, fdata in enumerate(favicons):
            if not isinstance(fdata, bytes) or not fdata:
                continue
            b64   = base64.encodebytes(fdata).decode()
            fhash = self._mmh3_hash(b64.encode())
            ips   = await loop.run_in_executor(None, self._search_shodan, fhash)
            for ip in ips:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    conf = (ConfidenceLevel.HIGH.value + 0.1
                            if SHODAN_API_KEY
                            else ConfidenceLevel.HIGH.value + 0.05)
                    results.append(OriginResult(
                        ip=ip,
                        source="favicon_hash:shodan_api" if SHODAN_API_KEY else "favicon_hash:shodan",
                        confidence=conf,
                        details={"method": "favicon_hash", "hash": fhash,
                                 "favicon_path": self._FAVICON_PATHS[i],
                                 "api_used": bool(SHODAN_API_KEY)},
                    ))
        return results


class CensysScanner:
    _API_URL = "https://search.censys.io/api/v2/hosts/search"

    def __init__(self, domain: str):
        self.domain = domain

    async def scan(self) -> list[OriginResult]:
        if not (CENSYS_API_ID and CENSYS_API_SECRET):
            return []
        loop    = asyncio.get_event_loop()
        results: list[OriginResult] = []

        def _query() -> Optional[str]:
            return _fetch_url(
                f"{self._API_URL}?q={self.domain}&per_page=100",
                timeout=15,
                auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            )

        resp = await loop.run_in_executor(None, _query)
        if not resp:
            return results
        try:
            data = json.loads(resp)
            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip", "")
                if not ip:
                    continue
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf and not _is_private_ip(ip):
                    names = hit.get("dns", {}).get("reverse_dns", {}).get("names", [])
                    results.append(OriginResult(
                        ip=ip,
                        source="censys:api",
                        confidence=ConfidenceLevel.HIGH.value + 0.05,
                        details={"method": "censys_api", "hostnames": names},
                        hostnames=names,
                    ))
        except Exception:
            pass
        return results


class ASNRangeScanner:
    _BGPVIEW = "https://api.bgpview.io/asn/{asn}/prefixes"

    def __init__(self, domain: str):
        self.domain = domain

    def _get_asn(self) -> Optional[str]:
        try:
            ip   = socket.gethostbyname(self.domain)
            data = _fetch_url(f"https://ipinfo.io/{ip}/json", timeout=5)
            if data:
                return json.loads(data).get("org", "").split(" ")[0] or None
        except Exception:
            pass
        return None

    def _get_asn_prefixes(self, asn: str) -> list[str]:
        data = _fetch_url(self._BGPVIEW.format(asn=asn.lstrip("ASas")), timeout=8)
        if data:
            try:
                return [e.get("prefix", "")
                        for e in json.loads(data).get("data", {}).get("ipv4_prefixes", [])]
            except Exception:
                pass
        return []

    def _scan_prefix(self, prefix: str) -> list[str]:
        ips: list[str] = []
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if net.num_addresses > 65536:
                return ips
            for addr in net.hosts():
                try:
                    socket.create_connection((str(addr), 443), timeout=1).close()
                    ips.append(str(addr))
                except Exception:
                    pass
        except Exception:
            pass
        return ips

    async def scan(self) -> list[OriginResult]:
        loop     = asyncio.get_event_loop()
        results: list[OriginResult] = []
        asn      = await loop.run_in_executor(None, self._get_asn)
        if not asn:
            return results
        prefixes = await loop.run_in_executor(None, self._get_asn_prefixes, asn)
        small    = [p for p in prefixes if "/" in p and int(p.split("/")[1]) >= 24]
        with ThreadPoolExecutor(max_workers=10) as ex:
            all_ips = await asyncio.gather(
                *[loop.run_in_executor(ex, self._scan_prefix, p) for p in small[:20]],
                return_exceptions=True,
            )
        for ip_list in all_ips:
            if not isinstance(ip_list, list):
                continue
            for ip in ip_list:
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append(OriginResult(
                        ip=ip,
                        source=f"asn_range:{asn}",
                        confidence=ConfidenceLevel.MEDIUM.value,
                        details={"method": "asn_prefix_scan", "asn": asn},
                    ))
        return results


class CrossSourceCorrelator:
    def __init__(self, verifier: OriginVerifier, min_sources: int = 2):
        self._verifier    = verifier
        self._min_sources = min_sources
        self._seen: Dict[str, int]  = defaultdict(int)
        self._lock = asyncio.Lock()

    async def feed(self, results: list[OriginResult], report: ReconReport) -> list[OriginResult]:
        newly_verified: list[OriginResult] = []
        async with self._lock:
            for r in results:
                self._seen[r.ip] += 1
                report.add(r)

            for ip, count in self._seen.items():
                if count >= self._min_sources:
                    candidate = next(
                        (c for c in report.origin_candidates if c.ip == ip and not c.verified),
                        None,
                    )
                    if candidate:
                        newly_verified.append(candidate)

        if newly_verified:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=min(10, len(newly_verified))) as ex:
                verify_results = await asyncio.gather(
                    *[loop.run_in_executor(ex, self._verifier.verify, c.ip)
                      for c in newly_verified],
                    return_exceptions=True,
                )
            async with self._lock:
                for i, vr in enumerate(verify_results):
                    if not isinstance(vr, tuple):
                        continue
                    ok, cert_ok, http_ok = vr
                    c = newly_verified[i]
                    c.verified      = ok
                    c.cert_verified = cert_ok
                    c.http_verified = http_ok
                    if ok:
                        bonus = 0.0
                        if cert_ok:
                            bonus += 0.15
                        if http_ok:
                            bonus += 0.05
                        cross_bonus     = min(self._seen[c.ip] * 0.05, 0.20)
                        c.confidence    = min(c.confidence + bonus + cross_bonus, 1.0)
                    report._update_best()

        return newly_verified


class OriginServerIPHunter:
    def __init__(
        self,
        domain: str,
        verify: bool = True,
        enrich: bool = True,
        extra_waf_ranges: Optional[list[str]] = None,
        manual_ip: Optional[str] = None,
        scanner_concurrency: int = 4,
        scanner_timeout: float = 90.0,
    ):
        self.domain            = domain.lower().strip()
        self._verify           = verify
        self._enrich           = enrich
        self._extra_waf_ranges = extra_waf_ranges or []
        self._manual_ip        = manual_ip
        self._scanner_concurrency = max(1, scanner_concurrency)
        self._scanner_timeout = max(5.0, scanner_timeout)
        self._report           = ReconReport(target=self.domain)
        self._verifier         = OriginVerifier(self.domain)
        self._enricher         = IPEnricher()
        self._waf_resolver     = _WAFVendorResolver(self.domain)
        self._correlator       = CrossSourceCorrelator(self._verifier, min_sources=2)
        self._scanners = [
            DNSHistoryScanner(self.domain),
            SSLCertificateScanner(self.domain),
            SubdomainEnumerator(self.domain),
            DNSMisconfigurationScanner(self.domain),
            CloudProviderLeakScanner(self.domain),
            GitHubLeakScanner(self.domain),
            HTTPHeaderLeakScanner(self.domain),
            FaviconHashScanner(self.domain),
            ASNRangeScanner(self.domain),
            CensysScanner(self.domain),
        ]

    async def hunt(self) -> ReconReport:
        start = time.monotonic()
        loop  = asyncio.get_event_loop()

        if self._manual_ip:
            result = OriginResult(
                ip=self._manual_ip,
                source="manual:--server-ip",
                confidence=ConfidenceLevel.CRITICAL.value,
                details={"method": "manual"},
            )
            if self._verify:
                ok, cert_ok, http_ok = await loop.run_in_executor(
                    None, self._verifier.verify, self._manual_ip
                )
                result.verified      = ok
                result.cert_verified = cert_ok
                result.http_verified = http_ok
                if ok:
                    result.confidence = min(result.confidence + 0.05, 1.0)
            if self._enrich:
                await loop.run_in_executor(None, self._enricher.enrich, result)
            self._report.add(result)
            self._report.verified_ips          = [self._manual_ip] if result.verified else []
            self._report.total_sources_checked = 0
            self._report.duration              = time.monotonic() - start
            return self._report

        vendor, names = await loop.run_in_executor(None, self._waf_resolver.detect)
        self._report.waf_vendor = vendor
        self._report.waf_names  = names

        sem = asyncio.Semaphore(self._scanner_concurrency)

        async def run_scanner(scanner):
            try:
                async with sem:
                    results = await asyncio.wait_for(
                        scanner.scan(),
                        timeout=self._scanner_timeout,
                    )
                await self._correlator.feed(results, self._report)
            except (asyncio.TimeoutError, Exception):
                pass

        await asyncio.gather(*[run_scanner(s) for s in self._scanners])

        candidates = self._report.origin_candidates

        if self._verify and candidates:
            unverified = [c for c in candidates if not c.verified]
            if unverified:
                with ThreadPoolExecutor(max_workers=20) as ex:
                    verify_results = await asyncio.gather(
                        *[loop.run_in_executor(ex, self._verifier.verify, c.ip)
                          for c in unverified],
                        return_exceptions=True,
                    )
                for i, vr in enumerate(verify_results):
                    if not isinstance(vr, tuple):
                        continue
                    ok, cert_ok, http_ok = vr
                    unverified[i].verified      = ok
                    unverified[i].cert_verified = cert_ok
                    unverified[i].http_verified = http_ok
                    if ok:
                        bonus = 0.0
                        if cert_ok:
                            bonus += 0.15
                        if http_ok:
                            bonus += 0.05
                        unverified[i].confidence = min(
                            unverified[i].confidence + bonus, 1.0
                        )

        if self._enrich and candidates:
            with ThreadPoolExecutor(max_workers=10) as ex:
                await asyncio.gather(
                    *[loop.run_in_executor(ex, self._enricher.enrich, c)
                      for c in candidates],
                    return_exceptions=True,
                )

        self._report.verified_ips          = [r.ip for r in candidates if r.verified]
        self._report.total_sources_checked = len(self._scanners)
        self._report.duration              = time.monotonic() - start
        self._report._update_best()
        return self._report

    @property
    def report(self) -> ReconReport:
        return self._report