from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np

try:
    import _fast_scanner as _fsc
    _FAST = True
except ImportError:
    _FAST = False

try:
    from core.waf_detector import WAFDetector as _CoreWAFDetector
    _HAVE_DETECTOR = True
except ImportError:
    _HAVE_DETECTOR = False

_PAYLOAD_DIR = Path(__file__).parent / "test"


def _load(filename: str) -> List[str]:
    p = _PAYLOAD_DIR / filename
    if not p.exists():
        return []
    with open(p, encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


class VulnCategory(Enum):
    SQLI              = "sql_injection"
    XSS               = "xss"
    RCE               = "rce"
    LFI               = "lfi"
    HEADER_INJECTION  = "header_injection"
    METHOD_BYPASS     = "method_bypass"
    RATE_LIMIT        = "rate_limit"
    ENCODING_BYPASS   = "encoding_bypass"
    RULE_GAP          = "rule_gap"
    MISCONFIGURATION  = "misconfiguration"
    TLS_ANOMALY       = "tls_anomaly"
    SESSION_BYPASS    = "session_bypass"
    TIMING_ANOMALY    = "timing_anomaly"
    BEHAVIOURAL       = "behavioural"
    NETWORK_LAYER     = "network_layer"


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class RequestOutcome(Enum):
    PASSED    = "passed"
    BLOCKED   = "blocked"
    CHALLENGE = "challenge"
    ERROR     = "error"
    TIMEOUT   = "timeout"


@dataclass
class ProbeRequest:
    url:      str
    method:   str
    headers:  Dict[str, str]
    payload:  str
    category: VulnCategory
    encoding: str = "none"
    note:     str = ""


@dataclass
class ProbeResult:
    request:          ProbeRequest
    outcome:          RequestOutcome
    status_code:      int
    response_time:    float
    response_size:    int
    response_body:    str
    response_headers: Dict[str, str]
    timestamp:        float = field(default_factory=time.monotonic)
    error:            Optional[str] = None
    tls_version:      Optional[str] = None
    cert_fingerprint: Optional[str] = None

    def to_trace(self) -> dict:
        return {
            "timestamp":        self.timestamp,
            "layer":            self.request.category.value,
            "method":           self.request.method,
            "url":              self.request.url,
            "payload":          self.request.payload,
            "encoding":         self.request.encoding,
            "outcome":          self.outcome.value,
            "status_code":      self.status_code,
            "response_time":    round(self.response_time * 1000, 2),
            "response_size":    self.response_size,
            "response_body":    self.response_body[:512],
            "response_headers": self.response_headers,
            "error":            self.error,
        }


@dataclass
class VulnFinding:
    category:       VulnCategory
    severity:       VulnSeverity
    title:          str
    description:    str
    evidence:       List[ProbeResult]
    confidence:     float
    verified:       bool          = False
    false_positive: bool          = False
    cve:            Optional[str] = None
    remediation:    str           = ""
    layer:          str           = ""
    discovered_at:  float         = field(default_factory=time.monotonic)

    def to_dict(self) -> dict:
        return {
            "category":       self.category.value,
            "severity":       self.severity.value,
            "title":          self.title,
            "description":    self.description,
            "confidence":     round(self.confidence, 4),
            "verified":       self.verified,
            "false_positive": self.false_positive,
            "cve":            self.cve,
            "remediation":    self.remediation,
            "layer":          self.layer,
            "discovered_at":  datetime.fromtimestamp(self.discovered_at).isoformat(),
            "evidence_count": len(self.evidence),
            "evidence_sample": [
                {
                    "payload":          e.request.payload[:200],
                    "status_code":      e.status_code,
                    "outcome":          e.outcome.value,
                    "response_time_ms": round(e.response_time * 1000, 2),
                    "encoding":         e.request.encoding,
                }
                for e in self.evidence[:5]
            ],
        }


@dataclass
class ScanStatistics:
    total_requests: int   = 0
    passed:         int   = 0
    blocked:        int   = 0
    challenged:     int   = 0
    errors:         int   = 0
    timeouts:       int   = 0
    response_times: List[float] = field(default_factory=list)
    block_rates:    Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    pass_rates:     Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    timeline:       List[Tuple[float, str, str]] = field(default_factory=list)

    def record(self, result: ProbeResult):
        self.total_requests += 1
        self.response_times.append(result.response_time)
        cat = result.request.category.value
        if result.outcome == RequestOutcome.PASSED:
            self.passed     += 1
            self.pass_rates[cat].append(1.0)
            self.block_rates[cat].append(0.0)
        elif result.outcome == RequestOutcome.BLOCKED:
            self.blocked    += 1
            self.pass_rates[cat].append(0.0)
            self.block_rates[cat].append(1.0)
        elif result.outcome == RequestOutcome.CHALLENGE:
            self.challenged += 1
            self.pass_rates[cat].append(0.5)
            self.block_rates[cat].append(0.5)
        elif result.outcome == RequestOutcome.TIMEOUT:
            self.timeouts   += 1
        else:
            self.errors     += 1
        self.timeline.append((result.timestamp, result.request.payload[:60],
                               result.outcome.value))

    def analyse(self) -> dict:
        if not self.response_times:
            return {}
        if _FAST:
            rt = _fsc.rolling_stats(self.response_times)
            rt_dict = {
                "mean_ms":   round(rt["mean"] * 1000, 2),
                "median_ms": round(rt["p50"]  * 1000, 2),
                "p95_ms":    round(rt["p95"]  * 1000, 2),
                "p99_ms":    round(rt["p99"]  * 1000, 2),
                "std_ms":    round(rt["std"]  * 1000, 2),
                "min_ms":    round(rt["min"]  * 1000, 2),
                "max_ms":    round(rt["max"]  * 1000, 2),
            }
        else:
            arr = np.array(self.response_times, dtype=np.float64)
            rt_dict = {
                "mean_ms":   round(float(np.mean(arr))          * 1000, 2),
                "median_ms": round(float(np.median(arr))        * 1000, 2),
                "p95_ms":    round(float(np.percentile(arr,95)) * 1000, 2),
                "p99_ms":    round(float(np.percentile(arr,99)) * 1000, 2),
                "std_ms":    round(float(np.std(arr))           * 1000, 2),
                "min_ms":    round(float(np.min(arr))           * 1000, 2),
                "max_ms":    round(float(np.max(arr))           * 1000, 2),
            }
        total = max(self.total_requests, 1)
        by_cat: dict = {}
        for cat in set(list(self.block_rates) + list(self.pass_rates)):
            br = np.array(self.block_rates.get(cat, [0.0]))
            pr = np.array(self.pass_rates.get(cat, [0.0]))
            by_cat[cat] = {
                "block_rate":  round(float(np.mean(br)), 4),
                "pass_rate":   round(float(np.mean(pr)), 4),
                "sample_size": len(br),
                "std":         round(float(np.std(br)),  4),
            }
        return {
            "total_requests": self.total_requests,
            "pass_rate":      round(self.passed     / total, 4),
            "block_rate":     round(self.blocked    / total, 4),
            "challenge_rate": round(self.challenged / total, 4),
            "error_rate":     round((self.errors + self.timeouts) / total, 4),
            "response_time":  rt_dict,
            "by_category":    by_cat,
        }


class ScanSession:
    VERSION = "2.5.0"

    def __init__(self, output_dir: Path, target: str):
        self._dir    = output_dir
        self._target = target
        self._dir.mkdir(parents=True, exist_ok=True)
        self.history: List[dict] = []
        self._load()

    def _load(self):
        for fp in sorted(self._dir.glob("report_*.json")):
            try:
                with open(fp, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("target") == self._target:
                    self.history.append(data)
            except Exception:
                pass

    def prior_pass_rates(self) -> Dict[str, float]:
        acc: Dict[str, List[float]] = defaultdict(list)
        for report in self.history:
            for cat, v in report.get("statistics", {}).get("by_category", {}).items():
                acc[cat].append(v.get("pass_rate", 0.0))
        return {cat: float(np.mean(vals)) for cat, vals in acc.items()}

    def prior_findings(self) -> List[dict]:
        findings = []
        for report in self.history:
            findings.extend(report.get("findings", []))
        return findings

    def scan_count(self) -> int:
        return len(self.history)

    def save_report(self, data: dict):
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fpath = self._dir / f"report_{ts}.json"
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return fpath


class WAFFingerprinter:
    def __init__(self, target: str):
        self.target  = target
        self.waf     = "unknown"
        self.version = ""
        self.headers: Dict[str, str] = {}
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode   = ssl.CERT_NONE

    def fingerprint(self) -> Tuple[str, str, Dict[str, str]]:
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ctx)
            )
            req = urllib.request.Request(
                self.target,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
            )
            with opener.open(req, timeout=10) as resp:
                self.headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(4096).decode(errors="ignore")
        except Exception:
            body = ""

        if _HAVE_DETECTOR:
            det   = _CoreWAFDetector()
            found = det.detect_all(
                response_body=body,
                headers=self.headers,
                cookies={},
                status_code=200,
            )
            if found:
                self.waf = ", ".join(found)
        else:
            resp_str = " ".join(f"{k}: {v}" for k, v in self.headers.items()) + body
            for sig, name in [
                ("cf-ray",           "cloudflare"),
                ("x-iinfo",          "imperva"),
                ("x-sucuri-id",      "sucuri"),
                ("x-amzn-requestid", "aws_waf"),
                ("x-check-cacheable","akamai"),
                ("barra_counter",    "barracuda"),
                ("fortigate",        "fortiweb"),
                ("x-waf-status",     "f5_bigip"),
                ("mod_security",     "modsecurity"),
            ]:
                if sig in resp_str.lower():
                    self.waf = name
                    break

        srv = self.headers.get("server", "")
        m   = re.search(r"[\d.]+", srv)
        if m:
            self.version = m.group(0)

        return self.waf, self.version, self.headers


class PayloadEngine:
    _ENCODINGS = [
        ("url",         lambda p: urllib.parse.quote(p)),
        ("double_url",  lambda p: urllib.parse.quote(urllib.parse.quote(p))),
        ("html_ent",    lambda p: p.replace("<", "&lt;").replace(">", "&gt;")),
        ("unicode_esc", lambda p: p.encode("unicode_escape").decode()),
        ("null_byte",   lambda p: p + "%00"),
        ("case_swap",   lambda p: p.swapcase()),
        ("tab_space",   lambda p: p.replace(" ", "\t")),
        ("comment",     lambda p: p.replace(" ", "/**/") if " " in p else p + "/**/"),
        ("hex",         lambda p: "".join(f"%{ord(c):02x}" for c in p)),
        ("utf8_over",   lambda p: p.replace("'", "%ef%bc%87")),
    ]

    def __init__(self):
        self._sqli    = _load("sqli.txt")
        self._xss     = _load("xss.txt")
        self._rce     = _load("rce.txt")
        self._lfi     = _load("lfi.txt")
        self._headers = _load("header_injection.txt")
        self._bypass  = _load("bypass_techniques.txt")
        self._session = _load("session_bypass.txt")
        self._misconf = _load("misconfig_probes.txt")

    def get(self, category: VulnCategory) -> List[Tuple[str, str]]:
        base: List[str] = {
            VulnCategory.SQLI:             self._sqli,
            VulnCategory.XSS:              self._xss,
            VulnCategory.RCE:              self._rce,
            VulnCategory.LFI:              self._lfi,
            VulnCategory.HEADER_INJECTION: self._headers,
            VulnCategory.ENCODING_BYPASS:  self._sqli[:10] + self._xss[:10],
            VulnCategory.SESSION_BYPASS:   self._session,
            VulnCategory.MISCONFIGURATION: self._misconf,
            VulnCategory.RULE_GAP:         self._bypass,
        }.get(category, [])

        results: List[Tuple[str, str]] = [(p, "none") for p in base]

        if category == VulnCategory.ENCODING_BYPASS:
            for payload in base:
                for enc_name, enc_fn in self._ENCODINGS:
                    try:
                        results.append((enc_fn(payload), enc_name))
                    except Exception:
                        pass
        return results


class RequestThrottler:
    def __init__(self, rps: float = 3.0):
        self._interval = 1.0 / max(rps, 0.1)
        self._last     = 0.0
        self._lock     = threading.Lock()

    def wait(self):
        with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last = time.monotonic()

    def set_rps(self, rps: float):
        with self._lock:
            self._interval = 1.0 / max(rps, 0.1)

    def cooldown(self, seconds: float):
        time.sleep(seconds)

    @staticmethod
    def make() -> "RequestThrottler":
        return RequestThrottler()


class HTTPProber:
    def __init__(self, target: str, timeout: float = 12.0):
        parsed       = urllib.parse.urlparse(target)
        self.scheme  = parsed.scheme or "https"
        self.host    = parsed.netloc
        self.base    = f"{self.scheme}://{self.host}"
        self.timeout = timeout
        self._ctx    = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode   = ssl.CERT_NONE

    def probe(self, probe: ProbeRequest) -> ProbeResult:
        start = time.monotonic()
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ctx)
            )
            req = urllib.request.Request(
                probe.url, method=probe.method, headers=probe.headers,
            )
            with opener.open(req, timeout=self.timeout) as resp:
                body    = resp.read(8192).decode(errors="ignore")
                elapsed = time.monotonic() - start
                hdrs    = {k.lower(): v for k, v in resp.headers.items()}
                outcome = self._classify(resp.status, body, hdrs)
                tls_ver = getattr(resp.fp, "_sock", None)
                tls_ver = getattr(tls_ver, "version", lambda: None)() if tls_ver else None
                return ProbeResult(
                    request=probe, outcome=outcome,
                    status_code=resp.status, response_time=elapsed,
                    response_size=len(body), response_body=body[:2048],
                    response_headers=hdrs, tls_version=tls_ver,
                )
        except urllib.error.HTTPError as e:
            elapsed = time.monotonic() - start
            body = ""
            try:
                body = e.read(2048).decode(errors="ignore")
            except Exception:
                pass
            hdrs    = {k.lower(): v for k, v in e.headers.items()}
            outcome = self._classify(e.code, body, hdrs)
            return ProbeResult(
                request=probe, outcome=outcome,
                status_code=e.code, response_time=elapsed,
                response_size=len(body), response_body=body,
                response_headers=hdrs,
            )
        except TimeoutError:
            return ProbeResult(
                request=probe, outcome=RequestOutcome.TIMEOUT,
                status_code=0, response_time=self.timeout,
                response_size=0, response_body="", response_headers={},
                error="timeout",
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return ProbeResult(
                request=probe, outcome=RequestOutcome.ERROR,
                status_code=0, response_time=elapsed,
                response_size=0, response_body="", response_headers={},
                error=str(exc),
            )

    @staticmethod
    def _classify(code: int, body: str, hdrs: dict) -> RequestOutcome:
        if _FAST:
            import json as _json
            outcome = _fsc.classify_response(code, body, _json.dumps(hdrs))
            return RequestOutcome(outcome) if outcome in RequestOutcome._value2member_map_ \
                   else RequestOutcome.BLOCKED
        bl = body.lower()
        chall_kw = ["challenge","captcha","verify","human","just a moment","turnstile"]
        block_kw = ["blocked","forbidden","access denied","request rejected",
                    "security violation","attack detected","waf","firewall"]
        if any(k in bl for k in chall_kw):
            return RequestOutcome.CHALLENGE
        if code in {400,403,405,406,429,444,503,502,520}:
            return RequestOutcome.BLOCKED
        if any(k in bl for k in block_kw):
            return RequestOutcome.BLOCKED
        if 200 <= code < 400:
            return RequestOutcome.PASSED
        return RequestOutcome.BLOCKED


class ConfidenceTracker:
    def __init__(self, prior_rates: Optional[Dict[str, float]] = None):
        self._scores: Dict[str, List[float]] = defaultdict(list)
        self._lock   = threading.Lock()
        if prior_rates:
            for cat, rate in prior_rates.items():
                for _ in range(5):
                    self._scores[cat].append(rate)

    def record(self, category: str, passed: bool, weight: float = 1.0):
        with self._lock:
            self._scores[category].append(weight if passed else 0.0)

    def confidence(self, category: str) -> float:
        with self._lock:
            scores = self._scores.get(category, [])
            if not scores:
                return 0.0
            arr  = np.array(scores, dtype=np.float64)
            n    = len(arr)
            mean = float(np.mean(arr))
            if n < 3:
                return mean * 0.5
            if n < 10:
                return mean * 0.75
            std       = float(np.std(arr))
            stability = 1.0 - min(std, 1.0)
            return min((mean * 0.7 + stability * 0.3) * (1.0 - 1.0 / (n + 1)), 1.0)

    def overall(self) -> float:
        with self._lock:
            all_s: List[float] = []
            for v in self._scores.values():
                all_s.extend(v)
            return float(np.mean(np.array(all_s))) if all_s else 0.0


class NetworkLayer:
    NAME = "Layer1:Network"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        parsed  = urllib.parse.urlparse(self._target)
        host    = parsed.netloc.split(":")[0]

        alt_hosts = [
            "127.0.0.1", "localhost", f"internal.{host}",
            f"admin.{host}", f"origin.{host}", f"direct.{host}",
            host + ".evil.com",
        ]
        for alt in alt_hosts:
            self._throttler.wait()
            probe = ProbeRequest(
                url=self._target, method="GET",
                headers={"Host": alt, "User-Agent": "Mozilla/5.0"},
                payload=f"HOST:{alt}",
                category=VulnCategory.NETWORK_LAYER,
                note="virtual_host_bypass",
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.NETWORK_LAYER.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)

        for path in ["/.git/HEAD", "/.env", "/wp-config.php",
                     "/server-status", "/phpinfo.php", "/.htaccess"]:
            self._throttler.wait()
            url   = f"{parsed.scheme}://{parsed.netloc}{path}"
            probe = ProbeRequest(
                url=url, method="GET",
                headers={"User-Agent": "Mozilla/5.0"},
                payload=f"PATHPROBE:{path}",
                category=VulnCategory.NETWORK_LAYER,
                note="sensitive_path",
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.NETWORK_LAYER.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class RuleEngineLayer:
    NAME = "Layer2:RuleEngine"

    _INJECT_PARAMS = ["q", "id", "search", "query", "input", "data",
                      "page", "file", "url", "name", "cmd", "exec"]

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 payloads: PayloadEngine):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence
        self._payloads   = payloads

    def _make_url(self, payload: str) -> str:
        sep    = "&" if "?" in self._target else "?"
        params = "&".join(f"{p}={urllib.parse.quote(payload)}"
                          for p in self._INJECT_PARAMS[:3])
        return f"{self._target}{sep}{params}"

    def scan_category(self, category: VulnCategory) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for payload, encoding in self._payloads.get(category):
            self._throttler.wait()
            probe = ProbeRequest(
                url=self._make_url(payload),
                method="GET",
                headers={"User-Agent": "Mozilla/5.0",
                         "Accept": "text/html,*/*;q=0.8"},
                payload=payload,
                category=category,
                encoding=encoding,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(category.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class RateLimitLayer:
    NAME     = "Layer3:RateLimit"
    COOLDOWN = 15.0

    def __init__(self, target: str, prober: HTTPProber,
                 stats: ScanStatistics, confidence: ConfidenceTracker):
        self._target     = target
        self._prober     = prober
        self._stats      = stats
        self._confidence = confidence
        self._throttler  = RequestThrottler(rps=3.0)

    def scan(self, burst: int = 40, sustained_rps: float = 15.0,
             duration: float = 10.0) -> List[ProbeResult]:
        results: List[ProbeResult] = []

        probe = ProbeRequest(
            url=self._target, method="GET",
            headers={"User-Agent": "Mozilla/5.0"},
            payload="RATE_BURST", category=VulnCategory.RATE_LIMIT,
        )

        with ThreadPoolExecutor(max_workers=burst) as ex:
            futs = [ex.submit(self._prober.probe, probe) for _ in range(burst)]
            for fut in futs:
                r = fut.result()
                self._stats.record(r)
                self._confidence.record(VulnCategory.RATE_LIMIT.value,
                                        r.outcome == RequestOutcome.PASSED)
                results.append(r)

        self._throttler.cooldown(self.COOLDOWN)

        interval = 1.0 / sustained_rps
        end_ts   = time.monotonic() + duration
        while time.monotonic() < end_ts:
            r = self._prober.probe(ProbeRequest(
                url=self._target, method="GET",
                headers={"User-Agent": "Mozilla/5.0"},
                payload="RATE_SUSTAINED", category=VulnCategory.RATE_LIMIT,
            ))
            self._stats.record(r)
            self._confidence.record(VulnCategory.RATE_LIMIT.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
            time.sleep(interval)

        self._throttler.cooldown(self.COOLDOWN)
        return results


class EvasionLayer:
    NAME = "Layer4:Evasion"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 payloads: PayloadEngine):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence
        self._payloads   = payloads

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        sep = "&" if "?" in self._target else "?"
        for payload, encoding in self._payloads.get(VulnCategory.ENCODING_BYPASS):
            self._throttler.wait()
            probe = ProbeRequest(
                url=f"{self._target}{sep}q={payload}",
                method="GET",
                headers={"User-Agent": "Mozilla/5.0",
                         "Accept-Encoding": "gzip, deflate, br"},
                payload=payload,
                category=VulnCategory.ENCODING_BYPASS,
                encoding=encoding,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.ENCODING_BYPASS.value,
                                    r.outcome == RequestOutcome.PASSED)
            if _FAST:
                _fsc.compute_entropy(payload)
            results.append(r)
        return results


class BehaviouralLayer:
    NAME = "Layer5:Behavioural"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 baseline_ms: float = 0.0):
        self._target      = target
        self._prober      = prober
        self._throttler   = throttler
        self._stats       = stats
        self._confidence  = confidence
        self._baseline_ms = baseline_ms

    def scan(self, rounds: int = 20) -> Tuple[List[ProbeResult], dict]:
        results: List[ProbeResult] = []
        times:   List[float]       = []
        for _ in range(rounds):
            self._throttler.wait()
            probe = ProbeRequest(
                url=self._target, method="GET",
                headers={"User-Agent": "Mozilla/5.0"},
                payload="TIMING_PROBE", category=VulnCategory.BEHAVIOURAL,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.BEHAVIOURAL.value,
                                    r.outcome != RequestOutcome.TIMEOUT)
            results.append(r)
            times.append(r.response_time)

        if _FAST:
            anomaly = _fsc.detect_timing_anomaly(times, self._baseline_ms)
        else:
            arr   = np.array(times) * 1000
            mean  = float(np.mean(arr))
            delta = mean - self._baseline_ms
            score = min(max(0.0, (delta - 200) / 2000), 1.0)
            anomaly = {
                "anomaly": score >= 0.35,
                "score":   round(score, 4),
                "mean_ms": round(mean,  2),
                "delta_ms":round(delta, 2),
                "pattern": "high_latency" if delta > 500 else "normal",
            }
        return results, anomaly


class HeaderLayer:
    NAME = "Layer6:Header"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 payloads: PayloadEngine):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence
        self._payloads   = payloads

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for raw_header, _ in self._payloads.get(VulnCategory.HEADER_INJECTION):
            self._throttler.wait()
            hdrs  = {"User-Agent": "Mozilla/5.0"}
            parts = raw_header.split(":", 1)
            if len(parts) == 2:
                hdrs[parts[0].strip()] = parts[1].strip()
            probe = ProbeRequest(
                url=self._target, method="GET",
                headers=hdrs, payload=raw_header,
                category=VulnCategory.HEADER_INJECTION,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.HEADER_INJECTION.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class TLSInspectionLayer:
    NAME = "Layer7:TLS"

    def __init__(self, target: str, stats: ScanStatistics,
                 confidence: ConfidenceTracker):
        self._target     = target
        self._stats      = stats
        self._confidence = confidence
        parsed           = urllib.parse.urlparse(target)
        self._host       = parsed.hostname or ""
        self._port       = parsed.port or 443

    def scan(self) -> dict:
        result = {
            "tls_versions":    [],
            "cert_cn":         "",
            "cert_san":        [],
            "cert_fp":         "",
            "sni_bypass":      False,
            "old_tls_allowed": False,
        }
        for min_ver, label in [
            (ssl.TLSVersion.TLSv1,   "TLSv1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version   = min_ver
                ctx.maximum_version   = min_ver
                ctx.check_hostname    = False
                ctx.verify_mode       = ssl.CERT_NONE
                with socket.create_connection(
                        (self._host, self._port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self._host) as ssock:
                        result["tls_versions"].append(label)
                        if label in ("TLSv1.0", "TLSv1.1"):
                            result["old_tls_allowed"] = True
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            result["cert_fp"] = hashlib.sha256(cert).hexdigest()[:16]
            except Exception:
                pass

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode   = ssl.CERT_NONE
            with socket.create_connection((self._host, self._port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="invalid.sni.test") as ssock:
                    result["sni_bypass"] = True
        except Exception:
            pass

        self._confidence.record(VulnCategory.TLS_ANOMALY.value,
                                result["old_tls_allowed"] or result["sni_bypass"])
        return result


class MethodVerbLayer:
    NAME = "Layer8:MethodVerb"

    _METHODS = ["GET","POST","PUT","DELETE","PATCH","OPTIONS",
                "TRACE","HEAD","CONNECT","PROPFIND","PURGE",
                "MKCOL","MOVE","COPY","LOCK","UNLOCK"]

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for method in self._METHODS:
            self._throttler.wait()
            probe = ProbeRequest(
                url=self._target, method=method,
                headers={"User-Agent": "Mozilla/5.0",
                         "X-HTTP-Method-Override": method},
                payload=f"METHOD:{method}",
                category=VulnCategory.METHOD_BYPASS,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.METHOD_BYPASS.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class SessionLayer:
    NAME = "Layer9:Session"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 payloads: PayloadEngine):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence
        self._payloads   = payloads

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for payload, encoding in self._payloads.get(VulnCategory.SESSION_BYPASS):
            self._throttler.wait()
            probe = ProbeRequest(
                url=self._target, method="GET",
                headers={
                    "User-Agent":    "Mozilla/5.0",
                    "Cookie":        payload,
                    "Authorization": f"Bearer {payload}",
                },
                payload=payload,
                category=VulnCategory.SESSION_BYPASS,
                encoding=encoding,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.SESSION_BYPASS.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class MisconfigLayer:
    NAME = "Layer10:Misconfig"

    def __init__(self, target: str, prober: HTTPProber, throttler: RequestThrottler,
                 stats: ScanStatistics, confidence: ConfidenceTracker,
                 payloads: PayloadEngine):
        self._target     = target
        self._prober     = prober
        self._throttler  = throttler
        self._stats      = stats
        self._confidence = confidence
        self._payloads   = payloads

    def scan(self) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        parsed  = urllib.parse.urlparse(self._target)
        for path, _ in self._payloads.get(VulnCategory.MISCONFIGURATION):
            self._throttler.wait()
            url   = f"{parsed.scheme}://{parsed.netloc}{path}"
            probe = ProbeRequest(
                url=url, method="GET",
                headers={"User-Agent": "Mozilla/5.0"},
                payload=path,
                category=VulnCategory.MISCONFIGURATION,
            )
            r = self._prober.probe(probe)
            self._stats.record(r)
            self._confidence.record(VulnCategory.MISCONFIGURATION.value,
                                    r.outcome == RequestOutcome.PASSED)
            results.append(r)
        return results


class FindingAnalyser:
    _MIN_CONF    = 0.30
    _MIN_SAMPLES = 3

    _META: Dict[VulnCategory, Tuple[str, VulnSeverity, str, Optional[str]]] = {
        VulnCategory.SQLI:   (
            "SQL Injection Rule Gap", VulnSeverity.CRITICAL,
            "Strengthen SQLi ruleset; use parameterized queries.", "CVE-2022-27978"),
        VulnCategory.XSS:    (
            "XSS Filter Bypass", VulnSeverity.HIGH,
            "Update XSS ruleset; enforce Content-Security-Policy.", None),
        VulnCategory.RCE:    (
            "Remote Code Execution Rule Gap", VulnSeverity.CRITICAL,
            "Enforce strict RCE rules; sandbox application execution.", None),
        VulnCategory.LFI:    (
            "Local File Inclusion Bypass", VulnSeverity.HIGH,
            "Enable path-traversal normalization; restrict file access.", None),
        VulnCategory.HEADER_INJECTION: (
            "HTTP Header Injection / IP Spoofing", VulnSeverity.MEDIUM,
            "Validate/strip untrusted header values on ingress.", None),
        VulnCategory.METHOD_BYPASS: (
            "HTTP Method Bypass", VulnSeverity.MEDIUM,
            "Whitelist allowed HTTP verbs; block TRACE/CONNECT.", None),
        VulnCategory.RATE_LIMIT: (
            "Rate Limiting Weakness", VulnSeverity.MEDIUM,
            "Enforce IP-based and token-bucket rate limiting.", None),
        VulnCategory.ENCODING_BYPASS: (
            "Encoding / Normalization Bypass", VulnSeverity.HIGH,
            "Enable double-decode; normalise all input before inspection.", None),
        VulnCategory.TLS_ANOMALY: (
            "TLS Misconfiguration", VulnSeverity.MEDIUM,
            "Disable TLS < 1.2; enforce strict SNI validation.", None),
        VulnCategory.SESSION_BYPASS: (
            "Session / Auth Bypass", VulnSeverity.HIGH,
            "Validate all auth tokens server-side; rotate session IDs.", None),
        VulnCategory.MISCONFIGURATION: (
            "WAF Misconfiguration / Info Leak", VulnSeverity.MEDIUM,
            "Restrict sensitive paths; remove server version banners.", None),
        VulnCategory.NETWORK_LAYER: (
            "Network-Layer Bypass (Virtual Host / Path)", VulnSeverity.HIGH,
            "Validate Host header; block direct-IP access.", None),
        VulnCategory.BEHAVIOURAL: (
            "Timing Anomaly / Tarpit Detected", VulnSeverity.LOW,
            "Review rate-limit and JS-challenge thresholds.", None),
    }

    def analyse(self, category: VulnCategory, results: List[ProbeResult],
                confidence: ConfidenceTracker,
                stats: ScanStatistics) -> Optional[VulnFinding]:
        if len(results) < self._MIN_SAMPLES:
            return None
        passed = [r for r in results if r.outcome == RequestOutcome.PASSED]
        total  = len(results)
        pr     = len(passed) / total
        conf   = confidence.confidence(category.value)

        if pr < 0.05 or conf < self._MIN_CONF:
            return None

        meta = self._META.get(category)
        if not meta:
            title = f"{category.value} Vulnerability"
            sev   = VulnSeverity.LOW
            rem   = "Review WAF configuration."
            cve   = None
        else:
            title, base_sev, rem, cve = meta
            sev = self._severity(category, pr, conf, base_sev)

        desc = (f"{title} — pass_rate={pr:.1%}  confidence={conf:.1%}  "
                f"samples={total}")

        return VulnFinding(
            category=category, severity=sev, title=title,
            description=desc, evidence=passed[:15],
            confidence=conf, cve=cve, remediation=rem,
            layer=category.value,
        )

    @staticmethod
    def _severity(cat: VulnCategory, pr: float, conf: float,
                  base: VulnSeverity) -> VulnSeverity:
        crit = {VulnCategory.SQLI, VulnCategory.RCE}
        if cat in crit:
            if pr > 0.4 and conf > 0.65:
                return VulnSeverity.CRITICAL
            if pr > 0.15:
                return VulnSeverity.HIGH
            return VulnSeverity.MEDIUM
        if pr > 0.5 and conf > 0.6:
            return VulnSeverity.HIGH
        return base


class VulnVerifier:
    def __init__(self, prober: HTTPProber, throttler: RequestThrottler):
        self._prober    = prober
        self._throttler = throttler

    def verify(self, finding: VulnFinding,
               baseline: List[ProbeResult]) -> VulnFinding:
        if not finding.evidence:
            finding.false_positive = True
            return finding

        sample       = finding.evidence[:5]
        passed_count = 0
        for r in sample:
            self._throttler.wait()
            retry = self._prober.probe(r.request)
            if retry.outcome == RequestOutcome.PASSED:
                passed_count += 1

        if passed_count == 0:
            finding.false_positive = True
            finding.verified       = False
            return finding

        base_pr = 0.0
        if baseline:
            base_pr = len([r for r in baseline
                           if r.outcome == RequestOutcome.PASSED]) / len(baseline)

        vpr = passed_count / len(sample)
        if vpr > base_pr + 0.25:
            finding.verified       = True
            finding.false_positive = False
            finding.confidence     = min(finding.confidence + vpr * 0.15, 1.0)
        else:
            finding.false_positive = vpr < 0.2
            finding.verified       = vpr >= 0.5
        return finding


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self._dir = output_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def save_finding(self, finding: VulnFinding, target: str):
        if finding.false_positive:
            return
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        fname = f"{finding.category.value}_{finding.severity.value}_{ts}.json"
        with open(self._dir / fname, "w", encoding="utf-8") as f:
            json.dump({"target": target, "finding": finding.to_dict()},
                      f, indent=2, ensure_ascii=False)

    def save_full(self, session: ScanSession, target: str,
                  findings: List[VulnFinding], stats: ScanStatistics,
                  waf_info: dict, tls_info: dict, duration: float) -> Path:
        data = {
            "target":     target,
            "scan_ts":    datetime.now().isoformat(),
            "scanner":    "EvilWAF v2.5.1",
            "duration_s": round(duration, 2),
            "scan_index": session.scan_count(),
            "waf_info":   waf_info,
            "tls_info":   tls_info,
            "summary": {
                "total":    len(findings),
                "verified": sum(1 for f in findings if f.verified),
                "fp":       sum(1 for f in findings if f.false_positive),
                **{s.value: sum(1 for f in findings
                                if f.severity == s and not f.false_positive)
                   for s in VulnSeverity},
            },
            "statistics": stats.analyse(),
            "findings":   [f.to_dict() for f in findings if not f.false_positive],
        }
        return session.save_report(data)


class WAFVulnScanner:
    def __init__(
        self,
        target:          str,
        output_dir:      Optional[str]                = None,
        rps:             float                        = 3.0,
        timeout:         float                        = 12.0,
        categories:      Optional[List[VulnCategory]] = None,
        verify_findings: bool                         = True,
        min_confidence:  float                        = 0.30,
        layer_cooldown:  float                        = 8.0,
    ):
        self.target          = target if target.startswith("http") else f"https://{target}"
        self._rps            = rps
        self._timeout        = timeout
        self._verify         = verify_findings
        self._min_conf       = min_confidence
        self._layer_cooldown = layer_cooldown
        self._categories     = categories or list(VulnCategory)

        parsed      = urllib.parse.urlparse(self.target)
        out_default = Path("vulns") / parsed.netloc.replace(":", "_")
        out_path    = Path(output_dir) if output_dir else out_default

        self._session    = ScanSession(out_path, self.target)
        self._prober     = HTTPProber(self.target, timeout)
        self._stats      = ScanStatistics()
        self._confidence = ConfidenceTracker(
            prior_rates=self._session.prior_pass_rates()
        )
        self._payloads   = PayloadEngine()
        self._analyser   = FindingAnalyser()
        self._reporter   = ReportGenerator(out_path)

        self._raw_traces:  List[dict] = []
        self._traces_lock = threading.Lock()

        def _t() -> RequestThrottler:
            return RequestThrottler(rps)

        self._l1_network  = NetworkLayer(self.target, self._prober, _t(), self._stats, self._confidence)
        self._l2_rules    = RuleEngineLayer(self.target, self._prober, _t(), self._stats, self._confidence, self._payloads)
        self._l3_rate     = RateLimitLayer(self.target, self._prober, self._stats, self._confidence)
        self._l4_evasion  = EvasionLayer(self.target, self._prober, _t(), self._stats, self._confidence, self._payloads)
        self._l5_behav    = BehaviouralLayer(self.target, self._prober, _t(), self._stats, self._confidence)
        self._l6_header   = HeaderLayer(self.target, self._prober, _t(), self._stats, self._confidence, self._payloads)
        self._l7_tls      = TLSInspectionLayer(self.target, self._stats, self._confidence)
        self._l8_method   = MethodVerbLayer(self.target, self._prober, _t(), self._stats, self._confidence)
        self._l9_session  = SessionLayer(self.target, self._prober, _t(), self._stats, self._confidence, self._payloads)
        self._l10_misconf = MisconfigLayer(self.target, self._prober, _t(), self._stats, self._confidence, self._payloads)
        self._verifier    = VulnVerifier(self._prober, _t())

        self._findings:  List[VulnFinding] = []
        self._running    = False
        self._start_time = 0.0
        self._waf_info:  dict = {}
        self._tls_info:  dict = {}

    def _record_traces(self, results: List[ProbeResult]):
        with self._traces_lock:
            for r in results:
                self._raw_traces.append(r.to_trace())

    def _baseline(self) -> Tuple[List[ProbeResult], float]:
        results: List[ProbeResult] = []
        parsed  = urllib.parse.urlparse(self.target)
        t       = RequestThrottler(self._rps)
        for path in ["/", "/index.html", "/favicon.ico", "/robots.txt"]:
            url   = f"{parsed.scheme}://{parsed.netloc}{path}"
            probe = ProbeRequest(
                url=url, method="GET",
                headers={"User-Agent": "Mozilla/5.0"},
                payload="BASELINE", category=VulnCategory.RULE_GAP,
            )
            t.wait()
            results.append(self._prober.probe(probe))
        times_ms = [r.response_time * 1000 for r in results
                    if r.outcome not in (RequestOutcome.ERROR, RequestOutcome.TIMEOUT)]
        bms = float(np.mean(times_ms)) if times_ms else 0.0
        return results, bms

    def _emit(self, category: VulnCategory, results: List[ProbeResult],
              baseline: List[ProbeResult], on_finding: Optional[Callable]):
        self._record_traces(results)
        finding = self._analyser.analyse(category, results, self._confidence, self._stats)
        if finding and finding.confidence >= self._min_conf:
            if self._verify:
                finding = self._verifier.verify(finding, baseline)
            if not finding.false_positive:
                self._findings.append(finding)
                self._reporter.save_finding(finding, self.target)
                if on_finding:
                    on_finding(finding)

    def scan_layer(self, category: VulnCategory,
                   on_finding: Optional[Callable] = None) -> List[VulnFinding]:
        baseline, baseline_ms         = self._baseline()
        self._l5_behav._baseline_ms   = baseline_ms
        dispatch = {
            VulnCategory.METHOD_BYPASS:    self._l8_method.scan,
            VulnCategory.RATE_LIMIT:       self._l3_rate.scan,
            VulnCategory.NETWORK_LAYER:    self._l1_network.scan,
            VulnCategory.ENCODING_BYPASS:  self._l4_evasion.scan,
            VulnCategory.HEADER_INJECTION: self._l6_header.scan,
            VulnCategory.SESSION_BYPASS:   self._l9_session.scan,
            VulnCategory.MISCONFIGURATION: self._l10_misconf.scan,
        }
        if category == VulnCategory.BEHAVIOURAL:
            results, _ = self._l5_behav.scan()
        elif category in dispatch:
            results = dispatch[category]()
        else:
            results = self._l2_rules.scan_category(category)
        self._emit(category, results, baseline, on_finding)
        return list(self._findings)

    def scan(self,
             on_finding:  Optional[Callable] = None,
             on_progress: Optional[Callable] = None) -> List[VulnFinding]:

        self._running    = True
        self._start_time = time.monotonic()

        fp = WAFFingerprinter(self.target)
        waf, ver, hdrs  = fp.fingerprint()
        self._waf_info  = {"waf": waf, "version": ver,
                            "headers": dict(list(hdrs.items())[:10])}

        baseline, baseline_ms       = self._baseline()
        self._l5_behav._baseline_ms = baseline_ms

        total_steps = 12
        step        = 0

        def prog(name: str):
            nonlocal step
            step += 1
            if on_progress:
                on_progress(step, total_steps, name)

        def run(name: str, category: VulnCategory,
                fn: Callable[[], List[ProbeResult]], cooldown: bool = False):
            prog(name)
            if not self._running:
                return
            results = fn()
            self._emit(category, results, baseline, on_finding)
            if cooldown:
                time.sleep(self._layer_cooldown)

        run(NetworkLayer.NAME, VulnCategory.NETWORK_LAYER, self._l1_network.scan)

        for cat in [VulnCategory.SQLI, VulnCategory.XSS,
                    VulnCategory.RCE,  VulnCategory.LFI]:
            if not self._running:
                break
            prog(f"{RuleEngineLayer.NAME}:{cat.value}")
            r = self._l2_rules.scan_category(cat)
            self._emit(cat, r, baseline, on_finding)

        run(RateLimitLayer.NAME,   VulnCategory.RATE_LIMIT,       self._l3_rate.scan,    cooldown=True)
        run(EvasionLayer.NAME,     VulnCategory.ENCODING_BYPASS,  self._l4_evasion.scan)

        prog(BehaviouralLayer.NAME)
        if self._running:
            r, anomaly = self._l5_behav.scan()
            self._record_traces(r)
            if anomaly.get("anomaly"):
                self._emit(VulnCategory.BEHAVIOURAL, r, baseline, on_finding)

        run(HeaderLayer.NAME,      VulnCategory.HEADER_INJECTION, self._l6_header.scan)

        prog(TLSInspectionLayer.NAME)
        if self._running:
            self._tls_info = self._l7_tls.scan()
            if self._tls_info.get("old_tls_allowed") or self._tls_info.get("sni_bypass"):
                self._findings.append(VulnFinding(
                    category=VulnCategory.TLS_ANOMALY,
                    severity=VulnSeverity.MEDIUM,
                    title="TLS Misconfiguration",
                    description=(
                        f"old_tls={self._tls_info['old_tls_allowed']}  "
                        f"sni_bypass={self._tls_info['sni_bypass']}  "
                        f"versions={self._tls_info['tls_versions']}"
                    ),
                    evidence=[], confidence=0.85, verified=True,
                    remediation="Disable TLS < 1.2; enforce strict SNI.",
                    layer=TLSInspectionLayer.NAME,
                ))

        run(MethodVerbLayer.NAME,  VulnCategory.METHOD_BYPASS,    self._l8_method.scan)
        run(SessionLayer.NAME,     VulnCategory.SESSION_BYPASS,   self._l9_session.scan)
        run(MisconfigLayer.NAME,   VulnCategory.MISCONFIGURATION, self._l10_misconf.scan)

        duration = time.monotonic() - self._start_time
        self._save_traces()
        self._reporter.save_full(
            self._session, self.target, self._findings,
            self._stats, self._waf_info, self._tls_info, duration,
        )
        self._running = False
        return self._findings

    def _save_traces(self):
        with self._traces_lock:
            if not self._raw_traces:
                return
            ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
            fpath = self._reporter._dir / f"traces_{ts}.json"
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump({
                    "target":       self.target,
                    "scan_ts":      datetime.now().isoformat(),
                    "total_traces": len(self._raw_traces),
                    "traces":       self._raw_traces,
                }, f, indent=2, ensure_ascii=False)

    def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return self._stats.analyse()

    def get_confidence(self) -> float:
        return self._confidence.overall()

    def get_findings(self) -> List[VulnFinding]:
        return list(self._findings)

    def get_raw_traces(self) -> List[dict]:
        with self._traces_lock:
            return list(self._raw_traces)

    @property
    def waf_info(self) -> dict:
        return self._waf_info
