#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3
import urwid

from core.interceptor import (
    Interceptor,
    ProxyRecord,
    create_interceptor,
)
from core.waf_detector import WAFDetector
from chemistry.origin_server_ip import OriginServerIPHunter, ReconReport, OriginResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BAD_CODES = {400, 403, 405, 429, 500, 502, 503}


def _fmt_size(body: bytes) -> str:
    n = len(body) if body else 0
    if n < 1024:
        return f"{n}B"
    elif n < 1048576:
        return f"{n/1024:.1f}K"
    return f"{n/1048576:.1f}M"


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{int(seconds//60)}m{seconds%60:.0f}s"


def _detect_waf(target_url: str) -> Optional[str]:
    det = WAFDetector()
    try:
        r = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
        found = det.detect_all(
            response_body=r.text,
            headers=dict(r.headers),
            cookies={k: v for k, v in r.cookies.items()},
            status_code=r.status_code,
        )
        return ", ".join(found) if found else None
    except Exception:
        return None


def _hunt_origin_ip_verbose(target: str) -> Optional[str]:
    parsed = urlparse(target)
    domain = parsed.hostname or parsed.netloc

    print(f"\n[*] Origin IP Hunter started for: {domain}")
    print(f"[*] Launching scanners in parallel:\n")

    scanner_names = [
        "dns_history",
        "ssl_certificate",
        "subdomain_enum",
        "dns_misconfig",
        "cloud_leak",
        "github_leak",
        "http_header_leak",
        "favicon_hash",
        "asn_range",
        "censys",
    ]
    for name in scanner_names:
        print(f"    > {name}")
    print()

    seen_ips: Dict[str, Dict] = {}
    lock     = threading.Lock()
    start_ts = time.time()

    def print_ip_found(result: OriginResult, is_new: bool):
        elapsed      = time.time() - start_ts
        tag          = "NEW" if is_new else "UPD"
        verified_str = ""
        if result.verified:
            parts = []
            if result.cert_verified:
                parts.append("cert")
            if result.http_verified:
                parts.append("http")
            verified_str = f" verified={'+'.join(parts)}"
        cross_str = f" sources={result.cross_source_count}" if result.cross_source_count > 1 else ""
        print(
            f"  [{tag}] {result.ip:<18}"
            f" conf={result.confidence:.0%}"
            f" src={result.source}"
            f"{cross_str}"
            f"{verified_str}"
            f" t={elapsed:.1f}s"
        )

    class VerboseHunter(OriginServerIPHunter):
        async def hunt(self) -> ReconReport:
            report_start = time.monotonic()
            loop         = asyncio.get_event_loop()

            vendor, names = await loop.run_in_executor(None, self._waf_resolver.detect)
            self._report.waf_vendor = vendor
            self._report.waf_names  = names
            if names:
                print(f"  [WAF] Detected: {', '.join(names)}\n")

            async def run_scanner(scanner):
                scanner_name = type(scanner).__name__
                try:
                    results        = await scanner.scan()
                    if results:
                        print(f"  [scanner:{scanner_name}] found {len(results)} candidate(s)")
                    newly_verified = await self._correlator.feed(results, self._report)
                    for r in results:
                        with lock:
                            is_new = r.ip not in seen_ips
                            if is_new:
                                seen_ips[r.ip] = {"conf": r.confidence, "sources": 1}
                            else:
                                seen_ips[r.ip]["sources"] += 1
                        print_ip_found(r, is_new)
                    if newly_verified:
                        print(f"\n  [cross-source] {len(newly_verified)} IP(s) triggered early verification:")
                        for r in newly_verified:
                            print_ip_found(r, False)
                        print()
                except Exception as e:
                    print(f"  [scanner:{scanner_name}] error: {e}")

            await asyncio.gather(*[run_scanner(s) for s in self._scanners])

            candidates = self._report.origin_candidates
            unverified = [c for c in candidates if not c.verified]

            if self._verify and unverified:
                print(f"\n  [verify] Running final verification on {len(unverified)} unverified IP(s)...")
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=20) as ex:
                    verify_results = await asyncio.gather(
                        *[loop.run_in_executor(ex, self._verifier.verify, c.ip)
                          for c in unverified],
                        return_exceptions=True,
                    )
                for i, vr in enumerate(verify_results):
                    if not isinstance(vr, tuple):
                        continue
                    ok, cert_ok, http_ok        = vr
                    unverified[i].verified      = ok
                    unverified[i].cert_verified = cert_ok
                    unverified[i].http_verified = http_ok
                    if ok:
                        bonus = 0.0
                        if cert_ok:
                            bonus += 0.15
                        if http_ok:
                            bonus += 0.05
                        unverified[i].confidence = min(unverified[i].confidence + bonus, 1.0)
                        print_ip_found(unverified[i], False)

            if self._enrich and candidates:
                print(f"\n  [enrich] Enriching {len(candidates)} candidate(s) with ASN/org/port data...")
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=10) as ex:
                    await asyncio.gather(
                        *[loop.run_in_executor(ex, self._enricher.enrich, c)
                          for c in candidates],
                        return_exceptions=True,
                    )

            self._report.verified_ips          = [r.ip for r in candidates if r.verified]
            self._report.total_sources_checked = len(self._scanners)
            self._report.duration              = time.monotonic() - report_start
            self._report._update_best()
            return self._report

    try:
        hunter = VerboseHunter(domain=domain, verify=True, enrich=True)
        loop   = asyncio.new_event_loop()
        report: ReconReport = loop.run_until_complete(hunter.hunt())
        loop.close()

        elapsed = time.time() - start_ts
        print(f"\n{'='*60}")
        print(f"  Hunt complete in {elapsed:.1f}s")
        print(f"  Total candidates : {len(report.origin_candidates)}")
        print(f"  Verified IPs     : {len(report.verified_ips)}")
        print()

        if report.sorted_candidates:
            print("  Candidates (ranked by confidence):")
            for r in report.sorted_candidates[:10]:
                verified_tag = ""
                if r.verified:
                    parts = []
                    if r.cert_verified:
                        parts.append("cert")
                    if r.http_verified:
                        parts.append("http")
                    verified_tag = f" [VERIFIED:{'+'.join(parts)}]"
                org_str     = f" org={r.org}"         if r.org     else ""
                country_str = f" country={r.country}" if r.country else ""
                cross_str   = f" sources={r.cross_source_count}"
                print(
                    f"    {r.ip:<18}"
                    f" conf={r.confidence:.0%}"
                    f"{verified_tag}"
                    f"{cross_str}"
                    f"{org_str}"
                    f"{country_str}"
                )

        if report.best_candidate:
            best = report.best_candidate
            print(f"\n  Best candidate   : {best.ip}")
            print(f"  Confidence       : {best.confidence:.0%}")
            print(f"  Source           : {best.source}")
            print(f"  Verified         : {best.verified}")
            if best.org:
                print(f"  Org              : {best.org}")
            if best.country:
                print(f"  Country          : {best.country}")
            if best.ports:
                print(f"  Open ports       : {best.ports}")
            print(f"{'='*60}\n")
            return best.ip

        print(f"{'='*60}\n")
        print("[!] No origin IP found")
    except Exception as e:
        print(f"[!] Hunt failed: {e}")
    return None


def _ask_connect_proxy(ip: str) -> bool:
    print(f"[?] Use {ip} as origin IP for bypass? [y/n]: ", end="", flush=True)
    try:
        return input().strip().lower() == "y"
    except Exception:
        return False


class TorIPTable:
    def __init__(self, max_entries: int = 1000):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._max     = max_entries
        self._counter = 0

    def add(self, ip: str, duration: float, status: str = "Running"):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "nt":       self._counter,
                "ip":       ip,
                "duration": duration,
                "status":   status,
                "ts":       time.time(),
            })
            if len(self._entries) > self._max:
                self._entries.pop(0)

    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def get_recent(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class TechniqueTable:
    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._lock    = threading.Lock()
        self._counter = 0

    def add(self, tls_id: str, tcp_profile: str):
        with self._lock:
            self._counter += 1
            self._entries.append({
                "rq":  self._counter,
                "tls": tls_id or "N/A",
                "tcp": tcp_profile or "N/A",
            })
            if len(self._entries) > 100:
                self._entries.pop(0)

    def get_recent(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries[-n:])


class TorIPScrollPanel:
    def __init__(self, tor_table: TorIPTable):
        self._tor_table  = tor_table
        self._walker     = urwid.SimpleFocusListWalker([])
        self._last_count = 0

      
        hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' TN'))),
                ('fixed', 18, urwid.Text(('ws_hdr', 'IP Address'))),
                ('fixed', 8,  urwid.Text(('ws_hdr', 'Time'))),
                ('weight', 1, urwid.Text(('ws_hdr', 'Status'))),
            ], dividechars=1),
            'ws_hdr',
        )
        self.widget = urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([
                    ('pack',      hdr),
                    ('weight', 1, urwid.ListBox(self._walker)),
                ]),
                title=" TOR IP Rotation ", title_align='left',
            ),
            'ws_bg',
        )

    def refresh(self):
        entries = self._tor_table.get_all()
        if len(entries) == self._last_count:
            return
        for e in entries[self._last_count:]:
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_value', f' {str(e["nt"]).rjust(3)}'))),
                ('fixed', 18, urwid.Text(('ws_ip',    (e["ip"] or "N/A")[:17]))),
                ('fixed', 8,  urwid.Text(('ws_value', _fmt_duration(e["duration"])[:7]))),
                ('weight', 1, urwid.Text(('ws_ok',    e["status"][:9]))),
            ], dividechars=1)
            self._walker.append(urwid.AttrMap(cols, 'ws_bg'))
        self._last_count = len(entries)
        if self._walker:
            try:
                self._walker.set_focus(len(self._walker) - 1)
            except Exception:
                pass


class EvilWAFTUI:
    def __init__(
        self,
        server:     Interceptor,
        target_url: Optional[str],
        tor_table:  TorIPTable,
        tech_table: TechniqueTable,
        server_ip:  Optional[str] = None,
        waf_name:   Optional[str] = None,
        enable_tor: bool = False,
        upstream_proxy_count: int = 0,
    ):
        self.server      = server
        self.target_url  = target_url
        self.tor_table   = tor_table
        self.tech_table  = tech_table
        self.server_ip   = server_ip
        self.waf_name    = waf_name
        self.enable_tor  = enable_tor
        self.upstream_proxy_count = upstream_proxy_count

        self.traffic_data: List[ProxyRecord] = []
        self.selected_row  = 0
        self._auto_follow  = True
        self.loop: Optional[urwid.MainLoop] = None
        self._tor_panel: Optional[TorIPScrollPanel] = None

        self.palette = [
            # Header na status
            ('header',      'black,bold',    'dark cyan'),
            ('normal',      'white',         'dark blue'),
            ('status',      'black,bold',    'dark cyan'),

            # Traffic Monitor 
            ('tr_normal',   'black',         'white'),
            ('tr_even',     'black',         'white'),
            ('tr_odd',      'dark blue',     'white'),
            ('tr_follow',   'black,bold',    'light cyan'),
            ('tr_selected', 'black,bold',    'light green'),
            ('tr_bad',      'dark red,bold', 'white'),
            ('tr_hdr',      'black,bold',    'dark cyan'),
            ('tr_pass',     'dark green,bold','white'),
            ('tr_block',    'dark red,bold', 'white'),
            ('tr_unkn',     'black',         'white'),
            ('tr_time',     'black,bold',    'white'),
            ('tr_host',     'black,bold',    'white'),
            ('tr_method',   'black,bold',    'white'),
            ('tr_status',   'black,bold',    'white'),
            ('tr_size',     'black,bold',    'white'),
            ('tr_proto',    'black,bold',    'white'),

          
            ('ws_bg',       'white',         'black'),
            ('ws_hdr',      'black,bold',    'dark cyan'),
            ('ws_label',    'white,bold',    'black'),
            ('ws_value',    'white',         'black'),
            ('ws_ip',       'light cyan',    'black'),
            ('ws_ok',       'light green',   'black'),
            ('ws_tech_rq',  'white,bold',    'black'),
            ('ws_tech_tls', 'light cyan',    'black'),
            ('ws_tech_tcp', 'white',         'black'),
            ('ws_inactive', 'dark gray',     'black'),
            ('ws_time',     'white',         'black'),
            ('ws_tech',     'white',         'black'),
            ('ws_ind_pass', 'light green,bold','black'),
            ('ws_ind_block','light red,bold','black'),
            ('ws_ind_unkn', 'dark gray',     'black'),
        ]
        self._build_ui()

    def _build_ui(self):
        self.traffic_walker = urwid.SimpleFocusListWalker([])

        traffic_hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 10, urwid.Text(('tr_hdr', ' Time'))),
                ('fixed', 20, urwid.Text(('tr_hdr', 'Host'))),
                ('fixed', 6,  urwid.Text(('tr_hdr', 'M'))),
                ('fixed', 5,  urwid.Text(('tr_hdr', 'St'))),
                ('fixed', 6,  urwid.Text(('tr_hdr', 'Proto'))),
                ('fixed', 7,  urwid.Text(('tr_hdr', 'Size'))),
                ('weight', 1, urwid.Text(('tr_hdr', 'Result'))),
            ], dividechars=1),
            'tr_hdr',
        )
        self.follow_text = urwid.Text(('ws_ok', ' [FOLLOW] '))
        traffic_panel = urwid.LineBox(
            urwid.Pile([
                ('pack',      traffic_hdr),
                ('weight', 1, urwid.AttrMap(urwid.ListBox(self.traffic_walker), 'tr_normal')),
                ('pack',      urwid.AttrMap(urwid.Padding(self.follow_text, left=1), 'tr_normal')),
            ]),
            title=" Traffic Monitor ", title_align='left',
        )
        right = self._build_right()
        body  = urwid.Columns([
            ('weight', 3, traffic_panel),
            ('weight', 2, urwid.Pile(right)),
        ])
        self.status_text = urwid.Text("")
        footer = urwid.AttrMap(
            urwid.LineBox(urwid.Padding(self.status_text, left=1, right=1)),
            'status',
        )
        self.frame = urwid.Frame(
            header=self._make_header(),
            body=body,
            footer=footer,
        )
        self.loop = urwid.MainLoop(
            self.frame,
            palette=self.palette,
            unhandled_input=self._handle_input,
        )
        self.loop.set_alarm_in(0.3, self._refresh)

    def _build_right(self) -> list:
        panels = []

        # Tor panel 
        if self.enable_tor:
            self._tor_panel = TorIPScrollPanel(self.tor_table)
            panels.append(('weight', 2, self._tor_panel.widget))

        # Active Techniques 
        self.tech_walker = urwid.SimpleFocusListWalker([])
        tech_hdr = urwid.AttrMap(
            urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_hdr', ' RQ'))),
                ('fixed', 18, urwid.Text(('ws_hdr', 'TLS Fingerprint'))),
                ('weight', 1, urwid.Text(('ws_hdr', 'TCP Profile'))),
            ], dividechars=1),
            'ws_hdr',
        )
        panels.append(('weight', 1, urwid.AttrMap(
            urwid.LineBox(
                urwid.Pile([
                    ('pack',      tech_hdr),
                    ('weight', 1, urwid.ListBox(self.tech_walker)),
                ]),
                title=" Active Techniques ", title_align='left',
            ),
            'ws_bg',
        )))

        # Server IP panel
        self.server_ip_text = urwid.Text("")
        if self.server_ip:
            panels.append(('pack', urwid.AttrMap(
                urwid.LineBox(
                    urwid.Padding(self.server_ip_text, left=1, right=1),
                    title=" Server IP ", title_align='left',
                ),
                'ws_bg',
            )))

        # Live Activity panel
        self.live_walker = urwid.SimpleFocusListWalker([])
        panels.append(('weight', 1, urwid.AttrMap(
            urwid.LineBox(
                urwid.ListBox(self.live_walker),
                title=" Live Activity ", title_align='left',
            ),
            'ws_bg',
        )))

        return panels

    def _make_header(self) -> urwid.Widget:
        parsed = urlparse(self.target_url or "")
        h      = parsed.netloc or "N/A"
        waf_p  = f" | WAF: {self.waf_name}" if self.waf_name else ""
        ip_p   = f" | Origin: {self.server_ip}" if self.server_ip else ""
        tor_p  = " | TOR: ON" if self.enable_tor else ""
        proxy_p = f" | Proxy: {self.upstream_proxy_count}" if self.upstream_proxy_count else ""
        return urwid.AttrMap(
            urwid.Text(
                ('header', f" EvilWAF v2.4 | {h}{waf_p}{ip_p}{tor_p}{proxy_p}   q=Quit  up/down=browse  f=follow "),
                align='center',
            ),
            'header',
        )

    def _update_traffic(self):
        self.traffic_walker.clear()
        records           = self.server.get_records()[-60:]
        self.traffic_data = records

        if not records:
            return

        if self._auto_follow:
            self.selected_row = len(records) - 1

        self.selected_row = max(0, min(self.selected_row, len(records) - 1))

        for idx, rec in enumerate(records):
            req   = rec.request
            resp  = rec.response
            ts    = time.strftime('%H:%M:%S', time.localtime(req.timestamp))
            host  = (req.host or 'N/A')[:19]
            meth  = (req.method or 'N/A')[:5]
            st    = str(resp.status_code) if resp.status_code else '---'
            proto = 'HTTPS' if req.is_https else 'HTTP'
            sz    = _fmt_size(resp.body)
            res   = 'PASS' if rec.passed else ('BLCK' if rec.blocked else 'UNKN')
            is_follow = self._auto_follow and idx == self.selected_row
            is_manual = not self._auto_follow and idx == self.selected_row
            is_bad    = resp.status_code in BAD_CODES

            def make_cols(attr, _proto=proto):
                return urwid.Columns([
                    ('fixed', 10, urwid.Text((attr, f' {ts}'))),
                    ('fixed', 20, urwid.Text((attr, host))),
                    ('fixed', 6,  urwid.Text((attr, meth))),
                    ('fixed', 5,  urwid.Text((attr, st))),
                    ('fixed', 6,  urwid.Text((attr, _proto))),
                    ('fixed', 7,  urwid.Text((attr, sz))),
                    ('weight', 1, urwid.Text((attr, res))),
                ], dividechars=1)

            if is_follow:
                self.traffic_walker.append(urwid.AttrMap(make_cols('tr_follow'), 'tr_follow'))
            elif is_manual:
                self.traffic_walker.append(urwid.AttrMap(make_cols('tr_selected'), 'tr_selected'))
            elif is_bad:
                self.traffic_walker.append(urwid.AttrMap(make_cols('tr_bad'), 'tr_bad'))
            else:
                ra     = 'tr_even' if idx % 2 == 0 else 'tr_odd'
                ra_res = 'tr_pass' if rec.passed else ('tr_block' if rec.blocked else 'tr_unkn')
                cols = urwid.Columns([
                    ('fixed', 10, urwid.Text(('tr_time',   f' {ts}'))),
                    ('fixed', 20, urwid.Text(('tr_host',   host))),
                    ('fixed', 6,  urwid.Text(('tr_method', meth))),
                    ('fixed', 5,  urwid.Text(('tr_status', st))),
                    ('fixed', 6,  urwid.Text(('tr_proto',  proto))),
                    ('fixed', 7,  urwid.Text(('tr_size',   sz))),
                    ('weight', 1, urwid.Text((ra_res,      res))),
                ], dividechars=1)
                self.traffic_walker.append(urwid.AttrMap(cols, ra))

        if self.traffic_walker:
            try:
                self.traffic_walker.set_focus(self.selected_row)
            except Exception:
                pass

        if self._auto_follow:
            self.follow_text.set_text(('ws_ok', ' [FOLLOW] f=pause '))
        else:
            self.follow_text.set_text(('tr_block', f' [PAUSED] row={self.selected_row + 1}/{len(records)}  f=resume '))

    def _update_tech_panel(self):
        self.tech_walker.clear()
        entries = self.tech_table.get_recent(6)
        if not entries:
            self.tech_walker.append(urwid.AttrMap(
                urwid.Text(('ws_inactive', ' Waiting...')), 'ws_bg'))
            return
        for i, e in enumerate(reversed(entries)):
            cols = urwid.Columns([
                ('fixed', 5,  urwid.Text(('ws_tech_rq',  f' {str(e["rq"]).rjust(3)}'))),
                ('fixed', 18, urwid.Text(('ws_tech_tls', (e["tls"] or "N/A")[:17]))),
                ('weight', 1, urwid.Text(('ws_tech_tcp', (e["tcp"] or "N/A")[:13]))),
            ], dividechars=1)
            self.tech_walker.append(urwid.AttrMap(cols, 'ws_bg'))

    def _update_server_ip_panel(self):
        # Wireshark style — black bg, white text
        if not self.server_ip:
            return
        self.server_ip_text.set_text([
            ('ws_label', ' Origin IP : '),
            ('ws_ip',    self.server_ip),
            ('ws_bg',    '\n'),
            ('ws_label', ' Mode      : '),
            ('ws_value', 'Direct Bypass'),
        ])

    def _update_live_panel(self):
        self.live_walker.clear()
        for rec in reversed(self.server.get_records()[-15:]):
            req  = rec.request
            ts   = time.strftime('%H:%M:%S', time.localtime(req.timestamp))
            tech = (rec.technique_applied or "N/A")[:16]
            sz   = _fmt_size(rec.response.body)
            if rec.passed:
                ind = ('ws_ind_pass', '+')
            elif rec.blocked:
                ind = ('ws_ind_block', '-')
            else:
                ind = ('ws_ind_unkn', '?')
            self.live_walker.append(urwid.Text([
                ('ws_time',  f'[{ts}] '),
                ind,
                ('ws_value', f' {(req.host or "N/A")[:14]} '),
                ('ws_value', f'{sz} '),
                ('ws_tech',  tech),
            ]))
        if self.live_walker:
            try:
                self.live_walker.set_focus(0)
            except Exception:
                pass

    def _update_status(self):
        records  = self.server.get_records()
        total    = len(records)
        passed   = sum(1 for r in records if r.passed)
        blocked  = sum(1 for r in records if r.blocked)
        rate     = (passed / total * 100) if total else 0.0
        tor_ips  = self.tor_table.get_all()
        tor_cnt  = len(tor_ips)
        cur_ip   = tor_ips[-1]["ip"] if tor_ips else "N/A"
        tor_str  = f"ON ip={cur_ip} rotations={tor_cnt}" if self.enable_tor else "OFF"
        ip_str   = f" | Origin:{self.server_ip}" if self.server_ip else ""
        mode_str = " FOLLOW" if self._auto_follow else " PAUSED"
        self.status_text.set_text([
            ('status', f' Total:{total} '),
            ('status', f'Pass:{passed} '),
            ('status', f'Block:{blocked} '),
            ('status', f'Rate:{rate:.1f}% '),
            ('status', f'TOR:{tor_str}'),
            ('status', ip_str),
            ('status', f' |{mode_str} '),
            ('status', f' {time.strftime("%H:%M:%S")} '),
        ])

    def _refresh(self, loop: urwid.MainLoop, _: Any):
        try:
            self._update_traffic()
            if self.enable_tor and self._tor_panel:
                self._tor_panel.refresh()
            self._update_tech_panel()
            self._update_server_ip_panel()
            self._update_live_panel()
            self._update_status()
        except Exception:
            pass
        loop.set_alarm_in(0.3, self._refresh)

    def _handle_input(self, key: str):
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        elif key in ('f', 'F', 'end'):
            self._auto_follow = not self._auto_follow
            if self._auto_follow and self.traffic_data:
                self.selected_row = len(self.traffic_data) - 1
            self._update_traffic()
        elif key == 'up':
            self._auto_follow = False
            if self.selected_row > 0:
                self.selected_row -= 1
            self._update_traffic()
        elif key == 'down':
            self._auto_follow = False
            if self.selected_row < len(self.traffic_data) - 1:
                self.selected_row += 1
            self._update_traffic()
        elif key == 'page up':
            self._auto_follow = False
            self.selected_row = max(0, self.selected_row - 10)
            self._update_traffic()
        elif key == 'page down':
            self._auto_follow = False
            self.selected_row = min(len(self.traffic_data) - 1, self.selected_row + 10)
            self._update_traffic()
        elif key == 'home':
            self._auto_follow = False
            self.selected_row = 0
            self._update_traffic()

    def start(self):
        self.loop.run()


class EvilWAFOrchestrator:
    def __init__(
        self,
        listen_host:      str,
        listen_port:      int,
        enable_tor:       bool,
        tor_control_port: int,
        tor_password:     str,
        tor_rotate_every: int,
        server_ip:        Optional[str] = None,
        target_host:      Optional[str] = None,
        upstream_proxies: Optional[List[str]] = None,
    ):
        self._enable_tor = enable_tor
        self._running    = False

        self._server = create_interceptor(
            listen_host=listen_host,
            listen_port=listen_port,
            intercept_https=True,
            tor_control_port=tor_control_port,
            tor_password=tor_password,
            tor_rotate_every=tor_rotate_every,
            override_ip=server_ip,
            target_host=target_host,
            upstream_proxies=upstream_proxies,
        )

        self._tor_table  = TorIPTable()
        self._tech_table = TechniqueTable()
        self._tor_thread:  Optional[threading.Thread] = None
        self._tech_thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._server.start()
        self._tor_thread  = threading.Thread(target=self._watch_tor,  daemon=True)
        self._tech_thread = threading.Thread(target=self._watch_tech, daemon=True)
        self._tor_thread.start()
        self._tech_thread.start()

    def stop(self):
        self._running = False
        try:
            self._server.stop()
        except Exception:
            pass

    def _watch_tor(self):
        last_ip = None
        last_ts = time.time()
        while self._running:
            try:
                if self._enable_tor and self._server._tor.is_tor_alive():
                    self._server._tor.rotate_and_verify()
                    ip = getattr(self._server._tor, '_current_ip', None)
                    if not ip:
                        try:
                            ip = self._server._tor.get_current_ip()
                        except Exception:
                            ip = None
                    if ip and ip != last_ip:
                        self._tor_table.add(ip, time.time() - last_ts, "Running")
                        last_ip = ip
                        last_ts = time.time()
            except Exception:
                pass
            time.sleep(1)

    def _watch_tech(self):
        last_count = 0
        while self._running:
            try:
                records = self._server.get_records()
                if len(records) > last_count:
                    tls_id   = getattr(self._server._tls_fp,    '_last_identifier', 'N/A') or 'N/A'
                    tcp_prof = getattr(self._server._tcp_manip, '_last_profile',    'N/A') or 'N/A'
                    self._tech_table.add(tls_id, tcp_prof)
                    last_count = len(records)
            except Exception:
                pass
            time.sleep(0.5)

    @property
    def server(self) -> Interceptor:
        return self._server

    @property
    def tor_table(self) -> TorIPTable:
        return self._tor_table

    @property
    def tech_table(self) -> TechniqueTable:
        return self._tech_table


def signal_handler(signum: int, frame: Any):
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        prog="evilwaf",
        description="EvilWAF v2.4 — Transparent WAF Bypass Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Flags:\n"
            "  -t / --target          Target URL (required)\n"
            "  --listen-host          Proxy listen address (default: 127.0.0.1)\n"
            "  --listen-port          Proxy listen port (default: 8080)\n"
            "  --enable-tor           Route all traffic through TOR with per-request IP rotation\n"
            "  --tor-control-port     TOR control port (default: 9051)\n"
            "  --tor-password         TOR control password\n"
            "  --tor-rotate-every     Rotate TOR IP every N requests (default: 1)\n"
            "  --server-ip            Force all requests to this origin IP (WAF bypass)\n"
            "  --auto-hunt            Auto-discover origin IP behind WAF\n"
            "  --upstream-proxy URL   Upstream proxy (http://, socks5://, socks4://)\n"
            "  --proxy-file FILE      File with proxy URLs for rotation\n"
            "  --no-tui               Headless mode, print traffic to stdout\n"
            "\n"
            "API Keys (optional, set as environment variables):\n"
            "  SHODAN_API_KEY         Shodan API key\n"
            "  SECURITYTRAILS_API_KEY SecurityTrails API key\n"
            "  VIRUSTOTAL_API_KEY     VirusTotal API key\n"
            "  CENSYS_API_ID          Censys API ID\n"
            "  CENSYS_API_SECRET      Censys API secret\n"
            "\n"
            "Point your tool:\n"
            "  sqlmap -u 'https://target.com/page?id=1' --proxy=http://127.0.0.1:8080\n"
            "  ffuf -u https://target.com/FUZZ -x http://127.0.0.1:8080\n"
        ),
    )

    parser.add_argument("-t", "--target",          type=str, required=True,  metavar="URL")
    parser.add_argument("--listen-host",           type=str, default="127.0.0.1")
    parser.add_argument("--listen-port",           type=int, default=8080)
    parser.add_argument("--enable-tor",            action="store_true")
    parser.add_argument("--tor-control-port",      type=int, default=9051)
    parser.add_argument("--tor-password",          type=str, default="")
    parser.add_argument("--tor-rotate-every",      type=int, default=1)
    parser.add_argument("--server-ip",             type=str, default=None)
    parser.add_argument("--auto-hunt",             action="store_true")
    parser.add_argument("--upstream-proxy",        type=str, default=None, metavar="URL",
                        help="Upstream proxy URL (http://host:port, socks5://host:port)")
    parser.add_argument("--proxy-file",            type=str, default=None, metavar="FILE",
                        help="File with proxy URLs, one per line, for rotation")
    parser.add_argument("--no-tui",                action="store_true")

    args = parser.parse_args()

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] Invalid target: {args.target}")
        sys.exit(1)

    if args.server_ip and args.auto_hunt:
        print("[!] --server-ip and --auto-hunt cannot be used together")
        sys.exit(1)

    upstream_proxies = None
    if args.upstream_proxy:
        upstream_proxies = [args.upstream_proxy]
    if args.proxy_file:
        with open(args.proxy_file) as f:
            file_proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        upstream_proxies = (upstream_proxies or []) + file_proxies

    print("[*] EvilWAF v2.4")
    print(f"[*] Target : {args.target}")
    print("[*] Detecting WAF...", end="", flush=True)
    waf_name = _detect_waf(args.target)
    print(f"\r[*] WAF    : {waf_name or 'none detected'}")

    server_ip: Optional[str] = None

    if args.server_ip:
        server_ip = args.server_ip
        print(f"[*] Mode   : Manual IP bypass -> {server_ip}")
    elif args.auto_hunt:
        found = _hunt_origin_ip_verbose(args.target)
        if found:
            if _ask_connect_proxy(found):
                server_ip = found
                print(f"[+] Routing traffic -> {server_ip}")
            else:
                print(f"[*] Tip: use --server-ip {found}")
                sys.exit(0)
        else:
            print("[!] Origin IP not found — standard proxy mode")
    else:
        print("[*] Mode   : Standard proxy")

    if args.enable_tor:
        print("[*] TOR    : Enabled — rotating IP every request")

    if upstream_proxies:
        print(f"[*] Proxy  : {len(upstream_proxies)} upstream proxy(ies)")

    print(f"[*] Listen : {args.listen_host}:{args.listen_port}")

    orchestrator = EvilWAFOrchestrator(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        enable_tor=args.enable_tor,
        tor_control_port=args.tor_control_port,
        tor_password=args.tor_password,
        tor_rotate_every=args.tor_rotate_every,
        server_ip=server_ip,
        target_host=parsed.hostname,
        upstream_proxies=upstream_proxies,
    )

    orchestrator.start()
    time.sleep(0.8)

    print(f"[+] Proxy ready : http://{args.listen_host}:{args.listen_port}")
    if server_ip:
        print(f"[+] Routing     : {parsed.hostname} -> {server_ip}")

    if args.enable_tor:
        alive = orchestrator.server._tor.is_tor_alive()
        cur   = orchestrator.server._tor.get_current_ip() if alive else None
        print(f"[+] TOR status  : {'active — ' + (cur or 'N/A') if alive else 'not reachable'}")

    try:
        if args.no_tui:
            print("[*] Headless mode — Ctrl+C to stop\n")
            print(f"{'RQ':<6} {'Host':<20} {'Time':<10} {'St':<5} {'Proto':<6} {'Result':<6} {'Tech'}")
            print("-" * 72)
            last = 0
            rq   = 0
            while True:
                time.sleep(1)
                records = orchestrator.server.get_records()
                if len(records) > last:
                    for rec in records[last:]:
                        rq    += 1
                        ts     = time.strftime('%H:%M:%S', time.localtime(rec.request.timestamp))
                        host   = (rec.request.host or "N/A")[:19]
                        st     = str(rec.response.status_code) if rec.response.status_code else "---"
                        proto  = 'HTTPS' if rec.request.is_https else 'HTTP'
                        res    = "PASS" if rec.passed else ("BLCK" if rec.blocked else "UNKN")
                        tech   = rec.technique_applied or "N/A"
                        print(f"{str(rq):<6} {host:<20} {ts:<10} {st:<5} {proto:<6} {res:<6} {tech}")
                    last = len(records)
        else:
            tui = EvilWAFTUI(
                server=orchestrator.server,
                target_url=args.target,
                tor_table=orchestrator.tor_table,
                tech_table=orchestrator.tech_table,
                server_ip=server_ip,
                waf_name=waf_name,
                enable_tor=args.enable_tor,
                upstream_proxy_count=len(upstream_proxies) if upstream_proxies else 0,
            )
            tui.start()
    except KeyboardInterrupt:
        pass
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()
