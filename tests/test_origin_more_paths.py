import json
import socket
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.origin_server_ip as o


class OriginMorePathsTest(unittest.IsolatedAsyncioTestCase):
    async def test_misc_helpers_and_verifier_cert(self):
        r1 = o.OriginResult("1.1.1.1", "a", 0.1)
        r2 = o.OriginResult("1.1.1.1", "b", 0.2)
        self.assertEqual(r1, r2)
        self.assertEqual(hash(r1), hash(r2))

        v = o.OriginVerifier("example.com")

        class Sock:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getpeercert(self):
                return {"subjectAltName": [("DNS", "*.example.com")]}

        class Ctx:
            check_hostname = False
            verify_mode = None

            def wrap_socket(self, raw, server_hostname=None):
                return Sock()

        with mock.patch.object(o.ssl, "create_default_context", return_value=Ctx()):
            with mock.patch.object(o.socket, "create_connection", return_value=object()):
                self.assertTrue(v.verify_cert("8.8.8.8"))

    async def test_dns_history_api_key_branches(self):
        s = o.DNSHistoryScanner("example.com")
        with mock.patch.object(o, "_DNS_HISTORY_SOURCES", ["https://d/{domain}"]):
            with mock.patch.object(o, "SECURITYTRAILS_API_KEY", "k1"):
                with mock.patch.object(o, "VIRUSTOTAL_API_KEY", "k2"):
                    with mock.patch.object(o, "_fetch_url", return_value=json.dumps({"records": [{"values": [{"ip": "8.8.8.8"}]}]})):
                        with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                            out = await s.scan()
        self.assertTrue(out)

    async def test_subdomain_passive_and_resolve_errors(self):
        s = o.SubdomainEnumerator("example.com")
        d = {"subdomains": ["a.example.com"], "passive_dns": [{"hostname": "b.example.com"}], "data": [{"domain": "c.example.com"}]}
        subs = s._parse_passive(json.dumps(d))
        self.assertTrue(subs)

        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertIsNone(s._resolve("x"))

        with mock.patch.object(o, "_PASSIVE_SUBDOMAIN_SOURCES", ["https://x/{domain}"]):
            with mock.patch.object(o, "_fetch_url", return_value="x.example.com"):
                out = await s._passive_enum()
                self.assertTrue(out)

    async def test_dns_misconfig_dmarc_srv_and_wildcard(self):
        s = o.DNSMisconfigurationScanner("example.com")

        class RD:
            def __init__(self, t):
                self.t = t

            def to_text(self):
                return self.t

        def resolve_side_effect(target, rt):
            return [RD("mx.example.com 8.8.8.8")]

        s.resolver.resolve = mock.Mock(side_effect=resolve_side_effect)
        with mock.patch.object(o.socket, "gethostbyname", return_value="8.8.8.8"):
            self.assertTrue(s._query_record("DMARC"))
            self.assertTrue(s._query_record("SRV"))
            self.assertTrue(s._check_wildcard_dns())

    async def test_favicon_and_censys_and_asn_paths(self):
        fav = o.FaviconHashScanner("example.com")

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"abc"

        with mock.patch.object(o, "urlopen", return_value=Resp()):
            self.assertEqual(fav._fetch_favicon("/favicon.ico"), b"abc")
        with mock.patch.object(o, "urlopen", side_effect=Exception("x")):
            self.assertIsNone(fav._fetch_favicon("/favicon.ico"))

        with mock.patch.object(o, "SHODAN_API_KEY", "k"):
            with mock.patch.object(o, "_fetch_url", return_value="not json"):
                with mock.patch.object(o, "_extract_ips", return_value=["8.8.8.8"]):
                    ips = fav._search_shodan(1)
                    self.assertEqual(ips, ["8.8.8.8"])

        with mock.patch.object(o, "CENSYS_API_ID", None):
            with mock.patch.object(o, "CENSYS_API_SECRET", None):
                c = o.CensysScanner("example.com")
                self.assertEqual(await c.scan(), [])

        asn = o.ASNRangeScanner("example.com")
        with mock.patch.object(o.socket, "gethostbyname", return_value="8.8.8.8"):
            with mock.patch.object(o, "_fetch_url", return_value=json.dumps({"org": "AS15169 Google"})):
                self.assertEqual(asn._get_asn(), "AS15169")
        with mock.patch.object(o, "_fetch_url", return_value=json.dumps({"data": {"ipv4_prefixes": [{"prefix": "8.8.8.0/24"}]}})):
            self.assertEqual(asn._get_asn_prefixes("AS15169"), ["8.8.8.0/24"])

        with mock.patch.object(o.ipaddress, "ip_network", side_effect=Exception("x")):
            self.assertEqual(asn._scan_prefix("8.8.8.0/24"), [])

    async def test_correlator_exception_result_and_property(self):
        verifier = mock.Mock()
        verifier.verify.side_effect = [Exception("x")]
        c = o.CrossSourceCorrelator(verifier, min_sources=1)
        report = o.ReconReport("example.com")
        out = await c.feed([o.OriginResult("8.8.8.8", "s", 0.6)], report)
        self.assertTrue(out)

        h = o.OriginServerIPHunter("example.com")
        self.assertIs(h.report, h._report)


if __name__ == "__main__":
    unittest.main()
