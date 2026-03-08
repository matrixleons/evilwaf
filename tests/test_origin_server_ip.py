import json
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.origin_server_ip as o


class OriginHelpersTest(unittest.TestCase):
    def test_recon_report_add_and_sort(self):
        report = o.ReconReport(target="example.com")
        a = o.OriginResult(ip="1.1.1.1", source="dns:a", confidence=0.6)
        b = o.OriginResult(ip="1.1.1.1", source="ssl:b", confidence=0.8, verified=True)
        report.add(a)
        report.add(b)
        self.assertEqual(report.best_candidate.ip, "1.1.1.1")
        self.assertEqual(report.best_candidate.confidence, 0.8)
        self.assertTrue(report.get_cross_source_ips(2))
        self.assertTrue(report.sorted_candidates)
        self.assertTrue(report.high_confidence_candidates)

    def test_ip_helpers(self):
        with mock.patch.object(o, "WAF_IP_RANGES", {}):
            is_waf, _ = o._is_waf_ip("1.1.1.1", extra_ranges=["1.1.1.0/24"])
            self.assertTrue(is_waf)
        self.assertTrue(o._is_private_ip("10.0.0.1"))
        self.assertFalse(o._is_private_ip("8.8.8.8"))
        ips = o._extract_ips("x 8.8.8.8 y 10.0.0.1 z")
        self.assertEqual(ips, ["8.8.8.8"])

    def test_fetch_url_and_resolve(self):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"ok"

        with mock.patch.object(o, "urlopen", return_value=Resp()):
            self.assertEqual(o._fetch_url("http://x"), "ok")

        with mock.patch.object(o, "urlopen", side_effect=Exception("x")):
            self.assertIsNone(o._fetch_url("http://x"))

        with mock.patch.object(o.socket, "gethostbyname", return_value="8.8.8.8"):
            self.assertEqual(o._resolve_hostname("example.com"), "8.8.8.8")

    def test_enricher(self):
        r = o.OriginResult(ip="8.8.8.8", source="x", confidence=0.5)

        def fake_fetch(url, timeout=10, headers=None, auth=None):
            if "ipinfo" in url:
                return json.dumps({"org": "AS1 Example", "country": "US", "hostname": "a.example.com"})
            return json.dumps({"ports": [80, 443], "hostnames": ["b.example.com"]})

        with mock.patch.object(o, "_fetch_url", side_effect=fake_fetch):
            out = o.IPEnricher().enrich(r)
            self.assertEqual(out.country, "US")
            self.assertIn(443, out.ports)

    def test_vendor_resolver(self):
        resolver = o._WAFVendorResolver("example.com")
        with mock.patch.object(o.socket, "gethostbyname", return_value="104.16.0.1"):
            v, names = resolver.detect()
            self.assertNotEqual(v, o.WAFVendor.UNKNOWN)
            self.assertTrue(names)

        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            with mock.patch.object(o, "_fetch_url", return_value="attention required cloudflare"):
                v, names = resolver.detect()
                self.assertTrue(names)


class OriginScannersTest(unittest.IsolatedAsyncioTestCase):
    async def test_dns_history_parse(self):
        s = o.DNSHistoryScanner("example.com")
        text = json.dumps({"records": [{"values": [{"ip": "8.8.8.8"}]}]})
        self.assertIn("8.8.8.8", s._parse(text, "securitytrails_api"))
        self.assertIn("8.8.8.8", s._parse("8.8.8.8", "other"))

    async def test_subdomain_parser(self):
        s = o.SubdomainEnumerator("example.com")
        data = json.dumps([{"name_value": "a.example.com"}])
        out = s._parse_passive(data)
        self.assertIn("a", out)

    async def test_ssl_ct_parser(self):
        s = o.SSLCertificateScanner("example.com")
        data = json.dumps([{"name_value": "a.example.com\n*.b.example.com"}])
        subs = s._parse_ct(data)
        self.assertIn("a.example.com", subs)

    async def test_origin_verifier_verify_http_and_verify(self):
        v = o.OriginVerifier("example.com")

        class Conn:
            def __init__(self):
                self.c = 0

            def sendall(self, data):
                return None

            def recv(self, n):
                self.c += 1
                if self.c == 1:
                    return b"HTTP/1.1 200 OK\r\n\r\n"
                return b""

            def close(self):
                return None

        class Ctx:
            check_hostname = False
            verify_mode = None

            def wrap_socket(self, raw, server_hostname=None):
                return Conn()

        with mock.patch.object(o.ssl, "create_default_context", return_value=Ctx()):
            with mock.patch.object(o.socket, "create_connection", return_value=object()):
                self.assertTrue(v.verify_http("8.8.8.8"))

        with mock.patch.object(v, "verify_cert", return_value=False):
            with mock.patch.object(v, "verify_http", return_value=True):
                ok, cert_ok, http_ok = v.verify("8.8.8.8")
                self.assertTrue(ok)
                self.assertFalse(cert_ok)
                self.assertTrue(http_ok)


if __name__ == "__main__":
    unittest.main()
