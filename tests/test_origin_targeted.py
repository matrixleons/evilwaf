import json
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.origin_server_ip as o


class OriginTargetedTest(unittest.IsolatedAsyncioTestCase):
    async def test_helper_branches(self):
        self.assertEqual(o._is_waf_ip("bad"), (False, o.WAFVendor.UNKNOWN))
        self.assertEqual(o._is_waf_ip("1.2.3.4", extra_ranges=["1.2.3.0/24"])[1], o.WAFVendor.UNKNOWN)
        with mock.patch.object(o, "WAF_IP_RANGES", {}):
            self.assertEqual(o._is_waf_ip("8.8.8.8"), (False, o.WAFVendor.UNKNOWN))
        self.assertTrue(o._is_private_ip("bad"))

        with mock.patch.object(o, "urlopen", side_effect=Exception("x")):
            self.assertIsNone(o._fetch_url("https://example.com"))
        with mock.patch.object(o, "urlopen", side_effect=Exception("x")):
            self.assertIsNone(o._fetch_url("https://example.com", headers={"X": "1"}, auth=("a", "b")))

        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertIsNone(o._resolve_hostname("x"))

    async def test_recon_report_merge_fields(self):
        report = o.ReconReport("example.com")
        a = o.OriginResult("8.8.8.8", "s1:a", 0.3)
        b = o.OriginResult("8.8.8.8", "s2:b", 0.9, verified=True, cert_verified=True, http_verified=True, asn="AS1", org="Org")
        report.add(a)
        report.add(b)
        self.assertTrue(report.origin_candidates[0].verified)
        self.assertEqual(report.best_candidate.ip, "8.8.8.8")

    async def test_enricher_and_verifier_exceptions(self):
        e = o.IPEnricher()
        r = o.OriginResult("8.8.8.8", "x", 0.4)
        with mock.patch.object(o, "_fetch_url", side_effect=["{", "{"]):
            out = e.enrich(r)
            self.assertEqual(out.ip, "8.8.8.8")

        v = o.OriginVerifier("example.com")
        with mock.patch.object(v, "verify_cert", return_value=False):
            with mock.patch.object(v, "verify_http", return_value=True):
                self.assertEqual(v.verify("8.8.8.8"), (True, False, True))

        with mock.patch.object(o.socket, "create_connection", side_effect=Exception("x")):
            self.assertFalse(v.verify_http("8.8.8.8"))
        with mock.patch.object(o.ssl, "create_default_context", side_effect=Exception("x")):
            self.assertFalse(v.verify_cert("8.8.8.8"))

        class Conn:
            def __init__(self):
                self.calls = 0

            def sendall(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 33000
                return b""

            def close(self):
                return None

        with mock.patch.object(o.ssl, "create_default_context", side_effect=Exception("x")):
            with mock.patch.object(o.socket, "create_connection", return_value=Conn()):
                self.assertTrue(v.verify_http("8.8.8.8"))

    async def test_waf_vendor_resolver_branches(self):
        r = o._WAFVendorResolver("example.com")
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            with mock.patch.object(o, "_fetch_url", return_value="body"):
                with mock.patch.object(r._sig, "detect_from_response", return_value=["cloudflare"]):
                    vendor, names = r.detect()
                    self.assertEqual(vendor, o.WAFVendor.CLOUDFLARE)
                    self.assertTrue(names)
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            with mock.patch.object(o, "_fetch_url", return_value="body"):
                with mock.patch.object(r._sig, "detect_from_response", side_effect=Exception("x")):
                    vendor3, _ = r.detect()
                    self.assertEqual(vendor3, o.WAFVendor.UNKNOWN)
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            with mock.patch.object(o, "_fetch_url", return_value="body"):
                with mock.patch.object(r._sig, "detect_from_response", return_value=["vendor cloudflare edge"]):
                    vendor4, _ = r.detect()
                    self.assertEqual(vendor4, o.WAFVendor.CLOUDFLARE)

        with mock.patch.object(o.socket, "gethostbyname", return_value="1.1.1.1"):
            with mock.patch.object(o, "_is_waf_ip", return_value=(True, o.WAFVendor.AKAMAI)):
                vendor2, _ = r.detect()
                self.assertEqual(vendor2, o.WAFVendor.AKAMAI)

    async def test_scanner_small_branches(self):
        s = o.DNSHistoryScanner("example.com")
        with mock.patch.object(o, "_DNS_HISTORY_SOURCES", ["https://a/{domain}"]):
            with mock.patch.object(o, "_fetch_url", side_effect=[Exception("x")]):
                out = await s.scan()
                self.assertEqual(out, [])
        with mock.patch.object(o, "_DNS_HISTORY_SOURCES", ["https://a/{domain}"]):
            with mock.patch.object(o, "_fetch_url", return_value="8.8.8.8"):
                with mock.patch.object(s, "_parse", return_value=["8.8.8.8"]):
                    with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                        self.assertTrue(await s.scan())

        self.assertTrue(s._parse("bad", "securitytrails_api") == [] or isinstance(s._parse("bad", "securitytrails_api"), list))

        ssl_sc = o.SSLCertificateScanner("example.com")
        self.assertTrue(ssl_sc._parse_ct("not-json") == [] or isinstance(ssl_sc._parse_ct("not-json"), list))
        with mock.patch.object(o.socket, "create_connection", side_effect=Exception("x")):
            self.assertFalse(ssl_sc._probe_cert_san("8.8.8.8"))

        sub = o.SubdomainEnumerator("example.com")
        data = {"subdomains": [{"hostname": "a.example.com"}], "data": ["b.example.com"]}
        out_subs = sub._parse_passive(json.dumps(data))
        self.assertTrue(isinstance(out_subs, list))
        with mock.patch.object(o.socket, "gethostbyname", return_value="10.0.0.1"):
            self.assertIsNone(sub._resolve("x"))
        with mock.patch.object(o.socket, "gethostbyname", return_value="8.8.8.8"):
            with mock.patch.object(o, "_is_waf_ip", return_value=(True, o.WAFVendor.UNKNOWN)):
                self.assertIsNone(sub._resolve("x"))
        with mock.patch.object(o.socket, "gethostbyname", return_value="8.8.8.8"):
            with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                out_ok = sub._resolve("x")
                self.assertEqual(out_ok.ip, "8.8.8.8")

    async def test_dns_misconfig_cloud_github_header_favicon(self):
        dns_sc = o.DNSMisconfigurationScanner("example.com")
        dns_sc.resolver.resolve = mock.Mock(side_effect=Exception("x"))
        self.assertEqual(dns_sc._query_record("A"), [])
        self.assertEqual(dns_sc._check_zone_transfer(), [])
        class RD3:
            def to_text(self):
                return "mx bad.example."
        dns_sc.resolver.resolve = mock.Mock(return_value=[RD3()])
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertEqual(dns_sc._query_record("MX"), [])
        class NS:
            target = "ns1.example.com."
        class Zone:
            nodes = {"n": mock.Mock(rdatasets=[[mock.Mock(to_text=mock.Mock(side_effect=Exception("x")))]] )}
        dns_sc.resolver.resolve = mock.Mock(return_value=[NS()])
        with mock.patch.object(o.dns.query, "xfr", return_value=object()):
            with mock.patch.object(o.dns.zone, "from_xfr", return_value=Zone()):
                self.assertEqual(dns_sc._check_zone_transfer(), [])
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertEqual(dns_sc._check_wildcard_dns(), [])
        with mock.patch.object(dns_sc, "_query_record", side_effect=Exception("x")):
            self.assertEqual(await dns_sc.scan(), [])

        cloud = o.CloudProviderLeakScanner("example.com")
        cloud.resolver.resolve = mock.Mock(side_effect=Exception("x"))
        self.assertEqual(cloud._follow_cname_chain("example.com"), [])

        class RD:
            def __init__(self, t):
                self._t = t

            def to_text(self):
                return self._t

        cloud.resolver.resolve = mock.Mock(return_value=[RD('"v=spf1 include:inc.example.com ~all"')])
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertEqual(cloud._check_txt_spf_includes(), [])
        class RD2:
            def __init__(self, t):
                self.target = t
        cloud.resolver.resolve = mock.Mock(return_value=[RD2("a.cloudfront.net.")])
        with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
            self.assertEqual(cloud._follow_cname_chain("example.com"), [])

        gh = o.GitHubLeakScanner("example.com")
        with mock.patch.object(o, "_CODE_SEARCH_SOURCES", ["u1"]):
            with mock.patch.object(o, "_fetch_url", return_value="1.2.3.4 and bad"):
                with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                    out = await gh.scan()
                    self.assertTrue(out)
        with mock.patch.object(o, "_CODE_SEARCH_SOURCES", ["u1"]):
            with mock.patch.object(o, "_fetch_url", return_value=Exception("x")):
                self.assertEqual(await gh.scan(), [])
        with mock.patch.object(o, "_CODE_SEARCH_SOURCES", ["u1"]):
            with mock.patch.object(o, "_fetch_url", return_value="bad ip 999.999.1.1"):
                self.assertEqual(await gh.scan(), [])
        with mock.patch.object(o, "_CODE_SEARCH_SOURCES", ["u1"]):
            with mock.patch.object(o, "_fetch_url", return_value="xxx"):
                with mock.patch.object(gh, "_extract_from_code", return_value=["bad-ip"]):
                    self.assertEqual(await gh.scan(), [])

        h = o.HTTPHeaderLeakScanner("example.com")
        with mock.patch.object(o.http.client, "HTTPSConnection", side_effect=Exception("x")):
            self.assertEqual(h._probe_path("/"), [])
        with mock.patch.object(o, "_HTTP_PROBE_PATHS", ["/a"]):
            with mock.patch.object(h, "_probe_path", return_value=Exception("x")):
                self.assertEqual(await h.scan(), [])

        f = o.FaviconHashScanner("example.com")
        with mock.patch.object(o, "SHODAN_API_KEY", "k"):
            with mock.patch.object(o, "_fetch_url", return_value='{"matches":[{"ip_str":"8.8.8.8"}]}'):
                self.assertEqual(f._search_shodan(1), ["8.8.8.8"])
        with mock.patch.object(o, "_HTTP_LEAK_HEADERS", ["Server"]):
            class Resp:
                def getheader(self, *_):
                    return "origin.example.net"
            class Conn:
                def request(self, *_args, **_kwargs):
                    return None
                def getresponse(self):
                    return Resp()
            with mock.patch.object(o.http.client, "HTTPSConnection", return_value=Conn()):
                with mock.patch.object(o.socket, "gethostbyname", side_effect=o.socket.gaierror()):
                    self.assertEqual(h._probe_path("/"), [])
        with mock.patch.object(o.FaviconHashScanner, "_FAVICON_PATHS", ["/f"]):
            with mock.patch.object(f, "_fetch_favicon", return_value=Exception("x")):
                self.assertEqual(await f.scan(), [])

    async def test_censys_asn_correlator_hunter_branches(self):
        c = o.CensysScanner("example.com")
        with mock.patch.object(o, "CENSYS_API_ID", "id"):
            with mock.patch.object(o, "CENSYS_API_SECRET", "sec"):
                with mock.patch.object(o, "_fetch_url", return_value="bad-json"):
                    self.assertEqual(await c.scan(), [])
                with mock.patch.object(o, "_fetch_url", return_value=json.dumps({"result": {"hits": [{"ip": ""}]}})):
                    self.assertEqual(await c.scan(), [])
                with mock.patch.object(o, "_fetch_url", return_value=None):
                    self.assertEqual(await c.scan(), [])

        asn = o.ASNRangeScanner("example.com")
        with mock.patch.object(o.socket, "gethostbyname", side_effect=Exception("x")):
            self.assertIsNone(asn._get_asn())

        with mock.patch.object(o, "_fetch_url", return_value="{"):
            self.assertEqual(asn._get_asn_prefixes("AS1"), [])

        with mock.patch.object(o.ipaddress, "ip_network") as net:
            net.return_value.num_addresses = 70000
            self.assertEqual(asn._scan_prefix("8.8.8.0/16"), [])
        class Net:
            num_addresses = 10
            def hosts(self):
                return [o.ipaddress.ip_address("8.8.8.8")]
        with mock.patch.object(o.ipaddress, "ip_network", return_value=Net()):
            with mock.patch.object(o.socket, "create_connection", side_effect=Exception("x")):
                self.assertEqual(asn._scan_prefix("8.8.8.0/24"), [])
        class GoodSock:
            def close(self):
                return None
        with mock.patch.object(o.ipaddress, "ip_network", return_value=Net()):
            with mock.patch.object(o.socket, "create_connection", return_value=GoodSock()):
                self.assertEqual(asn._scan_prefix("8.8.8.0/24"), ["8.8.8.8"])
        with mock.patch.object(asn, "_get_asn", return_value=None):
            self.assertEqual(await asn.scan(), [])
        with mock.patch.object(asn, "_get_asn", return_value="AS1"):
            with mock.patch.object(asn, "_get_asn_prefixes", return_value=["8.8.8.0/24"]):
                with mock.patch.object(asn, "_scan_prefix", return_value=Exception("x")):
                    self.assertEqual(await asn.scan(), [])

        verifier = mock.Mock()
        verifier.verify.return_value = (True, True, True)
        corr = o.CrossSourceCorrelator(verifier, min_sources=1)
        report = o.ReconReport("example.com")
        out = await corr.feed([o.OriginResult("8.8.8.8", "src", 0.4)], report)
        self.assertTrue(out and out[0].verified)
        verifier2 = mock.Mock()
        verifier2.verify.return_value = (True, False, True)
        corr2 = o.CrossSourceCorrelator(verifier2, min_sources=1)
        report_b = o.ReconReport("example.com")
        out_b = await corr2.feed([o.OriginResult("1.1.1.1", "src", 0.4)], report_b)
        self.assertTrue(out_b and out_b[0].http_verified)

        h = o.OriginServerIPHunter("example.com", verify=True, enrich=True)
        h._scanners = [mock.Mock(scan=mock.AsyncMock(side_effect=Exception("x")))]
        with mock.patch.object(h._waf_resolver, "detect", return_value=(o.WAFVendor.UNKNOWN, [])):
            report2 = await h.hunt()
        self.assertEqual(report2.total_sources_checked, 1)
        h2 = o.OriginServerIPHunter("example.com", verify=True, enrich=False, manual_ip="8.8.8.8")
        with mock.patch.object(h2._verifier, "verify", return_value=(True, False, True)):
            report3 = await h2.hunt()
            self.assertAlmostEqual(report3.origin_candidates[0].confidence, 1.0)
        h3 = o.OriginServerIPHunter("example.com", verify=True, enrich=False, manual_ip=None)
        h3._scanners = [mock.Mock(scan=mock.AsyncMock(return_value=[o.OriginResult("8.8.8.8", "s", 0.4)]))]
        with mock.patch.object(h3._waf_resolver, "detect", return_value=(o.WAFVendor.UNKNOWN, [])):
            with mock.patch.object(h3._verifier, "verify", return_value=(True, False, True)):
                out3 = await h3.hunt()
                self.assertTrue(out3.origin_candidates[0].http_verified)


if __name__ == "__main__":
    unittest.main()
