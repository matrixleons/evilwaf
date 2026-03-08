import json
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.origin_server_ip as o


class ScannerFlowTest(unittest.IsolatedAsyncioTestCase):
    async def test_dns_history_scan(self):
        s = o.DNSHistoryScanner("example.com")
        with mock.patch.object(o, "_DNS_HISTORY_SOURCES", ["https://x/{domain}"]):
            with mock.patch.object(o, "_fetch_url", return_value="8.8.8.8"):
                with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                    out = await s.scan()
        self.assertTrue(out)

    async def test_ssl_cert_scan(self):
        s = o.SSLCertificateScanner("example.com")
        ct = json.dumps([{"name_value": "a.example.com"}])
        with mock.patch.object(o, "_CT_LOG_SOURCES", ["https://ct/{domain}"]):
            with mock.patch.object(o, "_fetch_url", return_value=ct):
                with mock.patch.object(o, "_resolve_hostname", return_value="8.8.8.8"):
                    with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                        with mock.patch.object(s, "_probe_cert_san", return_value=True):
                            out = await s.scan()
        self.assertTrue(out)
        self.assertTrue(out[0].cert_verified)

    async def test_subdomain_scan(self):
        s = o.SubdomainEnumerator("example.com")
        with mock.patch.object(s, "_passive_enum", return_value=["a"]):
            with mock.patch.object(o, "_SUBDOMAIN_WORDLIST", ["b"]):
                with mock.patch.object(s, "_resolve", side_effect=[o.OriginResult("8.8.8.8", "x", 0.7), None]):
                    out = await s.scan()
        self.assertEqual(len(out), 1)

    async def test_dns_misconfig_scan(self):
        s = o.DNSMisconfigurationScanner("example.com")
        with mock.patch.object(s, "_query_record", return_value=["8.8.8.8"]):
            with mock.patch.object(s, "_check_zone_transfer", return_value=["1.1.1.1"]):
                with mock.patch.object(s, "_check_wildcard_dns", return_value=["9.9.9.9"]):
                    with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                        out = await s.scan()
        self.assertGreaterEqual(len(out), 3)

    async def test_cloud_and_github_and_http_header_scan(self):
        cloud = o.CloudProviderLeakScanner("example.com")
        gh = o.GitHubLeakScanner("example.com")
        hdr = o.HTTPHeaderLeakScanner("example.com")

        dummy = o.OriginResult("8.8.8.8", "x", 0.8)
        with mock.patch.object(cloud, "_follow_cname_chain", return_value=[dummy]):
            with mock.patch.object(cloud, "_check_txt_spf_includes", return_value=[dummy]):
                out_cloud = await cloud.scan()
        self.assertEqual(len(out_cloud), 2)

        with mock.patch.object(o, "_CODE_SEARCH_SOURCES", ["https://code/{domain}"]):
            with mock.patch.object(o, "_fetch_url", return_value="8.8.8.8"):
                with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                    out_gh = await gh.scan()
        self.assertTrue(out_gh)

        with mock.patch.object(o, "_HTTP_PROBE_PATHS", ["/"]):
            with mock.patch.object(hdr, "_probe_path", return_value=["8.8.8.8"]):
                with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                    out_hdr = await hdr.scan()
        self.assertTrue(out_hdr)

    async def test_favicon_censys_asn_scan(self):
        fav = o.FaviconHashScanner("example.com")
        cens = o.CensysScanner("example.com")
        asn = o.ASNRangeScanner("example.com")

        with mock.patch.object(fav, "_fetch_favicon", return_value=b"abcd"):
            with mock.patch.object(fav, "_search_shodan", return_value=["8.8.8.8"]):
                with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                    out_fav = await fav.scan()
        self.assertTrue(out_fav)

        with mock.patch.object(o, "CENSYS_API_ID", "id"):
            with mock.patch.object(o, "CENSYS_API_SECRET", "secret"):
                data = json.dumps({"result": {"hits": [{"ip": "8.8.8.8", "dns": {"reverse_dns": {"names": ["a"]}}}]}})
                with mock.patch.object(o, "_fetch_url", return_value=data):
                    with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                        out_c = await cens.scan()
        self.assertTrue(out_c)

        with mock.patch.object(asn, "_get_asn", return_value="AS15169"):
            with mock.patch.object(asn, "_get_asn_prefixes", return_value=["8.8.8.0/24"]):
                with mock.patch.object(asn, "_scan_prefix", return_value=["8.8.8.8"]):
                    with mock.patch.object(o, "_is_waf_ip", return_value=(False, o.WAFVendor.UNKNOWN)):
                        out_a = await asn.scan()
        self.assertTrue(out_a)

    async def test_correlator_and_hunter(self):
        verifier = mock.Mock()
        verifier.verify.return_value = (True, True, False)
        c = o.CrossSourceCorrelator(verifier, min_sources=2)
        report = o.ReconReport("example.com")

        r1 = o.OriginResult("8.8.8.8", "s1", 0.6)
        r2 = o.OriginResult("8.8.8.8", "s2", 0.7)
        out = await c.feed([r1], report)
        self.assertEqual(out, [])
        out = await c.feed([r2], report)
        self.assertTrue(out)
        self.assertTrue(out[0].verified)

        h = o.OriginServerIPHunter("example.com", verify=True, enrich=True, manual_ip="8.8.8.8")
        with mock.patch.object(h._verifier, "verify", return_value=(True, True, True)):
            with mock.patch.object(h._enricher, "enrich", side_effect=lambda x: x):
                rep = await h.hunt()
        self.assertTrue(rep.best_candidate)
        self.assertTrue(rep.verified_ips)

    async def test_hunter_full_flow_non_manual(self):
        h = o.OriginServerIPHunter("example.com", verify=True, enrich=True, manual_ip=None)
        h._scanners = [mock.Mock(), mock.Mock()]
        h._scanners[0].scan = mock.AsyncMock(return_value=[o.OriginResult("8.8.8.8", "s1", 0.6)])
        h._scanners[1].scan = mock.AsyncMock(return_value=[o.OriginResult("9.9.9.9", "s2", 0.7)])

        async def fake_feed(results, report):
            for r in results:
                report.add(r)
            return []

        h._correlator.feed = mock.AsyncMock(side_effect=fake_feed)

        with mock.patch.object(h._waf_resolver, "detect", return_value=(o.WAFVendor.CLOUDFLARE, ["cloudflare"])):
            with mock.patch.object(h._verifier, "verify", return_value=(True, True, False)):
                with mock.patch.object(h._enricher, "enrich", side_effect=lambda x: x):
                    rep = await h.hunt()

        self.assertEqual(rep.total_sources_checked, 2)
        self.assertTrue(rep.best_candidate)
        self.assertEqual(rep.waf_vendor, o.WAFVendor.CLOUDFLARE)
        self.assertTrue(rep.verified_ips)


if __name__ == "__main__":
    unittest.main()
