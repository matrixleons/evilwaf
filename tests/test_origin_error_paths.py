import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.origin_server_ip as o


class OriginErrorPathsTest(unittest.IsolatedAsyncioTestCase):
    async def test_hunter_scanner_exceptions_and_verify_exceptions(self):
        h = o.OriginServerIPHunter("example.com", verify=True, enrich=False)

        class BadScanner:
            async def scan(self):
                raise Exception("boom")

        class GoodScanner:
            async def scan(self):
                return [o.OriginResult("8.8.8.8", "good", 0.6)]

        h._scanners = [BadScanner(), GoodScanner()]

        async def feed(results, report):
            for r in results:
                report.add(r)
            return []

        h._correlator.feed = mock.AsyncMock(side_effect=feed)
        with mock.patch.object(h._waf_resolver, "detect", return_value=(o.WAFVendor.UNKNOWN, [])):
            with mock.patch.object(h._verifier, "verify", side_effect=[Exception("x")]):
                rep = await h.hunt()

        self.assertTrue(rep.origin_candidates)
        self.assertEqual(rep.verified_ips, [])

    async def test_scanner_exception_fallbacks(self):
        dns = o.DNSMisconfigurationScanner("example.com")
        dns.resolver.resolve = mock.Mock(side_effect=Exception("x"))
        self.assertEqual(dns._query_record("A"), [])
        self.assertEqual(dns._check_zone_transfer(), [])

        cloud = o.CloudProviderLeakScanner("example.com")
        cloud.resolver.resolve = mock.Mock(side_effect=Exception("x"))
        self.assertEqual(cloud._follow_cname_chain("example.com"), [])
        self.assertEqual(cloud._check_txt_spf_includes(), [])

        hdr = o.HTTPHeaderLeakScanner("example.com")
        with mock.patch.object(o.http.client, "HTTPSConnection", side_effect=Exception("x")):
            self.assertEqual(hdr._probe_path("/"), [])


if __name__ == "__main__":
    unittest.main()
