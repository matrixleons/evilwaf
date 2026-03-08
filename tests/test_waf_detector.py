import unittest

from core.waf_detector import WAFDetector


class WAFDetectorTest(unittest.TestCase):
    def setUp(self):
        self.det = WAFDetector()

    def test_detect_from_headers_and_response_and_cookies(self):
        headers = {"Server": "cloudflare", "CF-RAY": "abc"}
        body = "attention required by cloudflare"
        cookies = {"__cf_bm": "x"}

        names = set(self.det.detect_all(body, headers, cookies, 403))
        self.assertIn("Cloudflare", names)

    def test_signature_management_and_search(self):
        self.det.add_custom_signature(
            waf_id="custom",
            name="CustomWAF",
            patterns=[r"customwaf"],
            headers={"X-Custom": r"enabled"},
            cookies=["cwaf"],
            response_codes=[499],
        )

        info = self.det.get_waf_info("custom")
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "CustomWAF")
        self.assertGreaterEqual(self.det.get_signature_count(), 1)

        search = self.det.search_pattern("custom")
        self.assertTrue(any("CustomWAF" in x[0] for x in search))
        info_none = self.det.get_waf_info("nope")
        self.assertIsNone(info_none)
        self.assertTrue(self.det.remove_signature("custom"))
        self.assertFalse(self.det.remove_signature("custom"))

    def test_detect_by_status_and_list(self):
        names = self.det.detect_from_status_code(403)
        self.assertTrue(len(names) > 0)
        listed = self.det.list_all_wafs()
        self.assertTrue(any(name in listed for name in names))
        sig = self.det.waf_signatures["cloudflare"]
        self.assertTrue(self.det._check_response_match("x", {"CF-RAY": "v"}, sig))
        results = self.det.search_pattern("cf-ray")
        self.assertTrue(results)


if __name__ == "__main__":
    unittest.main()
