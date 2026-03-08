import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import chemistry.proxy_rotator as p
import chemistry.tcp_options as t
import chemistry.tls_rotator as tls
import chemistry.tor_rotator as tor


class ChemistryModulesTest(unittest.TestCase):
    def test_tcp_options_profiles_rotate_and_send_syn(self):
        m = t.TCPOptionsManipulator()
        prof = m.get_profile("chrome")
        self.assertIn("options", prof)
        r = m.rotate()
        self.assertIn("window", r)

        class Resp:
            def haslayer(self, layer):
                return True

            def __getitem__(self, item):
                class TLayer:
                    flags = "SA"

                return TLayer()

        with mock.patch.object(t, "sr1", return_value=Resp()):
            self.assertIsNotNone(m.send_syn("8.8.8.8", 443, "chrome"))

    def test_tls_fingerprinter_paths(self):
        f = tls.TLSFingerprinter()
        _, id1 = f.get_session("chrome_120")
        self.assertEqual(id1, "chrome_120")

        _, id2 = f.rotate()
        self.assertNotEqual(id2, id1)

        _, custom = f.get_custom_session("chrome_android")
        self.assertEqual(custom, "chrome_android")

        _, mapped = f.paired_with_tcp("windows11")
        self.assertEqual(mapped, "edge_120")

        data = f.per_request_session()
        self.assertIn("session", data)

    def test_proxy_rotator_flow(self):
        with mock.patch.object(p.ProxyRotator, "_probe_proxies", return_value=[]):
            r = p.ProxyRotator(["http://user:pass@127.0.0.1:8080"])
            parsed = r._parse_proxy_url("socks5://127.0.0.1:9050")
            self.assertEqual(parsed["scheme"], "socks5")

            sock = mock.Mock()
            with mock.patch.object(p.socks, "create_connection", return_value=sock):
                out = r.create_connection("example.com", 80)
                self.assertIs(out, sock)

            self.assertTrue(r.get_proxy_dict())
            self.assertIn("proxies", r.per_request_proxy())
            self.assertIn("available_proxies", r.get_stats())

    def test_tor_rotator_flow(self):
        with mock.patch.object(tor.TorRotator, "_probe_proxies", return_value=[{"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}]):
            with mock.patch.object(tor.TorRotator, "_probe_control_ports", return_value=[9051]):
                r = tor.TorRotator(control_password="")

        self.assertTrue(r.should_rotate(2, 2))
        self.assertIn("proxies", r.per_request_proxy())
        self.assertIn("available_proxies", r.get_stats())

        with mock.patch.object(r, "_rotate_all_circuits", return_value=True):
            with mock.patch.object(tor.time, "sleep", return_value=None):
                self.assertTrue(r.rotate_circuit())

        fake_resp = mock.Mock()
        fake_resp.json.return_value = {"ip": "203.0.113.5", "IsTor": True}
        with mock.patch.object(tor.requests, "get", return_value=fake_resp):
            self.assertEqual(r.get_current_ip(), "203.0.113.5")
            self.assertTrue(r.is_tor_alive())

        with mock.patch.object(r, "rotate_circuit", return_value=True):
            with mock.patch.object(r, "get_current_ip", return_value="203.0.113.6"):
                with mock.patch.object(tor.time, "sleep", return_value=None):
                    ok, ip = r.rotate_and_verify(max_attempts=1)
                    self.assertTrue(ok)
                    self.assertEqual(ip, "203.0.113.6")


if __name__ == "__main__":
    unittest.main()
