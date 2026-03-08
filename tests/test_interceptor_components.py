import io
import os
import socket
import tempfile
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorComponentTest(unittest.TestCase):
    def test_certificate_authority_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            ca = i.CertificateAuthority(ca_dir=d)
            cert_path, key_path = ca.get_certificate_for_host("example.com")
            self.assertTrue(os.path.exists(cert_path))
            self.assertTrue(os.path.exists(key_path))
            exp = ca.export_ca_certificates(d)
            self.assertTrue(os.path.exists(exp["pem"]))
            ca.cleanup()

    def test_h1_parser_build_and_parse(self):
        req = i.InterceptedRequest(method="GET", path="/a", host="example.com", port=80, headers={"x": "1"})
        raw_req = i.H1Parser.build_request(req)
        self.assertIn(b"GET /a HTTP/1.1", raw_req)

        parsed = i.H1Parser.parse_request_line(b"GET /x HTTP/1.1\r\n")
        self.assertEqual(parsed[0], "GET")

        resp = i.InterceptedResponse(status_code=200, status_text="OK", headers={"X": "1"}, body=b"abc")
        raw_resp = i.H1Parser.build_response(resp)
        self.assertIn(b"HTTP/1.1 200 OK", raw_resp)
        parsed_resp = i.H1Parser.parse_response_line(raw_resp)
        self.assertEqual(parsed_resp[1], 200)

        hdrs = i.H1Parser.extract_headers(b"HTTP/1.1 200 OK\r\nX-Test: a\r\n\r\n")
        self.assertEqual(hdrs["x-test"], "a")

    def test_h1_read_message_with_socketpair(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
            h, body = i.H1Parser.read_message(a, timeout=1)
            self.assertIn(b"200 OK", h)
            self.assertEqual(body, b"abc")
        finally:
            a.close()
            b.close()

    def test_response_advisor_and_magic(self):
        class DummyTor:
            def should_rotate(self, request_count, rotate_every=1):
                return False

            def is_tor_alive(self):
                return False

        magic = i.Magic(tor=DummyTor(), rotate_every=3)
        advisor = i.ResponseAdvisor(magic=magic, max_retries=1, retry_delay=0.1)
        req = i.InterceptedRequest(host="example.com")
        rec = i.ProxyRecord()

        d1 = advisor.advise(i.InterceptedResponse(status_code=403), req, rec)
        self.assertEqual(d1.action, "retry")
        d2 = advisor.advise(i.InterceptedResponse(status_code=403), req, rec)
        self.assertEqual(d2.action, "forward")

        with mock.patch.object(magic._tls, "rotate") as tls_rotate:
            magic.error_solver(i.ssl.SSLError("x"))
            tls_rotate.assert_called_once()

    def test_forwarder(self):
        class H:
            command = "GET"

            def __init__(self):
                self.headers = []
                self.wfile = io.BytesIO()

            def send_response(self, code, text):
                self.code = code
                self.text = text

            def send_header(self, k, v):
                self.headers.append((k, v))

            def end_headers(self):
                return None

        h = H()
        resp = i.InterceptedResponse(status_code=200, status_text="OK", headers={"X": "1"}, body=b"abc")
        self.assertTrue(i.Forwarder().forward(resp, h))
        self.assertEqual(h.code, 200)

    def test_interceptor_helpers(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._records = [i.ProxyRecord()]
        inter._records_lock = i.threading.Lock()
        self.assertTrue(inter._is_waf_block(403))
        self.assertFalse(inter._is_waf_block(200))
        self.assertEqual(len(inter.get_records()), 1)
        inter.clear_records()
        self.assertEqual(inter.get_records(), [])


if __name__ == "__main__":
    unittest.main()
