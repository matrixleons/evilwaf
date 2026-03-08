import threading
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorBranchesTest(unittest.TestCase):
    def test_h2_make_success_and_handle_router(self):
        h = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="x",
            port=443,
            server_alpn="h2",
            callbacks={},
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )

        hc = mock.Mock()
        with mock.patch.object(i, "H2_AVAILABLE", True):
            with mock.patch.object(i, "H2Connection", return_value=hc):
                self.assertIs(h._make_client_h2(), hc)
                self.assertIs(h._make_server_h2(), hc)

        with mock.patch.object(i, "H2_AVAILABLE", True):
            with mock.patch.object(h, "_handle_h2_to_h2", return_value=[1]):
                self.assertEqual(h.handle(), [1])
        with mock.patch.object(i, "H2_AVAILABLE", False):
            with mock.patch.object(h, "_relay_raw", return_value=[2]):
                self.assertEqual(h.handle(), [2])
            h.server_alpn = "http/1.1"
            with mock.patch.object(h, "_handle_h1_to_h1", return_value=[3]):
                self.assertEqual(h.handle(), [3])

    def test_h1_to_h1_break_paths(self):
        h = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="x",
            port=443,
            server_alpn="http/1.1",
            callbacks={},
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )

        # no request raw
        with mock.patch.object(i.H1Parser, "read_message", return_value=(b"", b"")):
            self.assertEqual(h._handle_h1_to_h1(), [])

        # PRI preface branch
        with mock.patch.object(i.H1Parser, "read_message", return_value=(b"PRI * HTTP/2.0\r\n", b"")):
            with mock.patch.object(h, "_relay_raw", return_value=[]):
                self.assertEqual(h._handle_h1_to_h1(), [])

        # parse request line failure
        with mock.patch.object(i.H1Parser, "read_message", return_value=(b"BAD\r\n\r\n", b"")):
            with mock.patch.object(i.H1Parser, "parse_request_line", return_value=None):
                self.assertEqual(h._handle_h1_to_h1(), [])

    def test_h1_to_h1_send_breaks(self):
        callbacks = {"request": None, "response": None, "record": None}
        h = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="x",
            port=443,
            server_alpn="http/1.1",
            callbacks=callbacks,
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )
        h.magic.apply.return_value = {"tcp": {}, "tor": {}}

        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        with mock.patch.object(i.H1Parser, "read_message", side_effect=[(req, b"")]):
            with mock.patch.object(i.H1Parser, "parse_request_line", return_value=("GET", "/", "1.1")):
                with mock.patch.object(i.H1Parser, "extract_headers", return_value={}):
                    with mock.patch.object(i.H1Parser, "build_request", return_value=b"x"):
                        h.server_tls.sendall.side_effect = Exception("x")
                        self.assertEqual(h._handle_h1_to_h1(), [])

        # response missing branch
        h.server_tls.sendall.side_effect = None
        with mock.patch.object(i.H1Parser, "read_message", side_effect=[(req, b""), (b"", b"")]):
            with mock.patch.object(i.H1Parser, "parse_request_line", return_value=("GET", "/", "1.1")):
                with mock.patch.object(i.H1Parser, "extract_headers", return_value={}):
                    with mock.patch.object(i.H1Parser, "build_request", return_value=b"x"):
                        self.assertEqual(h._handle_h1_to_h1(), [])

    def test_create_upstream_proxy_and_process_http_error(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._proxy_rotator = mock.Mock()
        inter._proxy_rotator.create_connection.return_value = mock.Mock()
        out = inter._create_upstream_connection("x", 1)
        self.assertIsNotNone(out)

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._override_ip = None
        inter2._create_upstream_connection = mock.Mock(side_effect=Exception("boom"))
        req = i.InterceptedRequest(url="http://example.com/", host="example.com")
        resp = inter2._process_http_request(req)
        self.assertEqual(resp.status_code, 502)

    def test_process_http_https_branch(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._override_ip = None

        sock = mock.Mock()
        tls_sock = mock.Mock()
        inter._create_upstream_connection = mock.Mock(return_value=sock)
        ctx = mock.Mock()
        ctx.wrap_socket.return_value = tls_sock

        req = i.InterceptedRequest(url="https://example.com/path", host="example.com")
        with mock.patch.object(i.TLSContextFactory, "client_context", return_value=ctx):
            with mock.patch.object(i.H1Parser, "build_request", return_value=b"x"):
                with mock.patch.object(i.H1Parser, "read_message", return_value=(b"HTTP/1.1 200 OK\r\n\r\n", b"")):
                    with mock.patch.object(i.H1Parser, "parse_response_line", return_value=("1.1", 200, "OK")):
                        with mock.patch.object(i.H1Parser, "extract_headers", return_value={}):
                            resp = inter._process_http_request(req)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
