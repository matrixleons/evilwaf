import types
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorLowLevelTest(unittest.TestCase):
    def test_h2connection_methods(self):
        class FakeH2Conn:
            def __init__(self, config=None):
                self._sent = b""

            def initiate_connection(self):
                return None

            def data_to_send(self, n):
                return b"x"

            def receive_data(self, data):
                return ["e"]

            def send_headers(self, *args, **kwargs):
                return None

            def send_data(self, *args, **kwargs):
                return None

            def reset_stream(self, *args, **kwargs):
                return None

            def close_connection(self):
                return None

        fake_h2 = types.SimpleNamespace(
            config=types.SimpleNamespace(H2Configuration=lambda **kwargs: object()),
            connection=types.SimpleNamespace(H2Connection=FakeH2Conn),
        )

        sock = mock.Mock()
        sock.recv.return_value = b"abc"
        with mock.patch("core.interceptor.h2", fake_h2, create=True):
            c = i.H2Connection(sock, is_server=True, hostname="x")
            c.initiate()
            ev = c.recv_events()
            self.assertEqual(ev, ["e"])
            c.send_headers(1, [(":method", "GET")])
            c.send_data(1, b"abc", end_stream=True)
            c.reset_stream(1)
            c.close()

    def test_h2connection_recv_error_and_control_exceptions(self):
        class FakeH2Conn:
            def __init__(self, config=None):
                pass

            def data_to_send(self, n):
                return b""

            def receive_data(self, data):
                raise i.ssl.SSLError("x")

            def send_headers(self, *args, **kwargs):
                raise Exception("x")

            def send_data(self, *args, **kwargs):
                raise Exception("x")

            def reset_stream(self, *args, **kwargs):
                raise Exception("x")

            def close_connection(self):
                raise Exception("x")

            def initiate_connection(self):
                return None

        fake_h2 = types.SimpleNamespace(
            config=types.SimpleNamespace(H2Configuration=lambda **kwargs: object()),
            connection=types.SimpleNamespace(H2Connection=FakeH2Conn),
        )

        sock = mock.Mock()
        sock.recv.side_effect = i.socket.timeout()
        with mock.patch("core.interceptor.h2", fake_h2, create=True):
            c = i.H2Connection(sock, is_server=False, hostname="x")
            self.assertEqual(c.recv_events(), [])
            with self.assertRaises(Exception):
                c.send_headers(1, [])
            with self.assertRaises(Exception):
                c.send_data(1, b"x")
            c.reset_stream(1)
            c.close()

    def test_h1parser_special_branches(self):
        s = mock.Mock()
        s.recv.side_effect = [b"\x16abc"]
        h, b = i.H1Parser.read_message(s)
        self.assertEqual((h, b), (b"", b""))

        s2 = mock.Mock()
        s2.recv.side_effect = [b"PRI * HTTP/2.0"]
        h2, b2 = i.H1Parser.read_message(s2)
        self.assertEqual((h2, b2), (b"", b""))

        class Sock:
            def __init__(self):
                self.parts = [b"4\r\ntest\r\n0\r\n\r\n"]

            def settimeout(self, t):
                return None

            def recv(self, n):
                if self.parts:
                    return self.parts.pop(0)
                return b""

        out = i.H1Parser._read_chunked(Sock(), b"")
        self.assertEqual(out, b"test")

    def test_tls_context_factory_fallback_and_mitm_success(self):
        orig = i.ssl.SSLContext.set_ciphers

        def flaky_set_ciphers(self, value):
            if value == i.TLSContextFactory.CIPHERS:
                raise i.ssl.SSLError("x")
            return orig(self, value)

        with mock.patch.object(i.ssl.SSLContext, "set_ciphers", flaky_set_ciphers):
            c = i.TLSContextFactory.client_context(["http/1.1"])
            self.assertIsNotNone(c)

        ca = mock.Mock()
        ca.get_certificate_for_host.return_value = ("cert", "key")
        hs = i.MITMHandshaker(ca=ca, override_ip="8.8.8.8")

        client_tls = mock.Mock()
        client_tls.selected_alpn_protocol.return_value = "h2"
        server_ctx = mock.Mock()
        server_ctx.wrap_socket.return_value = client_tls

        server_raw = mock.Mock()
        server_raw.setsockopt = mock.Mock()

        upstream_tls = mock.Mock()
        upstream_tls.selected_alpn_protocol.return_value = "h2"
        client_ctx = mock.Mock()
        client_ctx.wrap_socket.return_value = upstream_tls

        with mock.patch.object(i.TLSContextFactory, "server_context", return_value=server_ctx):
            with mock.patch.object(i.socket, "create_connection", return_value=server_raw):
                with mock.patch.object(i.TLSContextFactory, "client_context", return_value=client_ctx):
                    out = hs.perform(mock.Mock(), "example.com", 443)
                    self.assertTrue(out["success"])
                    self.assertEqual(out["alpn"], "h2")


if __name__ == "__main__":
    unittest.main()
