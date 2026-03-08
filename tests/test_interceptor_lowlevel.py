import types
import unittest
from unittest import mock
import tempfile
import os
import importlib
import sys

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorLowLevelTest(unittest.TestCase):
    def test_import_success_paths_for_optional_deps(self):
        # Exercise optional import branches for h2/aioquic.
        h2_mod = types.ModuleType("h2")
        h2_cfg = types.ModuleType("h2.config")
        h2_conn = types.ModuleType("h2.connection")
        h2_events = types.ModuleType("h2.events")
        h2_exc = types.ModuleType("h2.exceptions")
        aioquic = types.ModuleType("aioquic")
        aq_quic = types.ModuleType("aioquic.quic")
        aq_conf = types.ModuleType("aioquic.quic.configuration")
        aq_conn = types.ModuleType("aioquic.quic.connection")
        aq_events = types.ModuleType("aioquic.quic.events")

        backup = dict(sys.modules)
        try:
            sys.modules.update({
                "h2": h2_mod,
                "h2.config": h2_cfg,
                "h2.connection": h2_conn,
                "h2.events": h2_events,
                "h2.exceptions": h2_exc,
                "aioquic": aioquic,
                "aioquic.quic": aq_quic,
                "aioquic.quic.configuration": aq_conf,
                "aioquic.quic.connection": aq_conn,
                "aioquic.quic.events": aq_events,
            })
            m = importlib.reload(i)
            self.assertTrue(hasattr(m, "H2_AVAILABLE"))
            self.assertTrue(hasattr(m, "AIOQUIC_AVAILABLE"))
        finally:
            sys.modules.clear()
            sys.modules.update(backup)
            importlib.reload(i)

    def test_ca_cache_and_helpers_branches(self):
        with tempfile.TemporaryDirectory() as d:
            ca = i.CertificateAuthority(ca_dir=d)
            self.assertEqual(ca._asterisk_forms(""), ["*"])
            forms = ca._asterisk_forms("a.b.c")
            self.assertIn("*.b.c", forms)

            ca.STORE_CAP = 1
            c1 = ca.get_certificate_for_host("a.example.com")
            c2 = ca.get_certificate_for_host("b.example.com")
            self.assertTrue(c1 and c2)

            # Force cleanup exception paths.
            with mock.patch("shutil.rmtree", side_effect=Exception("x")):
                ca.cleanup()

    def test_tls_server_context_fallback_cipher(self):
        with tempfile.TemporaryDirectory() as d:
            cert = os.path.join(d, "c.pem")
            key = os.path.join(d, "k.pem")
            with open(cert, "w", encoding="utf-8") as f:
                f.write("")
            with open(key, "w", encoding="utf-8") as f:
                f.write("")

            orig = i.ssl.SSLContext.set_ciphers

            def flaky(self, value):
                if value == i.TLSContextFactory.CIPHERS:
                    raise i.ssl.SSLError("x")
                return orig(self, value)

            with mock.patch.object(i.ssl.SSLContext, "set_ciphers", flaky):
                with mock.patch.object(i.ssl.SSLContext, "load_cert_chain", return_value=None):
                    ctx = i.TLSContextFactory.server_context(cert, key, ["http/1.1"])
                    self.assertIsNotNone(ctx)

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

    def test_h2session_handle_router_and_builders(self):
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
            records_lock=i.threading.Lock(),
            is_waf_block=lambda _: False,
        )

        with mock.patch.object(i, "H2_AVAILABLE", False):
            self.assertEqual(h.handle(), [])
            self.assertIsNone(h._make_client_h2())
            self.assertIsNone(h._make_server_h2())

        with mock.patch.object(i, "H2_AVAILABLE", True):
            with mock.patch.object(i, "H2Connection", side_effect=Exception("x")):
                self.assertIsNone(h._make_client_h2())
                self.assertIsNone(h._make_server_h2())
        self.assertTrue(h._make_server_h1())

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
