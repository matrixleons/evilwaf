import os
import sys
import tempfile
import unittest
from unittest import mock

from _deps import install_dependency_stubs
install_dependency_stubs()

from core.proxy_file import load_proxy_file
import chemistry.origin_server_ip as origin_server_ip
import core.interceptor as interceptor_mod


class FixesTest(unittest.TestCase):
    def test_load_proxy_file_ignores_whitespace_prefixed_comments(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("\n")
            f.write("# full comment\n")
            f.write("   # spaced comment\n")
            f.write("http://proxy1:8080\n")
            f.write("  socks5://proxy2:1080  \n")
            path = f.name
        try:
            self.assertEqual(
                load_proxy_file(path),
                ["http://proxy1:8080", "socks5://proxy2:1080"],
            )
        finally:
            os.unlink(path)

    def test_magic_uses_configured_rotate_every(self):
        class DummyTCP:
            def per_request_options(self):
                return {"profile": "chrome"}

        class DummyTLS:
            def paired_with_tcp(self, profile):
                return object(), "dummy"

        class DummyTor:
            def __init__(self):
                self.calls = []

            def should_rotate(self, request_count, rotate_every=1):
                self.calls.append((request_count, rotate_every))
                return False

            def is_tor_alive(self):
                return False

        tor = DummyTor()
        magic = interceptor_mod.Magic(
            tcp=DummyTCP(),
            tls=DummyTLS(),
            tor=tor,
            rotate_every=7,
        )
        magic.apply()
        self.assertEqual(tor.calls, [(1, 7)])

    def test_interceptor_process_http_uses_override_ip_for_connect_host(self):
        interceptor = interceptor_mod.Interceptor.__new__(interceptor_mod.Interceptor)
        interceptor._override_ip = "203.0.113.10"
        captured = {}

        class DummySock:
            def sendall(self, data):
                return None

            def close(self):
                return None

        def fake_create_upstream_connection(host, port, timeout=30):
            captured["host"] = host
            captured["port"] = port
            return DummySock()

        interceptor._create_upstream_connection = fake_create_upstream_connection

        req = interceptor_mod.InterceptedRequest(
            url="http://example.com/test",
            host="example.com",
        )
        with mock.patch.object(interceptor_mod.H1Parser, "build_request", return_value=b"GET / HTTP/1.1\r\n\r\n"):
            with mock.patch.object(interceptor_mod.H1Parser, "read_message", return_value=(b"", b"")):
                interceptor._process_http_request(req)

        self.assertEqual(captured["host"], "203.0.113.10")
        self.assertEqual(captured["port"], 80)

    def test_interceptor_passes_override_ip_to_mitm_handshaker(self):
        captured = {}

        class DummyCA:
            pass

        class DummyHandshaker:
            def __init__(self, ca, override_ip=None, proxy_rotator=None):
                captured["override_ip"] = override_ip

        class DummyTor:
            def __init__(self, *args, **kwargs):
                pass

        class DummyTCP:
            pass

        class DummyTLS:
            pass

        with mock.patch.object(interceptor_mod, "CertificateAuthority", DummyCA):
            with mock.patch.object(interceptor_mod, "MITMHandshaker", DummyHandshaker):
                with mock.patch.object(interceptor_mod, "TorRotator", DummyTor):
                    with mock.patch.object(interceptor_mod, "TCPOptionsManipulator", DummyTCP):
                        with mock.patch.object(interceptor_mod, "TLSFingerprinter", DummyTLS):
                            interceptor_mod.Interceptor(override_ip="198.51.100.7")

        self.assertEqual(captured["override_ip"], "198.51.100.7")

    def test_origin_verifier_https_branch_uses_context_wrap_socket(self):
        verifier = origin_server_ip.OriginVerifier("example.com")

        class DummyConn:
            def sendall(self, data):
                return None

            def recv(self, size):
                if not hasattr(self, "_sent"):
                    self._sent = True
                    return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                return b""

            def close(self):
                return None

        class DummyContext:
            def __init__(self):
                self.wrap_calls = 0

            def wrap_socket(self, raw, server_hostname=None):
                self.wrap_calls += 1
                return DummyConn()

        ctx = DummyContext()

        with mock.patch.object(origin_server_ip.ssl, "create_default_context", return_value=ctx):
            with mock.patch.object(origin_server_ip.socket, "create_connection", return_value=object()):
                self.assertTrue(verifier.verify_http("203.0.113.8"))

        self.assertEqual(ctx.wrap_calls, 1)


if __name__ == "__main__":
    unittest.main()
