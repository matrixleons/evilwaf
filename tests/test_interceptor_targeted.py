import io
import threading
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorTargetedTest(unittest.TestCase):
    def _capture_handler_class(self, inter):
        captured = {}

        class DummyServer:
            def __init__(self, addr, handler_cls):
                captured["handler"] = handler_cls

            def serve_forever(self):
                return None

            def shutdown(self):
                return None

            def server_close(self):
                return None

        class DummyThread:
            def __init__(self, target=None, daemon=None):
                self._target = target

            def start(self):
                return None

        class TestSock:
            def settimeout(self, _):
                return None

            def connect_ex(self, _):
                return 0

            def close(self):
                return None

        with mock.patch.object(i, "ThreadedHTTPServer", DummyServer):
            with mock.patch.object(i.threading, "Thread", DummyThread):
                with mock.patch.object(i.socket, "socket", return_value=TestSock()):
                    inter.start()
        return captured["handler"]

    def test_ca_san_and_cache_branches(self):
        ca = i.CertificateAuthority()
        bad_host = "bad\udcff.example.com"
        real_dns = i.x509.DNSName
        with mock.patch.object(i.x509, "DNSName", side_effect=[real_dns("example.com"), Exception("idna-fail")]):
            san = ca._create_san_extension(bad_host)
        self.assertTrue(san)

        ca.cert_cache["*.example.com"] = ("c", "k")
        self.assertEqual(ca.get_certificate_for_host("api.example.com"), ("c", "k"))

    def test_ca_expire_cleanup_exception_branch(self):
        with mock.patch.object(i.CertificateAuthority, "_generate_host_certificate", return_value=("/tmp/x/c.pem", "/tmp/x/k.pem")):
            ca = i.CertificateAuthority()
            ca.STORE_CAP = 1
            ca.get_certificate_for_host("a.example.com")
            with mock.patch("shutil.rmtree", side_effect=Exception("x")):
                ca.get_certificate_for_host("b.example.com")

    def test_h2connection_and_h1parser_edge_branches(self):
        class FakeH2:
            def __init__(self, config=None):
                pass

            def initiate_connection(self):
                return None

            def data_to_send(self, n):
                return b""

            def receive_data(self, data):
                return []

        fake_h2 = mock.Mock()
        fake_h2.config.H2Configuration.return_value = object()
        fake_h2.connection.H2Connection = FakeH2

        sock = mock.Mock()
        sock.recv.return_value = b""
        with mock.patch("core.interceptor.h2", fake_h2, create=True):
            c = i.H2Connection(sock, is_server=False)
            c.initiate()
            self.assertEqual(c.recv_events(), [])

        class WantReadSock:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    raise i.ssl.SSLWantReadError()
                return b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"

        h, b = i.H1Parser.read_message(WantReadSock())
        self.assertTrue(h and b == b"")

        class TimeoutSock:
            def settimeout(self, _):
                return None

            def recv(self, _):
                raise i.socket.timeout()

        self.assertEqual(i.H1Parser.read_message(TimeoutSock()), (b"", b""))
        self.assertIsNone(i.H1Parser.parse_request_line(b"BAD"))
        self.assertIsNone(i.H1Parser.parse_response_line(b"BAD"))

    def test_h1parser_chunked_edge_paths(self):
        class SockNoMore:
            def settimeout(self, _):
                return None

            def recv(self, _):
                return b""

        self.assertEqual(i.H1Parser._read_chunked(SockNoMore(), b""), b"")

        class SockInvalid:
            def __init__(self):
                self.parts = [b"xx\r\n"]

            def settimeout(self, _):
                return None

            def recv(self, _):
                return self.parts.pop(0) if self.parts else b""

        self.assertEqual(i.H1Parser._read_chunked(SockInvalid(), b""), b"")

        class SockTooBig:
            def __init__(self):
                self.parts = [b"4000000\r\n"]

            def settimeout(self, _):
                return None

            def recv(self, _):
                return self.parts.pop(0) if self.parts else b""

        self.assertEqual(i.H1Parser._read_chunked(SockTooBig(), b""), b"")

    def test_h1parser_more_read_message_branches(self):
        raw = b"GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n12"

        class SockNoHeaders:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                return b"abc" if self.calls == 1 else b""

        self.assertEqual(i.H1Parser.read_message(SockNoHeaders()), (b"abc", b""))

        class SockLong:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                return b"x" * 140000 if self.calls == 1 else b""

        h, _ = i.H1Parser.read_message(SockLong())
        self.assertTrue(h)

        class SockCLBreak:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return raw
                return b""

        h2, b2 = i.H1Parser.read_message(SockCLBreak())
        self.assertTrue(h2 and b2 == b"12")

        class SockCLExcept:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return raw
                raise i.socket.timeout()

        h3, b3 = i.H1Parser.read_message(SockCLExcept())
        self.assertTrue(h3 and b3 == b"12")

        class SockChunked:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                return b""

        with mock.patch.object(i.H1Parser, "_read_chunked", return_value=b"abc"):
            h4, b4 = i.H1Parser.read_message(SockChunked())
            self.assertEqual(b4, b"abc")

        class SockReadChunkErr:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return b"5\r\n"
                raise i.socket.timeout()

        self.assertEqual(i.H1Parser._read_chunked(SockReadChunkErr(), b""), b"")

    def test_mitm_and_advisor_magic_forwarder(self):
        ca = mock.Mock()
        ca.get_certificate_for_host.return_value = ("c", "k")
        hs = i.MITMHandshaker(ca=ca)
        hs._proxy_rotator = mock.Mock()
        hs._proxy_rotator.create_connection.side_effect = i.ssl.SSLError("bad")

        with mock.patch.object(i.TLSContextFactory, "server_context") as sc:
            sc.return_value.wrap_socket.return_value = mock.Mock(selected_alpn_protocol=mock.Mock(return_value="h2"))
            out = hs.perform(mock.Mock(), "example.com", 443)
            self.assertIn("SSL:", out["error"])

        hs._proxy_rotator.create_connection.side_effect = Exception("boom")
        with mock.patch.object(i.TLSContextFactory, "server_context") as sc:
            sc.return_value.wrap_socket.return_value = mock.Mock(selected_alpn_protocol=mock.Mock(return_value=None))
            out2 = hs.perform(mock.Mock(), "example.com", 443)
            self.assertEqual(out2["success"], False)
        hs._proxy_rotator.create_connection.side_effect = i.ssl.SSLError("bad-close")
        cclose = mock.Mock(selected_alpn_protocol=mock.Mock(return_value=None))
        cclose.close.side_effect = Exception("x")
        with mock.patch.object(i.TLSContextFactory, "server_context") as sc:
            sc.return_value.wrap_socket.return_value = cclose
            _ = hs.perform(mock.Mock(), "example.com", 443)

        tor = mock.Mock()
        tor.should_rotate.return_value = True
        tor.is_tor_alive.return_value = True
        tor.rotate_and_verify.return_value = (True, "1.1.1.1")
        tor.get_proxy_dict.return_value = {"http": "socks5://127.0.0.1:9050"}
        m = i.Magic(tcp=mock.Mock(per_request_options=mock.Mock(return_value={"profile": "p"})), tls=mock.Mock(paired_with_tcp=mock.Mock(return_value=("s", "id"))), tor=tor)
        self.assertTrue(m.apply()["tor"]["active"])

        tor.is_tor_alive.return_value = False
        self.assertEqual(m._bind_to_tor(), {"active": False})

        req = i.InterceptedRequest(host="h")
        adv = i.ResponseAdvisor(magic=m, max_retries=1, retry_delay=0.1)
        self.assertEqual(adv.advise(i.InterceptedResponse(status_code=200), req, i.ProxyRecord()).action, "forward")
        self.assertEqual(adv.advise(i.InterceptedResponse(status_code=509, headers={"retry-after": "3"}), req, i.ProxyRecord()).action, "rotate_and_retry")
        self.assertEqual(adv.advise(i.InterceptedResponse(status_code=777), req, i.ProxyRecord()).action, "forward")
        self.assertEqual(i.ResponseAdvisor(magic=m, max_retries=0)._rotate_and_retry(i.InterceptedResponse(status_code=509), req, i.ProxyRecord()).action, "forward")
        self.assertEqual(i.ResponseAdvisor(magic=m, max_retries=1, retry_delay=1.2)._get_delay(i.InterceptedResponse(status_code=509, headers={"retry-after": "bad"})), 1.2)
        m._tls.rotate.side_effect = Exception("x")
        m._tcp.rotate.side_effect = Exception("x")
        m.error_solver(i.ssl.SSLError("x"))
        m.error_solver(ConnectionResetError("x"))

        class H:
            command = "GET"
            wfile = io.BytesIO()

            def send_response(self, *_):
                raise RuntimeError("x")

            def send_header(self, *_):
                return None

            def end_headers(self):
                return None

        bad = H()
        self.assertFalse(i.Forwarder().forward(i.InterceptedResponse(status_code=0), bad))

    def test_h2session_and_relay_exception_lines(self):
        h = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="x",
            port=443,
            server_alpn="h2",
            callbacks={"record": None},
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )
        with mock.patch.object(h, "_make_client_h2", return_value=None):
            with mock.patch.object(h, "_relay_raw", return_value=[]):
                self.assertEqual(h._handle_h2_to_h2(), [])

        class EP:
            def __init__(self):
                self.conn = mock.Mock()
                self.close = mock.Mock(side_effect=Exception("x"))

            def recv_events(self, timeout=30):
                return []

        ep = EP()
        with mock.patch.object(h, "_make_client_h2", return_value=ep):
            with mock.patch.object(h, "_make_server_h2", return_value=ep):
                self.assertEqual(h._handle_h2_to_h2(), [])

        h1 = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="x",
            port=443,
            server_alpn="http/1.1",
            callbacks={"request": None, "response": None, "record": None},
            magic=mock.Mock(apply=mock.Mock(return_value={"tcp": {}, "tor": {}}), _bind_to_tor=mock.Mock()),
            advisor=mock.Mock(advise=mock.Mock(return_value=i.AdvisorDecision(action="rotate_and_retry", delay=0.01, rotate_ip=True))),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )
        req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        with mock.patch.object(i.H1Parser, "read_message", side_effect=[(req, b""), (b"HTTP/1.1 503 X\r\n\r\n", b""), Exception("x")]):
            with mock.patch.object(i.H1Parser, "parse_request_line", return_value=("GET", "/", "1.1")):
                with mock.patch.object(i.H1Parser, "extract_headers", return_value={"connection": "close"}):
                    with mock.patch.object(i.H1Parser, "build_request", return_value=b"x"):
                        with mock.patch.object(i.H1Parser, "build_response", return_value=b"y"):
                            h1.client_tls.sendall.side_effect = Exception("x")
                            self.assertEqual(h1._handle_h1_to_h1(), [])

        class TLS:
            def __init__(self, vals):
                self.vals = list(vals)

            def setblocking(self, _):
                return None

            def read(self, _):
                v = self.vals.pop(0)
                if isinstance(v, Exception):
                    raise v
                return v

            def sendall(self, _):
                return None

        rr = i.H2SessionHandler(
            client_tls=TLS([b"a", b"", i.ssl.SSLWantReadError()]),
            server_tls=TLS([b"b", b"", Exception("x")]),
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
        with mock.patch.object(i.select, "select", side_effect=[([rr.client_tls, rr.server_tls], [], []), ([rr.client_tls], [], []), ([rr.server_tls], [], []), ([], [], [])]):
            self.assertEqual(rr._relay_raw(), [])

    def test_interceptor_helpers_and_proxyhandler_inner(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._host = "127.0.0.1"
        inter._port = 18888
        inter._running = False
        inter._thread = None
        inter._records = []
        inter._records_lock = threading.Lock()
        inter._callbacks = {"request": None, "response": None, "record": None}
        inter.intercept_https = False
        inter._create_upstream_connection = mock.Mock()
        inter._handle_tunnel = mock.Mock()
        inter._is_waf_block = lambda _: False
        inter._process_http_request = mock.Mock(return_value=i.InterceptedResponse(status_code=200, status_text="OK", headers={}, body=b""))
        inter._magic = mock.Mock()
        inter._forwarder = mock.Mock(forward=mock.Mock(return_value=True))
        inter._handshaker = mock.Mock()
        inter._advisor = mock.Mock()
        inter.ca = mock.Mock(export_ca_certificates=mock.Mock(return_value={"pem": "x"}), cleanup=mock.Mock())

        hcls = self._capture_handler_class(inter)
        h = hcls.__new__(hcls)
        h.command = "GET"
        h.path = "/x?a=1"
        h.headers = {"Host": "example.com:8080", "Cookie": "a=b"}
        h.rfile = io.BytesIO(b"")
        parsed = h._parse_request()
        self.assertEqual(parsed.url, "http://example.com:8080/x?a=1")

        h2 = hcls.__new__(hcls)
        h2.command = "POST"
        h2.path = "http://example.com/a?z=1"
        h2.headers = {"Host": "example.com", "Content-Length": "3"}
        h2.rfile = io.BytesIO(b"abc")
        parsed2 = h2._parse_request()
        self.assertEqual(parsed2.query_params.get("z"), ["1"])

        with mock.patch("core.interceptor.BaseHTTPRequestHandler.handle_one_request", side_effect=OSError()):
            h.handle_one_request()
        with mock.patch("core.interceptor.BaseHTTPRequestHandler.handle", side_effect=BrokenPipeError()):
            h.handle()

        inter._handle_tunnel = i.Interceptor._handle_tunnel.__get__(inter, i.Interceptor)
        c = mock.Mock()
        s = mock.Mock()
        with mock.patch.object(i.select, "select", return_value=([], [], [c])):
            inter._handle_tunnel(c, s)

        self.assertEqual(inter.export_ca_certificates(), {"pem": "x"})

    def test_interceptor_remaining_paths(self):
        ca = i.CertificateAuthority()
        ca.ca_cert_path = "x"
        ca.ca_key_path = "y"
        with mock.patch("builtins.open", mock.mock_open(read_data=b"dummy")):
            with mock.patch.object(i.x509, "load_pem_x509_certificate", return_value=mock.Mock()):
                with mock.patch.object(i.serialization, "load_pem_private_key", return_value=mock.Mock()):
                    with mock.patch.object(i.rsa, "generate_private_key", return_value=mock.Mock(private_bytes=mock.Mock(return_value=b"k"))):
                        real_name_attr = i.x509.NameAttribute
                        def na(oid, val):
                            if oid == i.NameOID.COMMON_NAME:
                                raise Exception("x")
                            return real_name_attr(oid, val)
                        with mock.patch.object(i.x509, "NameAttribute", side_effect=na):
                            class B:
                                def subject_name(self, *_): return self
                                def issuer_name(self, *_): return self
                                def public_key(self, *_): return self
                                def serial_number(self, *_): return self
                                def not_valid_before(self, *_): return self
                                def not_valid_after(self, *_): return self
                                def add_extension(self, *_args, **_kwargs): return self
                                def sign(self, *_args, **_kwargs):
                                    return mock.Mock(public_bytes=mock.Mock(return_value=b"c"))
                            real_dns = i.x509.DNSName
                            with mock.patch.object(i.x509, "CertificateBuilder", return_value=B()):
                                with mock.patch.object(i.x509, "DNSName", side_effect=[real_dns("example.com"), Exception("x")]):
                                    with mock.patch.object(i.x509.AuthorityKeyIdentifier, "from_issuer_public_key", return_value=mock.Mock()):
                                        with mock.patch.object(i.x509.SubjectKeyIdentifier, "from_public_key", return_value=mock.Mock()):
                                            ca._generate_host_certificate("bad\udcff.example.com")

        inter = i.Interceptor.__new__(i.Interceptor)
        inter._override_ip = None
        bad_sock = mock.Mock()
        bad_sock.close.side_effect = Exception("x")
        inter._create_upstream_connection = mock.Mock(return_value=bad_sock)
        req = i.InterceptedRequest(url="http://example.com/a?b=1", host="example.com")
        with mock.patch.object(i.H1Parser, "build_request", return_value=b"x"):
            with mock.patch.object(i.H1Parser, "read_message", return_value=(b"", b"")):
                inter._process_http_request(req)

        inter._host = "1.2.3.4"
        inter._port = 1234
        inter._running = True
        self.assertTrue(inter.is_running())
        self.assertEqual(inter.get_listen_address(), "1.2.3.4:1234")

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._host = "127.0.0.1"
        inter2._port = 18889
        inter2._running = False
        inter2._thread = None
        inter2._records = []
        inter2._records_lock = threading.Lock()
        inter2._callbacks = {"request": mock.Mock(), "response": None, "record": mock.Mock()}
        inter2.intercept_https = True
        inter2.https_intercepted = 0
        inter2.https_tunneled = 0
        inter2.https_errors = 0
        inter2._create_upstream_connection = mock.Mock()
        inter2._handle_tunnel = mock.Mock()
        inter2._is_waf_block = lambda _: False
        inter2._process_http_request = mock.Mock(return_value=i.InterceptedResponse(status_code=200, status_text="OK", headers={}, body=b""))
        inter2._magic = mock.Mock()
        inter2._forwarder = mock.Mock(forward=mock.Mock(return_value=True))
        inter2._advisor = mock.Mock()
        inter2.ca = mock.Mock(export_ca_certificates=mock.Mock(return_value={"pem": "x"}), cleanup=mock.Mock())

        tls1 = mock.Mock()
        tls1.close.side_effect = Exception("x")
        tls2 = mock.Mock()
        tls2.close.side_effect = Exception("x")
        inter2._handshaker = mock.Mock(perform=mock.Mock(return_value={"success": True, "client_tls": tls1, "server_tls": tls2, "alpn": "http/1.1"}))
        hcls = self._capture_handler_class(inter2)
        h = hcls.__new__(hcls)
        h.path = "example.com:443"
        h.request = mock.Mock()
        h.wfile = mock.Mock()
        h.wfile.flush.side_effect = Exception("x")
        h.send_response = mock.Mock()
        h.send_header = mock.Mock()
        h.end_headers = mock.Mock()
        with mock.patch.object(i.H2SessionHandler, "handle", return_value=[]):
            h.do_CONNECT()

        hbad = hcls.__new__(hcls)
        hbad.path = "example.com:443"
        hbad.request = mock.Mock()
        hbad.wfile = mock.Mock(flush=mock.Mock(return_value=None))
        hbad.send_response = mock.Mock()
        hbad.send_header = mock.Mock()
        hbad.end_headers = mock.Mock()
        hbad.send_error = mock.Mock(side_effect=Exception("x"))
        inter2._handshaker.perform.return_value = {"success": False, "error": "x"}
        rsock = mock.Mock()
        rsock.close.side_effect = Exception("x")
        inter2._create_upstream_connection = mock.Mock(return_value=rsock)
        hbad.do_CONNECT()
        inter2._create_upstream_connection = mock.Mock(side_effect=Exception("x"))
        hbad.do_CONNECT()

        inter2.intercept_https = False
        hplain = hcls.__new__(hcls)
        hplain.path = "example.com:443"
        hplain.request = mock.Mock()
        hplain.wfile = mock.Mock(flush=mock.Mock(side_effect=Exception("x")))
        hplain.send_response = mock.Mock()
        hplain.send_header = mock.Mock()
        hplain.end_headers = mock.Mock()
        hplain.send_error = mock.Mock(side_effect=Exception("x"))
        rsock2 = mock.Mock()
        rsock2.close.side_effect = Exception("x")
        inter2._create_upstream_connection = mock.Mock(return_value=rsock2)
        hplain.do_CONNECT()
        inter2._create_upstream_connection = mock.Mock(side_effect=Exception("x"))
        hplain.do_CONNECT()

        hparse = hcls.__new__(hcls)
        hparse.command = "POST"
        hparse.path = "/x"
        hparse.headers = {"Host": "example.com:abc", "Content-Length": "1"}
        class BadRead:
            def read(self, _):
                raise Exception("x")
        hparse.rfile = BadRead()
        parsed = hparse._parse_request()
        self.assertEqual(parsed.port, 80)

        hdisp = hcls.__new__(hcls)
        hdisp.send_error = mock.Mock(side_effect=Exception("x"))
        hdisp._parse_request = mock.Mock(side_effect=Exception("x"))
        hdisp._dispatch()

        inter3 = i.Interceptor.__new__(i.Interceptor)
        inter3._host = "127.0.0.1"
        inter3._port = 18890
        inter3._running = False
        inter3._server = None
        inter3._thread = None
        inter3.ca = mock.Mock()
        inter3._records = []
        inter3._records_lock = i.threading.Lock()
        inter3._callbacks = {"request": None, "response": None, "record": None}
        inter3.intercept_https = False
        inter3._create_upstream_connection = mock.Mock()
        inter3._handle_tunnel = mock.Mock()
        inter3._is_waf_block = lambda c: False
        inter3._process_http_request = mock.Mock()
        inter3._magic = mock.Mock()
        inter3._forwarder = mock.Mock()
        inter3._handshaker = mock.Mock()
        inter3._advisor = mock.Mock()
        inter3._tor = mock.Mock()
        class SockBad:
            def settimeout(self, _):
                return None
            def connect_ex(self, _):
                return 1
            def close(self):
                return None
        class Srv:
            def __init__(self, *_):
                return None
            def serve_forever(self):
                return None
        class T:
            def __init__(self, target=None, daemon=None):
                self._target = target
            def start(self):
                return None
        with mock.patch.object(i, "ThreadedHTTPServer", Srv):
            with mock.patch.object(i.threading, "Thread", T):
                with mock.patch.object(i.socket, "socket", return_value=SockBad()):
                    with self.assertRaises(RuntimeError):
                        inter3.start()

    def test_final_interceptor_gap_lines(self):
        class SockCLAdd:
            def __init__(self):
                self.calls = 0

            def settimeout(self, _):
                return None

            def recv(self, _):
                self.calls += 1
                if self.calls == 1:
                    return b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12"
                if self.calls == 2:
                    return b"345"
                return b""

        h, b = i.H1Parser.read_message(SockCLAdd())
        self.assertTrue(h and b == b"12345")

        class SockSizeErr:
            def settimeout(self, _):
                return None

            def recv(self, _):
                raise i.socket.timeout()

        self.assertEqual(i.H1Parser._read_chunked(SockSizeErr(), b""), b"")

        class SockChunkGrow:
            def __init__(self):
                self.parts = [b"2\r\na", b"b\r\n", b""]

            def settimeout(self, _):
                return None

            def recv(self, _):
                return self.parts.pop(0) if self.parts else b""

        self.assertEqual(i.H1Parser._read_chunked(SockChunkGrow(), b""), b"ab")
        class SockChunkNoMore:
            def __init__(self):
                self.parts = [b"3\r\na", b""]
            def settimeout(self, _):
                return None
            def recv(self, _):
                return self.parts.pop(0) if self.parts else b""
        self.assertEqual(i.H1Parser._read_chunked(SockChunkNoMore(), b""), b"")

        ca = mock.Mock()
        ca.get_certificate_for_host.return_value = ("c", "k")
        hs = i.MITMHandshaker(ca=ca)
        hs._proxy_rotator = mock.Mock(create_connection=mock.Mock(side_effect=Exception("x")))
        c = mock.Mock(selected_alpn_protocol=mock.Mock(return_value=None))
        c.close.side_effect = Exception("x")
        with mock.patch.object(i.TLSContextFactory, "server_context") as sc:
            sc.return_value.wrap_socket.return_value = c
            _ = hs.perform(mock.Mock(), "example.com", 443)

        class TLS:
            def __init__(self, read_side_effect=None, read_vals=None, setblocking_err=False):
                self._se = read_side_effect
                self._vals = list(read_vals or [])
                self._sb = setblocking_err

            def setblocking(self, _):
                if self._sb:
                    raise Exception("x")
                return None

            def read(self, _):
                if self._se:
                    raise self._se
                return self._vals.pop(0) if self._vals else b""

            def sendall(self, _):
                return None

        hndl = i.H2SessionHandler(TLS(), TLS(), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", return_value=([], [], [object()])):
            self.assertEqual(hndl._relay_raw(), [])

        hndl2 = i.H2SessionHandler(TLS(read_side_effect=Exception("x")), TLS(), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", return_value=([hndl2.client_tls], [], [])):
            self.assertEqual(hndl2._relay_raw(), [])
        hndl2b = i.H2SessionHandler(TLS(read_side_effect=i.ssl.SSLWantReadError()), TLS(), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", side_effect=[([hndl2b.client_tls], [], []), Exception("stop")]):
            self.assertEqual(hndl2b._relay_raw(), [])

        hndl3 = i.H2SessionHandler(TLS(), TLS(read_vals=[b""]), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", return_value=([hndl3.server_tls], [], [])):
            self.assertEqual(hndl3._relay_raw(), [])

        hndl4 = i.H2SessionHandler(TLS(), TLS(read_side_effect=i.ssl.SSLWantReadError()), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", side_effect=[([hndl4.server_tls], [], []), Exception("stop")]):
            self.assertEqual(hndl4._relay_raw(), [])
        hndl5 = i.H2SessionHandler(TLS(), TLS(read_side_effect=Exception("x")), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        with mock.patch.object(i.select, "select", return_value=([hndl5.server_tls], [], [])):
            self.assertEqual(hndl5._relay_raw(), [])

        hndl6 = i.H2SessionHandler(TLS(setblocking_err=True), TLS(), "x", 443, "h2", {}, mock.Mock(), mock.Mock(), [], threading.Lock(), lambda _: False)
        self.assertEqual(hndl6._relay_raw(), [])

        inter = i.Interceptor.__new__(i.Interceptor)
        inter._host = "127.0.0.1"
        inter._port = 19991
        inter._running = False
        inter._thread = None
        inter._records = []
        inter._records_lock = threading.Lock()
        inter._callbacks = {"request": mock.Mock(), "response": None, "record": mock.Mock()}
        inter.intercept_https = False
        inter._create_upstream_connection = mock.Mock()
        inter._handle_tunnel = i.Interceptor._handle_tunnel.__get__(inter, i.Interceptor)
        inter._is_waf_block = lambda _: False
        inter._process_http_request = mock.Mock(return_value=i.InterceptedResponse(status_code=200, status_text="OK", headers={}, body=b""))
        inter._magic = mock.Mock()
        inter._forwarder = mock.Mock(forward=mock.Mock(return_value=True))
        inter._handshaker = mock.Mock()
        inter._advisor = mock.Mock()
        inter.ca = mock.Mock()

        hcls = self._capture_handler_class(inter)
        h = hcls.__new__(hcls)
        h.command = "GET"
        h.path = "/"
        h.headers = {"Host": "example.com"}
        h.rfile = io.BytesIO(b"")
        h.send_error = mock.Mock()
        h._dispatch()
        self.assertTrue(inter._callbacks["request"].called)
        self.assertTrue(inter._callbacks["record"].called)

        s1 = mock.Mock()
        s2 = mock.Mock()
        s1.recv.return_value = b"x"
        s2.sendall.side_effect = Exception("x")
        s1.setblocking.return_value = None
        s2.setblocking.return_value = None
        with mock.patch.object(i.select, "select", return_value=([s1], [], [])):
            inter._handle_tunnel(s1, s2)


if __name__ == "__main__":
    unittest.main()
