import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class _EchoServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self._running:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = c.recv(1024)
                if data:
                    c.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass

    def stop(self):
        self._running = False
        try:
            self.sock.close()
        except Exception:
            pass


class _DummyTor:
    def __init__(self, *args, **kwargs):
        pass

    def should_rotate(self, request_count, rotate_every=1):
        return False

    def is_tor_alive(self):
        return False


class ProxyIntegrationTest(unittest.TestCase):
    def _recv_all(self, s):
        chunks = []
        s.settimeout(2)
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)

    def test_http_proxy_flow(self):
        target = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        t = threading.Thread(target=target.serve_forever, daemon=True)
        t.start()

        with mock.patch.object(i, "TorRotator", _DummyTor):
            proxy = i.Interceptor(listen_host="127.0.0.1", listen_port=18080, intercept_https=False)
            proxy.start()

        try:
            s = socket.create_connection(("127.0.0.1", 18080), timeout=2)
            req = (
                f"GET http://127.0.0.1:{target.server_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target.server_port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            out = self._recv_all(s)
            s.close()
            self.assertIn(b"200", out)
            self.assertIn(b"hello", out)
            self.assertTrue(proxy.get_records())
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()

    def test_connect_tunnel_flow_no_intercept(self):
        echo = _EchoServer()
        with mock.patch.object(i, "TorRotator", _DummyTor):
            proxy = i.Interceptor(listen_host="127.0.0.1", listen_port=18081, intercept_https=False)
            proxy.start()

        try:
            s = socket.create_connection(("127.0.0.1", 18081), timeout=2)
            req = (
                f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo.port}\r\n\r\n"
            ).encode()
            s.sendall(req)
            resp = s.recv(1024)
            self.assertIn(b"200", resp)
            s.sendall(b"ping")
            echoed = s.recv(1024)
            self.assertIn(b"ping", echoed)
            s.close()
        finally:
            proxy.stop()
            echo.stop()

    def test_connect_intercept_success_and_fallback_paths(self):
        echo = _EchoServer()

        with mock.patch.object(i, "TorRotator", _DummyTor):
            proxy = i.Interceptor(listen_host="127.0.0.1", listen_port=18082, intercept_https=True)

        class _TLSMock:
            def close(self):
                return None

        with mock.patch.object(i.H2SessionHandler, "handle", return_value=[]):
            proxy._handshaker.perform = mock.Mock(return_value={
                "success": True,
                "client_tls": _TLSMock(),
                "server_tls": _TLSMock(),
                "alpn": "http/1.1",
            })
            proxy.start()
            try:
                s = socket.create_connection(("127.0.0.1", 18082), timeout=2)
                s.sendall(f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                resp = s.recv(1024)
                self.assertIn(b"200", resp)
                s.close()
            finally:
                proxy.stop()

        # fallback when handshake fails
        with mock.patch.object(i, "TorRotator", _DummyTor):
            proxy2 = i.Interceptor(listen_host="127.0.0.1", listen_port=18083, intercept_https=True)
        proxy2._handshaker.perform = mock.Mock(return_value={"success": False, "error": "x"})
        with mock.patch.object(proxy2, "_create_upstream_connection", wraps=proxy2._create_upstream_connection) as cconn:
            proxy2.start()
            try:
                s = socket.create_connection(("127.0.0.1", 18083), timeout=2)
                s.sendall(f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                _ = s.recv(1024)
                s.close()
                time.sleep(0.1)
                self.assertTrue(cconn.called)
            finally:
                proxy2.stop()
                echo.stop()


if __name__ == "__main__":
    unittest.main()
