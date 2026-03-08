import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(ln)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class _DummyTor:
    def __init__(self, *args, **kwargs):
        pass

    def should_rotate(self, request_count, rotate_every=1):
        return False

    def is_tor_alive(self):
        return False


class ProxyErrorIntegrationTest(unittest.TestCase):
    def _recv(self, s):
        s.settimeout(2)
        chunks = []
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)

    def test_post_head_and_dispatch_error(self):
        target = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=target.serve_forever, daemon=True).start()

        port = _free_port()
        with mock.patch.object(i, "TorRotator", _DummyTor):
            proxy = i.Interceptor(listen_host="127.0.0.1", listen_port=port, intercept_https=False)
            proxy.start()

        try:
            # POST path
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            body = b"abc"
            req = (
                f"POST http://127.0.0.1:{target.server_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target.server_port}\r\n"
                "Cookie: a=1; b=2\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + body
            s.sendall(req)
            out = self._recv(s)
            s.close()
            self.assertIn(b"201", out)

            # HEAD path
            s2 = socket.create_connection(("127.0.0.1", port), timeout=2)
            req2 = (
                f"HEAD http://127.0.0.1:{target.server_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target.server_port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            s2.sendall(req2)
            out2 = self._recv(s2)
            s2.close()
            self.assertIn(b"204", out2)

            # force dispatch error
            proxy._process_http_request = mock.Mock(side_effect=Exception("boom"))
            s3 = socket.create_connection(("127.0.0.1", port), timeout=2)
            s3.sendall(req2)
            out3 = self._recv(s3)
            s3.close()
            self.assertIn(b"502", out3)
        finally:
            proxy.stop()
            target.shutdown()
            target.server_close()

    def test_connect_error_branches(self):
        # no intercept: create_upstream_connection raises
        port1 = _free_port()
        with mock.patch.object(i, "TorRotator", _DummyTor):
            p1 = i.Interceptor(listen_host="127.0.0.1", listen_port=port1, intercept_https=False)
        p1._create_upstream_connection = mock.Mock(side_effect=Exception("x"))
        p1.start()
        try:
            s = socket.create_connection(("127.0.0.1", port1), timeout=2)
            s.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: x\r\n\r\n")
            out = self._recv(s)
            s.close()
            self.assertIn(b"502", out)
        finally:
            p1.stop()

        # intercept mode, handshake fail + upstream failure
        port2 = _free_port()
        with mock.patch.object(i, "TorRotator", _DummyTor):
            p2 = i.Interceptor(listen_host="127.0.0.1", listen_port=port2, intercept_https=True)
        p2._handshaker.perform = mock.Mock(return_value={"success": False, "error": "x"})
        p2._create_upstream_connection = mock.Mock(side_effect=Exception("x"))
        p2.start()
        try:
            s2 = socket.create_connection(("127.0.0.1", port2), timeout=2)
            s2.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: x\r\n\r\n")
            out2 = self._recv(s2)
            s2.close()
            self.assertIn(b"502", out2)
        finally:
            p2.stop()


if __name__ == "__main__":
    unittest.main()
