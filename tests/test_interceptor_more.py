import socket
import ssl
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorMoreTest(unittest.TestCase):
    def test_tls_context_factory(self):
        c = i.TLSContextFactory.client_context(["http/1.1"])
        self.assertIsInstance(c, ssl.SSLContext)

    def test_mitm_handshaker_failure(self):
        hs = i.MITMHandshaker(ca=mock.Mock(), override_ip="1.1.1.1")
        hs.ca.get_certificate_for_host.return_value = ("/tmp/a", "/tmp/b")

        with mock.patch.object(i.TLSContextFactory, "server_context", side_effect=Exception("x")):
            out = hs.perform(mock.Mock(), "example.com", 443)
            self.assertFalse(out["success"])
            self.assertTrue(out["error"])

    def test_magic_bind_to_tor(self):
        tor = mock.Mock()
        tor.is_tor_alive.return_value = True
        tor.rotate_and_verify.return_value = (True, "8.8.8.8")
        tor.get_proxy_dict.return_value = {"http": "x"}
        m = i.Magic(tor=tor)
        out = m._bind_to_tor()
        self.assertTrue(out["active"])

    def test_create_interceptor(self):
        with mock.patch.object(i, "Interceptor") as cls:
            i.create_interceptor(listen_port=9999)
            cls.assert_called_once()

    def test_interceptor_create_upstream_connection_no_proxy(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._proxy_rotator = None

        sock = mock.Mock()
        with mock.patch.object(i.socket, "create_connection", return_value=sock):
            out = inter._create_upstream_connection("example.com", 80)
        self.assertIs(out, sock)

    def test_handle_tunnel_exits_on_exception(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        a, b = socket.socketpair()
        try:
            with mock.patch.object(i.select, "select", side_effect=Exception("stop")):
                inter._handle_tunnel(a, b)
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()
