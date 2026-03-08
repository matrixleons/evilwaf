import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class InterceptorStartStopTest(unittest.TestCase):
    def test_start_failure_sets_running_false(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._host = "127.0.0.1"
        inter._port = 1
        inter._running = False
        inter._server = None
        inter._thread = None
        inter.ca = mock.Mock()
        inter._records = []
        inter._records_lock = i.threading.Lock()
        inter._callbacks = {"request": None, "response": None, "record": None}
        inter.intercept_https = False
        inter._create_upstream_connection = mock.Mock()
        inter._handle_tunnel = mock.Mock()
        inter._is_waf_block = lambda c: False
        inter._process_http_request = mock.Mock()
        inter._magic = mock.Mock()
        inter._forwarder = mock.Mock()
        inter._handshaker = mock.Mock()
        inter._advisor = mock.Mock()
        inter._tor = mock.Mock()

        with mock.patch.object(i, "ThreadedHTTPServer", side_effect=OSError("bind fail")):
            with self.assertRaises(RuntimeError):
                inter.start()
        self.assertFalse(inter._running)

    def test_stop_without_server(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._running = True
        inter._server = None
        inter.ca = mock.Mock()
        inter.stop()
        inter.ca.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
