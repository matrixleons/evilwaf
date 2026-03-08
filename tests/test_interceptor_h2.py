import types
import unittest
from unittest import mock
import threading

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class _InlineThread:
    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        if self._target:
            self._target()

    def join(self, timeout=None):
        return None


class InterceptorH2Test(unittest.TestCase):
    def test_handle_h2_to_h2_records(self):
        class RequestReceived:
            def __init__(self, stream_id, headers, stream_ended=None):
                self.stream_id = stream_id
                self.headers = headers
                self.stream_ended = stream_ended

        class DataReceived:
            def __init__(self, stream_id, data):
                self.stream_id = stream_id
                self.data = data
                self.flow_controlled_length = len(data)

        class StreamEnded:
            def __init__(self, stream_id):
                self.stream_id = stream_id

        class ResponseReceived:
            def __init__(self, stream_id, headers, stream_ended=None):
                self.stream_id = stream_id
                self.headers = headers
                self.stream_ended = stream_ended

        class WindowUpdated:
            pass

        class ConnectionTerminated:
            pass

        fake_h2 = types.SimpleNamespace(
            events=types.SimpleNamespace(
                RequestReceived=RequestReceived,
                DataReceived=DataReceived,
                StreamEnded=StreamEnded,
                ResponseReceived=ResponseReceived,
                WindowUpdated=WindowUpdated,
                ConnectionTerminated=ConnectionTerminated,
            )
        )

        class FakeConn:
            def acknowledge_received_data(self, n, sid):
                return None

            def end_stream(self, sid):
                return None

        class FakeEndpoint:
            def __init__(self, events_batches):
                self._batches = list(events_batches)
                self.conn = FakeConn()

            def recv_events(self, timeout=30):
                if self._batches:
                    return self._batches.pop(0)
                return []

            def send_headers(self, *args, **kwargs):
                return None

            def send_data(self, *args, **kwargs):
                return None

            def _flush(self):
                return None

            def close(self):
                return None

        req_h = [(":method", "GET"), (":path", "/"), ("x-test", "1")]
        resp_h = {":status": "200", "server": "x"}
        client_ep = FakeEndpoint([
            [RequestReceived(1, req_h), DataReceived(1, b"abc"), StreamEnded(1)],
            [ConnectionTerminated()],
        ])
        server_ep = FakeEndpoint([
            [ResponseReceived(1, resp_h), DataReceived(1, b"ok"), StreamEnded(1)],
            [ConnectionTerminated()],
        ])

        callbacks = {"record": mock.Mock(), "request": None, "response": None}
        records = []
        handler = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="example.com",
            port=443,
            server_alpn="h2",
            callbacks=callbacks,
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=records,
            records_lock=threading.Lock(),
            is_waf_block=lambda code: code == 403,
        )

        with mock.patch("core.interceptor.h2", fake_h2, create=True):
            with mock.patch.object(i, "H2_AVAILABLE", True):
                with mock.patch.object(i.threading, "Thread", _InlineThread):
                    with mock.patch.object(handler, "_make_client_h2", return_value=client_ep):
                        with mock.patch.object(handler, "_make_server_h2", return_value=server_ep):
                            out = handler._handle_h2_to_h2()

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].response.status_code, 200)

    def test_handle_h1_to_h1_and_retry(self):
        callbacks = {"record": mock.Mock(), "request": mock.Mock(), "response": mock.Mock()}
        records = []
        advisor = mock.Mock()
        advisor.advise.side_effect = [
            i.AdvisorDecision(action="retry", delay=0, rotate_ip=False),
        ]
        magic = mock.Mock()
        magic.apply.return_value = {"tcp": {"profile": "x"}, "tor": {"active": True}}
        server_tls = mock.Mock()
        client_tls = mock.Mock()

        handler = i.H2SessionHandler(
            client_tls=client_tls,
            server_tls=server_tls,
            host="example.com",
            port=443,
            server_alpn="http/1.1",
            callbacks=callbacks,
            magic=magic,
            advisor=advisor,
            records_list=records,
            records_lock=threading.Lock(),
            is_waf_block=lambda code: code == 403,
        )

        req_raw = b"GET /a HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        resp1 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\nX"
        resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

        with mock.patch.object(i.H1Parser, "read_message", side_effect=[(req_raw, b""), (resp1.split(b"\r\n\r\n")[0] + b"\r\n\r\n", b"X"), (resp2.split(b"\r\n\r\n")[0] + b"\r\n\r\n", b"OK"), (b"", b"")]):
            out = handler._handle_h1_to_h1()

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].response.status_code, 200)

    def test_relay_raw_path(self):
        class _TLS:
            def __init__(self, reads):
                self._reads = list(reads)
                self.sent = []

            def setblocking(self, v):
                return None

            def read(self, n):
                if self._reads:
                    return self._reads.pop(0)
                return b""

            def sendall(self, d):
                self.sent.append(d)

        c = _TLS([b"abc", b""])
        s = _TLS([b"xyz", b""])
        h = i.H2SessionHandler(
            client_tls=c,
            server_tls=s,
            host="x",
            port=443,
            server_alpn="h2",
            callbacks={},
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda x: False,
        )

        with mock.patch.object(i.select, "select", side_effect=[([c, s], [], []), Exception("stop")]):
            out = h._relay_raw()
        self.assertEqual(out, [])
        self.assertTrue(c.sent or s.sent)

    def test_handle_h2_to_h2_exception_branches(self):
        class RequestReceived:
            def __init__(self, stream_id, headers, stream_ended=None):
                self.stream_id = stream_id
                self.headers = headers
                self.stream_ended = stream_ended

        class DataReceived:
            def __init__(self, stream_id, data):
                self.stream_id = stream_id
                self.data = data
                self.flow_controlled_length = len(data)

        class StreamEnded:
            def __init__(self, stream_id):
                self.stream_id = stream_id

        class ResponseReceived:
            def __init__(self, stream_id, headers, stream_ended=None):
                self.stream_id = stream_id
                self.headers = headers
                self.stream_ended = stream_ended

        class WindowUpdated:
            pass

        class ConnectionTerminated:
            pass

        fake_h2 = types.SimpleNamespace(
            events=types.SimpleNamespace(
                RequestReceived=RequestReceived,
                DataReceived=DataReceived,
                StreamEnded=StreamEnded,
                ResponseReceived=ResponseReceived,
                WindowUpdated=WindowUpdated,
                ConnectionTerminated=ConnectionTerminated,
            )
        )

        class BadConn:
            def acknowledge_received_data(self, n, sid):
                raise Exception("x")

            def end_stream(self, sid):
                raise Exception("x")

        class BadEndpoint:
            def __init__(self, batches):
                self._batches = list(batches)
                self.conn = BadConn()

            def recv_events(self, timeout=30):
                if self._batches:
                    return self._batches.pop(0)
                return []

            def send_headers(self, *args, **kwargs):
                raise Exception("x")

            def send_data(self, *args, **kwargs):
                raise Exception("x")

            def _flush(self):
                raise Exception("x")

            def close(self):
                return None

        client_ep = BadEndpoint([
            [RequestReceived(1, [(":method", "GET"), (":path", "/")]), DataReceived(1, b"a"), StreamEnded(1)],
            [WindowUpdated(), ConnectionTerminated()],
        ])
        server_ep = BadEndpoint([
            [ResponseReceived(1, {":status": "500"}), DataReceived(1, b"b"), StreamEnded(1)],
            [ConnectionTerminated()],
        ])

        handler = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="example.com",
            port=443,
            server_alpn="h2",
            callbacks={"record": None, "request": None, "response": None},
            magic=mock.Mock(),
            advisor=mock.Mock(),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda _: False,
        )

        with mock.patch("core.interceptor.h2", fake_h2, create=True):
            with mock.patch.object(i, "H2_AVAILABLE", True):
                with mock.patch.object(i.threading, "Thread", _InlineThread):
                    with mock.patch.object(handler, "_make_client_h2", return_value=client_ep):
                        with mock.patch.object(handler, "_make_server_h2", return_value=server_ep):
                            out = handler._handle_h2_to_h2()
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main()
