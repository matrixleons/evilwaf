import io
import json
import tempfile
import threading
import unittest
from unittest import mock

from _deps import install_dependency_stubs

install_dependency_stubs()

import core.interceptor as i


class RecordSpoolTest(unittest.TestCase):
    def test_append_record_spills_oldest_when_buffer_full(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._records = i.deque(maxlen=1)
        inter._records_lock = threading.Lock()
        inter._record_spool_lock = threading.Lock()
        inter._record_spool_fp = io.StringIO()

        old = i.ProxyRecord(
            request=i.InterceptedRequest(timestamp=1.0, method="GET", host="old.example", path="/a"),
            response=i.InterceptedResponse(status_code=200, response_time=0.1),
            technique_applied="x",
            passed=True,
            blocked=False,
        )
        new = i.ProxyRecord(
            request=i.InterceptedRequest(timestamp=2.0, method="POST", host="new.example", path="/b"),
            response=i.InterceptedResponse(status_code=403, response_time=0.2),
            technique_applied="y",
            passed=False,
            blocked=True,
        )

        inter._append_record(old)
        inter._append_record(new)

        self.assertEqual(len(inter._records), 1)
        self.assertEqual(inter._records[0].request.host, "new.example")
        spilled = inter._record_spool_fp.getvalue().strip().splitlines()
        self.assertEqual(len(spilled), 1)
        payload = json.loads(spilled[0])
        self.assertEqual(payload["host"], "old.example")
        self.assertEqual(payload["status_code"], 200)

    def test_spill_and_append_fallback_paths(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._record_spool_fp = None
        inter._record_spool_lock = None
        inter._spill_record(i.ProxyRecord())

        inter._record_spool_fp = io.StringIO()
        inter._record_spool_lock = None
        rec = i.ProxyRecord(
            request=i.InterceptedRequest(timestamp=3.0, method="GET", host="nolock.example", path="/"),
            response=i.InterceptedResponse(status_code=201, response_time=0.05),
            passed=True,
        )
        inter._spill_record(rec)
        self.assertIn("nolock.example", inter._record_spool_fp.getvalue())

        inter2 = i.Interceptor.__new__(i.Interceptor)
        inter2._records = None
        inter2._records_lock = None
        inter2._record_spool_fp = None
        inter2._record_spool_lock = None
        inter2._append_record(i.ProxyRecord())

        inter3 = i.Interceptor.__new__(i.Interceptor)
        inter3._records = i.deque(maxlen=1)
        inter3._records_lock = None
        inter3._record_spool_fp = io.StringIO()
        inter3._record_spool_lock = None
        inter3._append_record(
            i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=4.0, method="GET", host="first.example"),
                response=i.InterceptedResponse(status_code=202),
            )
        )
        inter3._append_record(
            i.ProxyRecord(
                request=i.InterceptedRequest(timestamp=5.0, method="GET", host="second.example"),
                response=i.InterceptedResponse(status_code=203),
            )
        )
        self.assertEqual(inter3._records[0].request.host, "second.example")
        self.assertIn("first.example", inter3._record_spool_fp.getvalue())

    def test_h2session_handler_uses_record_sink_in_h1_flow(self):
        sink = mock.Mock()
        handler = i.H2SessionHandler(
            client_tls=mock.Mock(),
            server_tls=mock.Mock(),
            host="example.com",
            port=443,
            server_alpn="http/1.1",
            callbacks={},
            magic=mock.Mock(apply=mock.Mock(return_value={"tcp": {"profile": "p"}, "tor": {"active": False}})),
            advisor=mock.Mock(advise=mock.Mock(return_value=i.AdvisorDecision(action="forward"))),
            records_list=[],
            records_lock=threading.Lock(),
            is_waf_block=lambda code: code == 403,
            record_sink=sink,
        )
        req_raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp_raw = b"HTTP/1.1 200 OK\r\n\r\n"
        with mock.patch.object(
            i.H1Parser,
            "read_message",
            side_effect=[(req_raw, b""), (resp_raw, b""), (b"", b"")],
        ):
            out = handler._handle_h1_to_h1()
        self.assertEqual(len(out), 1)
        sink.assert_called_once()

    def test_interceptor_opens_and_closes_spool_file(self):
        with tempfile.TemporaryDirectory() as d:
            spool_path = f"{d}/records.jsonl"
            inter = i.Interceptor(record_spool_path=spool_path)
            self.assertIsNotNone(inter._record_spool_fp)
            inter.stop()
            self.assertIsNone(inter._record_spool_fp)

    def test_stop_closes_spool_without_lock(self):
        inter = i.Interceptor.__new__(i.Interceptor)
        inter._running = True
        inter._server = None
        inter._record_spool_fp = io.StringIO()
        inter._record_spool_lock = None
        inter.ca = mock.Mock()
        inter.stop()
        self.assertIsNone(inter._record_spool_fp)
        inter.ca.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
