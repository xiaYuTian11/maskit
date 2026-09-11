"""Usage snapshots from supported SSE protocols must merge without double counting."""
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import shield_defaults as defaults
import panel
import transparent as tr


def event(data):
    return "data: " + json.dumps(data) + "\n\n"


class StreamingUsageTests(unittest.TestCase):
    def test_anthropic_snapshots_merge_without_summing_cumulative_counts(self):
        start = {"type": "message_start", "message": {"usage": {"input_tokens": 25, "output_tokens": 1}}}
        updates = [{"type": "message_delta", "usage": {"output_tokens": n}} for n in (10, 15)]
        text = "".join(event(d) for d in [start, *updates])
        expected = {"prompt_tokens": 25, "completion_tokens": 15}
        self.assertEqual(defaults.extract_usage(text), expected)
        usage = {}
        for data in [start, *updates]:
            usage = defaults.extract_usage(event(data), previous=usage)
        self.assertEqual(usage, expected)

    def test_response_terminal_events_and_existing_json_shapes(self):
        expected = {"prompt_tokens": 37, "completion_tokens": 11}
        for kind in ("response.completed", "response.incomplete", "response.failed"):
            with self.subTest(kind=kind):
                data = {"type": kind, "response": {"usage": {"input_tokens": 37, "output_tokens": 11}}}
                self.assertEqual(defaults.extract_usage(event(data)), expected)
        for data in ({"usage": expected}, {"usage": {"input_tokens": 37, "output_tokens": 11}},
                     {"meta": {"tokens": expected}}, {"usage": {}, "meta": {"tokens": expected}}):
            with self.subTest(data=data):
                self.assertEqual(defaults.extract_usage(json.dumps(data)), expected)
        self.assertEqual(defaults.extract_usage('{"usage":{"total_tokens":128}}'),
                         {"prompt_tokens": 128, "completion_tokens": 0})

    def test_invalid_fields_do_not_erase_usage_and_explicit_zero_is_valid(self):
        previous = {"prompt_tokens": 25, "completion_tokens": 15}
        for bad in (None, "not-a-count", -1, float("inf")):
            with self.subTest(bad=bad):
                data = {"usage": {"input_tokens": bad, "output_tokens": 0}}
                self.assertEqual(defaults.extract_usage(event(data), previous),
                                 {"prompt_tokens": 25, "completion_tokens": 0})
        self.assertEqual(previous, {"prompt_tokens": 25, "completion_tokens": 15})
        self.assertEqual(defaults.extract_usage("data: [DONE]\n\n", previous), previous)

    def test_stream_callback_keeps_usage_after_text_truncation_and_network_splits(self):
        sid = "usage-test"
        tr._new_session(sid)
        self.addCleanup(tr.sessions.pop, sid, None)
        flow = SimpleNamespace(metadata={})
        with mock.patch.object(tr, "_SSE_KEEP_MAX", 1), \
             mock.patch.object(tr, "_emit_restore_summary") as summary, \
             mock.patch.object(tr, "_audit_response"), \
             mock.patch.object(tr, "_scan_response"), \
             mock.patch.object(tr, "_emit") as emit:
            stream = tr._sse_stream_factory(flow, sid, "example.invalid", "POST", "/v1/messages", {})
            data = [
                {"type": "message_start", "message": {"usage": {"input_tokens": 25, "output_tokens": 1}}},
                {"type": "content_block_delta", "index": 0, "delta": {"text": "test" * 100}},
                {"type": "message_delta", "usage": {"output_tokens": 15}},
                {"type": "message_stop"},
            ]
            raw = "".join(event(d) for d in data).encode()
            for offset in range(0, len(raw), 17):
                stream(raw[offset:offset + 17])
            stream(b"")
        emit.assert_not_called()
        summary.assert_called_once()
        self.assertEqual(summary.call_args.kwargs["stream_usage"],
                         {"prompt_tokens": 25, "completion_tokens": 15})

    def test_total_fallback_with_zero_fields_remains_compatible(self):
        for fields in ({"completion_tokens": 0}, {"prompt_tokens": 0},
                       {"input_tokens": 0, "output_tokens": 0}):
            with self.subTest(fields=fields):
                data = {"usage": {"total_tokens": 128, **fields}}
                self.assertEqual(defaults.extract_usage(json.dumps(data)),
                                 {"prompt_tokens": 128, "completion_tokens": 0})
        self.assertEqual(defaults.extract_usage(event({"usage": {
            "total_tokens": 128, "prompt_tokens": 100, "completion_tokens": 28}})),
            {"prompt_tokens": 100, "completion_tokens": 28})

    def forward_response(self, raw, content_type, chunk_size):
        handler_type = panel._make_passthrough_handler("https://example.invalid")
        handler = object.__new__(handler_type)
        handler.headers = {}
        handler.rfile = io.BytesIO()
        handler.wfile = io.BytesIO()
        handler.client_address = ("127.0.0.1", 12345)
        handler.path = "/v1/messages"
        handler.command = "POST"
        for name in ("send_response", "send_header", "end_headers", "send_error"):
            setattr(handler, name, mock.Mock())
        headers = {"Content-Type": content_type, "Content-Length": str(len(raw))}
        response = mock.Mock(status=200)
        response.getheader.side_effect = lambda name, default=None: headers.get(name, default)
        response.getheaders.return_value = list(headers.items())
        response.read1.side_effect = [raw[i:i + chunk_size] for i in range(0, len(raw), chunk_size)] + [b""]
        with mock.patch.object(panel.http.client, "HTTPSConnection") as connection, \
             mock.patch.object(panel, "enqueue_event") as enqueue:
            connection.return_value.getresponse.return_value = response
            handler._do_forward()
        handler.send_error.assert_not_called()
        connection.return_value.close.assert_called_once()
        self.assertEqual(handler.wfile.getvalue(), raw)
        enqueue.assert_called_once()
        self.assertEqual(enqueue.call_args.args[0]["type"], "PASS")
        return enqueue.call_args.args[0]["usage"]

    def test_passthrough_keeps_initial_usage_in_long_split_stream(self):
        start = {"type": "message_start", "message": {"usage": {"input_tokens": 25, "output_tokens": 1}}}
        content = {"type": "content_block_delta", "index": 0, "delta": {"text": "test" * 300}}
        end = {"type": "message_delta", "usage": {"output_tokens": 15}}
        raw = (event(start) + event(content) * 100 + event(end)).encode()
        self.assertGreater(len(raw), 65536)
        for size in (17, 65536):
            with self.subTest(chunk_size=size):
                self.assertEqual(self.forward_response(raw, "text/event-stream", size),
                                 {"prompt_tokens": 25, "completion_tokens": 15})

    def test_passthrough_skips_oversized_lines_and_recovers_usage_at_eof(self):
        start = event({"type": "message_start", "message": {"usage": {"input_tokens": 25}}})
        huge = event({"type": "content_block_delta", "delta": {"text": "x" * 100000}})
        end = event({"type": "message_delta", "usage": {"output_tokens": 15}}).rstrip()
        raw = (start + huge + end).replace("\n", "\r\n").encode()
        self.assertEqual(self.forward_response(raw, "text/event-stream", 4096),
                         {"prompt_tokens": 25, "completion_tokens": 15})

    def test_passthrough_keeps_non_streaming_json_usage(self):
        raw = json.dumps({"usage": {"prompt_tokens": 25, "completion_tokens": 15}}).encode()
        self.assertEqual(self.forward_response(raw, "application/json", 17),
                         {"prompt_tokens": 25, "completion_tokens": 15})
