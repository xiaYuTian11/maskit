"""Usage snapshots from supported SSE protocols must merge without double counting."""
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import shield_defaults as defaults
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
