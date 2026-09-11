"""Independent completion choices must keep independent restoration buffers."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import transparent as tr


def choice(index, text="", finish=None):
    return {"index": index, "delta": {"content": text}, "finish_reason": finish}


class SseChoiceChannelTests(unittest.TestCase):
    def setUp(self):
        for name in ("sessions", "_RECENT_FWD", "_RECENT_REV"):
            patcher = mock.patch.object(tr, name, {})
            patcher.start()
            self.addCleanup(patcher.stop)
        self.sid = "choice-test"
        tr._new_session(self.sid)
        self.tokens = ("{{NAME_bcdfgh}}", "{{NAME_jkmnpq}}")
        self.originals = ("Alice Example", 'Bob "Example"\nSecond line')
        tr.sessions[self.sid]["rev"].update(zip(self.tokens, self.originals))

    def restore_events(self, events):
        result = []
        for data in events:
            payload = data if isinstance(data, str) else json.dumps(data)
            text = tr._restore_sse_event("data: " + payload, self.sid)
            for line in text.splitlines():
                if line.startswith("data: ") and line != "data: [DONE]":
                    result.append(json.loads(line[6:]))
        return result

    def contents(self, events):
        result = {}
        for event in events:
            for position, item in enumerate(event.get("choices", [])):
                index = item.get("index", position)
                result[index] = result.get(index, "") + item.get("delta", {}).get("content", "")
        return result

    def test_sparse_and_reordered_choices_restore_independently(self):
        a, b = self.tokens
        events = [
            {"choices": [choice(4, a[:9])]},
            {"choices": [choice(9, b[:9])]},
            {"choices": [choice(9, b[9:]), choice(4, a[9:])]},
            "[DONE]",
        ]
        self.assertEqual(self.contents(self.restore_events(events)),
                         {4: self.originals[0], 9: self.originals[1]})

    def test_one_choice_finishes_with_text_while_the_other_keeps_streaming(self):
        a, b = self.tokens
        events = [
            {"choices": [choice(0, a[:9]), choice(1, b[:9])]},
            {"choices": [choice(0, a[9:], "stop")]},
            {"choices": [choice(1, b[9:], "stop")]},
            "[DONE]",
        ]
        self.assertEqual(self.contents(self.restore_events(events)), dict(enumerate(self.originals)))
        self.assertEqual(tr.sessions[self.sid]["pending"], {})

    def test_finishing_choice_does_not_flush_another_choices_tool_arguments(self):
        token = self.tokens[1]
        def tool(piece):
            return {"choices": [{"index": 1, "delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": piece}}]}}]}
        events = [tool('{"name":"' + token[:9]), {"choices": [choice(0, "done", "stop")]},
                  tool(token[9:] + '"}'), {"choices": [choice(1, finish="tool_calls")]}, "[DONE]"]
        restored = self.restore_events(events)
        arguments = "".join(call["function"].get("arguments", "")
                            for event in restored for item in event.get("choices", [])
                            for call in item.get("delta", {}).get("tool_calls", []))
        self.assertEqual(json.loads(arguments), {"name": self.originals[1]})

    def test_missing_index_and_final_partial_tokens_remain_compatible(self):
        token = self.tokens[1]
        # The model omitted the final braces. Flush must still JSON-escape the
        # recovered value when the destination is a tool argument string.
        events = [{"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {
            "arguments": token[:-2]}}]}}]}, "[DONE]"]
        restored = self.restore_events(events)
        arguments = "".join(call["function"].get("arguments", "")
                            for event in restored for item in event.get("choices", [])
                            for call in item.get("delta", {}).get("tool_calls", []))
        self.assertEqual(json.loads('"' + arguments + '"'), self.originals[1])
