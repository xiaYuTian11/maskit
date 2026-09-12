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

    def test_responses_done_snapshots_clear_only_the_matching_channel(self):
        cases = (("output_text", "text", "text", False),
                 ("function_call_arguments", "arguments", "args", True),
                 ("reasoning_text", "text", "reason", False))
        for kind, field, channel, arguments in cases:
            with self.subTest(kind=kind):
                a, b = self.tokens
                self.restore_events([
                    {"type": f"response.{kind}.delta", "output_index": 4, "delta": b[:9]},
                    {"type": "response.output_text.delta", "output_index": 9, "delta": a[:9]},
                ])
                snapshot = json.dumps({"name": b}) if arguments else b
                done = {"type": f"response.{kind}.done", "output_index": 4, field: snapshot}
                # Include the event header used by Responses clients, and check
                # that no old delta is synthesized around the complete snapshot.
                restored = tr._restore_sse_event(
                    f"event: response.{kind}.done\ndata: " + json.dumps(done), self.sid)
                self.assertEqual(restored.count("event: "), 1)
                payloads = [json.loads(line[6:]) for line in restored.splitlines() if line.startswith("data: ")]
                self.assertEqual(len(payloads), 1)
                value = payloads[0][field]
                self.assertEqual(json.loads(value) if arguments else value,
                                 {"name": self.originals[1]} if arguments else self.originals[1])
                session = tr.sessions[self.sid]
                self.assertNotIn(f"r4.{channel}", session["pending"])
                self.assertNotIn(f"r4.{channel}", session.get("flush_tmpl", {}))
                self.assertEqual(session["pending"]["r9.text"], a[:9])
                ending = self.restore_events([
                    {"type": "response.output_text.delta", "output_index": 9, "delta": a[9:]},
                    {"type": "response.completed", "response": {}}, "[DONE]",
                ])
                deltas = [d for d in ending if d.get("type", "").endswith(".delta")]
                self.assertEqual(deltas, [{"type": "response.output_text.delta", "output_index": 9,
                                           "delta": self.originals[0]}])
                self.assertEqual(session["pending"], {})

    def test_responses_done_events_name_their_own_channel(self):
        """.done 必须报出自己那条通道，否则终态到了也不会刷它。

        并与写入侧 `_sse_text_slots` 交叉验证：终态前缀和 delta 写的必须是同一个
        通道名 —— 写成另一个名字等于刷了一条没人用的通道，残留照旧被扣着。
        """
        for kind, channel in (("reasoning_text", "reason"),
                              ("function_call_arguments", "args")):
            with self.subTest(kind=kind):
                writer = tr._sse_text_slots(
                    {"type": f"response.{kind}.delta", "output_index": 7, "delta": ""})[0][0]
                self.assertEqual(writer, "r7." + channel)
                self.assertEqual(
                    tr._sse_terminal_prefixes(
                        {"type": f"response.{kind}.done", "output_index": 7}),
                    ("r7." + channel,))

    def test_done_without_snapshot_still_releases_the_held_tail(self):
        """上游偶尔发不带快照字段的 .done：残留必须就地补发，不能拖到 [DONE]。

        没有终态前缀时 `_sse_terminal_prefixes` 返回 `()`，调用点的
        `if ending is None or ending` 为假 → 根本不刷，直到 [DONE] 才吐出来。
        """
        token = self.tokens[0]
        self.restore_events([
            {"type": "response.reasoning_text.delta", "output_index": 0,
             "delta": "think " + token[:-2]},
        ])
        self.assertIn("r0.reason", tr.sessions[self.sid]["pending"])
        out = tr._restore_sse_event(
            "data: " + json.dumps(
                {"type": "response.reasoning_text.done", "output_index": 0}),
            self.sid)
        payloads = [json.loads(line[6:]) for line in out.splitlines()
                    if line.startswith("data: ")]
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0]["delta"], self.originals[0])
        self.assertEqual(payloads[1]["type"], "response.reasoning_text.done")
        self.assertNotIn("r0.reason", tr.sessions[self.sid]["pending"])

    def test_responses_content_parts_keep_independent_buffers(self):
        """同一 output item 的多个 content part 必须各自缓冲（issue #29）。

        规范允许一个 message item 的 content 是数组（多个 output_text part）。
        只按 output_index 建通道时，part 0 的半截占位符会被 part 1 的增量续上，
        part 0 自己反而丢了内容 —— 属于静默串字。
        """
        tok = self.tokens[0]
        events = self.restore_events([
            {"type": "response.output_text.delta", "output_index": 0,
             "content_index": 0, "delta": "P0:" + tok[:8]},
            {"type": "response.output_text.delta", "output_index": 0,
             "content_index": 1, "delta": "P1:正文"},
            {"type": "response.output_text.delta", "output_index": 0,
             "content_index": 0, "delta": tok[8:]},
            "[DONE]",
        ])
        parts = {}
        for ev in events:
            if ev.get("type") != "response.output_text.delta":
                continue
            ci = ev.get("content_index", 0)
            parts[ci] = parts.get(ci, "") + ev.get("delta", "")
        self.assertIn(self.originals[0], parts.get(0, ""), "part0 的占位符必须还原")
        self.assertNotIn(self.originals[0], parts.get(1, ""), "part0 的原文不能串到 part1")
        self.assertNotIn(tok[:8], parts.get(1, ""), "part0 的半截占位符不能混进 part1")
        self.assertEqual(parts.get(1, ""), "P1:正文")

    def test_responses_part_done_leaves_sibling_part_buffer_intact(self):
        """part 0 的 .done 只收尾 part 0，不能冲掉 part 1 的半截缓冲。

        收尾通道与写入通道同源（都含 content_index）才能做到这一点。
        """
        tok = self.tokens[1]
        self.restore_events([
            {"type": "response.output_text.delta", "output_index": 0,
             "content_index": 1, "delta": "P1:" + tok[:8]},
        ])
        self.assertIn("r0.1.text", tr.sessions[self.sid]["pending"])
        self.restore_events([
            {"type": "response.output_text.done", "output_index": 0,
             "content_index": 0, "text": "part0 完整内容"},
        ])
        self.assertIn("r0.1.text", tr.sessions[self.sid]["pending"],
                      "part0 的 .done 不许冲掉 part1 的缓冲")

    def test_responses_channel_key_is_unchanged_without_content_index(self):
        """没有 content_index（或为 0）时通道键必须和改动前一字不差。

        官方目前每个 message 只发一个 part；存量单 part 流（以及所有既有用例
        断言的 r{n}.text 形态）必须零变化。
        """
        self.assertEqual(
            tr._sse_response_channel(
                {"type": "response.output_text.delta", "output_index": 3, "delta": "x"},
                "text"),
            "r3.text")
        self.assertEqual(
            tr._sse_response_channel(
                {"type": "response.output_text.delta", "output_index": 3,
                 "content_index": 0, "delta": "x"},
                "text"),
            "r3.text")
        # 只有真的出现第 2 个 part 才分出新通道
        self.assertEqual(
            tr._sse_response_channel(
                {"type": "response.output_text.delta", "output_index": 3,
                 "content_index": 2, "delta": "x"},
                "text"),
            "r3.2.text")
