"""`type` 字段取非字符串值时的健壮性（2026-10-25 真机事故回归）。

## 事故

v0.12.0 上线后真机出现两类硬报错，都源自「把 JSON 里的 `type` 当字符串用」：

1. `sse_stream:unhashable type: 'list'` —— 响应侧流式整条降级为原样透传；
2. 请求侧 `mask_body` 抛 `unhashable type: 'list'` → fail-closed 直接 503。

## 为什么 `type` 会不是字符串

JSON Schema 里 `type` 是**合法保留字**，取值可以是：

- 数组：`{"type": ["string", "null"]}`
- 对象：`{"properties": {"type": {"enum": [...], "type": "string"}}}`

而 Anthropic / OpenAI 的工具定义、Gemini 的 responseSchema 全都会带这种形态。
只要客户端把工具定义放进请求或上游回显工具定义，`type` 就不是字符串。

## 判据

所有「拿 `type` 做集合/字典成员判断」的点必须先收窄成 `isinstance(str)`。
`_restore_tree` 早在 issue #44 修过一次（`tests/test_restore_type_collision.py`），
但 `protocol_contracts.match` / `protected_fields` 与 `_sse_terminal_prefixes`
这两处漏了 —— 同一类坑的第二次踩中，所以这次把**所有**落点一起钉住。

本文件按「输入形态」穷举，而不是按函数逐个写：新增一个吃 `type` 的点时，
只要它参与这三条路径（请求脱敏 / 响应还原 / 流式收尾），就会在这里被覆盖。
"""
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import transparent as tr
import protocol_contracts as pc


# 非字符串 `type` 的两种真实形态（都不可 hash）
NON_STRING_TYPES = (
    ["string", "null"],
    {"enum": ["file", "snippet"], "type": "string"},
    [],  # 空数组同样是 list
)


def _fresh_sid(name):
    sid = "nonstr-" + name
    tr._new_session(sid)
    return sid


class ProtocolContractsTests(unittest.TestCase):
    """`protocol_contracts.match` / `protected_fields` 不得因 type 非字符串抛异常。"""

    def test_match_survives_non_string_type(self):
        for bad in NON_STRING_TYPES:
            with self.subTest(type_value=bad):
                obj = {"type": bad, "text": "hello", "signature": "sig"}
                # 不抛异常是唯一硬要求；返回 None（未命中载体）也完全可以接受。
                got = pc.match(obj, "content", "messages", ("messages", 0, "content"), "assistant", False)
                self.assertIsNone(got)

    def test_protected_fields_survives_non_string_type(self):
        for carrier in pc.CARRIERS:
            for bad in NON_STRING_TYPES:
                with self.subTest(carrier=carrier.key, type_value=bad):
                    obj = {"type": bad, "signature": "sig", "data": "blob",
                           "encrypted_content": "blob", "thoughtSignature": "sig"}
                    # 未命中的载体也必须能算（返回空集合），不能抛
                    self.assertIsInstance(pc.protected_fields(carrier, obj), frozenset)

    def test_string_type_still_matches(self):
        """收窄不能把正常形态一起废掉——误杀比误放更隐蔽。"""
        obj = {"type": "thinking", "thinking": "body", "signature": "sig"}
        got = pc.match(obj, "content", "messages", ("messages", 0, "content"), "assistant", False)
        self.assertIsNotNone(got)
        self.assertEqual(pc.protected_fields(got, obj), frozenset({"signature"}))


class MaskTreeTests(unittest.TestCase):
    """请求侧：工具定义 / 结构化输出里的 `type` 数组不能让脱敏管线崩。"""

    def test_mask_tree_survives_non_string_type(self):
        sid = _fresh_sid("mask")
        for bad in NON_STRING_TYPES:
            with self.subTest(type_value=bad):
                body = {
                    "model": "m",
                    "messages": [
                        {"role": "assistant", "content": [
                            {"type": bad, "text": "hello"},
                        ]},
                    ],
                }
                # 真实调用路径：mask_body 是请求侧唯一入口
                out = tr.mask_body(json.dumps(body), sid)
                # 不抛异常即通过；返回 str（splice 路径）或 bytes 都可以接受。
                self.assertIn(type(out), (str, bytes))

    def test_tool_schema_type_array_is_preserved(self):
        """JSON Schema 的 `type: ["string","null"]` 是**定义区**，不该被改写。

        这条同时锁住「崩溃修好」与「修复没把定义区判据改坏」两件事。
        """
        sid = _fresh_sid("schema")
        body = {
            "model": "m",
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "q": {"type": ["string", "null"], "description": "query"},
                        },
                    },
                },
            }],
            "messages": [{"role": "user", "content": "hi"}],
        }
        out = tr.mask_body(json.dumps(body), sid)
        got = json.loads(out) if isinstance(out, (str, bytes)) else out
        prop = got["tools"][0]["function"]["parameters"]["properties"]["q"]
        self.assertEqual(prop["type"], ["string", "null"])
        self.assertEqual(got["tools"][0]["function"]["name"], "lookup")


class SseTerminalPrefixTests(unittest.TestCase):
    """流式收尾判据：`choices` 不是 list 时不得抛（真机 `sse_stream` 报错点）。"""

    def test_choices_non_list_does_not_raise(self):
        for bad_choices in (True, 1, "x", {"delta": {}}, None):
            with self.subTest(choices=bad_choices):
                got = tr._sse_terminal_prefixes({"choices": bad_choices})
                self.assertEqual(got, ())

    def test_choices_element_non_dict_does_not_raise(self):
        got = tr._sse_terminal_prefixes({"choices": [None, 1, "x", []]})
        self.assertEqual(got, ())

    def test_finish_reason_still_detected(self):
        got = tr._sse_terminal_prefixes({"choices": [{"index": 0, "finish_reason": "stop"}]})
        self.assertEqual(got, ("c0.",))

    def test_restore_sse_event_survives_bad_choices(self):
        sid = _fresh_sid("sse")
        block = "data: " + json.dumps({"choices": True, "type": "x"}) + "\n"
        # 不抛异常即通过（降级为原样透传是允许的）
        out = tr._restore_sse_event(block, sid, final=False, terminal=[])
        self.assertIn("data:", out)


class ChoicesIterationTests(unittest.TestCase):
    """`_extract_chat_dialog` / `_parse_response_payload` 等读 `choices` 的路径同样要容忍非 list。"""

    def test_choices_non_list_does_not_raise(self):
        for bad in (True, 1, "x", {"delta": {}}):
            with self.subTest(choices=bad):
                payload = json.dumps({"choices": bad, "type": "x"})
                # 两条响应摘要抽取入口：SSE 文本 / JSON 文本
                self.assertIsInstance(tr._extract_chat_dialog(payload, 200), str)
                self.assertIsInstance(
                    tr._parse_response_payload(payload, "text/event-stream"), tuple)
                self.assertIsInstance(
                    tr._parse_response_payload(payload, "application/json"), tuple)

    def test_choices_element_non_dict_does_not_raise(self):
        payload = json.dumps({"choices": [None, 1, "x", []]})
        self.assertIsInstance(tr._extract_chat_dialog(payload, 200), str)
        self.assertIsInstance(
            tr._parse_response_payload(payload, "application/json"), tuple)


if __name__ == "__main__":
    unittest.main()
