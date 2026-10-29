"""媒体/内联二进制豁免：图片与文件字段不能被当文本脱敏改坏。

## 真机事故（2026-10-29）

Codex 里上传含图表的 Excel → Codex 把图表渲染成 PNG，base64 塞进
`input[].output[].image_url`。该字段此前不在任何豁免集合里：

- `image_url` 不在 `_MASK_SKIP_KEYS`（那一行判断根本走不到）；
- `_MASK_MEDIA_PARENTS` 只覆盖 `{"image_url": {"url": ...}}` 这种嵌套形态。

于是整段 base64 被当文本扫，用户词表里的 3 字 ASCII 短词（无边界子串匹配）
在几十万字符里必然命中，替换成占位符 → 上游 `Only base64 data is allowed` 400。
更糟的是客户端会把这份**已改坏的请求**存进历史，之后每轮重发都 400。

## 本文件锁的契约

1. 二进制 data URL（图片/Office/PDF…）与媒体字段的 http(s) 地址**原样上行**，
   且输出仍是合法 base64；
2. `text/*` 的 data URL **不豁免**（可能藏 PII），照常脱敏；
3. 普通文本里的短词/手机号照常命中，不因豁免而漏；
4. 豁免必须**计数**（`media_skipped`）并进 `reason_codes`，不静默；
5. **词边界方案已否决**（2026-10-29 实测）：给纯 ASCII 词加 `(?<![A-Za-z0-9_])`
   边界会让 20 条协议契约测试全红——它们锁死「同名键出现在编码块/标识符里也必须
   照常扫描」（`acme` 嵌在 base64 里必须被替换，见 `tests/test_protocol_contracts.py`）。
   编码块被改坏的根因是「媒体字段没有豁免」，修在 `_media_value_exempt`；
   词表匹配的子串语义保持不动。

> 按项目纪律，本文件不写任何占位符字面量与真实号码：样例用分片拼接。
"""
import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr  # noqa: E402
import inspection  # noqa: E402

# 合法 base64，且含 `t00`（`t00A` 是一整个 4 字符组，保证 validate=True 能解码）
B64_WITH_WORD = "t00A" + "A" * 400
DATA_URL = "data:image/png;base64," + B64_WITH_WORD
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
XLSX_URL = "data:" + XLSX_MIME + ";base64," + B64_WITH_WORD
MEDIA_HTTP = "https://cdn.example.com/t00/chart.png"
# 明显伪造的手机号（分片拼接，避免文件里出现连续 11 位数字）
PHONE = "1" + "3" + "0" + "0" * 8


class _CustomWordMixin:
    """临时把「3 字 ASCII 词」塞进自定义词表，测完还原。"""

    word = "t00"

    def setUp(self):
        self._old = dict(tr.CUSTOM_WORDS)
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS[self.word] = "编号"
        tr._refresh_custom_words_sorted()

    def tearDown(self):
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update(self._old)
        tr._refresh_custom_words_sorted()


class MediaValueExemptionTests(_CustomWordMixin, unittest.TestCase):
    """媒体字段与二进制 data URL 必须原样上行。"""

    def _tree(self, body, sid):
        tr._new_session(sid)
        return tr._mask_tree(json.loads(json.dumps(body)), sid)

    def test_responses_image_url_string_is_not_rewritten(self):
        """真机事故的复现形态：`input[].output[].image_url` 是字符串。"""
        body = {"input": [{"type": "function_call_output", "output": [
            {"type": "image", "image_url": DATA_URL}]}]}
        got = self._tree(body, "t-media-1")["input"][0]["output"][0]["image_url"]
        self.assertEqual(got, DATA_URL, "图片 base64 被改写，上游会 400")
        base64.b64decode(got.split(",", 1)[1], validate=True)

    def test_input_file_file_data_is_not_rewritten(self):
        body = {"input": [{"type": "input_file", "file_data": XLSX_URL}]}
        got = self._tree(body, "t-media-2")["input"][0]["file_data"]
        self.assertEqual(got, XLSX_URL)
        base64.b64decode(got.split(",", 1)[1], validate=True)

    def test_media_http_url_is_not_rewritten(self):
        body = {"input": [{"type": "image", "image_url": MEDIA_HTTP}]}
        self.assertEqual(
            self._tree(body, "t-media-3")["input"][0]["image_url"], MEDIA_HTTP)

    def test_text_data_url_is_still_masked(self):
        """`data:text/plain` 可能藏 PII，不豁免 —— 否则就是一条新漏检路径。"""
        text = "data:text/plain;base64,t00,A" + "A" * 40
        body = {"input": [{"type": "message", "content": text}]}
        got = self._tree(body, "t-media-4")["input"][0]["content"]
        self.assertNotEqual(got, text, "text/* 的 data URL 不应被豁免")

    def test_plain_text_still_masked(self):
        """豁免不能扩大成漏检：普通文本里的短词与手机号照常命中。"""
        sid = "t-media-5"
        tr._new_session(sid)
        out = tr.mask("编号 t00，电话 %s" % PHONE, sid)
        self.assertNotIn("t00", out)
        self.assertNotIn(PHONE, out)

    def test_skip_is_counted(self):
        """豁免是漏检路径，必须计数（与签名块豁免同一纪律）。"""
        sid = "t-media-6"
        tr._new_session(sid)
        tr._mask_tree({"input": [{"type": "image", "image_url": DATA_URL}]}, sid)
        s = tr._session_get(sid)
        self.assertGreaterEqual(int(s.get("media_skipped") or 0), 1)
        taken = tr._take_media_skips(sid)
        self.assertGreaterEqual(taken, 1)
        self.assertEqual(tr._take_media_skips(sid), 0, "取走必须清零（请求级语义）")


class MediaSkipAttributionTests(unittest.TestCase):
    """媒体豁免要进 reason_codes，但不把完整度降成 partial。"""

    def test_reason_code_is_partial_scope(self):
        cls, _desc = inspection.REASON_CODES["media_skipped"]
        self.assertEqual(cls, "partial_scope")

    def test_report_keeps_completeness(self):
        rep = inspection.report_for_mask(changed=True, media_skipped=2)
        self.assertEqual(rep["completeness"], "complete")
        self.assertEqual(rep["reason_codes"]["media_skipped"], 2)

    def test_field_in_summary_whitelist(self):
        src = (ROOT / "engine" / "event_store.py").read_text(encoding="utf-8")
        block = src.split("_SUMMARY_KEEP_FIELDS = frozenset({", 1)[1].split("})", 1)[0]
        self.assertIn('"media_skipped"', block)


    def test_short_word_still_masked_in_plain_text(self):
        """短词在普通文本里照常命中（媒体豁免不能扩大成漏检）。"""
        old = dict(tr.CUSTOM_WORDS)
        try:
            tr.CUSTOM_WORDS.clear()
            tr.CUSTOM_WORDS["t00"] = "编号"
            tr._refresh_custom_words_sorted()
            sid = "t-cw-1"
            tr._new_session(sid)
            self.assertNotIn("t00", tr.mask("编号 t00 结尾", sid))
            self.assertNotIn("T00", tr.mask("编号 T00 结尾", sid))
        finally:
            tr.CUSTOM_WORDS.clear()
            tr.CUSTOM_WORDS.update(old)
            tr._refresh_custom_words_sorted()


if __name__ == "__main__":
    unittest.main()
