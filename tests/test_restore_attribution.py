"""还原失败归因：把「没还原」拆成可行动的原因。

## 真机日志分析结论（2026-10-25，43763 条事件只读复盘）

本机事件库 `~/.local/share/maskit/shield-events.sqlite3` 的统计：

| 指标 | 数值 |
|---|---|
| RESTORE 事件总数 | 21,267 |
| `restore_status = restored` | 13,930（65.5%） |
| `restore_status = no_placeholder_in_response` | **7,192（33.8%）** |
| `restore_status = unresolved`（真·映射丢失） | **3（0.01%）** |
| 最终响应里仍残留严格形态占位符 | **1 条** |

也就是说：

1. **「占位符没被还原」几乎不存在**（1/21267）。用户看到的 `{{...}}` 残留不是主因。
2. **`unresolved` 只有 3 条**，且都不是台账丢失（86 条 `foreign` 全是模型自造 token）。
3. 大头是 `no_placeholder_in_response`（7192 条，34%），它的语义是
   「**这次请求遮了东西，但模型回答里一个占位符都没提**」。

这个数字本身没错，但它把**三种完全不同的事**混成了一个：
   · 模型压根没提到那些值（正常，占绝大多数）；
   · 模型提到了，但改写了占位符形态（宽松正则没兜住 —— 真问题）；
   · 响应根本没走到还原（流中断 / 客户端断开 / 上游 5xx）。

用户看到「33% 没还原」只会以为引擎坏了。必须细分。

## 本文件锁的契约

1. `no_placeholder_in_response` 必须**细分**为可归因的子状态。
2. 细分**不能改变**「有没有真的漏还原」的判定（`unresolved` 仍是唯一告警态）。
3. 归因字段必须进事件白名单（否则「发了但看不见」）。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class RestoreStatusTests(unittest.TestCase):
    """`_restore_status_of` 的细分判据。"""

    def _status(self, **kw):
        return tr._restore_status_of(**kw)

    def test_no_masks_is_no_sensitive_data(self):
        self.assertEqual(self._status(masked_count=0), "no_sensitive_data")

    def test_unresolved_wins(self):
        """`unresolved` 仍是**唯一**告警态，优先级最高。"""
        self.assertEqual(
            self._status(masked_count=5, unresolved=1, restored_count=3),
            "unresolved",
        )

    def test_restored(self):
        self.assertEqual(
            self._status(masked_count=5, restored_count=3), "restored"
        )

    def test_not_mentioned_substatus(self):
        """模型压根没提那些值 —— 正常情况，不该被当成失败。

        `model_mentioned_none` 必须存在，且与「模型提了但形态坏了」区分开。
        """
        self.assertEqual(
            self._status(masked_count=5, restored_count=0, placeholder_seen=False),
            "not_mentioned",
        )

    def test_rewritten_placeholder_substatus(self):
        """模型提了占位符、但形态被改写且没兜住 —— 这才是需要关注的。

        判据：响应里出现了「像占位符」的片段（宽松形态），但严格/宽松都没替换成功。
        """
        self.assertEqual(
            self._status(masked_count=5, restored_count=0, placeholder_seen=True),
            "placeholder_rewritten",
        )

    def test_incomplete_response_substatus(self):
        """响应没走完（流中断/客户端断开）—— 不是引擎的还原能力问题。"""
        self.assertEqual(
            self._status(masked_count=5, restored_count=0, complete=False),
            "response_incomplete",
        )

    def test_priority_order(self):
        """优先级：unresolved > response_incomplete > placeholder_rewritten > not_mentioned。"""
        self.assertEqual(
            self._status(masked_count=5, unresolved=1, complete=False,
                         placeholder_seen=True),
            "unresolved",
        )
        self.assertEqual(
            self._status(masked_count=5, complete=False, placeholder_seen=True),
            "response_incomplete",
        )
        self.assertEqual(
            self._status(masked_count=5, placeholder_seen=True),
            "placeholder_rewritten",
        )


class EventFieldTests(unittest.TestCase):
    """归因字段必须真的进事件、且进白名单。"""

    def test_placeholder_seen_helper_exists(self):
        self.assertTrue(
            hasattr(tr, "_response_has_placeholder_shape"),
            "缺少 `_response_has_placeholder_shape`（判定「模型提没提占位符」）",
        )

    def test_detects_strict_placeholder(self):
        self.assertTrue(tr._response_has_placeholder_shape("见 {{PHONE_abcdef}}"))
        self.assertTrue(tr._response_has_placeholder_shape("见 {{PHONE_abcd12}}"))

    def test_detects_loose_placeholder(self):
        """模型常剥掉花括号：`PHONE_abcdef` 也算「提了」。"""
        self.assertTrue(tr._response_has_placeholder_shape("见 PHONE_abcdef"))

    def test_ignores_normal_text(self):
        for text in ("这里没有占位符", "UTF_8 编码", "HTTP_status 500", ""):
            self.assertFalse(
                tr._response_has_placeholder_shape(text),
                f"普通文本被误判成占位符：{text!r}",
            )

    def test_fields_are_in_summary_whitelist(self):
        """新增归因字段必须在 summary 白名单里（否则「发了但看不见」）。"""
        src = (ROOT / "engine" / "event_store.py").read_text(encoding="utf-8")
        block = src.split("_SUMMARY_KEEP_FIELDS = frozenset({", 1)[1].split("})", 1)[0]
        for field in ("restore_status", "placeholder_seen"):
            self.assertIn('"%s"' % field, block, f"summary 白名单缺 {field}")


class EgressPreviewTests(unittest.TestCase):
    """脱敏取证：内存留最近 N 条「厂商实际收到的 body」。"""

    def test_ring_buffer_exists(self):
        self.assertTrue(hasattr(tr, "_EGRESS_PREVIEW_MAX"), "缺少取证缓冲上限")
        self.assertTrue(hasattr(tr, "_egress_preview_add"), "缺少取证缓冲写入")
        self.assertTrue(hasattr(tr, "_egress_preview_list"), "缺少取证缓冲读取")

    def test_buffer_is_bounded(self):
        self.assertGreater(tr._EGRESS_PREVIEW_MAX, 0)
        self.assertLessEqual(tr._EGRESS_PREVIEW_MAX, 200)

    def test_buffer_holds_no_plaintext_of_credentials(self):
        """凭据类原文**不**进缓冲（它会被 UI 展示，等于把凭据放进诊断面）。"""
        tr._egress_preview_reset()
        tr._egress_preview_add(
            sid="s1", host="api.example.com", path="/v1/messages",
            masked="x {{SECRET_abcdef}} y", labels={"x": "SECRET"},
        )
        items = tr._egress_preview_list()
        self.assertEqual(len(items), 1)
        self.assertIn("{{SECRET_", items[0]["masked"], "占位符形态应当保留（供对照）")

    def test_ring_buffer_drops_oldest(self):
        tr._egress_preview_reset()
        for i in range(tr._EGRESS_PREVIEW_MAX + 5):
            tr._egress_preview_add(
                sid=f"s{i}", host="h", path="/p", masked=f"body {i}", labels={},
            )
        items = tr._egress_preview_list()
        self.assertEqual(len(items), tr._EGRESS_PREVIEW_MAX, "缓冲没有按上限淘汰")
        # 最新的一定在
        self.assertIn(f"body {tr._EGRESS_PREVIEW_MAX + 4}", items[-1]["masked"])


if __name__ == "__main__":
    unittest.main()
