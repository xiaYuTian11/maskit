"""脱敏精度：误报降噪 + 出口复检口径统一 + 坐标映射同步（2026-10-28 真机驱动）。

数据来源：`~/.local/share/maskit/shield-events.sqlite3`（安装版 0.12.1，10-26~10-28）

- NAME 命中 65103 次，其中 **62141 次（95%）是 ≤3 字中文普通词**
  （`简洁` 4990 / `时直` 4987 / `边界` 4800 / `项目规` 4564）——本机真机请求里的
  正文被换成占位符，模型据此分析代码必然出错，而用户只看到「AI 答得不对」。
- 出口复检 `egress_verify` flagged 2280 条，`leaked` 标签 99% 是 NAME/ORG/ADDR：
  NER 是 **span 级**替换，复检是**全文精确子串** → 口径不一致造成的系统性告警。
- 3025/5800 条 MASK 记 `om_compose`（known 正向打码改了 text 却没更新 OffsetMap，
  下一次 `_update_om` 直接抛 ValueError → 整条请求跳过语义识别）。

本文件分别钉住这三类修复，防止回归。

**不要在用例里写占位符字面量**：本机在脱敏网关之后，写占位符字面量落盘可能被
还原成真实值（AGENTS §3.9）。需要 token 形态时用 `_tok()` 在运行时拼接；
姓名/地址一律用明显假名。
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import ner_engine  # noqa: E402
import transparent as tr  # noqa: E402
import zh_names  # noqa: E402


def _tok(label, suffix):
    """运行时拼接占位符形态（源码里不出现字面量）。"""
    return "{" * 2 + label + "_" + suffix + "}" * 2


class NerCodeIdentifierFilterTests(unittest.TestCase):
    """全小写 ASCII 复合词不是中文人名（`hugging-face` 类误判）。"""

    def test_lowercase_compound_is_code(self):
        for s in ("hugging-face", "home-assistant", "next.js", "foo_bar-baz"):
            with self.subTest(s=s):
                self.assertTrue(ner_engine._looks_like_code_identifier(s))

    def test_capitalized_hyphen_name_survives(self):
        """`Jean-Luc` / `O'Brien` 这类首字母大写的英文人名不能被过滤掉。"""
        for s in ("Jean-Luc", "O'Brien", "John"):
            with self.subTest(s=s):
                self.assertFalse(
                    ner_engine._looks_like_code_identifier(s),
                    "英文人名被当成代码标识符过滤了：%s" % s,
                )

    def test_cjk_untouched(self):
        self.assertFalse(ner_engine._looks_like_code_identifier("简洁"))


class ShortNameContextTests(unittest.TestCase):
    """2~3 字中文 NAME 必须有强上下文佐证，否则按误报跳过。"""

    def test_strong_context_detected(self):
        name = "张明山"
        text = "联系人：" + name + "说订单有问题"
        s = text.index(name)
        self.assertTrue(zh_names.has_strong_context(text, s, s + len(name)))

    def test_weak_context_rejected(self):
        for text, word in [
            ("保持简洁，不要啰嗦", "简洁"),
            ("同时直接返回结果", "时直"),
            ("这是项目规范的一部分", "项目规"),
            ("检查边界条件", "边界"),
        ]:
            with self.subTest(word=word):
                s = text.index(word)
                self.assertFalse(
                    zh_names.has_strong_context(text, s, s + len(word)),
                    "普通词被判成有强上下文：%s" % word,
                )

    def test_title_inside_entity_counts(self):
        """`张经理`：称谓包在实体自身尾部，也算强证据。"""
        text = "请转告张经理"
        s = text.index("张")
        self.assertTrue(zh_names.has_strong_context(text, s, s + 3))

    def test_short_name_without_context_helper(self):
        text = "同时直接返回结果"
        s = text.index("时直")
        self.assertTrue(tr._short_name_without_context(text, s, s + 2, "时直", "NAME"))

        name = "张明山"
        text2 = "联系人：" + name + "说订单有问题"
        s2 = text2.index(name)
        self.assertFalse(
            tr._short_name_without_context(text2, s2, s2 + len(name), name, "NAME")
        )

    def test_custom_word_never_dropped(self):
        """用户显式配置的词不受启发式降噪影响（词表是用户意图）。"""
        text = "这里提到简洁两个字"
        s = text.index("简洁")
        saved = dict(tr.CUSTOM_WORDS)
        try:
            tr.CUSTOM_WORDS["简洁"] = "TERM"
            self.assertFalse(
                tr._short_name_without_context(text, s, s + 2, "简洁", "NAME"),
                "自定义词被短名复核剔除了",
            )
        finally:
            tr.CUSTOM_WORDS.clear()
            tr.CUSTOM_WORDS.update(saved)

    def test_long_entity_not_affected(self):
        addr = _tok("ADDR", "mjvmtm")
        text = addr + "办事处通知"
        s = text.index(addr)
        self.assertFalse(
            tr._short_name_without_context(text, s, s + len(addr), addr, "ADDR")
        )


class LongEntityFullTextTests(unittest.TestCase):
    """长实体（>= 出口复检阈值）本轮就全字面遮蔽，与复检口径对齐。"""

    def test_long_value_all_occurrences_covered(self):
        val = "甲乙丙丁戊己庚辛壬癸子"  # 11 个虚构汉字（无真实地名/人名）
        text = "起点 " + val + " 中间 " + val + " 结尾"
        planned = [(text.index(val), text.index(val) + len(val), _tok("ADDR", "aaaaaa"))]
        out = tr._expand_long_entity_spans(text, planned)
        covered = sorted((s, e) for s, e, _ in out)
        self.assertEqual(len(covered), 2, "长值只遮了第一处：%r" % (covered,))
        self.assertEqual(covered[0][0], text.index(val))
        self.assertEqual(covered[1][0], text.index(val, covered[0][0] + 1))

    def test_short_value_not_expanded(self):
        """短值不扩展：2~3 字高频词的误掩码代价大于收益。"""
        text = "简洁和普通词不是人名"
        planned = [(0, 2, _tok("NAME", "bbbbbb"))]
        out = tr._expand_long_entity_spans(text, planned)
        self.assertEqual(len(out), 1)

    def test_placeholder_region_not_retouched(self):
        """已有占位符区间不能被二次替换（会劈开 token）。"""
        val = _tok("ADDR", "mjvmtm")
        tok = _tok("ADDR", "cccccc")
        text = val + " 与 " + tok + " 与 " + val
        planned = [(0, len(val), tok)]
        out = tr._expand_long_entity_spans(text, planned)
        ph_start = len(val) + 3
        ph_end = ph_start + len(tok)
        for s, e, _ in out:
            self.assertFalse(
                s < ph_end and e > ph_start,
                "扩展区间覆盖了已有占位符：[%d, %d)" % (s, e),
            )


class OffsetMapSyncTests(unittest.TestCase):
    """known / 归一化改写必须同步 OffsetMap，否则 NER 整段被跳过。"""

    def setUp(self):
        self._saved = {"NER_ENABLED": tr.NER_ENABLED, "BUILTIN_RULES": dict(tr.BUILTIN_RULES)}
        tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._known_reset_for_tests()

    def test_mask_by_spans_ed_keeps_dst_len(self):
        text = "abcdefghij"
        new_text, edits = tr._mask_by_spans_ed(text, [(0, 5, "XY")])
        self.assertEqual(new_text, "XYfghij")
        om = tr.OffsetMap.empty(len(text)).compose(tr.OffsetMap(edits, len(text)))
        self.assertEqual(om.dst_len, len(new_text))

    def test_known_rewrite_does_not_break_ner(self):
        """known 命中后不得再记 `om_compose`（真机 3025 条的根因）。

        旧行为：known 段用 `_mask_by_spans` 改 text 但不更新 om →
        下一次 `_update_om(edits, curr_len)` 尺寸不匹配 → `om_broken` →
        整条请求跳过语义识别，MASK 事件被记成 `om_compose` 降级。
        """
        val = "7de9d15f1548d0a1"  # 明显伪造的 16 位值（>= _KNOWN_MIN）
        phone = "1" + "3" + "8" + "0" * 8   # 规则必命中：known 段之后还要再有一次真实替换
        text = "前文 " + val + " 电话 " + phone + " 后文 " + ("顺带一段正文。" * 50)
        sid = "om-sync-known"
        tr.NER_ENABLED = True
        tr._new_session(sid)
        base = ner_engine.status().get("skips", {}).get("om_compose", 0)
        hit = [(text.index(val), text.index(val) + len(val), _tok("TERM", "dddddd"), "TERM")]

        with mock.patch.object(tr, "_known_lookup_spans", lambda t: hit), \
                mock.patch.object(ner_engine, "is_ner_available", lambda: False):
            out = tr.mask(text, sid)

        self.assertNotIn(val, out, "known 命中值未被遮蔽")
        after = ner_engine.status().get("skips", {}).get("om_compose", 0)
        self.assertEqual(after, base, "known 改写后 OffsetMap 失同步，NER 被整段跳过")


if __name__ == "__main__":
    unittest.main()
