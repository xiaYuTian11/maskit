"""NER 零风险早退与正则口径对等（2026-11-02）。

锁住两件事：
1. `ner_engine._PLACEHOLDER_ANY_RX` 与 `transparent._PLACEHOLDER_RX` 必须同口径 ——
   两个模块不能互相 import（transparent 在导入闭包里 import ner_engine），所以只能
   靠这条用例钉住。漂移后果：早退判据失效（把含明文的叶子当"已遮完"跳过 = 漏检）。
2. `_is_fully_placeholderized` 的判据方向必须是**保守**的：只要还剩一个汉字就返回
   False（宁可多算，不可漏扫）。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import ner_engine as N  # noqa: E402
import transparent as TR  # noqa: E402


class PlaceholderRxParityTests(unittest.TestCase):
    def test_same_placeholder_forms_match_both_regexes(self):
        """两边正则对同一批形态的判定必须一致（形态由 transparent 是唯一真相来源）。"""
        suffix_hex = "abc123"
        suffix_cons = "bcdfgh"          # 6 位纯辅音（新格式）
        samples = [
            "{{NAME_%s}}" % suffix_hex,
            "{{PHONE_%s}}" % suffix_cons,
            "{{IDCARD_%s}}" % suffix_hex,
            "{{A_%s}}" % suffix_hex,     # 最短标签
        ]
        for s in samples:
            self.assertTrue(TR._PLACEHOLDER_RX.search(s), "产品侧正则应命中: %s" % s)
            self.assertTrue(N._PLACEHOLDER_ANY_RX.search(s), "NER 侧正则应命中: %s" % s)

    def test_non_placeholder_forms_match_neither(self):
        for s in ("{{name_abc123}}", "{{NAME_XYZ123}}", "NAME_abc123", "{{NAME_abc12}}"):
            self.assertIsNone(TR._PLACEHOLDER_RX.search(s), "产品侧不应命中: %s" % s)
            self.assertIsNone(N._PLACEHOLDER_ANY_RX.search(s), "NER 侧不应命中: %s" % s)


class FullyPlaceholderizedTests(unittest.TestCase):
    def test_fully_placeholderized_returns_true(self):
        """**只剩占位符 + 非汉字字符**（标点/英文/空白/数字）→ 可跳过推理。

        注意：只要还有汉字（如 `联系人是`、`请回电`）就**不**属于本类 ——
        那类文本仍要推理（里面可能藏着人名）。这是判据的保守边界，不是缺陷。
        """
        for s in (
            "{{NAME_abc123}}",
            "{{NAME_abc123}} / {{PHONE_bcdfgh}}",
            "prefix {{NAME_abc123}} suffix",
            "{{NAME_abc123}}, {{IDCARD_abc123}}.",
            "",
        ):
            self.assertTrue(N._is_fully_placeholderized(s), repr(s))

    def test_any_remaining_han_returns_false(self):
        """只要还剩**一个**汉字就必须走正常推理（宁可多算，不可漏扫）。"""
        for s in (
            "{{NAME_abc123}} 王大锤",
            "联系人是{{NAME_abc123}}，请回电。",
            "{{NAME_abc123}}。还",
            "还有明文",
        ):
            self.assertFalse(N._is_fully_placeholderized(s), repr(s))

    def test_extract_entities_skips_placeholderized_text(self):
        """已完全遮好的文本：不产生实体。"""
        with N._CACHE_LOCK:
            N._CACHE.clear()
            N._CACHE_CHARS = 0
        out = N.extract_entities("{{NAME_abc123}} / {{PHONE_bcdfgh}}")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
