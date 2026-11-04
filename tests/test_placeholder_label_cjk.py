"""占位符标签支持 CJK（2026-11-04）。

背景：自定义敏感词的分类名是中文（人名 / 地域 / 密级 / 军事单位…）。旧实现
`_safe_label` 把非 ASCII 全删、空串兜底成 `TERM`，于是模型看到的一律是
`{{TERM_xxxxxx}}` —— 既读不出类别语义，也分不清两个 token 属于不同分类
（用户实测反馈：想让模型知道「这两个是人名」）。

本文件锁三件事：
1. `_safe_label` 保留中文、仍然剥掉下划线与引号（后缀切分依赖「标签不含下划线」）；
2. `_PLACEHOLDER_RX` 等**全部**占位符正则都认中文标签 —— 漏一处就表现为
   「打码正常、还原全丢」，而且事件里只会静默默认成 unresolved；
3. 标签是中文的 token 能正常签发、还原、按后缀反查，且（关键）**归一化后仍相等**
   —— `_suffix_real_token` 靠 `_safe_label` 比对两边标签，两边不同源就会拒绝还原。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as TR  # noqa: E402
import event_store as ES  # noqa: E402
import ner_engine as NE  # noqa: E402


CJK_TOKENS = (
    "{{人名_bcdfgh}}",
    "{{地名_bcdfgh}}",
    "{{密级_bcdfgh}}",
    "{{军事单位_bcdfgh}}",
    "{{人名_abc123}}",       # 存量 hex6 后缀 + 中文标签
)


class SafeLabelTests(unittest.TestCase):
    def test_keeps_cjk_and_uppercases_ascii(self):
        self.assertEqual(TR._safe_label("人名"), "人名")
        self.assertEqual(TR._safe_label("密级"), "密级")
        self.assertEqual(TR._safe_label("api_key"), "APIKEY")

    def test_strips_underscore_and_punctuation(self):
        """下划线必须剥掉：`_token_suffix` 用 rsplit("_", 1) 切后缀。

        标签里若残留下划线，切分点会落到标签中间，整个还原链路错位。
        """
        self.assertEqual(TR._safe_label("人_名"), "人名")
        self.assertEqual(TR._safe_label("a b"), "AB")
        self.assertEqual(TR._safe_label("人名（正式）"), "人名正式")

    def test_empty_falls_back_to_term(self):
        """空标签兜底仍是 TERM：存量 token 里有它，不能改。"""
        self.assertEqual(TR._safe_label(""), "TERM")
        self.assertEqual(TR._safe_label("   "), "TERM")

    def test_truncates_to_twelve_chars(self):
        """长度上限与正则 {1,12} 必须一致，否则签出的 token 自己匹配不上。"""
        lab = TR._safe_label("一二三四五六七八九十甲乙丙")
        self.assertEqual(len(lab), 12)
        tok = "{{%s_bcdfgh}}" % lab
        self.assertTrue(TR._PLACEHOLDER_RX.fullmatch(tok), "签出的 token 必须被严格正则认")


class PlaceholderRegexParityTests(unittest.TestCase):
    """产品侧 / 面板侧 / NER 侧 / 事件库侧的占位符正则必须同口径。

    四份正则分布在四个模块里（不能互相 import），只能靠用例钉住。
    """

    def test_strict_forms_match_everywhere(self):
        for tok in CJK_TOKENS:
            self.assertTrue(TR._PLACEHOLDER_RX.fullmatch(tok), "transparent 严格: %s" % tok)
            self.assertTrue(TR._PLACEHOLDER_PARTS_RX.fullmatch(tok), "parts: %s" % tok)
            self.assertTrue(ES._PLACEHOLDER_RE.fullmatch(tok), "event_store: %s" % tok)
            # ner_engine 那份刻意不带结尾 `}}`（用于 search 早退判据），只做 search
            self.assertIsNotNone(NE._PLACEHOLDER_ANY_RX.search(tok), "ner_engine: %s" % tok)

    def test_panel_passthrough_regex_accepts_cjk(self):
        """面板透传还原用的正则（引擎停机时的唯一兜底）。

        它只认辅音后缀（不做标签容错），所以单独一组用例。
        """
        import panel
        for tok in ("{{人名_bcdfgh}}", "{{密级_bcdfgh}}"):
            self.assertTrue(panel._PT_TOKEN_RX.fullmatch(tok), tok)

    def test_partial_rx_holds_cjk_fragments(self):
        """流式切点落在中文标签中间时，必须被扣留等下一块拼。

        `_PARTIAL_RX` 的字符类漏 CJK 是**最隐蔽的一处**：打码与整包还原都正常，
        只有模型边生成边流式下发时会漏出 `{{人名_bc` 这种残片。
        """
        buf = "前缀 {{人名_bc"
        m = TR._PARTIAL_RX.search(buf)
        self.assertIsNotNone(m, "行尾半截占位符必须被识别")
        self.assertEqual(m.end(), len(buf))
        self.assertLessEqual(len(m.group()), TR._PARTIAL_MAX)

    def test_loose_rx_accepts_cjk_with_and_without_braces(self):
        for form in ("{{人名_bcdfgh}}", "{人名_bcdfgh}", "人名_bcdfgh"):
            self.assertIsNotNone(TR._LOOSE_PLACEHOLDER_RX.search(form), form)

    def test_braced_and_escaped_forms_accept_cjk(self):
        self.assertIsNotNone(TR._BRACED_PLACEHOLDER_RX.search("{{ 人名_bcdfgh }}"))
        self.assertIsNotNone(TR._ANY_BRACED_SUFFIX_RX.fullmatch("{{ 人名_bcdfgh }}"))
        self.assertIsNotNone(TR._ESCAPED_PLACEHOLDER_RX.search(r"\{\{人名_bcdfgh\}\}"))


class CjkLabelRoundTripTests(unittest.TestCase):
    """签发 → 打码 → 还原的端到端一致性（不碰网络与上游）。"""

    def test_mask_and_restore_with_cjk_label(self):
        TR.CUSTOM_WORDS = {"测试甲": "人名"}
        TR.SENSITIVE_DISABLED = set()
        TR.SENSITIVE_WORD_DISABLED = {}
        TR.SENSITIVE_WORD_WHOLE = set()
        TR._refresh_custom_words_sorted()
        TR._sync_custom_word_mappings()
        sid = "cjk-roundtrip"
        TR.sessions.pop(sid, None)
        try:
            masked = TR.mask("联系测试甲确认一下", sid)
            self.assertIn("人名_", masked, "自定义中文分类必须体现在标签里")
            self.assertNotIn("TERM_", masked, "不得再统一压成 TERM")
            tok = TR._PLACEHOLDER_RX.search(masked).group(0)
            self.assertTrue(tok.startswith("{{人名_"), tok)
            restored = TR.restore(masked, sid, channel="cjk", final=True)
            self.assertEqual(restored, "联系测试甲确认一下")
        finally:
            TR.sessions.pop(sid, None)
            TR.CUSTOM_WORDS = {}

    def test_suffix_lookup_tolerates_case_and_underscore_rewrite(self):
        """模型改写标签形态时，后缀反查仍要命中。

        两边标签都用 `_safe_label` 归一化才成立：一侧存中文、一侧比对归一化后的
        结果不同源 → 直接拒绝还原（表现为「明明映射还在，就是不还原」）。
        """
        TR.CUSTOM_WORDS = {"测试乙": "密级"}
        TR.SENSITIVE_DISABLED = set()
        TR.SENSITIVE_WORD_DISABLED = {}
        TR.SENSITIVE_WORD_WHOLE = set()
        TR._refresh_custom_words_sorted()
        TR._sync_custom_word_mappings()
        sid = "cjk-suffix"
        TR.sessions.pop(sid, None)
        try:
            masked = TR.mask("密级测试乙", sid)
            tok = TR._PLACEHOLDER_RX.search(masked).group(0)
            suffix = TR._token_suffix(tok)
            self.assertTrue(suffix)
            # 模型把标签写成带下划线的形态（`密_级`）：归一化后仍是「密级」
            rewritten = "{{密_级_%s}}" % suffix
            real = TR._suffix_real_token(rewritten)
            self.assertEqual(real, tok, "后缀反查必须容忍标签形态改写")
        finally:
            TR.sessions.pop(sid, None)
            TR.CUSTOM_WORDS = {}


class CredentialCategoryTests(unittest.TestCase):
    """用户显式标记为「凭据类」的自定义分类：原文永不落库。

    这是现有安全洞的封堵（2026-11-04）：凭据判定长期只看内置 CREDENTIAL_LABELS，
    用户把 API key 放进中文分类（如「密钥」）时 label 不在集合里 → 原文落库。
    """

    def tearDown(self):
        import credential_labels as CL
        CL.set_credential_categories([])

    def test_marked_category_is_credential(self):
        import credential_labels as CL
        CL.set_credential_categories(["密钥"])
        self.assertTrue(CL.is_credential("密钥"))
        self.assertTrue(CL.is_credential("API_KEY"), "内置集合不能被覆盖")
        self.assertFalse(CL.is_credential("人名"))

    def test_unmarked_category_is_not_credential(self):
        import credential_labels as CL
        self.assertFalse(CL.is_credential("密钥"))

    def test_set_replaces_not_appends(self):
        """配置热重载是整体替换：残留旧分类会让已删分类继续按凭据处理。"""
        import credential_labels as CL
        CL.set_credential_categories(["密钥", "密码表"])
        CL.set_credential_categories(["密码表"])
        self.assertFalse(CL.is_credential("密钥"))
        self.assertTrue(CL.is_credential("密码表"))

    def test_items_hide_original_for_marked_category(self):
        """端到端：标记后 items 里只有 preview + digest，没有 original。"""
        import credential_labels as CL
        CL.set_credential_categories(["密钥"])
        TR.CUSTOM_WORDS = {"测试丙": "密钥"}
        TR.SENSITIVE_DISABLED = set()
        TR.SENSITIVE_WORD_DISABLED = {}
        TR.SENSITIVE_WORD_WHOLE = set()
        TR._refresh_custom_words_sorted()
        TR._sync_custom_word_mappings()
        sid = "cred-cat"
        TR.sessions.pop(sid, None)
        try:
            TR.mask("口令测试丙", sid)
            items = TR._mask_event_items(sid)
            self.assertTrue(items, "应当产生明细项")
            item = items[0]
            self.assertTrue(item.get("cred"), "标记为凭据后必须带 cred 标记")
            self.assertNotIn("original", item, "凭据分类的原文不得出现在事件明细里")
            self.assertIn("digest", item)
        finally:
            TR.sessions.pop(sid, None)
            TR.CUSTOM_WORDS = {}

    def test_config_roundtrip_keeps_marker(self):
        """配置归一化必须保存标记，且只保留仍存在的分类。"""
        import panel
        cfg = panel.normalize_config({
            "sensitive": {"密钥": ["k1"], "人名": ["张三"]},
            "credential_categories": ["密钥", "已删除的分类"],
        })
        self.assertEqual(cfg["credential_categories"], ["密钥"])

    def test_config_accepts_dict_level_marker(self):
        """分类 dict 形态的 `credential: true` 与顶层列表等价。"""
        import panel
        cfg = panel.normalize_config({
            "sensitive": {"密钥": {"words": ["k1"], "credential": True}},
        })
        self.assertEqual(cfg["credential_categories"], ["密钥"])


if __name__ == "__main__":
    unittest.main()
