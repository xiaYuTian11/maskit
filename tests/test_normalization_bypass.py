"""输入归一化扫描（零宽 / 全角 / 变形字符绕过）。

## 为什么需要它

2026-10-25 隔离实例实测：同一批敏感值换一种「视觉等价」写法，规则**全部漏检**：

```
LEAK  138\u200b0013\u200b8000       （零宽空格插入）
LEAK  １３８００１３８０００         （全角数字）
LEAK  alice＠example.com            （全角 @）
LEAK  １１０１０１１９９００１０１１２３４（全角身份证）
```

而 `unicodedata.normalize("NFKC", ...)` 之后**全部命中** —— 说明缺的不是规则，
是**输入归一化**。这不是理论风险：用户从微信/Word/PDF 复制粘贴时，
全角标点与零宽字符是常态。

## 三条必须守住的契约

1. **归一化只用于「发现」，不用于「改写」**：发往上游的字节必须逐字节等于
   原文（除了被替换成占位符的那几段）。把全角改半角再发出去，等于擅自改动
   用户数据，而且会让上游看到用户从没输入过的文本。
2. **命中区间必须能映射回原文坐标**：归一化会改变字符数（全角→半角可能 1:1，
   但零宽删除是 1:0），所以必须建映射，不能用比例估算。
3. **还原必须逐字精确**：脱敏后再还原，结果必须与输入**逐字节相同**
   （含全角标点、零宽字符）。

## 实现选择

用「归一化视图 + 坐标映射表」而不是「把原文改写成归一化形态」：
- 视图只用于跑规则；
- 命中区间经映射反投回原文坐标；
- 替换发生在**原文**上。

映射表按「归一化后的每个字符对应原文的 [start, end)」建。零宽字符在归一化
视图里不存在，所以它们的原文区间不映射到任何视图位置——这正是我们要的
（零宽本身不该被替换，只影响它两侧的字符能否被规则看见）。
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

PHONE = "139" + "0" * 4 + "0123"          # 11 位，1[3-9] 开头，非全同
PHONE_FW = "".join(chr(ord(c) - ord("0") + ord("０")) for c in PHONE)


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    CONFIG = {"sensitive": {}, "builtin_rules": {"PHONE": True, "EMAIL": True}}

    def setUp(self):
        self._saved = {
            k: getattr(tr, k)
            for k in (
                "CUSTOM_WORDS", "BUILTIN_RULES", "SENSITIVE_DISABLED",
                "SENSITIVE_WORD_DISABLED", "SENSITIVE_WORD_WHOLE", "UPSTREAMS",
                "TARGET_DOMAINS", "API_PATHS", "CAPTURE_MODE", "FAIL_CLOSED",
                "_DATA_ROOT",
            )
        }
        self._mtime = tr._cfg_mtime[0]
        self._dir = tempfile.mkdtemp(prefix="maskit-norm-")
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                dict(
                    self.CONFIG,
                    target_domains=["api.example.com"],
                    api_paths=["/v1/messages"],
                ),
                fh,
                ensure_ascii=False,
            )
        tr._DATA_ROOT = Path(self._dir)
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        tr.BUILTIN_RULES = {k: False for k in tr.DEFAULT_BUILTIN_RULES}
        tr.BUILTIN_RULES.update({"PHONE": True, "EMAIL": True})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._cfg_mtime[0] = self._mtime
        shutil.rmtree(self._dir, ignore_errors=True)
        tr._known_reset_for_tests()

    def mask(self, text, sid="n1"):
        tr._new_session(sid)
        return tr.mask(text, sid)


class NormalizationUnitTests(_IsolatedCase):
    """归一化与坐标映射的单元契约。"""

    def test_normalize_helper_exists(self):
        self.assertTrue(
            hasattr(tr, "_normalize_view"),
            "缺少 `_normalize_view`（归一化视图 + 坐标映射的唯一入口）",
        )

    def test_view_is_nfkc_and_strips_zero_width(self):
        text = "１３８\u200b００１３"
        view, mapping = tr._normalize_view(text)
        self.assertNotIn("\u200b", view, "零宽字符未被剥离")
        self.assertIn("138", view, "全角数字未被 NFKC 归一")
        self.assertEqual(len(mapping), len(view), "映射表长度必须等于视图长度")

    def test_mapping_points_back_to_original(self):
        """视图里每个字符都要能映射回原文的一个非空区间。"""
        text = "a１b"
        view, mapping = tr._normalize_view(text)
        for i, (s, e) in enumerate(mapping):
            self.assertLess(s, e, f"视图第 {i} 位映射到空区间")
            self.assertLessEqual(e, len(text), "映射越界")
        # 视图里的 '1' 应当指向原文的全角 '１'
        idx = view.index("1")
        s, e = mapping[idx]
        self.assertEqual(text[s:e], "１", "映射指向了错误字符")

    def test_zero_width_does_not_break_neighbours(self):
        """零宽插在数字中间时，两侧字符在视图里必须相邻（这样才能被规则看见）。"""
        text = "138\u200b0013"
        view, _ = tr._normalize_view(text)
        self.assertEqual(view, "1380013", "零宽没被去掉，规则仍会被隔断")

    def test_normalization_is_idempotent_on_plain_ascii(self):
        """纯 ASCII 文本不该被改动（性能与正确性的前提）。

        `mapping is None` 是**契约的一部分**：它表示「视图 == 原文、坐标恒等」，
        调用方据此跳过映射（`_normalize_map_range` 对 None 直接返回原区间）。
        这比返回一张恒等表省下 len(text) 个 tuple——长会话里每个叶子都省。
        """
        text = "hello 13800138000 world"
        view, mapping = tr._normalize_view(text)
        self.assertIs(view, text, "纯 ASCII 不该产生新字符串")
        self.assertIsNone(mapping, "纯 ASCII 应返回 None 映射（表示恒等）")

    def test_map_range_on_identity_is_noop(self):
        """None 映射（恒等）时，反投必须原样返回区间。"""
        self.assertEqual(tr._normalize_map_range(None, 3, 7), (3, 7))


class PrecheckParityTests(unittest.TestCase):
    """预检正则必须与 NFKC 的「会变形」集合一致（穷举锁）。

    为什么必须有这条：`_DEFORMABLE_RX` 是「要不要建归一化视图」的**唯一**判据。
    漏一个字符就是一条视觉等价绕过（`²`→`2`、`𝐀`→`A`、`﹫`→`@`）。
    2026-10-25 复核时穷举扫出 **443 + 88** 个漏检字符，全部补齐后由本用例钉住。

    刻意排除 U+3200-33FF（中文兼容方块 `㍱` 等）：它们 NFKC 后变成汉字词组而非
    数字/符号，对规则命中无影响；收了只会让中文文本白建视图（那是 243ms/MB 的来源）。
    """

    # 排除段（与 `_DEFORMABLE_RX` 的注释一一对应）
    EXCLUDED = ((0x3200, 0x33FF),)

    def _excluded(self, cp):
        return any(lo <= cp <= hi for lo, hi in self.EXCLUDED)

    def test_no_deformable_char_is_missed(self):
        import unicodedata

        missed = []
        # BMP + 补充平面到 U+1FFFF（数学字母/带圈字母都在这一段）
        for cp in list(range(0x20, 0x10000)) + list(range(0x10000, 0x20000)):
            if self._excluded(cp):
                continue
            ch = chr(cp)
            norm = unicodedata.normalize("NFKC", ch)
            if norm == ch:
                continue
            # 只关心「NFKC 后会变成 ASCII 字母/数字/规则相关符号」的字符
            if not any(c.isascii() and (c.isalnum() or c in "@:=.-_/+") for c in norm):
                continue
            if not tr._DEFORMABLE_RX.match(ch):
                missed.append((hex(cp), ch, norm))
        self.assertEqual(
            missed[:10], [],
            f"预检漏掉 {len(missed)} 个会变形的字符（每条都是绕过路径）：{missed[:10]}",
        )

    def test_chinese_without_colon_does_not_trigger_view(self):
        """不含**全角冒号**的中文正文不该触发视图 —— 性能前提。

        为什么允许 `：` 触发：它是 SECRET 规则的分隔符（`密码：xxx`），
        NFKC 后会变半角 `:`，不收它就直接漏掉中文凭据场景。
        代价是含 `：` 的中文段落会建一次视图；而中文正文里 `：` 的密度远低于
        普通汉字，所以这是可接受的（实测含冒号的中文 1MB 归一化 <5ms）。
        """
        text = "这是一段普通中文，包含全角标点！？（）、以及「引号」。"
        self.assertIsNone(tr._normalize_view(text)[1],
                          "不含全角冒号的中文触发了归一化视图（会让每段中文都白建映射表）")

    def test_chinese_with_colon_triggers_view(self):
        """含全角冒号的中文**必须**触发（否则 `密码：xxx` 漏检）。"""
        text = "数据库密码：Abc123456"
        self.assertIsNotNone(tr._normalize_view(text)[1],
                             "含全角冒号的中文没触发视图，SECRET 规则会漏检")


class ValidatorParityTests(_IsolatedCase):
    """归一化补充扫描必须与主扫描用**同一套**值校验（2026-10-26 真机 503 的根因）。

    缺一个校验就是「第二套口径」：归一化路径比主路径宽松，于是同一段文本仅因为
    含变形字符（全角数字 / 零宽）就遮了主路径明确拒绝的值 —— 环回地址
    `127.0.0.1` 被当 IP_PUBLIC 遮掉，而纯 ASCII 叶子按 `_ip_public_ok` 不遮。
    出口复检于是看到「登记过但没遮」的残留 → 真机 12 条 503。

    本用例用 AST 读源码比对两处的校验集合，任何一个分支缺失就红 —— 靠行为断言
    覆盖不全（某些 label 需要特定开关与特定形态才会触发）。
    """

    def _validator_labels(self, block):
        """从代码块里抽出被校验的 label 集合。

        用正则而不是 AST：抽出来的是**片段**（从 `for` 循环到某个注释），
        独立 parse 会因缩进不完整报 IndentationError。判据足够窄 ——
        `<name> == "LABEL"` 且 name 必须是 `label` 或 `_lbl`（两处循环变量名）。
        """
        import re
        return set(re.findall(r'\b(?:label|_lbl)\s*==\s*"([A-Z0-9_]+)"', block))

    def test_normalize_scan_validators_match_main_scan(self):
        import re
        src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        # 主扫描块：必须锚到**主扫描那个** `for rx, label, group_idx in RULES:`。
        # 源码里这个循环头出现两次（复检的 `_mask_egress_label_matchers` 也用它），
        # 靠 `_rule_may_hit(text, label)` 区分。右界收在 `if matched:`（循环体末尾）——
        # 用「按唯一原文替换」会一路吃到后面几个函数的文档注释，把
        # `PRIVATE_KEY  只给密钥类型（RSA/EC/OPENSSH）` 这类散文误判成校验分支
        # （本用例第一版就是这么误报的）。
        m1 = re.search(
            r"for rx, label, group_idx in RULES:\s*\n\s*if not _rule_enabled\(label\):"
            r".*?\n        if matched:", src, re.S)
        self.assertIsNotNone(m1, "没找到主扫描块（源码结构变了，请同步本用例）")
        # 归一化补充扫描块
        m2 = re.search(r"归一化补充扫描（2026-10-25.*?text = _mask_by_spans\(text, _norm_spans\)",
                       src, re.S)
        self.assertIsNotNone(m2, "没找到归一化补充扫描块（源码结构变了，请同步本用例）")
        main = self._validator_labels(m1.group(0))
        norm = self._validator_labels(m2.group(0))
        self.assertTrue(main, "主扫描没解析出任何校验分支？AST 判据是不是失配了")
        self.assertEqual(
            sorted(main - norm), [],
            "归一化补充扫描缺少这些 label 的值校验（第二套口径 → 出口复检误判 503）：%s"
            % sorted(main - norm),
        )

    def test_loopback_ip_is_not_masked_even_with_deformable_chars(self):
        """行为侧反证：含全角字符时环回地址仍不该被当公网 IP 遮掉。"""
        old = tr.BUILTIN_RULES
        try:
            rules = dict(old)
            rules["IP_PUBLIC"] = True
            tr.BUILTIN_RULES = rules
            tr._new_session("vp1")
            out = tr.mask("全角１２３ 与 127.0.0.1 同时出现", "vp1")
            self.assertNotIn("{{IPPUBLIC_", out,
                             "环回地址在归一化路径被当公网 IP 遮了（与主扫描口径不一致）")
        finally:
            tr.BUILTIN_RULES = old


class BypassDetectionTests(_IsolatedCase):
    """绕过形态必须被抓住。"""

    def test_zero_width_phone_is_masked(self):
        text = f"回拨 {PHONE[:3]}\u200b{PHONE[3:]}"
        out = self.mask(text)
        self.assertIn("{{PHONE_", out, f"零宽插入绕过未修：{out!r}")

    def test_fullwidth_phone_is_masked(self):
        text = f"回拨 {PHONE_FW}"
        out = self.mask(text)
        self.assertIn("{{PHONE_", out, f"全角数字绕过未修：{out!r}")

    def test_fullwidth_at_email_is_masked(self):
        text = "联系 " + "alice" + "＠" + "example.com"
        out = self.mask(text)
        self.assertIn("{{EMAIL_", out, f"全角 @ 绕过未修：{out!r}")


class RewriteFidelityTests(_IsolatedCase):
    """最重要的契约：归一化**不许改动**发往上游的字节（除占位符那几段）。"""

    def test_untouched_text_keeps_original_bytes(self):
        """没命中的文本必须逐字节原样返回（含全角标点与零宽字符）。"""
        text = "这是一段没有敏感值的文本，全角标点：！？　以及零宽\u200b字符"
        out = self.mask(text)
        self.assertEqual(out, text, "未命中文本被归一化改动了")

    def test_masked_text_preserves_surrounding_characters(self):
        """命中时只替换值本身，两侧的全角/零宽字符必须原样保留。"""
        text = f"电话：{PHONE_FW}　谢谢！"
        out = self.mask(text)
        self.assertIn("{{PHONE_", out)
        self.assertIn("电话：", out, "前缀被改动")
        self.assertIn("　谢谢！", out, "全角空格/后缀被改动")

    def test_roundtrip_is_byte_exact(self):
        """脱敏 → 还原必须逐字节等于输入（含全角、零宽）。"""
        for i, text in enumerate([
            f"电话：{PHONE_FW}",
            f"回拨 {PHONE[:3]}\u200b{PHONE[3:]}",
            "联系 alice＠example.com 谢谢",
        ]):
            with self.subTest(case=i):
                sid = f"n-rt{i}"
                masked = self.mask(text, sid)
                self.assertNotEqual(masked, text, f"未命中：{text!r}")
                self.assertEqual(
                    tr.restore_final(masked, sid), text,
                    f"还原不逐字节：{text!r}",
                )

    def test_zero_width_inside_value_is_replaced_with_it(self):
        """零宽在值**内部**时必须跟着值一起被替换（它属于值，不属于排版）。

        这是有意的：`139\u200b0013...` 整体就是那个手机号，只替换数字部分会
        留下一个孤立的零宽字符，还原时还会把它吐回去（= 原文被改动）。
        与之相对：值**外部**的零宽/全角必须原样保留（见下一个用例）。
        """
        text = f"电话 {PHONE[:5]}\u200b{PHONE[5:]} 结束"
        out = self.mask(text)
        self.assertIn("{{PHONE_", out)
        self.assertNotIn("\u200b", out.split("{{PHONE_")[0][-3:],
                         "值前面的零宽被吞掉（那是排版，不属于值）")

    def test_zero_width_outside_value_is_preserved(self):
        """值外部的零宽必须原样保留（它是用户原文的一部分）。"""
        text = f"电话\u200b {PHONE} 结束"
        out = self.mask(text)
        self.assertIn("\u200b", out, "值外部的零宽被吞掉（原文被改动了）")


class PerformanceGuardTests(_IsolatedCase):
    """归一化不能成为新的性能悬崖。"""

    def test_normalization_is_linear(self):
        import time
        small = "a１b２c" * 100
        big = "a１b２c" * 1000
        t0 = time.perf_counter()
        tr._normalize_view(small)
        t_small = time.perf_counter() - t0
        t0 = time.perf_counter()
        tr._normalize_view(big)
        t_big = time.perf_counter() - t0
        # 10 倍长度不该超过 40 倍耗时（留足解释器噪声余量）
        self.assertLess(t_big, max(t_small * 40, 0.05), "归一化疑似超线性")

    def test_ascii_fast_path_skips_normalization(self):
        """纯 ASCII 必须走快路径（长会话里绝大多数叶子是 ASCII 或纯中文）。"""
        text = "x" * 10000
        view, mapping = tr._normalize_view(text)
        self.assertIs(view, text, "纯 ASCII 没有走快路径（多了一次全量拷贝）")


if __name__ == "__main__":
    unittest.main()
