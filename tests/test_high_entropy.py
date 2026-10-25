"""高熵凭据检测（无前缀、无标签的随机串）。

## 为什么需要

现有凭据覆盖靠两条路：
1. **已知前缀**（`sk-` / `ghp_` / `hf_` …）：格式固定，零误报，但只覆盖厂商公开的形态；
2. **关键词锚点**（`password=` / `DB_PASSWORD=` …）：靠赋值标签，覆盖 `.env` 类场景。

**内部服务令牌**两条都不沾：一串 32~64 位的随机字母数字，出现在日志、配置、
工具输出里，既没有厂商前缀，也没有 `password=` 这样的标签。

参照 `CassiopeiaCode/CosyRedactGateway` 的「高熵凭据检测」：对符合条件的文本块做
统计评分，找「显著不像自然语言」的随机形态。

## 判据（三层，全部满足才算）

1. **形态**：≥ 20 个字符的 ASCII 字母数字块（不含分隔符）；
2. **字符多样性**：至少 3 类字符（大写 / 小写 / 数字），且非纯数字；
3. **交叉熵**：二元字符转移的交叉熵显著低于自然语言基线。

第 3 条是核心：Shannon 熵只看「字符分布均匀度」，`aaaaaaaaaaaaaaaaaaaa` 与
`9f8e7d6c5b4a39281706f5e4d3c2b1a0` 的分布不同，但 `abcdefghijklmnopqrst` 这种
**有序序列**分布均匀、Shannon 熵也高，却是典型的示例值。二元转移熵能区分它们：
有序序列的转移几乎确定（熵低），随机串的转移分散（熵高）。

## 为什么默认**关闭**

高熵检测的误报面取决于文本内容：base64 附件、minified JS、哈希文件名都会命中。
本仓没有足够多的真实样本做离线校准（见 `aiplatform/perf` 的校准脚本），
所以默认关，用户显式开启后**先走 `warn`**（只提醒），确认误报率可接受再考虑 mask。
"""
import json
import math
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


def _rand_token(n=32):
    """确定性的伪随机串（不用 random，避免测试不可复现）。"""
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    seed = 0x2F6E2B1
    out = []
    for i in range(n):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(alpha[(seed >> 8) % len(alpha)])
    return "".join(out)


class ShapeTests(unittest.TestCase):
    """形态判据。"""

    def test_module_helpers_exist(self):
        for name in ("_high_entropy_spans", "_high_entropy_on", "_HIGH_ENTROPY_MIN_LEN"):
            self.assertTrue(hasattr(tr, name), f"缺少 {name}")

    def test_disabled_by_default(self):
        """默认关：没有足够的真实样本做离线校准，开着等于让用户当小白鼠。"""
        self.assertFalse(tr._high_entropy_on(), "高熵检测默认必须是关的")

    def test_min_length(self):
        self.assertGreaterEqual(tr._HIGH_ENTROPY_MIN_LEN, 20,
                                "过短的门槛会让误报率爆炸")

    def test_short_token_is_ignored(self):
        spans = tr._high_entropy_spans("x " + _rand_token(12) + " y")
        self.assertEqual(spans, [], "短于门槛的串不该被检出")

    def test_pure_digits_are_ignored(self):
        spans = tr._high_entropy_spans("id " + "9" * 40)
        self.assertEqual(spans, [], "纯数字不该被当凭据（那是序号/时间戳）")

    def test_ordered_sequence_is_ignored(self):
        """有序序列是**示例值**的典型形态，不是凭据。"""
        for seq in ("abcdefghijklmnopqrstuvwxyz", "0123456789012345678901234567890123"):
            with self.subTest(seq=seq[:8]):
                self.assertEqual(
                    tr._high_entropy_spans("x " + seq + " y"), [],
                    f"有序序列被误判成凭据：{seq[:8]}…",
                )

    def test_random_token_is_detected(self):
        tok = _rand_token(32)
        text = "token " + tok + " end"
        spans = tr._high_entropy_spans(text)
        self.assertEqual(len(spans), 1, f"随机串未被检出：{tok}")
        s, e, label = spans[0]
        # 正则按「≥ 20 位的字母数字块」切分，所以区间可能比 tok 更长
        # （`token` 本身也是 5 位字母——不足 20 不会并进来，但紧邻的数字串会）。
        # 判据：tok 必须被完整覆盖，且区间内容必须是随机形态。
        self.assertIn(tok, text[s:e], "区间没有完整覆盖目标串")
        self.assertGreaterEqual(e - s, len(tok), "区间比目标串还短")
        self.assertEqual(label, "SECRET", "标签应为 SECRET")

    def test_natural_language_is_ignored(self):
        text = ("The quick brown fox jumps over the lazy dog. " * 3)
        self.assertEqual(tr._high_entropy_spans(text), [], "自然语言被误判")


class EntropyTests(unittest.TestCase):
    """交叉熵判据必须能区分随机串与有序/重复串。"""

    def test_bigram_entropy_helper_exists(self):
        self.assertTrue(hasattr(tr, "_bigram_entropy"), "缺少 `_bigram_entropy`")

    def test_random_has_higher_entropy_than_ordered(self):
        rand = tr._bigram_entropy(_rand_token(48))
        ordered = tr._bigram_entropy("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst")
        self.assertGreater(rand, ordered, "二元转移熵没能区分随机串与有序串")

    def test_repeated_char_has_low_entropy(self):
        self.assertLess(tr._bigram_entropy("a" * 40), 1.0, "重复串的熵应当接近 0")

    def test_entropy_of_empty_is_zero(self):
        self.assertEqual(tr._bigram_entropy(""), 0.0)


class IntegrationTests(unittest.TestCase):
    """接入：默认关 → 开了之后走 warn（不直接 mask）。"""

    CONFIG = {"sensitive": {}, "builtin_rules": {}}

    def setUp(self):
        self._saved = {
            k: getattr(tr, k)
            for k in ("CUSTOM_WORDS", "BUILTIN_RULES", "RULE_ACTIONS",
                      "HIGH_ENTROPY_ENABLED", "SENSITIVE_DISABLED",
                      "SENSITIVE_WORD_DISABLED", "SENSITIVE_WORD_WHOLE",
                      "UPSTREAMS", "TARGET_DOMAINS", "API_PATHS",
                      "CAPTURE_MODE", "FAIL_CLOSED", "_DATA_ROOT")
        }
        self._mtime = tr._cfg_mtime[0]
        self._dir = tempfile.mkdtemp(prefix="maskit-he-")
        with open(os.path.join(self._dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(
                dict(self.CONFIG, target_domains=["api.example.com"],
                     api_paths=["/v1/messages"]),
                fh, ensure_ascii=False,
            )
        tr._DATA_ROOT = Path(self._dir)
        tr._cfg_mtime[0] = None
        tr._maybe_reload(force=True)
        tr.BUILTIN_RULES = {k: False for k in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._cfg_mtime[0] = self._mtime
        shutil.rmtree(self._dir, ignore_errors=True)
        tr._known_reset_for_tests()

    def test_off_means_no_detection(self):
        tok = _rand_token(32)
        tr._new_session("he1")
        out = tr.mask(f"token {tok} end", "he1")
        self.assertIn(tok, out, "默认关时不该检出")

    def test_on_warns_but_does_not_mask_by_default(self):
        """开启后默认只提醒（不直接改写）——误报率未校准前不能替用户决定。"""
        tok = _rand_token(32)
        tr.HIGH_ENTROPY_ENABLED = True
        tr._new_session("he2")
        out = tr.mask(f"token {tok} end", "he2")
        self.assertIn(tok, out, "开启后默认应当只提醒、不改写")
        s = tr._session_get("he2", {})
        self.assertGreater(int(s.get("warned") or 0), 0, "未记 warn 计数")


if __name__ == "__main__":
    unittest.main()
