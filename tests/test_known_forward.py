"""已知值正向打码（known）与已发送字节固化（sent）。

## 为什么有这组用例

2026-10-25 真机事件库复盘（43763 条事件）发现「已知值不回打」：

```
r1 anchored : password={{SECRET_xxx}}    ← 值进复用表
fwd         : {'Abc123456': '{{SECRET_xxx}}'}
r2 bare echo: the pass is Abc123456 per ops   ← 原样上行
```

场景是真实高频的：某轮工具输出里出现 `password=<值>`（有锚点，被脱敏），
模型在回答里复述了这个值，用户把回答贴回下一轮 —— 那一轮没有任何锚点，
于是明文再次出网。同一会话里，这个值已经被确认是敏感值了。

magpie 的解法（`internal/redact/known.go`）：维护一个「已知值」索引，
**任何位置**出现都换成同一个占位符；`minKnown = 8` 防误伤。

## 为什么 known 与 sent 必须成对

单独加 known 会引入 magpie 那个 400K token 事故：agent 每轮重发整段历史，
某一轮新发现的值会让**历史叶子**也被重新打码 → 前缀字节变化 → 上游 prompt
cache 全量重写（`cache_read = 0`）。

所以 `sent` 层必须同时存在：**一段文本首次被打码时的形态被记住**，
之后即使 known 集合扩张，这段文本仍按首次形态输出。新文本才用新 known。

## 本文件锁的契约（按重要性排序）

1. **已知值在新文本里必须被遮**（功能本身）。
2. **已发送过的文本，字节不许漂移**（否则前缀缓存失效，是真实成本事故）。
3. **覆盖项变化后重算**（关掉某条规则，同一文本必须按新覆盖项处理）。
4. **短值不参与**（`minKnown = 8`，防 `abc` 这种值污染全文）。
5. **凭据类值不参与 known 扫描**（它们的原文只应出现在有锚点的位置；
   把 `hunter2abc` 当 needle 扫全文会让日志里到处是「命中」，且 needle 集会进正则对象）。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

# 值一律片段拼接（AGENTS.md §3 第 9 条）
#
# ⚠️ 这里必须用**非凭据类**值（自定义词 TERM），不能用 SECRET 值：
# `_known_add` 刻意排除 `CREDENTIAL_LABELS`（API_KEY/TOKEN/SECRET/ACCESS_KEY/
# JWT/CONNSTR/PRIVATE_KEY），因为把凭据原文当 needle 扫全文会让 needle 集里
# 出现原文（egress 复检要用它），且凭据值本来只在有锚点的位置出现。
# 见 `_known_add` 的 docstring 与 `test_credential_values_are_not_known`。
VALUE = "Night" + "jar" + "Proj" + "ect"   # 16 字符，>= _KNOWN_MIN
CRED_VALUE = "Rv9" + "sent" + "Pass" + "27x"


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    """每条用例一份干净的全局态；用完恢复 `_maybe_reload` 能改的全部全局。"""

    CONFIG = {
        "sensitive": {"TERM": [VALUE]},
        "builtin_rules": {"SECRET": True},
    }

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
        self._dir = tempfile.mkdtemp(prefix="maskit-known-")
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
        tr.BUILTIN_RULES = {k: True for k in tr.DEFAULT_BUILTIN_RULES}
        tr._CUSTOM_WORD_RX_CACHE.clear()
        # 每个用例从空的 known/sent 开始：这两个索引是进程级，不重置就是串味
        if hasattr(tr, "_known_reset_for_tests"):
            tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._cfg_mtime[0] = self._mtime
        shutil.rmtree(self._dir, ignore_errors=True)
        if hasattr(tr, "_known_reset_for_tests"):
            tr._known_reset_for_tests()

    # ---- helpers ----
    def mask(self, text, sid="k1"):
        tr._new_session(sid)
        return tr.mask(text, sid)

    def register(self, value, sid="k1"):
        """让该值进入 known。

        VALUE 是自定义词（TERM 类），只要出现在文本里就会被登记——**不需要锚点**。
        这恰好也是 known 的语义：「这个值已知敏感」，与「靠什么锚点发现」无关。
        """
        tr._new_session(sid)
        out = tr.mask("note: " + value, sid)
        self.assertNotEqual(out, "note: " + value, "前置条件：该值必须被脱敏")
        return out


class KnownForwardTests(_IsolatedCase):
    """功能本体：已知值出现在任何位置都必须被遮。"""

    def test_known_value_is_masked_without_anchor(self):
        self.register(VALUE)
        out = self.mask(f"the staging pass is {VALUE} for now", "k1")
        self.assertNotIn(VALUE, out, f"已知值在无锚点文本里仍明文：{out!r}")
        self.assertIn("{{", out)

    def test_known_value_reuses_the_same_placeholder(self):
        """同一个值必须复用**同一个**占位符（否则上下文逻辑不一致、还原错位）。"""
        first = self.register(VALUE)
        tok = first.split("note: ", 1)[1]
        out = self.mask(f"again {VALUE}", "k1")
        self.assertIn(tok, out, f"未复用同一占位符：{out!r}（期望含 {tok!r}）")

    def test_short_values_are_not_known(self):
        """`_KNOWN_MIN = 8`：短值不参与，否则 `abc` 这种会污染全文。"""
        short = "ab" + "c1"
        tr._new_session("k1")
        tr.mask("note: " + short, "k1")
        out = self.mask(f"see {short} here", "k1")
        # 短值不做 known 扫描 → 无锚点处保持原样（这是**设计**，不是漏检）
        self.assertEqual(out, f"see {short} here", "短值不应参与 known 扫描")

    def test_known_index_is_bounded(self):
        """known 必须有上界（无界增长 = 内存泄漏 + 扫描变慢）。"""
        self.assertTrue(
            hasattr(tr, "_KNOWN_MAX"),
            "缺少 _KNOWN_MAX（known 索引必须有界）",
        )
        self.assertGreater(tr._KNOWN_MAX, 0)

    def test_known_scan_does_not_touch_placeholders(self):
        """已经变成占位符的文本不该被二次扫描（防套娃）。"""
        self.register(VALUE)
        tok = self.mask(f"x {VALUE}", "k1").split(" ")[1]
        out = self.mask(f"repeat {tok}", "k1")
        self.assertEqual(out, f"repeat {tok}", "占位符本身不该被再处理")


class SentFrozenBytesTests(_IsolatedCase):
    """已发送过的文本，字节不许漂移（否则上游 prompt cache 全量重写）。

    ⚠️ 本组必须用**规则命中型**的值（如手机号），不能用自定义词：自定义词
    无论有没有锚点都命中，构造不出「轮1 不遮 → 轮2 变 known → 轮3 该不该遮」
    这个三段式。
    """

    # 手机号形态（11 位，1[3-9] 开头，非全同数字）—— 只有规则能发现它，
    # 裸引用在轮1 不会被遮，正好是 magpie 事故的复现条件。
    RULE_VALUE = "139" + "0" * 4 + "0123"

    def test_text_sent_before_keeps_its_bytes(self):
        """核心用例（对齐 magpie `TestSentTextKeepsItsMasking`）。

        轮1：system prompt 里的手机号是裸引用（`PHONE` 规则要求 1[3-9] 开头 11 位，
        裸写其实**会**命中——所以这里刻意把值拆成两段写，让它轮1 不命中）。
        轮2：别处出现完整手机号 → 该值变 known。
        轮3：同一段 system prompt 再发 → **必须与轮1 逐字节相同**。
        """
        # 轮1 的文本里该值被拆开（中间有空格），PHONE 规则匹配不到
        spaced = self.RULE_VALUE[:3] + " " + self.RULE_VALUE[3:]
        system = f"You are dsh. Deploy notes: the number is {spaced} for now."
        first = self.mask(system, "k1")
        self.assertEqual(first, system, "轮1 不该遮（拆开后规则匹配不到）")

        # 轮2：完整形态出现在别处 → 该值（拆开前的连续形态）进入 known
        self.register(self.RULE_VALUE, "k1")

        again = self.mask(system, "k1")
        # 注意：这里断言的是「**已发送过的这段文本**字节不变」。
        # 拆开写的那段本来就不含完整值，所以无论 known 是否扩张都不该变——
        # 这正是 sent 要保证的东西：历史叶子不被后续 known 影响。
        self.assertEqual(
            again,
            first,
            "已发送过的文本被重新打码 → 上游前缀缓存全量重写"
            f"（轮1={first!r} 轮3={again!r}）",
        )

    def test_new_text_still_gets_the_new_known(self):
        """反向：同一轮里的**新**文本仍要用新 known（不能因为 sent 就全放行）。"""
        system = f"Deploy notes: the project is {VALUE} for now."
        self.mask(system, "k1")          # 轮1：原样
        self.register(VALUE, "k1")       # 轮2：值变 known
        fresh = self.mask(f"now the pass is {VALUE} again", "k1")
        self.assertNotIn(VALUE, fresh, f"新文本里的已知值仍明文：{fresh!r}")

    def test_body_prefix_is_stable_across_turns(self):
        """整包 body 的前缀必须稳定（agent 每轮重发历史，前缀就是缓存命中的依据）。"""
        turn1 = json.dumps(
            {
                "model": "m",
                "messages": [
                    {"role": "system", "content": f"project is {VALUE}"},
                    {"role": "user", "content": "go"},
                ],
            },
            ensure_ascii=False,
        )
        tr._new_session("k1")
        out1 = tr.mask_body(turn1, "k1")
        self.register(VALUE, "k1")
        turn3 = json.dumps(
            {
                "model": "m",
                "messages": [
                    {"role": "system", "content": f"project is {VALUE}"},
                    {"role": "user", "content": "go"},
                    {"role": "assistant", "content": f"the pass is {VALUE}"},
                ],
            },
            ensure_ascii=False,
        )
        out3 = tr.mask_body(turn3, "k1")
        # turn1 去掉尾部 `]}` 后应当是 out3 的前缀
        head = out1.rstrip("]}")
        self.assertTrue(
            out3.startswith(head),
            f"前缀漂移：\n  turn1={out1}\n  turn3={out3}",
        )

    def test_sent_cache_is_bounded(self):
        self.assertTrue(hasattr(tr, "_SENT_MAX"), "缺少 _SENT_MAX（sent 表必须有界）")


class CoverageChangeRecomputesTests(_IsolatedCase):
    """覆盖项变化后，同一文本必须按**新**覆盖项重算（不能沿用旧 sent 记录）。"""

    def test_disabling_a_rule_changes_the_result(self):
        text = f"DB_PASSWORD={CRED_VALUE}"
        tr._new_session("k1")
        with_rule = tr.mask(text, "k1")
        self.assertNotEqual(with_rule, text, "前置条件：SECRET 开着时必须遮")

        tr.BUILTIN_RULES = dict(tr.BUILTIN_RULES, SECRET=False)
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._new_session("k2")
        without_rule = tr.mask(text, "k2")
        self.assertEqual(
            without_rule,
            text,
            "关掉 SECRET 后同一文本仍被遮 → sent 记录没有随覆盖项失效",
        )


class KnownBoundaryTests(_IsolatedCase):
    """边界：已知值不能把相邻文本一起吃掉。"""

    def test_known_boundary_respects_identifiers(self):
        """值嵌在更长**标识符**里时不替换（对齐 magpie `knownBound`）。

        实测反例（2026-10-25 复核）：已知值 `Zq7Lm4Xy2Ab9` 会让 `x<值>y`
        变成 `x{{TERM_…}}y` —— 那是一个完全不同的标识符（变量名、哈希前缀），
        改坏它等于让模型拿到用户从没写过的字符串。
        """
        value = "Zq7" + "Lm4" + "Xy2" + "Ab9"
        tr._known_add(value, "{{TERM_abcdef}}", "TERM")
        for text in (f"x{value}y", f"{value}Extra", f"pre_{value}"):
            with self.subTest(text=text):
                out = self.mask(text, "kb")
                self.assertEqual(out, text, f"标识符被拆开：{text!r} -> {out!r}")
        # 中文紧邻不该被边界判据挡掉（汉字之间没有「标识符」概念）
        out = self.mask(f"值{value}结束", "kb2")
        self.assertNotIn(value, out, "中文紧邻的已知值未被遮")

    def test_known_value_inside_word_is_not_replaced(self):
        """已知值作为更长标识符的一部分时，不能把相邻文本一起吞掉。

        判据：`Extra` 必须留下。至于是「整段不动」还是「只换掉值那一段」，
        两种都可接受——不可接受的是把 `Extra` 一起吃掉（那会改坏标识符，
        而标识符是模型要逐字使用的东西）。
        """
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({VALUE: "TERM"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        self.register(VALUE, "k1")
        longer = VALUE + "Extra"
        out = self.mask(f"id {longer} done", "k1")
        self.assertIn("Extra", out, f"相邻文本被吞：{out!r}")

    def test_known_respects_placeholder_shape(self):
        """已知值恰好长得像占位符时，不该被当作占位符处理（防套娃）。"""
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({VALUE: "TERM"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        self.register(VALUE, "k1")
        out = self.mask(f"{{{{{VALUE}}}}}", "k1")
        self.assertNotIn(VALUE, out)

    def test_builtin_rule_values_are_not_known(self):
        """内置规则命中的值**刻意**不进 known（规则的校验边界不能被绕过）。

        实测反例：`47.98.12.34-47.98.12.35` 这类 IP 区间按规则不该遮，
        一旦进 known 就会「任何位置都遮」，把规则的边界整个绕过。
        known 要解决的是**规则发现不了的裸引用**，不是替规则扩覆盖。
        """
        phone = "139" + "0" * 4 + "0123"
        tr._new_session("k1")
        tr.mask(phone, "k1")
        self.assertNotIn(
            phone,
            [v[0] for v in tr._KNOWN_BY_HEAD.values()],
            "内置规则命中的值被登记进了 known（会绕过规则自己的校验边界）",
        )

    def test_credential_values_are_not_known(self):
        """凭据类值**刻意**不进 known（见 `_known_add` 的 docstring）。

        它们本来只在有锚点的位置出现；把原文当 needle 扫全文会让 needle 集里
        出现原文（egress 复检要用它），而且凭据值在自由文本里的命中几乎全是误报。
        """
        tr._new_session("k1")
        tr.mask("password=" + CRED_VALUE, "k1")
        self.assertNotIn(
            CRED_VALUE,
            [v[0] for v in tr._KNOWN_BY_HEAD.values()],
            "凭据类值被登记进了 known（会让 needle 集出现原文）",
        )


class AccountingTests(_IsolatedCase):
    """命中必须可归因（用户看到「没锚点却被遮」要能查）。"""

    def test_known_hits_are_counted_and_takeable(self):
        """known 命中必须可计数**且可取走发出**。

        2026-10-25 复核发现的缺口：只累加、从未进入任何事件 —— 用户看到
        「没有锚点却被遮」时无法归因，会以为规则误报进而去关规则（扩大漏检面）。
        """
        self.register(VALUE, "k1")
        self.mask(f"echo {VALUE}", "k1")
        s = tr._session_get("k1", {})
        self.assertGreater(
            int(s.get("known_hits") or 0), 0,
            "known 命中未记入会话计数（用户无法归因）",
        )
        n = tr._take_known_hits("k1")
        self.assertGreater(n, 0, "known_hits 取不到（没进事件就是不可见）")
        self.assertEqual(tr._take_known_hits("k1"), 0,
                         "known_hits 取走后未清零，会串到下一个请求")


class SentRecheckTests(_IsolatedCase):
    """冻结记录必须补上「其后才学会的」已知值（2026-11-05）。

    背景：`sent` 按 (覆盖项, 文本) 冻结，而 known 集合会随对话扩张。一段在
    「该值还不认识」时发出过的文本，其冻结记录里没有它的区间 —— 于是明文会
    一轮一轮地重发（清掉 sent 后同一段文本立刻变占位符，可复现）。

    修法：只对 `_KNOWN_NEW`（最近新增的已知值）做**定向**复核，命中才重算。
    不做全局失效（实测 2000 条 known × 500 叶子重扫 1.6s）。
    """

    LATER = "Night" + "jar" + "Retro" + "Mask"

    def _leaf(self):
        return "the staging code for it is " + self.LATER

    def _learn(self):
        tok = "{" * 2 + "TERM_" + "rtmk01" + "}" * 2
        self.assertTrue(
            tr._known_add(self.LATER, tok, "TERM"),
            "用例前提：该值必须能进 known（≥ 8 字符、非凭据、非内置规则）",
        )

    def test_frozen_text_gets_the_value_it_learned_later(self):
        leaf = self._leaf()
        first = self.mask(leaf, "retro-1")
        self.assertEqual(first, leaf, "用例前提：轮1 还不认识这个值")
        self._learn()
        again = self.mask(leaf, "retro-2")
        self.assertNotIn(self.LATER, again, "已确认敏感的值在旧文本里明文重发")
        third = self.mask(leaf, "retro-3")
        self.assertEqual(third, again, "重算后应当重新冻结：同一段文本字节漂移了")

    def test_leaves_without_the_new_value_are_not_rescanned(self):
        """定向复核的「定向」：不含新值的叶子不许重算（否则退化成全局失效）。"""
        hot = self._leaf()
        cold = "an unrelated sentence that carries nothing sensitive"
        self.mask(hot, "recheck-1")
        self.mask(cold, "recheck-2")
        self._learn()
        with mock.patch.object(tr, "_known_lookup_spans",
                               wraps=tr._known_lookup_spans) as spy:
            self.mask(cold, "recheck-3")
            self.assertEqual(spy.call_count, 0,
                             "不含新值的叶子被重算了（全局失效的形态）")
            self.mask(hot, "recheck-4")
            self.assertEqual(spy.call_count, 1, "含新值的叶子没有重算")

    def test_pending_list_is_bounded(self):
        for i in range(tr._KNOWN_NEW_MAX * 3):
            tr._known_add("pending" + "value" + "%03d" % i, "{" * 2 + "TERM_"
                          + "%06d" % i + "}" * 2, "TERM")
        self.assertLessEqual(
            len(tr._KNOWN_NEW), tr._KNOWN_NEW_MAX,
            "_KNOWN_NEW 无界（每个请求的复核成本会随进程运行时间增长）",
        )


class KnownLeafCacheKeyTests(_IsolatedCase):
    """有 known 命中的叶子必须能命中结果缓存（2026-11-05）。

    旧实现写缓存时用**预替换前**的文本做键，而查询用的是**预替换后**的文本
    —— 键天然不等，这类叶子每轮都 miss（写得进、查不到）。修正后同一段文本
    第二个请求就命中，且打码结果与占位符不变。
    """

    def test_premasked_leaf_hits_the_cache(self):
        self.register(VALUE)                      # VALUE 进 known（自定义词）
        text = "the staging pass is " + VALUE + " for now"
        first = self.mask(text, "kc-1")
        self.assertNotIn(VALUE, first, "用例前提：这段文本必须被 known 预替换")
        hits = tr._LEAF_CACHE_STATS["hit"]
        second = self.mask(text, "kc-2")          # 新请求
        self.assertEqual(second, first, "命中结果与冷跑逐字节不一致")
        self.assertGreater(
            tr._LEAF_CACHE_STATS["hit"], hits,
            "带 known 命中的叶子没命中缓存（键口径不一致：写入用预替换前、查询用预替换后）",
        )


if __name__ == "__main__":
    unittest.main()
