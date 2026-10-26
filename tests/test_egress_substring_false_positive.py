"""出口复检的子串误报（2026-10-26 真机 12 条 503 的根因）。

## 现象

v0.12.0 上线后，用户在真机上连续收到 `503 {"code":"shield_egress_unmasked"}`，
客户端「重试 5 次仍失败」。事件库里 09:41~09:43 共 12 条 `reason=egress_verify`
的 BLOCK，全部是同一种形态。

## 根因

`_mask_egress_verify` 的判据是**精确子串比对**：needle 是「本轮确实被遮过的原文」，
只要它在脱敏后的字节里**以任何形态再出现一次**就阻断。

但同一个原文出现在别处时，形态可能**本来就是规则主动拒绝的**：

| 原文（needle） | 别处的形态 | 规则为什么拒绝 |
|---|---|---|
| `139…5050`（11 位） | `139…50501`（12 位） | `ID_BOUND_R` 要求右侧非字母数字，`1` 不满足 |
| 同上 | `ID139…5050X` | `ID_BOUND_L` 要求左侧非字母数字，`D` 不满足 |
| `xia…@users.noreply.github.com` | 同上 + 结尾 `.` | EMAIL 的右边界排除 `.` |
| `user@<host>.service` | `https://user@<host>.service…` | 同上（`.` 结尾） |

这些是规则**看过并明确决定不遮**的位置 —— 原文子串残留是规则的正常输出，
不是漏检。把它们判成泄漏，等于让「AI 在正文里讨论过某个号码」这件事本身
把请求打成 503（真机就是这样：模型在分析文本里写了 `139…50501` 这个 12 位示例）。

## 修法

复检必须与**扫描规则同口径**：needle 的每个出现位置，用该 needle 的 label
对应的规则去复判那个位置 —— 规则在该位置会匹配并遮住它，才算「该遮没遮」。

- 内置规则标签（PHONE / EMAIL / CARD / IDCARD …）→ 规则 + 值校验复判；
- 非内置标签（自定义词 TERM / 编号 / 密级、NER 的 NAME / ORG / ADDR）→
  它们的语义本来就是**无边界子串匹配**，精确子串命中即泄漏（保持不变）。

## 必须同时守住的边界

1. 真泄漏仍然被抓（同一值在别处**明文完整出现**）。
2. 凭据类不进 needle（既有契约）。
3. 豁免块剔除（签名思考块）仍然生效。
4. 成本不失控：命中位置通常只有几十处，且先用子串定位再复判。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

# 片段拼接（AGENTS.md §3 第 9 条）：不写字面量，免得落盘/读回被网关改写
PHONE = "139" + "9682" + "5050"          # 11 位，合法手机号形态
PHONE_12 = PHONE + "1"                    # 12 位，PHONE 规则必然拒绝
PHONE_ID = "ID" + PHONE + "X"             # 字母边界，PHONE 规则必然拒绝
MAIL = "user" + "@" + "1000.service"
MAIL_DOT = MAIL + "."                     # 结尾点，EMAIL 右边界排除 `.`
CUSTOM_TERM = "Night" + "jar" + "Proj" + "ect"


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    """每个用例独立的会话 + known 表（与 test_egress_verify.py 同口径）。"""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="maskit-egress-fp-")
        self._old = getattr(tr, "_DATA_DIR", None)
        try:
            tr._DATA_DIR = self._dir
        except Exception:
            pass
        tr._known_reset_for_tests()
        tr._egress_preview_reset()
        tr.sessions.clear()

    def tearDown(self):
        tr.sessions.clear()
        tr._known_reset_for_tests()
        if self._old is not None:
            try:
                tr._DATA_DIR = self._old
            except Exception:
                pass

    def _run(self, sid, contents):
        """把 contents 逐条作为 user 消息塞进一次 mask_body，返回 (脱敏后文本, needles)。"""
        tr._new_session(sid)
        body = {"model": "m",
                "messages": [{"role": "user", "content": c} for c in contents]}
        out = tr.mask_body(json.dumps(body, ensure_ascii=False), sid)
        sess = tr._session_get(sid, {}) or {}
        needles = tr._mask_egress_needles(
            sess.get("fwd") or {}, sess.get("labels") or {},
            sess.get("new_orig") or set())
        return out, needles


class SubstringFalsePositiveTests(_IsolatedCase):
    """规则主动拒绝的形态**不是**泄漏（真机 503 的根因）。"""

    def test_longer_digit_run_is_not_a_leak(self):
        """needle 落在更长的数字串里（12 位）：PHONE 规则已拒绝，不算泄漏。"""
        out, needles = self._run("fp1", [f"号码 {PHONE}", f"id: {PHONE_12}"])
        self.assertIn(PHONE, needles, "前置条件：号码应当被登记为 needle")
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "fp1"),
            "12 位数字里的 11 位子串被误判成泄漏 → 真机 503",
        )

    def test_alpha_bounded_digits_are_not_a_leak(self):
        """needle 被字母包住（ID…X）：PHONE 左/右边界都不满足，不算泄漏。"""
        out, needles = self._run("fp2", [f"号码 {PHONE}", f"ID: {PHONE_ID}"])
        self.assertIn(PHONE, needles)
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "fp2"),
            "字母包住的号码被误判成泄漏",
        )

    def test_email_followed_by_dot_is_not_a_leak(self):
        """needle 后紧跟 `.`：EMAIL 右边界排除 `.`，不算泄漏。"""
        out, needles = self._run("fp3", [f"邮箱 {MAIL}", f"见 {MAIL_DOT}"])
        self.assertIn(MAIL, needles)
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "fp3"),
            "邮箱后跟句点被误判成泄漏",
        )

    def test_value_inside_code_fence_is_not_a_leak(self):
        """真机实际形态：模型在分析正文里用反引号讨论号码。"""
        out, needles = self._run(
            "fp4",
            [f"我的号码 {PHONE}",
             f"讨论一下：`{PHONE_12}`（12 位）与 `ID{PHONE}X` 这两种形态"],
        )
        self.assertIn(PHONE, needles)
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "fp4"),
            "正文里讨论过的号码形态被误判成泄漏（真机 09:41~09:43 的 12 条 503）",
        )


class PlaceholderSpliceTests(_IsolatedCase):
    """剥离占位符不能把两侧文本拼成一个"原文"（2026-10-26 真机第二类 503）。

    AI 在正文里写「部分被遮」的示例时会出现 `13996{{PHONE_xxxxxx}}825050`
    这种形态。旧实现 `_PLACEHOLDER_RX.sub("")` 把它拼成完整号码 → 复检报泄漏。
    但实际上的字节里中间是占位符，号码**并没有**明文出网。
    """

    def test_placeholder_between_digits_does_not_fake_a_match(self):
        out, needles = self._run(
            "pl1",
            [f"我的号码 {PHONE}",
             "示例：`13996{{PHONE_xxxxxx}}825050`（部分被遮）"])
        self.assertIn(PHONE, needles, "前置条件：号码应当被登记为 needle")
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "pl1"),
            "占位符被删掉后两侧数字拼成完整号码 → 假泄漏 → 503",
        )

    def test_placeholder_between_alpha_fragments_does_not_fake_a_match(self):
        out, needles = self._run(
            "pl2",
            [f"邮箱 {MAIL}",
             f"示例：`{MAIL[:4]}{{{{EMAIL_abcdef}}}}{MAIL[4:]}`（部分被遮）"])
        self.assertIn(MAIL, needles)
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "pl2"),
            "占位符被删掉后两侧片段拼成完整邮箱 → 假泄漏",
        )


class ExemptionIsNotSilentTests(_IsolatedCase):
    """放过的残留必须计数（AGENTS.md §3.8：豁免是漏检路径，不得静默）。"""

    def test_passed_occurrences_are_counted_and_takeable(self):
        out, needles = self._run("ps1", [f"号码 {PHONE}", f"`{PHONE_12}` 和 `ID{PHONE}X`"])
        self.assertIn(PHONE, needles)
        self.assertFalse(tr._mask_egress_verify(out, needles, "ps1"))
        self.assertEqual(
            tr._take_egress_pass("ps1"), 2,
            "复检放过的两处残留必须计数（否则用户分不清「没跑」与「跑了但全放行」）")
        self.assertEqual(tr._take_egress_pass("ps1"), 0, "取走后必须清零")

    def test_clean_text_does_not_record_pass(self):
        out, needles = self._run("ps2", [f"号码 {PHONE}", "没有别的形态了"])
        self.assertFalse(tr._mask_egress_verify(out, needles, "ps2"))
        self.assertEqual(tr._take_egress_pass("ps2"), 0,
                         "没有任何残留时不该记「放过」")


class MatcherTableThreadSafetyTests(_IsolatedCase):
    """复检的 label→规则表必须线程安全（2026-10-26 复核发现的 P2）。

    `_mask_egress_verify` 跑在 `_MASK_POOL` 专职线程里（宽度可配），两个 worker
    可能同时首次调用 `_mask_egress_label_matchers()`。原实现「判非空 → 逐条
    append」，第二个线程会看到**非空但残缺**的表就返回 → 该 label 查不到
    matcher → 落到 `return True`（判泄漏）。方向是误报，但配上
    `MASKIT_EGRESS_BLOCK=1` 就是假 503。
    """

    def test_table_is_published_atomically(self):
        """表的发布必须是**一次性**的，不能边建边可见。

        判据不看「并发跑多少次有没有出错」—— 那是概率性的，抓不住真竞态
        （实测：给无锁实现加 20ms 窗口后，8 线程用例照样绿）。改成结构性判据：
        建表过程中，全局表要么为空、要么已经是**完整**的（label 数与 RULES 一致）。
        无锁的「逐条 append」实现必然被抓住 —— 它在建到一半时全局表就非空了。
        """
        import transparent as _tr
        import re, pathlib as _pl
        src = (_pl.Path(__file__).resolve().parents[1] / "engine" / "transparent.py"
               ).read_text(encoding="utf-8")
        # 抽出 _mask_egress_label_matchers 的函数体
        m = re.search(r"def _mask_egress_label_matchers\(\):.*?\n    return _MASK_EGRESS_LABEL_RX",
                      src, re.S)
        self.assertIsNotNone(m, "没找到 _mask_egress_label_matchers（源码结构变了）")
        body = m.group(0)
        self.assertIn("with _MASK_EGRESS_LABEL_LOCK:", body,
                      "建表没有加锁：并发首次调用会看到「非空但残缺」的表")
        self.assertNotIn("_MASK_EGRESS_LABEL_RX.setdefault(", body,
                         "建表直接写全局表（边建边可见）→ 并发下必然出现残缺表；"
                         "必须先建到局部再一次性发布")
        self.assertIn("_MASK_EGRESS_LABEL_RX.update(built)", body,
                      "建表结果必须一次性发布（update 到全局）")

    def test_complete_table_after_build(self):
        """建完后每个内置规则 label 都必须有 matcher。"""
        table = tr._mask_egress_label_matchers()
        for lbl in ("PHONE", "EMAIL", "CARD", "IDCARD", "IP_PUBLIC",
                    "IPV6_PRIVATE", "CONNSTR"):
            self.assertIn(lbl, table, "缺少 %s 的 matcher" % lbl)


class RealLeakStillCaughtTests(_IsolatedCase):
    """修完不能漏真泄漏：同一值在别处**明文完整出现**必须仍然阻断。"""

    def test_plain_occurrence_in_another_leaf_is_still_caught(self):
        out, needles = self._run("rl1", [f"号码 {PHONE}", f"再写一遍 {PHONE}"])
        # 前置：两处都该被遮（同形态），此时没有残留
        self.assertEqual(out.count(PHONE), 0, "前置条件：同形态两处都该被遮")
        # 人为构造「本该遮但没遮」：把一处换成明文
        leaked = out.replace(tr._PLACEHOLDER_RX.search(out).group(), PHONE, 1)
        self.assertTrue(
            tr._mask_egress_verify(leaked, needles, "rl1"),
            "明文完整出现的真泄漏被放过了",
        )

    def test_direct_leak_detected(self):
        tr._new_session("rl2")
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": PHONE}), [PHONE], "rl2"),
            "明文完整出现的真泄漏被放过了",
        )

    def test_custom_word_substring_is_still_a_leak(self):
        """自定义词没有边界语义（无边界子串匹配），别处出现即应被遮 → 命中即泄漏。"""
        tr._new_session("rl3")
        needles = tr._mask_egress_needles(
            {CUSTOM_TERM: "{{TERM_abcdef}}"}, {CUSTOM_TERM: "TERM"})
        self.assertIn(CUSTOM_TERM, needles)
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": CUSTOM_TERM}), needles, "rl3"),
            "自定义词的明文出现被放过了（它的语义就是无边界子串匹配）",
        )


class ParityPreservedTests(_IsolatedCase):
    """既有契约不能被这次修改破坏。"""

    def test_exempt_block_still_not_treated_as_leak(self):
        """签名思考块（协议豁免区）里复述原文仍不算泄漏。"""
        sid = "pp1"
        tr._new_session(sid)
        body = {"model": "m", "messages": [
            {"role": "user", "content": f"note {PHONE} here"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": f"用户提到 {PHONE} 这个值",
                 "signature": "Aq" + "x" * 40}]},
        ]}
        out = tr.mask_body(json.dumps(body, ensure_ascii=False), sid)
        sess = tr._session_get(sid, {}) or {}
        needles = tr._mask_egress_needles(
            sess.get("fwd") or {}, sess.get("labels") or {},
            sess.get("new_orig") or set())
        self.assertTrue(needles, "前置条件：应当有 needle")
        self.assertFalse(
            tr._mask_egress_verify(out, needles, sid),
            "签名思考块被当成泄漏",
        )

    def test_credential_values_still_not_needles(self):
        cred = "Rv9" + "sent" + "Pass" + "27x"
        needles = tr._mask_egress_needles(
            {cred: "{{SECRET_abcdef}}"}, {cred: "SECRET"})
        self.assertNotIn(cred, needles, "凭据原文进了 needle 集")

    def test_budget_skip_still_skips(self):
        big = "x" * (tr._MASK_EGRESS_MAX_BYTES + 1024) + PHONE
        tr._new_session("pp2")
        self.assertFalse(tr._mask_egress_verify(big, [PHONE], "pp2"))
        self.assertTrue(tr._session_get("pp2", {}).get("egress_skipped"))


class RealSessionReplayTests(_IsolatedCase):
    """真机形态回放：长会话正文里反复讨论号码，复检必须不误报。"""

    def test_long_session_discussing_the_value_does_not_block(self):
        contents = [f"我的号码 {PHONE}"]
        # 模拟模型在分析正文里反复引用各种形态（真机 msg 49~71 就是这种内容）
        for i in range(12):
            contents.append(
                f"第{i}段分析：`{PHONE_12}` 是 12 位、`ID{PHONE}X` 有字母边界、"
                f"`{MAIL_DOT}` 结尾带点 —— 这些形态规则都不该遮")
        out, needles = self._run("rp1", contents)
        self.assertGreater(len(needles), 0, "前置条件：应当有 needle")
        self.assertFalse(
            tr._mask_egress_verify(out, needles, "rp1"),
            "长会话里反复讨论原文形态 → 复检误报 → 请求被 503",
        )


if __name__ == "__main__":
    unittest.main()
