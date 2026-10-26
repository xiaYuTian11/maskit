"""出口前复检（egress verify）。

## 为什么需要它

现在的链路是：脱敏 → `flow.request.content = masked_bytes` → 直接放行。
**没有任何一步回头确认「脱敏后的字节里还有没有原文」**。

同类的 `askalf/cordon` 有 `egressViolations`：对已脱敏 body 再读一遍，仍能匹配到
声明的标识符就拒发。这是最后一道网 —— 它抓的是「规则漏了 / 路径豁免错了 /
known 覆盖项算错了」这类**已知会发生的**缺陷，而不是假想风险。

本仓实测过的真实漏检路径（都在本方案其他批次里修了，但 egress 复检要能兜住
将来任何新的同类缺陷）：

  · 工具定义区被误豁免 → 值原样上行（A-2 前）
  · `.env` 形态的 SECRET 全漏（A-1 前）
  · 未知 body 形态在 explicit/local 模式下直通

## 三条必须守住的契约

1. **命中就阻断**（503 + `reason=egress_verify`），绝不放行。
2. **剥掉占位符再扫**：否则「已知值恰好出现在占位符里」会被误判成泄漏，
   而那是正常形态（占位符 = 已脱敏）。
3. **超预算不阻断**：needle 太多或 body 太大时跳过并**留痕**（`egress_skipped`）。
   否则大 body 会恒定 503 —— 那等于把可用性问题变成不可用。

## 成本（实测，决定默认能不能开）

| needle 数 | 1MB | 4MB |
|---:|---:|---:|
| 5~200 | 2~9 ms | 46~54 ms |
| 1000 | 38 ms | 154 ms |
| 2000 | 77 ms | 313 ms |

脱敏本身是 166 ms/MB，所以 ≤200 needle + ≤4MB 时复检 <5% 开销 → 默认开。
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

# 片段拼接（AGENTS.md §3 第 9 条）
TERM_VALUE = "Night" + "jar" + "Proj" + "ect"
CRED_VALUE = "Rv9" + "sent" + "Pass" + "27x"


def _engine():
    import transparent as tr
    return tr


tr = _engine()


class _IsolatedCase(unittest.TestCase):
    CONFIG = {"sensitive": {"TERM": [TERM_VALUE]}, "builtin_rules": {}}

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
        self._dir = tempfile.mkdtemp(prefix="maskit-egress-")
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
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._known_reset_for_tests()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(tr, k, v)
        tr._cfg_mtime[0] = self._mtime
        shutil.rmtree(self._dir, ignore_errors=True)
        tr._known_reset_for_tests()


class ConstantsTests(_IsolatedCase):
    """预算常量必须存在、且默认值有意义。"""

    def test_budget_constants_exist(self):
        for name in ("_MASK_EGRESS_MAX_NEEDLES", "_MASK_EGRESS_MAX_BYTES", "_MASK_EGRESS_ON"):
            self.assertTrue(hasattr(tr, name), f"缺少 {name}")

    def test_default_is_on(self):
        """默认必须是开的：这是最后一道网，关掉等于没有。"""
        self.assertTrue(tr._MASK_EGRESS_ON, "egress 复检默认必须是开的")

    def test_needle_budget_matches_measured_cost(self):
        """needle 上限必须与实测成本一致（200 → 4MB 约 46ms，<5% 开销）。"""
        self.assertGreaterEqual(tr._MASK_EGRESS_MAX_NEEDLES, 50)
        self.assertLessEqual(tr._MASK_EGRESS_MAX_NEEDLES, 500)


class VerificationTests(_IsolatedCase):
    """核心行为：漏检必须被抓住。"""

    def _verify(self, masked_text, values, sid="e1"):
        return tr._mask_egress_verify(masked_text, values, sid)

    def test_leaked_value_is_detected(self):
        """人为构造「值仍在脱敏后文本里」的场景 → 必须报泄漏。"""
        masked = f"hello {TERM_VALUE} world"
        hit = self._verify(masked, [TERM_VALUE])
        self.assertTrue(hit, "脱敏后仍含原文，复检没抓住")

    def test_clean_text_passes(self):
        masked = "hello {{TERM_abcdef}} world"
        self.assertFalse(self._verify(masked, [TERM_VALUE]), "干净文本被误判")

    def test_placeholders_are_stripped_before_scan(self):
        """占位符里**不该**出现原文，但万一出现也不能算泄漏（那是已脱敏形态）。"""
        # 构造一个「占位符的标签里含值」的极端形态：剥掉占位符后不该命中
        masked = "x {{TERM_abcdef}} y"
        self.assertFalse(self._verify(masked, ["TERM"]))

    def test_short_values_are_not_needles(self):
        """过短的值不进 needle 集（否则误报率爆炸）。"""
        self.assertFalse(
            self._verify("abc def", ["abc"]),
            "短值不该成为 needle",
        )

    def test_credential_values_are_not_needles(self):
        """凭据原文**不进** needle 集（它会被写进正则对象，等于把原文放进诊断面）。"""
        # fwd 的形态是 {原文: 占位符}（与 `_remember` / `sessions[sid]["fwd"]` 一致）
        needles = tr._mask_egress_needles(
            {CRED_VALUE: "{{SECRET_abcdef}}", TERM_VALUE: "{{TERM_abcdef}}"},
            {CRED_VALUE: "SECRET", TERM_VALUE: "TERM"},
        )
        self.assertNotIn(CRED_VALUE, needles, "凭据原文进了 needle 集")
        self.assertIn(TERM_VALUE, needles, "非凭据值应当进 needle 集")


class ExemptBlockParityTests(_IsolatedCase):
    """复检必须与「按协议契约整块豁免」同口径（2026-10-25 复核发现的 P1）。

    签名思考块（`thinking` + `signature` / `redacted_thinking`）在 `_mask_tree`
    里是整块原样上行 —— 这是已接受的取舍（`signed_blocks_skipped` 计数）。
    但复检拿会话 fwd 当 needle 扫整包字节，只要同一值在**别处**被遮过，
    就会在豁免块里命中 → 503 打断合法请求。

    而客户端回放 thinking 时，思考正文里复述用户原文是**多轮会话必然出现**的形态。
    """

    def test_exempt_block_is_not_treated_as_leak(self):
        tr._known_reset_for_tests()
        sid = "eb1"
        tr._new_session(sid)
        body = {
            "model": "m",
            "messages": [
                {"role": "user", "content": f"note {TERM_VALUE} here"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": f"用户提到 {TERM_VALUE} 这个值",
                     "signature": "Aq" + "x" * 40}]},
            ],
        }
        out = tr.mask_body(json.dumps(body, ensure_ascii=False), sid)
        sess = tr._session_get(sid, {})
        needles = tr._mask_egress_needles(
            sess.get("fwd") or {}, sess.get("labels") or {}, sess.get("new_orig") or set())
        self.assertTrue(needles, "前置条件：应当有 needle")
        self.assertFalse(
            tr._mask_egress_verify(out, needles, sid),
            "签名思考块（协议豁免区）被当成泄漏 → 合法请求会被 503",
        )

    def test_real_leak_outside_exempt_block_is_still_caught(self):
        """反向：豁免块之外的真泄漏必须仍然被抓（不能因为剔除而放行）。"""
        tr._known_reset_for_tests()
        sid = "eb2"
        tr._new_session(sid)
        tr.mask_body(json.dumps(
            {"model": "m", "messages": [{"role": "user", "content": TERM_VALUE}]}), sid)
        sess = tr._session_get(sid, {})
        needles = tr._mask_egress_needles(
            sess.get("fwd") or {}, sess.get("labels") or {}, sess.get("new_orig") or set())
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": TERM_VALUE}), needles, sid),
            "豁免块之外的泄漏被漏掉了（剔除逻辑过头）",
        )


class NeedleSourceTests(_IsolatedCase):
    """needle 必须取**本轮新增**，不能取会话累计（2026-10-25 复核发现的 P1）。

    `fwd` 是跨请求复用窗口，长会话可达数百条。一旦超过
    `_MASK_EGRESS_MAX_NEEDLES`，此后每轮都走 `needles_over_budget` ——
    闸门等于永久关掉。
    """

    def test_long_session_does_not_disable_verification(self):
        tr._known_reset_for_tests()
        sid = "ls1"
        tr._new_session(sid)
        sess = tr._session_get(sid, {})
        # 模拟长会话：历史累计 250 条映射（超过上限 200）
        for i in range(250):
            sess["fwd"][f"value{i:04d}abcdef"] = "{{TERM_%06x}}" % i
        # 本轮只新增 1 个值
        sess["new_orig"] = {TERM_VALUE}
        needles = tr._mask_egress_needles(sess["fwd"], sess.get("labels") or {},
                                          sess["new_orig"])
        self.assertEqual(needles, [TERM_VALUE],
                         "needle 取了会话累计而不是本轮新增")
        self.assertLessEqual(len(needles), tr._MASK_EGRESS_MAX_NEEDLES)
        # 本轮真泄漏必须仍被抓（而不是走 needles_over_budget）
        self.assertTrue(
            tr._mask_egress_verify(json.dumps({"c": TERM_VALUE}), needles, sid),
            "长会话下复检失效（needle 超预算）",
        )
        self.assertFalse(tr._session_get(sid, {}).get("egress_skipped"),
                         "长会话不该被判为超预算跳过")


class BudgetTests(_IsolatedCase):
    """超预算必须**跳过并留痕**，不能阻断（否则大 body 恒定 503）。"""

    def test_too_many_needles_is_skipped_not_blocked(self):
        values = [f"Vl{i:02d}" + "Xy2" + "Zq7" for i in range(tr._MASK_EGRESS_MAX_NEEDLES + 50)]
        text = "hello " + values[0]  # 第一个确实泄漏
        tr._new_session("e2")        # 生产链路上此时会话必然已存在
        hit = tr._mask_egress_verify(text, values, "e2")
        self.assertFalse(hit, "超预算时不该阻断（应跳过并留痕）")
        s = tr._session_get("e2", {})
        self.assertTrue(
            s.get("egress_skipped"),
            "超预算跳过必须留痕（否则用户以为复检跑过了）",
        )

    def test_oversize_body_is_skipped_not_blocked(self):
        big = "x" * (tr._MASK_EGRESS_MAX_BYTES + 1024) + TERM_VALUE
        tr._new_session("e3")
        hit = tr._mask_egress_verify(big, [TERM_VALUE], "e3")
        self.assertFalse(hit, "超大 body 时不该阻断")
        self.assertTrue(tr._session_get("e3", {}).get("egress_skipped"))

    def test_skip_is_takeable_for_events(self):
        """跳过标记必须能**取走发出**（「超预算跳过必须留痕」的唯一落点）。

        2026-10-25 复核发现的缺口：`egress_skipped` 只写不读，从未进事件 ——
        用户以为复检跑过了，其实没跑。
        """
        tr._new_session("e5")
        tr._mask_egress_note_skip("e5", "needles_over_budget")
        skipped, reason = tr._take_egress_skip("e5")
        self.assertTrue(skipped)
        self.assertEqual(reason, "needles_over_budget")
        self.assertEqual(tr._take_egress_skip("e5"), (False, ""),
                         "跳过标记取走后未清零，会串到下一个请求")

    def test_skip_reason_is_recorded(self):
        """跳过必须带原因码，便于用户区分「跑了没命中」与「压根没跑」。"""
        tr._new_session("e4")
        tr._mask_egress_note_skip("e4", "needles_over_budget")
        s = tr._session_get("e4", {})
        self.assertEqual(s.get("egress_skip_reason"), "needles_over_budget")


class IntegrationTests(_IsolatedCase):
    """端到端：经由真实请求管线，泄漏必须被阻断。"""

    def _drive(self, body, sid="e2e"):
        """跑一次 request()，返回 (上行字节, flow)。"""
        from types import SimpleNamespace

        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        tr.UPSTREAMS = [
            {
                "name": "up-a", "port": 18709, "base_path": "/up-a",
                "target": "https://api.example.com/v1",
                "paths": ["/v1/chat/completions"],
            }
        ]
        tr.CAPTURE_MODE = "reverse"
        tr.FAIL_CLOSED = True
        req = SimpleNamespace(
            method="POST", path="/chat/completions", pretty_host="127.0.0.1",
            host="127.0.0.1", port=18709, scheme="http", content=raw,
            text=raw.decode(), headers={"content-type": "application/json"},
            pretty_url="",
        )
        flow = SimpleNamespace(
            request=req, response=None, metadata={},
            client_conn=SimpleNamespace(sockname=("127.0.0.1", 18709)),
            server_conn=SimpleNamespace(via=None),
        )
        old_emit, old_reload = tr._emit, tr._maybe_reload
        events = []
        try:
            # 必须**收集**而不是丢弃：复检默认只记录不阻断，「留痕」就是唯一可观察
            # 的行为证据（2026-10-26 用户第一准则）。
            tr._emit = lambda *a, **k: events.append((a, k))
            tr._maybe_reload = lambda force=False: None
            from tests.test_regressions import _drive_request
            _drive_request(flow)
        finally:
            tr._emit, tr._maybe_reload = old_emit, old_reload
        self.events = events
        return (flow.request.content or b"").decode(), flow

    def test_leak_is_recorded_end_to_end(self):
        """端到端：人为制造「脱敏后仍含原文」，必须**留痕**（默认不阻断）。

        制造方式：把 `_mask_text` 临时替换成「原样返回」（模拟脱敏失效），
        然后走真实 request() 管线。这是复检存在的唯一理由——**主闸失效时它兜住**。

        ⚠️ 2026-10-26 用户第一准则：复检默认**只记录不阻断**（阻断会让整条业务
        链路不可用，详见 `_MASK_EGRESS_BLOCK`）。所以这里验的是「事件里有
        reason=egress_verify + decision=flagged」，而不是 503。阻断行为由
        `tests/test_egress_record_only.py::ExplicitBlockStillWorksTests` 单独覆盖。
        """
        body = {"model": "m", "messages": [{"role": "user", "content": f"see {TERM_VALUE}"}]}
        orig = tr._mask_text
        try:
            def _noop(text, sid):
                # 模拟「规则/路径判断错了」：登记映射、做了**别的**改写（让
                # masked_bytes 非 None），但该遮的值原样留下 —— 正是复检要抓的形态。
                if tr._session_get(sid) is None:
                    tr._new_session(sid)
                sess = tr._session_get(sid, {})
                tok = "{{TERM_abcdef}}"
                sess.setdefault("fwd", {})[TERM_VALUE] = tok
                sess.setdefault("labels", {})[TERM_VALUE] = "TERM"
                sess.setdefault("rev", {})[tok] = TERM_VALUE
                sess.setdefault("new_orig", set()).add(TERM_VALUE)
                # 只改一个无害字符，制造「body 被改写但值仍明文」
                return text.replace("see ", "look ") if "see " in text else text + " "
            tr._mask_text = _noop
            sent, flow = self._drive(body)
        finally:
            tr._mask_text = orig
        self.assertIsNone(flow.response, "默认配置下复检不该阻断请求（用户第一准则）")
        self.assertIn(TERM_VALUE, sent, "前置条件：桩确实留下了明文")
        flagged = [k for a, k in self.events if k.get("reason") == "egress_verify"]
        self.assertTrue(flagged, "复检没有留下 egress_verify 事件（等于静默放过）")
        self.assertEqual(flagged[0].get("decision"), "flagged")

    def test_zero_rewrite_is_also_verified(self):
        """**零改写**的请求也要复检（2026-10-25 复核发现的真实缺陷）。

        原实现整块包在 `if _res.masked_bytes is not None:` 里 —— 零改写时不复检。
        而「零改写」恰恰可能是「本该遮但规则漏了」，那正是这道网存在的理由。
        构造方式：让 `_mask_text` 原样返回但把值登记进 fwd（模拟规则漏检）。
        """
        body = {"model": "m", "messages": [{"role": "user", "content": f"see {TERM_VALUE}"}]}
        orig = tr._mask_text

        def _leaky(text, sid):
            if tr._session_get(sid) is None:
                tr._new_session(sid)
            sess = tr._session_get(sid, {})
            tok = "{{TERM_abcdef}}"
            sess.setdefault("fwd", {})[TERM_VALUE] = tok
            sess.setdefault("labels", {})[TERM_VALUE] = "TERM"
            sess.setdefault("rev", {})[tok] = TERM_VALUE
            # needle 现在只取「本轮新增」：桩必须登记，否则复检拿不到 needle
            sess.setdefault("new_orig", set()).add(TERM_VALUE)
            return text      # 零改写

        try:
            tr._mask_text = _leaky
            sent, flow = self._drive(body)
        finally:
            tr._mask_text = orig
        self.assertIsNone(flow.response, "默认配置下复检不该阻断（用户第一准则）")
        flagged = [k for a, k in self.events if k.get("reason") == "egress_verify"]
        self.assertTrue(flagged, "零改写的泄漏未被检测（复检被 if 挡住了）")

    def test_zero_rewrite_is_also_captured_for_forensics(self):
        """零改写的请求也要进取证缓冲（2026-10-25 复核）。

        零改写的请求同样上行，用户同样想核对「它是不是真的没被遮」——
        而那正是最需要证据的场景。原实现把取证整块包在
        `if masked_bytes is not None:` 里，零改写请求在缓冲里查不到。
        """
        tr._egress_preview_reset()
        body = {"model": "m", "messages": [{"role": "user", "content": "plain text"}]}
        sent, flow = self._drive(body)
        items = tr._egress_preview_list()
        self.assertTrue(items, "零改写的请求没有进取证缓冲")
        self.assertIn("plain text", items[-1]["masked"], "取证缓冲内容不对")

    def test_normal_request_passes_through(self):
        body = {"model": "m", "messages": [{"role": "user", "content": f"see {TERM_VALUE}"}]}
        sent, flow = self._drive(body)
        self.assertNotIn(TERM_VALUE, sent, "正常请求应当被脱敏")
        self.assertIsNone(flow.response, "正常请求不该被阻断")


if __name__ == "__main__":
    unittest.main()
