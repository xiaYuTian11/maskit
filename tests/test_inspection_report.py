"""统一检测口径与严格模式闸门（批次 2 / §B）契约测试。

设计依据：`ai-coding/plans/maskit-personal-upgrade-plan.md` §B（v3 定稿）。
四条口径：

1. `decision` / `completeness` / `reason_codes` 由 `engine/inspection.py` 统一派生，
   代理路径与扩展桥接**同源**（否则扩展用户永远只看到「0 命中」）；
2. `complete` 只表示「所配置的检测已执行完」，**不保证现实无漏检**；
   协议契约豁免（`signed_blocks_skipped`）属显式不扫面，不把完整度降成 `partial`，
   但必须出现在 `reason_codes`；
3. BLOCK 有十几处调用点，口径在 `_emit` 层一次性补齐（漏一处就是「什么都没发生」）；
4. 严格模式（`ner_require_complete`）：语义检测没跑完时**出网前**阻断（503），
   且不得把 exempt/info 类原因算成降级。
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import panel  # noqa: E402
import transparent as tr  # noqa: E402
import inspection as ins  # noqa: E402

# 合成假号码：分片拼接，避免样例以完整号码形态落盘（方案 §8 R11）。
PHONE = "139" + "0000" + "0000"


class InspectionPureFunctionTests(unittest.TestCase):
    """纯函数口径：类别 → 完整度 → 阻断判定。"""

    def test_decision_of_precedence(self):
        self.assertEqual(ins.decision_of(changed=True), ins.DECISION_MASKED)
        self.assertEqual(ins.decision_of(changed=False), ins.DECISION_SCANNED_CLEAN)
        self.assertEqual(ins.decision_of(changed=True, passthrough=True), ins.DECISION_PASSTHROUGH)
        self.assertEqual(ins.decision_of(changed=True, blocked=True), ins.DECISION_BLOCKED)

    def test_degraded_reason_makes_partial_but_exempt_does_not(self):
        self.assertEqual(ins.completeness_of({"budget_exhausted": 3}), ins.PARTIAL)
        self.assertEqual(ins.completeness_of({"signed_blocks_skipped": 2}), ins.COMPLETE,
                         "协议契约豁免是显式不扫面，不应把完整度打成 partial")
        self.assertEqual(ins.completeness_of({"cancelled": 1}), ins.COMPLETE)
        self.assertEqual(ins.completeness_of({"some_future_code": 1}), ins.COMPLETE,
                         "未知码不得凭空降级")
        self.assertEqual(ins.completeness_of({}), ins.COMPLETE)

    def test_has_blocking_reason(self):
        self.assertTrue(ins.has_blocking_reason({"budget_exhausted": 1}))
        self.assertTrue(ins.has_blocking_reason({"model_unavailable": 1}))
        self.assertFalse(ins.has_blocking_reason({"signed_blocks_skipped": 1}))
        self.assertFalse(ins.has_blocking_reason({"cancelled": 1}))
        self.assertFalse(ins.has_blocking_reason({"not_target": 1}))
        self.assertFalse(ins.has_blocking_reason(None))

    def test_report_helpers_keep_signed_blocks_visible(self):
        r = ins.report_for_mask(changed=True, ner_skips={"deadline": 2}, signed_skipped=1)
        self.assertEqual(r["decision"], "masked")
        self.assertEqual(r["completeness"], "partial")
        self.assertEqual(r["reason_codes"], {"deadline": 2, "signed_blocks_skipped": 1})
        skip = ins.report_for_skip(reason="not_target", blocked=False)
        self.assertEqual(skip["decision"], "passthrough")
        self.assertEqual(skip["completeness"], "complete")
        block = ins.report_for_skip(reason="engine_busy", blocked=True)
        self.assertEqual(block["decision"], "blocked")
        self.assertEqual(block["completeness"], "failed")
        restore = ins.report_for_restore(unresolved=2)
        self.assertNotIn("decision", restore, "还原不是扫描，不带 decision")
        self.assertEqual(restore["completeness"], "partial")
        self.assertEqual(restore["reason_codes"], {"unresolved_tokens": 2})
        self.assertEqual(ins.report_for_restore(unresolved=0), {"completeness": "complete"})


class EmitLayerTests(unittest.TestCase):
    """`_emit` 层的口径补齐（BLOCK 十几处调用点不能各自为政）。"""

    def setUp(self):
        self.captured = []
        self._orig = tr.enqueue_event
        tr.enqueue_event = lambda rec: self.captured.append(rec)
        tr._log = lambda *a, **k: None

    def tearDown(self):
        tr.enqueue_event = self._orig

    def test_block_events_get_report_automatically(self):
        tr._emit("BLOCK", reason="engine_busy", msg="x")
        rec = self.captured[-1]
        self.assertEqual(rec["decision"], "blocked")
        self.assertEqual(rec["completeness"], "failed")
        self.assertEqual(rec["reason_codes"], {"engine_busy": 1})

    def test_explicit_report_is_not_overwritten(self):
        tr._emit("BLOCK", reason="engine_busy",
                 **ins.build_report(decision=ins.DECISION_BLOCKED,
                                    reasons={"semantic_incomplete": 1}, failed=True))
        rec = self.captured[-1]
        self.assertEqual(rec["reason_codes"], {"semantic_incomplete": 1})

    def test_non_block_events_are_untouched(self):
        tr._emit("MASK", count=0)
        self.assertNotIn("decision", self.captured[-1])


class _ProxyHarness(unittest.TestCase):
    """驱动真实 request() 钩子（同 test_shield 的 `_drive_request` 口径）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_root = tr._DATA_ROOT
        self._orig_reload = tr._maybe_reload
        tr._DATA_ROOT = self.tmp
        tr._maybe_reload = lambda force=False: None
        # 让**真实的** `_emit` 跑（含它在 BLOCK 上的口径补齐），只把落地出口换成列表：
        # 直接替换 `_emit` 会把被测行为一并替换掉，测出来的是测试自己的实现。
        self._orig_sink = (tr.enqueue_event, tr._log)
        self.events = []
        tr.enqueue_event = lambda rec: self.events.append(rec)
        tr._log = lambda *a, **k: None
        tr.sessions.clear()
        # 目标判定与规则开关是模块级全局态：不显式设好，「目标请求」会被当成直通，
        # 压根不会走到脱敏管线（MASK 事件也不会有）。口径同 test_shield 的 setUp。
        self._orig_route = (tr.CAPTURE_MODE, tr.TARGET_DOMAINS, tr.API_PATHS,
                            tr.UPSTREAMS, tr.BUILTIN_RULES)
        tr.CAPTURE_MODE = "explicit"
        tr.TARGET_DOMAINS = ["api.openai.com", "anthropic.com"]
        tr.API_PATHS = ["/v1/chat/completions", "/v1/completions", "/v1/messages", "/v1/responses"]
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        tr.BUILTIN_RULES = {l: True for l in tr.DEFAULT_BUILTIN_RULES}
        self._orig_flag = tr.NER_REQUIRE_COMPLETE
        self.addCleanup(self._restore)

    def _restore(self):
        tr._DATA_ROOT = self._orig_root
        tr._maybe_reload = self._orig_reload
        tr.enqueue_event, tr._log = self._orig_sink
        tr.NER_REQUIRE_COMPLETE = self._orig_flag
        (tr.CAPTURE_MODE, tr.TARGET_DOMAINS, tr.API_PATHS,
         tr.UPSTREAMS, tr.BUILTIN_RULES) = self._orig_route
        tr.sessions.clear()

    @staticmethod
    def _flow(body):
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_host="api.openai.com",
                path="/v1/chat/completions",
                headers={"content-type": "application/json"},
                content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            ),
            response=None,
            metadata={},
        )

    def _drive(self, flow):
        res = tr.request(flow)
        if asyncio.iscoroutine(res):
            return asyncio.run(res)
        return res


class MaskEventReportTests(_ProxyHarness):
    """MASK 事件带统一口径（代理路径）。"""

    def test_mask_event_carries_decision_and_completeness(self):
        flow = self._flow({"model": "gpt-4o", "messages": [{"role": "user", "content": "电话 " + PHONE}]})
        self._drive(flow)
        masks = [rec for rec in self.events if rec["type"] == "MASK"]
        self.assertTrue(masks, "应产生 MASK 事件")
        rec = masks[-1]
        self.assertEqual(rec["decision"], "masked")
        self.assertEqual(rec["completeness"], "complete")

    def test_degraded_ner_marks_partial_without_blocking_by_default(self):
        flow = self._flow({"model": "gpt-4o", "messages": [{"role": "user", "content": "电话 " + PHONE}]})
        degraded = tr._MaskResult(masked_bytes=None, first_diff_byte=-1, scan_scope={},
                                  role_texts={}, ner_skips={"budget_exhausted": 4},
                                  ner_metrics={})
        with mock.patch.object(tr, "_mask_pipeline_worker", return_value=degraded):
            self._drive(flow)
        rec = [r for r in self.events if r["type"] == "MASK"][-1]
        self.assertEqual(rec["decision"], "scanned_clean")
        self.assertEqual(rec["completeness"], "partial")
        self.assertEqual(rec["reason_codes"], {"budget_exhausted": 4})
        self.assertNotIn("BLOCK", [r["type"] for r in self.events],
                         "默认 best-effort：降级只记账，不阻断")


class StrictModeGateTests(_ProxyHarness):
    """§B3 严格模式：语义检测没跑完 → 出网前阻断。"""

    def _run_with_skips(self, skips, require=True):
        tr.NER_REQUIRE_COMPLETE = require
        flow = self._flow({"model": "gpt-4o", "messages": [{"role": "user", "content": "电话 " + PHONE}]})
        degraded = tr._MaskResult(masked_bytes=b'{"model":"gpt-4o","messages":[]}', first_diff_byte=-1,
                                  scan_scope={}, role_texts={}, ner_skips=skips, ner_metrics={})
        with mock.patch.object(tr, "_mask_pipeline_worker", return_value=degraded):
            self._drive(flow)
        return flow

    def test_degraded_semantics_block_before_egress(self):
        flow = self._run_with_skips({"budget_exhausted": 2})
        self.assertIsNotNone(flow.response, "严格模式下必须阻断，绝不放行")
        self.assertEqual(flow.response.status_code, 503)
        payload = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(payload["error"]["code"], "shield_semantic_incomplete")
        self.assertTrue(payload["error"].get("hint"), "阻断必须给用户可执行的动作")
        self.assertEqual(payload["decision"], "blocked")
        blocks = [r for r in self.events if r["type"] == "BLOCK"]
        self.assertTrue(blocks, "阻断必须留 BLOCK 事件（否则用户无从归因）")
        self.assertEqual(blocks[-1]["reason"], "semantic_incomplete")
        self.assertEqual(blocks[-1]["decision"], "blocked")
        self.assertIn("budget_exhausted", blocks[-1]["reason_codes"])
        self.assertIn("semantic_incomplete", blocks[-1]["reason_codes"])

    def test_exempt_reason_does_not_trigger_strict_block(self):
        flow = self._run_with_skips({"signed_blocks_skipped": 3})
        self.assertIsNone(flow.response, "协议契约豁免不是降级，严格模式不得据此阻断")

    def test_strict_flag_off_keeps_best_effort(self):
        flow = self._run_with_skips({"budget_exhausted": 2}, require=False)
        self.assertIsNone(flow.response, "开关关闭时必须保持 best-effort")


class SizeGateAttributionTests(_ProxyHarness):
    """§H4(b)：413 必须可归因（hint + blocking + 统一口径），且不得改变闸门数值。"""

    def test_413_body_is_actionable(self):
        with mock.patch.object(tr, "_MAX_REQUEST_BODY", 512):
            flow = self._flow({"model": "gpt-4o", "messages": [
                {"role": "user", "content": "x" * 2000}]})
            self._drive(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 413)
        payload = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(payload["reason"], "request_too_large")
        self.assertTrue(payload.get("blocking"), "超限必须显式阻断（扩展侧据此不进默认直通桶）")
        self.assertIn("hint", payload, "错误体必须告诉用户该改什么")
        self.assertEqual(payload["decision"], "blocked")
        self.assertEqual(payload["limit_bytes"], 512)
        blocks = [r for r in self.events if r["type"] == "BLOCK"]
        self.assertEqual(blocks[-1]["reason"], "request_too_large")
        self.assertEqual(blocks[-1]["decision"], "blocked")
        self.assertEqual(blocks[-1]["reason_codes"], {"request_too_large": 1})
        self.assertTrue(blocks[-1].get("msg"), "BLOCK 事件带可读理由")


class ExtBridgeParityTests(unittest.TestCase):
    """§B4 扩展桥接与代理路径同口径。"""

    EXT_TOKEN = "ext-test-token-0123456789"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = {
            "config": panel.CONFIG_PATH,
            "root": tr._DATA_ROOT,
            "origin": panel._origin_check_enabled,
            "remote": panel.REMOTE_MODE,
        }
        panel.CONFIG_PATH = self.tmp / "config.json"
        tr._DATA_ROOT = self.tmp
        panel._origin_check_enabled = False
        panel.REMOTE_MODE = False
        cfg = panel.default_config()
        cfg.update({"ext_bridge_enabled": True, "ext_token": self.EXT_TOKEN})
        panel.save_config(cfg)
        tr.sessions.clear()
        self.client = panel.app.test_client()
        self.addCleanup(self._restore)

    def _restore(self):
        panel.CONFIG_PATH = self._orig["config"]
        tr._DATA_ROOT = self._orig["root"]
        panel._origin_check_enabled = self._orig["origin"]
        panel.REMOTE_MODE = self._orig["remote"]
        tr.sessions.clear()

    def _mask(self, text):
        return self.client.post("/api/ext/mask", json={"text": text, "host": "chatgpt.com"},
                                headers={"X-Shield-Token": self.EXT_TOKEN})

    def test_ext_mask_reports_same_shape_as_proxy(self):
        r = self._mask("电话 " + PHONE)
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertTrue(j.get("ok"))
        self.assertEqual(j["decision"], "masked")
        self.assertEqual(j["completeness"], "complete")

    def test_ext_mask_degraded_marks_partial(self):
        with mock.patch.object(tr, "_ner_skips_of_this_round", return_value={"deadline": 1}):
            r = self._mask("电话 " + PHONE)
        j = r.get_json()
        self.assertEqual(j["completeness"], "partial")
        self.assertEqual(j["reason_codes"], {"deadline": 1})
        self.assertTrue(j.get("ner_skipped"), "既有字段必须保持向后兼容")


if __name__ == "__main__":
    unittest.main()
