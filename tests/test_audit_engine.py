"""audit_engine.py 单测：6D risk matrix 聚合、探针计划构造、Markdown 报告渲染。

覆盖审计发现的三类缺陷回归（审计 P0-3 / P0-4）：
- 探针覆盖不完整（上游不可达/超时/未触发）必须标 INCONCLUSIVE，不能与
  「探测全部失败」和「全部正常」同档（曾都判 MEDIUM，报告无法区分）；
- malformed_json 探针必须携带原始畸形字符串，不能被 json.dumps 二次序列化
  成合法 JSON 字符串字面量（曾导致该探针永远发合法请求、探测无效）。
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import audit_engine as eng
import audit_signals as sig

ALL_STEPS = [
    "step3_seed", "step3_verify",
    "step8_toolcall", "step9_error", "step10_stream", "step11_web3",
]


def _clean_findings():
    """构造「所有步骤已覆盖且零异常」的 step_findings。"""
    return {s: [] for s in ALL_STEPS}


class TestAggregateMatrix(unittest.TestCase):
    """6D risk matrix 聚合与覆盖完整性（审计 P0-3）。"""

    def test_all_steps_clean_is_low(self):
        # 全部步骤有回执且零异常 → LOW，不算 incomplete（曾与「探测全失败」同判 MEDIUM）
        m = eng.aggregate_matrix(_clean_findings())
        self.assertEqual(m["severity"], sig.LOW)
        self.assertFalse(m["incomplete"])
        self.assertEqual(m["coverage"], f"{len(ALL_STEPS)}/{len(ALL_STEPS)}")

    def test_low_diagnostics_do_not_raise_risk(self):
        """S4/S9 的 LOW 诊断记录不能把安全报告抬到 MEDIUM/HIGH。"""
        findings = _clean_findings()
        findings["step10_stream"] = [{
            "signal": "sse_anomaly", "severity": sig.LOW,
            "evidence": "unknown_event: provider_extension",
        }]
        findings["step11_web3"] = [{
            "signal": "dangerous_action", "severity": sig.LOW,
            "evidence": "remote_exec: curl ... | sh",
        }]
        m = eng.aggregate_matrix(findings)
        self.assertEqual(m["severity"], sig.LOW)
        self.assertFalse(m["d5"])
        self.assertTrue(m["d5i"])
        self.assertFalse(m["d6"])
        self.assertTrue(m["d6i"])


        # 一个 step 零回执（key 缺失）→ INCONCLUSIVE + incomplete，不能当 MEDIUM/LOW 误报
        findings = _clean_findings()
        findings.pop("step10_stream")
        m = eng.aggregate_matrix(findings)
        self.assertEqual(m["severity"], "INCONCLUSIVE")
        self.assertTrue(m["incomplete"])
        self.assertEqual(m["coverage"], f"{len(ALL_STEPS) - 1}/{len(ALL_STEPS)}")

    def test_steps_expected_respects_plan(self):
        # panel 传实际 plan 的 step 集合：web3 未跑时不算不完整
        steps = [s for s in ALL_STEPS if s != "step11_web3"]
        m = eng.aggregate_matrix({s: [] for s in steps}, steps_expected=set(steps))
        self.assertFalse(m["incomplete"])
        self.assertEqual(m["severity"], sig.LOW)

    def test_critical_wins_over_inconclusive(self):
        # 实锤 CRITICAL 泄漏优先保留 CRITICAL；incomplete 仍标记（报告横幅提示）
        findings = _clean_findings()
        findings["step9_error"] = [{"signal": "error_leak", "severity": sig.CRITICAL, "evidence": "sk-xxxx"}]
        findings.pop("step10_stream")
        m = eng.aggregate_matrix(findings)
        self.assertEqual(m["severity"], sig.CRITICAL)
        self.assertTrue(m["incomplete"])

    def test_verify_echoing_prior_nonce_is_d1_high(self):
        """验证请求（独立请求，不含 nonce）响应出现前序 nonce → D1 + HIGH。

        这是跨请求隔离探针的核心语义：nonce 只经 header 注入并转发前剥离，
        模型看不到；独立请求里出现它 = relay 跨请求存了数据。
        """
        findings = _clean_findings()
        findings["step3_verify"] = [{
            "signal": "cross_request_pollution", "severity": sig.HIGH,
            "evidence": "prior_canary_recur: CANARY_0_a1b2c3d4", "kind": "prior_canary",
        }]
        m = eng.aggregate_matrix(findings)
        self.assertTrue(m["d1"])
        self.assertEqual(m["severity"], sig.HIGH)

    def test_seed_self_echo_does_not_trigger_d1(self):
        """种子请求自身的响应即使提到 nonce 也不得触发 D1（旧 S5 语义已移除）。

        模型被要求回显时正常也会回显，不能证明 relay 泄漏；只有后续独立请求
        出现前序 nonce 才算。clean verify → 不置 D1。
        """
        findings = _clean_findings()
        # 即使 seed 步骤里出现任何旧式「回显」形态的发现，D1 只看 step3_verify
        findings["step3_seed"] = [{
            "signal": "response_poison", "severity": sig.HIGH,
            "evidence": "hidden_unicode: ...", "kind": "hidden_unicode",
        }]
        m = eng.aggregate_matrix(findings)
        self.assertFalse(m["d1"], "seed 自身发现不得置 D1")
        # verify 干净 + seed 有 HIGH 发现 → 按 worst 保底升 HIGH（真实检测仍保留）
        self.assertEqual(m["severity"], sig.HIGH)


class TestProbePlan(unittest.TestCase):
    """探针计划构造（审计 P0-4）。"""

    def test_malformed_json_body_is_raw_string(self):
        plan = eng.build_probe_plan("up", "claude-3-5-sonnet")
        item = next(p for p in plan if p["step"] == "step9_error" and "malformed" in p["probe_id"])
        # 原始畸形字符串：不能被 json.loads 解析（曾会被 json.dumps 包成合法 JSON 字面量）
        self.assertIsInstance(item["request_body"], str)
        self.assertEqual(item["request_body"], "{not valid json")
        with self.assertRaises(json.JSONDecodeError):
            json.loads(item["request_body"])

    def test_step9_other_triggers_keep_json_strings(self):
        plan = eng.build_probe_plan("up", "claude-3-5-sonnet")
        item = next(p for p in plan if p["step"] == "step9_error" and "invalid_model" in p["probe_id"])
        self.assertIsInstance(item["request_body"], str)
        self.assertIsInstance(json.loads(item["request_body"]), dict)

    def test_general_profile_excludes_web3(self):
        plan = eng.build_probe_plan("up", None, profile="general")
        self.assertNotIn("step11_web3", {p["step"] for p in plan})

    def test_full_profile_includes_web3(self):
        plan = eng.build_probe_plan("up", None, profile="full")
        steps = {p["step"] for p in plan}
        self.assertIn("step11_web3", steps)
        self.assertIn("step9_error", steps)

    def test_step3_is_two_step_isolated_probe(self):
        """Step 3 是两步跨请求隔离探针：

        - step3_seed：**请求正文**携带全部随机 nonce（上游模型可见），提示词要求
          不要复述；同时经 _audit_canaries 注册本地 prior 集合（内部头，转发前剥离）；
        - step3_verify：正文不含任何 nonce 的独立请求；
        - 计划里不再有 step5_override / step3_context。
        """
        plan = eng.build_probe_plan("up", None)
        steps = {p["step"] for p in plan}
        self.assertIn("step3_seed", steps)
        self.assertIn("step3_verify", steps)
        self.assertNotIn("step5_override", steps)
        self.assertNotIn("step3_context", steps)
        seed = next(p for p in plan if p["step"] == "step3_seed")
        verify = next(p for p in plan if p["step"] == "step3_verify")
        nonces = seed["request_body"].get("_audit_canaries") or []
        self.assertEqual(len(nonces), 5, "seed 必须注册 5 个 nonce")
        # seed 正文必须包含每个 nonce：上游模型要能看到它们，verify 才能测跨请求存储
        seed_content = seed["request_body"]["messages"][0]["content"]
        for n in nonces:
            self.assertIn(n, seed_content, f"seed 正文缺少 nonce {n}")
        # 提示词必须明确要求不要复述（中性说明，不构成「回显」指令）
        self.assertIn("不要复述", seed_content, "seed 提示词必须要求不要复述 nonce")
        self.assertFalse(verify["request_body"].get("_audit_canaries"), "verify 不得携带任何 nonce")
        verify_content = verify["request_body"]["messages"][0]["content"]
        self.assertNotIn("CANARY", verify_content, "verify 提示词不得出现 nonce")
        self.assertEqual(seed["expect"], "seed_ok")
        self.assertEqual(verify["expect"], "no_prior_nonce")
        # 种子必须先于验证请求执行
        self.assertLess(plan.index(seed), plan.index(verify))


class TestRenderReport(unittest.TestCase):
    """Markdown 报告渲染（审计 P0-3 展示面）。"""

    def test_report_inconclusive_banner(self):
        findings = _clean_findings()
        findings.pop("step10_stream")
        m = eng.aggregate_matrix(findings)
        md = eng.render_markdown_report("up", "claude-3-5-sonnet", m, findings)
        self.assertIn("INCONCLUSIVE", md)
        self.assertIn("部分步骤无回执", md)
        self.assertIn(f"{len(ALL_STEPS) - 1}/{len(ALL_STEPS)}", md)

    def test_report_clean_no_banner(self):
        m = eng.aggregate_matrix(_clean_findings())
        md = eng.render_markdown_report("up", "claude-3-5-sonnet", m, _clean_findings())
        self.assertNotIn("INCONCLUSIVE", md)


class TestAggregateStepFindings(unittest.TestCase):
    """按 step 聚合 + sent 回执（审计 P0-3 真实链路）。"""

    def _plan_with_ids(self):
        plan = eng.build_probe_plan("up", None, profile="general")
        # 固定 probe_id 便于断言
        for i, p in enumerate(plan):
            p["probe_id"] = f"probe_{i}"
        return plan

    def test_sent_probe_ids_controls_coverage(self):
        # 部分探针无回执（未发送成功）→ 对应 step 不建 key → matrix incomplete
        plan = self._plan_with_ids()
        sent = {p["probe_id"] for p in plan if p["step"] != "step10_stream"}
        findings_by_probe = {p["probe_id"]: [] for p in plan}
        step_findings = eng.aggregate_step_findings(plan, findings_by_probe, sent_probe_ids=sent)
        self.assertNotIn("step10_stream", step_findings)
        m = eng.aggregate_matrix(step_findings, steps_expected={p["step"] for p in plan})
        self.assertTrue(m["incomplete"])
        self.assertEqual(m["severity"], "INCONCLUSIVE")

    def test_none_sent_backward_compatible(self):
        # sent_probe_ids=None（旧调用方）→ 所有 plan step 都建 key，行为与原来一致
        plan = self._plan_with_ids()
        findings_by_probe = {p["probe_id"]: [] for p in plan}
        step_findings = eng.aggregate_step_findings(plan, findings_by_probe, sent_probe_ids=None)
        self.assertEqual(set(step_findings.keys()), {p["step"] for p in plan})


if __name__ == "__main__":
    unittest.main()
