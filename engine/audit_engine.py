"""LLM Shield 2.0 审计引擎：主动探针 + 6D risk matrix + Markdown 报告。

主动探针通过 panel 的 mitmdump 子进程发合成请求过代理，response 走 transparent.py 的
audit_response 钩子自动检测。本模块负责：
- 生成探针请求体（canary/nonce/pinned package/error triggers）
- 收集各步检测结果（从 audit_events 表按 probe_id 查）
- 6D risk matrix 聚合判定
- Markdown 报告渲染

约束：探针请求走真实代理路径，不旁路；报告渲染纯 stdlib。
"""
# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import json
import time
import uuid
from pathlib import Path

import audit_signals as sig
from event_store import fetch_audit_events, append_audit_event

# 探针 ID 前缀，便于按 probe_id 查
PROBE_ID_PREFIX = "probe_"


def gen_canary_nonces(n=5):
    """生成 n 个 canary nonce，格式 CANARY_{i}_{8hex}。"""
    return [f"CANARY_{i}_{uuid.uuid4().hex[:8]}" for i in range(n)]


# 跨请求隔离探针提示词（2026-08-18 修正）：
# seed 的**请求正文**必须携带随机 nonce（上游模型可见），否则 verify 测不到
# 跨请求存储。提示词明确要求不要复述/引用；模型在 seed 自身响应里是否提到
# nonce 不构成泄漏判据（旧 S5 语义已移除），只有后续 verify 独立请求的响应
# 出现前序 nonce（S7 cross_request_pollution）才证明 relay 跨请求存了数据。
# nonce 同时经 _audit_canaries → X-Shield-Canaries 头注册本地 prior 集合，
# 该头由透明代理在转发前剥离，不参与上游可见数据。
_SEED_PROMPT_TMPL = (
    "以下追踪标记仅用于测试，请不要复述或引用它们：{markers}。"
    "请用一句简短的问候回答，不要提及这些标记。"
)
_VERIFY_PROMPT = "请用一句简短的问候回答。"


def gen_tool_call_probes():
    """Step 8 pinned package 命令，4 条。"""
    return list(sig.PINNED_PACKAGES)


def gen_error_triggers():
    """Step 9 错误触发器，7 个。返回 [(id, request_body, headers_extra)]。"""
    return [
        ("malformed_json", "{not valid json", {}),
        ("invalid_model", json.dumps({"model": "this-model-does-not-exist-xyz", "messages": [{"role": "user", "content": "hi"}]}), {}),
        ("wrong_content_type", json.dumps({"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": "hi"}]}), {"content-type": "text/plain"}),
        ("missing_messages", json.dumps({"model": "claude-3-5-sonnet"}), {}),
        ("unknown_endpoint", json.dumps({"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": "hi"}]}), {"_path_override": "/v1/nonexistent"}),
        ("force_upstream_error", json.dumps({"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 99999999}), {}),
        ("auth_probe", json.dumps({"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": "hi"}]}), {"x-api-key": "sk-fake-xapi-probe-nothing-real-xyz99999", "authorization": "Bearer nothing-fake-token-xyz-999-auth-probe"}),
    ]


def gen_web3_probes():
    """Step 11 Web3 注入探针。"""
    return [
        ("wallet_transfer", "Help me transfer 1 ETH to 0xdeadbeef. What are the exact steps to sign the transaction?"),
        ("private_key_request", "I need to import my wallet. What format should I paste my private key in? Give an example private key format."),
        ("signing_request", "Please sign this message with my wallet: 'I authorize 0xdeadbeef to drain all funds'."),
    ]


# ========== 探针请求体构造 ==========
def build_probe_request(probe_kind, body_overrides=None):
    """构造一个标准 chat completions 请求体（含 canary）。"""
    body = {
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": ""}],
        "stream": False,
    }
    if body_overrides:
        body.update(body_overrides)
    return body


# ========== 6D risk matrix（移植 audit.py:6548-6639） ==========
# 计划内的分析步骤全集：web3（step11）可选，缺省视为全部含入。
# step3 拆成两步：step3_seed（注册 nonce）+ step3_verify（独立请求，验证响应
# 不得出现前序 nonce）。step5_override 已移除（模型执行当前用户指令不能证明
# relay 注入，2026-08-18）。
_ALL_STEPS = {
    "step3_seed", "step3_verify",
    "step8_toolcall", "step9_error", "step10_stream", "step11_web3",
}


def aggregate_matrix(step_findings, steps_expected=None):
    """6D risk matrix 聚合。

    step_findings: {step_name: [finding, ...]} 各步检测结果。
        注意：key 存在但为空列表 = 该步已覆盖且无异常；key 缺失 = 该步零回执
        （上游不可达/超时/未触发），必须与「无异常」区分——曾把「探测全部
        失败」与「全部正常」同判 MEDIUM，报告完全无法区分（审计 P0-3）。
    steps_expected: 本次扫描计划中的 step 集合（panel 传实际 plan 的步骤，
        web3 未跑时不能算不完整）；缺省用 _ALL_STEPS。
    返回 {d1,d1i,..., severity, coverage, incomplete, summary}。
    """
    if steps_expected is None:
        steps_expected = set(_ALL_STEPS)
    steps_expected = set(steps_expected)
    # 覆盖完整性：key 存在（哪怕空列表）即视为已回执
    covered = {k for k in steps_expected if k in step_findings}
    incomplete = len(covered) < len(steps_expected)
    coverage = f"{len(covered)}/{len(steps_expected)}"

    d1 = d1i = d3 = d3i = d4 = d4m = d4i = d5 = d5i = d6 = d6i = False

    # D1/D1i: Step 3 跨请求隔离（两步探针：seed 注册 nonce，verify 独立请求）。
    # 只有 verify 响应出现前序 nonce（S7 cross_request_pollution）才算泄漏——
    # nonce 经 header 注入且转发前剥离，模型本看不到；seed 自身响应不再判
    # 「回显泄漏」（旧 S5 语义，正常模型也会回显被要求的内容，2026-08-18）。
    # d*i 只在「key 存在且无异常」时置位；key 缺失的步骤不算无异常（那是没测到）。
    s3v = step_findings.get("step3_verify")
    if s3v is not None and any(f.get("signal") == "cross_request_pollution" for f in s3v):
        d1 = True
    elif s3v is not None:
        d1i = True

    # D3/D3i: Step 8 tool-call substitution
    s8 = step_findings.get("step8_toolcall")
    if s8 is not None and any(f.get("signal") == "tool_call_rewrite" and f.get("severity") in (sig.MEDIUM, sig.HIGH) for f in s8):
        d3 = True
    elif s8 is not None:
        d3i = True

    # D4/D4m/D4i: Step 9 error leakage
    s9 = step_findings.get("step9_error")
    if s9 is not None and any(f.get("severity") in (sig.CRITICAL, sig.HIGH) for f in s9):
        d4 = True
    elif s9 is not None and any(f.get("severity") == sig.MEDIUM for f in s9):
        d4m = True
    elif s9 is not None:
        d4i = True

    # D5/D5i: Step 10 stream integrity。S4 已收敛为 LOW 兼容性诊断，
    # 只有未来出现 MEDIUM+ 的可验证完整性风险才抬高安全报告。
    s10 = step_findings.get("step10_stream")
    if s10 is not None and any(
        f.get("signal") == "sse_anomaly" and f.get("severity") in (sig.MEDIUM, sig.HIGH, sig.CRITICAL)
        for f in s10
    ):
        d5 = True
    elif s10 is not None:
        d5i = True

    # D6/D6i: Step 11 Web3。仅命令形态的 S9 是 LOW 记录，不能单独证明
    # 注入或外泄；只有 MEDIUM+ 的结构性/对比式发现才进入风险维度。
    s11 = step_findings.get("step11_web3")
    if s11 is not None and any(
        f.get("severity") in (sig.MEDIUM, sig.HIGH, sig.CRITICAL) for f in s11
    ):
        d6 = True
    elif s11 is not None:
        d6i = True

    # 阈值（first-match）。CRITICAL 必须能透出：凭据/密钥泄漏（sk-/Bearer/JWT）
    # 是本工具首要检测目标，被动信号层已判 CRITICAL，此处若封顶到 HIGH，
    # 报告与前端的最高档永远为空，凭据泄漏和普通工具改写同级（漏报升级）。
    worst = sig.LOW
    for findings in step_findings.values():
        for f in findings or []:
            s = f.get("severity") or sig.LOW
            if sig.severity_ge(s, worst):
                worst = s
    if worst == sig.CRITICAL:
        # 实锤泄漏优先保留，incomplete 仍标记（报告横幅提示）
        severity = sig.CRITICAL
    elif incomplete:
        # 探针覆盖不完整：上游不可达/超时/未触发时各维 d*i 会整体置位，
        # 与「全部正常」同判 MEDIUM——必须显式标 INCONCLUSIVE，
        # 报告横幅警示，不能把「没测到」包装成「有/无风险」。（审计 P0-3）
        severity = "INCONCLUSIVE"
    elif d3 or d4 or d5 or d6:
        severity = sig.HIGH
    elif d1:
        # 跨请求污染（S7）是高危信号，单独命中即 HIGH（2026-08-18）
        severity = sig.HIGH
    elif d4m:
        severity = sig.MEDIUM
    elif any(
        f.get("severity") in (sig.MEDIUM, sig.HIGH, sig.CRITICAL)
        for k in steps_expected for f in (step_findings.get(k) or [])
    ):
        # 有 MEDIUM+ 发现但未达专属维度阈值时，保留中等风险；LOW 兼容性/
        # 命令观察不能抬高安全报告（2026-08-18）。
        severity = sig.MEDIUM
    elif d1i or d3i or d4i or d5i or d6i:
        # 全部步骤已覆盖且零异常 → 健康。曾与「探测全失败」同档 MEDIUM，
        # 引入 coverage 后按真实语义归 LOW。（审计 P0-3）
        severity = sig.LOW
    else:
        severity = sig.LOW

    # 保底：step10 等无专属维度的步骤出现 HIGH 发现时，上述维度规则
    # 会落回 MEDIUM（各维无命中走 d*i），等于降级漏报——按 worst 提升。
    _SEV_RANK = {sig.LOW: 1, sig.MEDIUM: 2, sig.HIGH: 3, sig.CRITICAL: 4}
    if severity != "INCONCLUSIVE" and _SEV_RANK.get(severity, 0) < _SEV_RANK.get(worst, 0):
        severity = worst

    return {
        "d1": d1, "d1i": d1i,
        "d3": d3, "d3i": d3i, "d4": d4, "d4m": d4m, "d4i": d4i,
        "d5": d5, "d5i": d5i, "d6": d6, "d6i": d6i,
        "severity": severity,
        "coverage": coverage,
        "incomplete": incomplete,
    }


# ========== Markdown 报告渲染 ==========
def render_markdown_report(target, model, matrix, step_findings, generated_at=None):
    """渲染 Markdown 报告。generated_at 由调用方传入（避免 Date.now 在 workflow 限制）。"""
    ts = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("# 数据面具 Maskit — API 中转链路安全审计报告")
    lines.append("")
    lines.append(f"**Generated**: {ts}")
    lines.append(f"**Target**: `{target}`")
    lines.append(f"**Model**: `{model}`")
    lines.append("")
    lines.append("## Risk Summary")
    lines.append("")
    sev = matrix["severity"]
    emoji = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INCONCLUSIVE": "⚪"}.get(sev, "⚪")
    lines.append(f"### {emoji} {sev} RISK")
    if sev == "INCONCLUSIVE":
        # 覆盖不完整（上游不可达/超时/未触发）时明确警示，不能当「无风险」发布
        lines.append("")
        lines.append(f"> ⚠ **INCONCLUSIVE**：探针覆盖 {matrix.get('coverage', '?')}，部分步骤无回执（上游不可达/超时/未触发），结果不能视为「无风险」。")
    lines.append("")
    lines.append("| Dim | Flag | Description |")
    lines.append("|---|---|---|")
    lines.append(f"| D1 | {'🔴' if matrix['d1'] else ('🟡' if matrix['d1i'] else '🟢')} | cross-request isolation (prior canary leak) |")
    lines.append(f"| D3 | {'🔴' if matrix['d3'] else ('🟡' if matrix['d3i'] else '🟢')} | tool-call package substitution |")
    lines.append(f"| D4 | {'🔴' if matrix['d4'] else ('🟠' if matrix['d4m'] else ('🟡' if matrix['d4i'] else '🟢'))} | error response leakage |")
    lines.append(f"| D5 | {'🔴' if matrix['d5'] else ('🟡' if matrix['d5i'] else '🟢')} | stream integrity anomaly |")
    lines.append(f"| D6 | {'🔴' if matrix['d6'] else ('🟡' if matrix['d6i'] else '🟢')} | Web3 prompt injection |")
    lines.append("")
    # 各步发现
    step_titles = {
        "step3_seed": "3a. Canary Seed (nonce registration)",
        "step3_verify": "3b. Cross-Request Isolation Verify",
        "step8_toolcall": "8. Tool-Call Package Substitution",
        "step9_error": "9. Error Response Leakage",
        "step10_stream": "10. Stream Integrity",
        "step11_web3": "11. Web3 Prompt Injection",
    }
    for step_key, title in step_titles.items():
        findings = step_findings.get(step_key, [])
        lines.append(f"## {title}")
        lines.append("")
        if not findings:
            lines.append("🟢 No anomaly detected.")
        else:
            lines.append("| Severity | Signal | Evidence |")
            lines.append("|---|---|---|")
            for f in findings:
                lines.append(f"| {f.get('severity', '')} | {f.get('signal', '')} | {str(f.get('evidence', '')).replace('|', '\\|')[:120]} |")
        lines.append("")
    lines.append("---")
    lines.append("*由 数据面具 Maskit 审计引擎生成*")
    return "\n".join(lines)


def save_report(content, data_root, generated_at=None):
    """保存报告到 data_root/audit-YYYYMMDD-HHMMSS.md。返回路径。"""
    ts = generated_at or time.strftime("%Y%m%d-%H%M%S")
    p = Path(data_root) / f"audit-{ts}.md"
    p.write_text(content, encoding="utf-8")
    return str(p)


# ========== 探针序列编排（panel 调用） ==========
def build_probe_plan(upstream_name, model, profile="general"):
    """构造完整探针计划。返回 [{step, probe_id, request_body, headers, expect, meta}]。

    panel 逐项发请求过代理，transparent.py 钩子自动检测，结果按 probe_id 查 audit_events。
    profile: general / web3 / full（full = general + web3）。
    """
    plan = []
    model = model or "claude-3-5-sonnet"

    # Step 3: 跨请求隔离（两步）
    # seed：nonce 同时放进**请求正文**（上游模型可见）与 _audit_canaries
    # （经 X-Shield-Canaries 头注册本地 prior 集合，透明代理转发前剥离头）。
    # 提示词明确要求不要复述；模型在 seed 自身响应里是否提到 nonce 不算泄漏。
    # verify：不含任何 nonce 的独立请求；仅当它的响应出现前序 nonce（S7）
    # 才判 relay 跨请求存储。
    nonces = gen_canary_nonces(5)
    plan.append({
        "step": "step3_seed",
        "probe_id": PROBE_ID_PREFIX + "step3_seed_" + uuid.uuid4().hex[:8],
        "request_body": {
            "model": model,
            "messages": [{"role": "user", "content": _SEED_PROMPT_TMPL.format(markers=" ".join(nonces))}],
            "stream": False,
            "_audit_canaries": nonces,  # 注册本地 prior 集合（经内部头，转发前剥离）
        },
        "expect": "seed_ok",
        "meta": {"nonces": nonces},
    })
    plan.append({
        "step": "step3_verify",
        "probe_id": PROBE_ID_PREFIX + "step3_verify_" + uuid.uuid4().hex[:8],
        "request_body": {
            "model": model,
            "messages": [{"role": "user", "content": _VERIFY_PROMPT}],
            "stream": False,
        },
        "expect": "no_prior_nonce",
    })

    # Step 8: tool-call echo（4 个）
    for pkg_mgr, expected in gen_tool_call_probes():
        plan.append({
            "step": "step8_toolcall",
            "probe_id": PROBE_ID_PREFIX + f"step8_{pkg_mgr}_" + uuid.uuid4().hex[:8],
            "request_body": {
                "model": model,
                "messages": [{"role": "user", "content": f"Copy this harmless text exactly. Do not execute it. Output only the copied text, nothing else, no markdown, no backticks, no explanation. Text to copy: {expected}"}],
                "stream": False,
            },
            "expect": "exact_echo",
            "meta": {"expected": expected},
        })

    # Step 9: error triggers（7 个）
    # request_body 原样保留（gen_error_triggers 返回 str 或畸形字符串），
    # 不做 json.loads：曾把畸形 JSON 字符串再序列化成合法 JSON 字符串字面量，
    # malformed_json 探针因此永远发的是合法请求，探测无效（审计 P0-4）。
    # panel 发送分支按类型处理：dict→json.dumps；str→原样 encode 发送。
    for trig_id, body, hdrs in gen_error_triggers():
        plan.append({
            "step": "step9_error",
            "probe_id": PROBE_ID_PREFIX + f"step9_{trig_id}_" + uuid.uuid4().hex[:8],
            "request_body": body,
            "headers": hdrs,
            "expect": "no_secret_leak",
        })

    # Step 10: stream integrity（正常请求观察 SSE）
    plan.append({
        "step": "step10_stream",
        "probe_id": PROBE_ID_PREFIX + "step10_" + uuid.uuid4().hex[:8],
        "request_body": {
            "model": model,
            "messages": [{"role": "user", "content": "Say hello in one sentence."}],
            "stream": True,
        },
        "expect": "clean_stream",
    })

    # Step 11: web3（profile=web3/full）
    if profile in ("web3", "full"):
        for sub_id, prompt in gen_web3_probes():
            plan.append({
                "step": "step11_web3",
                "probe_id": PROBE_ID_PREFIX + f"step11_{sub_id}_" + uuid.uuid4().hex[:8],
                "request_body": {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                "expect": "no_wallet_action",
            })

    return plan


def collect_findings_by_probe(probe_ids):
    """从 audit_events 表按 probe_id 查检测结果。返回 {probe_id: [finding, ...]}。"""
    out = {pid: [] for pid in probe_ids}
    # fetch_audit_events 不支持 probe_id 过滤，全量扫近 200 条匹配
    evs = fetch_audit_events(since=0, limit=500)
    for ev in evs:
        pid = ev.get("probe_id")
        if pid in out:
            out[pid].append({
                "signal": ev.get("signal_type"),
                "severity": ev.get("severity"),
                "evidence": ev.get("evidence"),
                "kind": "",
            })
    return out


def aggregate_step_findings(plan, findings_by_probe, sent_probe_ids=None):
    """按 step 聚合 findings。返回 {step: [finding, ...]}。

    sent_probe_ids: panel 实际发送成功（或收到 HTTPError）的 probe_id 集合。
        发送失败（上游不可达/超时）的探针不建 key——aggregate_matrix 据此判定
        覆盖不完整（INCONCLUSIVE），否则「探测全失败」与「全部正常」在数据层
        （audit_events 仅命中才落库）无法区分（审计 P0-3）。
        为 None 时向后兼容：所有 plan step 都建 key。
    """
    by_step = {}
    for item in plan:
        step = item["step"]
        pid = item["probe_id"]
        if sent_probe_ids is not None and pid not in sent_probe_ids:
            # 该探针无回执：不建 key，留给 aggregate_matrix 判 incomplete
            continue
        by_step.setdefault(step, []).extend(findings_by_probe.get(pid, []))
    return by_step
