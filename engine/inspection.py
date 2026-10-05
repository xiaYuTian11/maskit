"""检测结论与完整度的统一口径（批次 2 / §B）。

不新建平行机制：数据源仍是既有的 `ner_skip_reasons`、命令拦截记录、审计截断标记与
本轮新增的 `signed_blocks_skipped`；本模块只负责**归一化 + 码表 + 纯函数派生**，
供代理路径（MASK/BLOCK 事件）与扩展桥接（`/api/ext/*`）**同口径**使用——
v1 的教训：只落代理路径，扩展用户依然看到「0 命中」。

口径约定：
- `decision`：这次请求的处置结论（四选一）；
- `completeness`：**所配置的检测**执行到什么程度；`complete` 只表示「已执行完」，
  **不保证现实中没有漏检**（诚实声明）；
- `reason_codes`：原因码计数，复用 `ner_skip_reasons` 的 `{code: count}` 形态。

本模块遵循 `audit_signals.py` 的纪律：纯 stdlib、永不抛异常、调用点在热路径上。
"""
from __future__ import annotations

DECISION_MASKED = "masked"              # 有内容被替换成占位符
DECISION_SCANNED_CLEAN = "scanned_clean"  # 扫了，没命中
DECISION_BLOCKED = "blocked"            # 主动阻断（fail-closed / 严格模式 / 体积闸）
DECISION_PASSTHROUGH = "passthrough"  # 明确直通（未脱敏）

# 完整度（语义：所配置的检测执行到哪一步）
COMPLETE = "complete"
PARTIAL = "partial"
FAILED = "failed"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"

# 原因码 →（类别，短说明）。
# 类别决定两件事：
#  ｜ degraded：检测没跑完（→ `partial`；严格模式下这些码是申请阻断的依据）
#  ｜ exempt ：按协议契约故意不扫（不算降级，但必须可见）
#  ｜ blocked ：主动阻断
#  ｜ info   ：过程信息，与完整度无关
REASON_CODES = {
    # NER / 语义识别降级
    "budget_exhausted": ("degraded", "语义识别预算耗尽"),
    "deadline": ("degraded", "语义识别达到时间上限"),
    "sem_timeout": ("degraded", "语义识别单段超时"),
    "infer_failed": ("degraded", "语义推理异常"),
    "model_unavailable": ("degraded", "语义模型不可用"),
    "model_missing": ("degraded", "语义模型文件缺失"),
    "global_throttled": ("degraded", "语义推理被限流"),
    "om_compose": ("degraded", "坐标合成降级，跳过语义识别"),
    "runtime": ("degraded", "语义识别运行时降级"),
    # 协议契约豁免
    "signed_blocks_skipped": ("exempt", "签名/密文思考块按协议契约整块未扫描"),
    # 主动阻断
    "request_too_large": ("blocked", "请求体超过体积闸"),
    "engine_busy": ("blocked", "并发准入不足"),
    "engine_timeout": ("blocked", "引擎端到端超时"),
    "pipeline_error": ("blocked", "脱敏管线异常（fail-closed）"),
    "command_blocked": ("blocked", "危险命令被阻断"),
    "semantic_incomplete": ("blocked", "严格模式：本次语义检测未完整执行"),
    # 过程信息
    "cancelled": ("info", "请求已取消"),
    "not_target": ("info", "未命中配置的客户端/路径，明文直通"),
    "host_not_configured": ("info", "客户端未配置，明文直通"),
    "path_not_configured": ("info", "路径未命中，明文直通"),
    "no_reverse_route": ("info", "未命中任何上游，明文直通"),
    "response_too_large": ("degraded", "响应体超上限，未还原"),
    "unresolved_tokens": ("degraded", "存在未能还原的占位符"),
    "audit_truncated": ("degraded", "响应审计未覆盖整个响应体"),
}

# 严格模式下应当阻断的原因码（“模型明确不适用”与纯过程信息不阻断）。
BLOCKING_CATEGORIES = frozenset({"degraded"})


def reason_category(code: str) -> str:
    """原因码 → 类别（未知码按 info 处理，不让未知码把完整度打成 partial）。"""
    return REASON_CODES.get(code, ("info", ""))[0]


def summary_of(reasons: dict | None) -> dict:
    """把「本轮原因」过滤成 {code: count} 形态（去空、保序），供 reason_codes 上报。"""
    if not reasons:
        return {}
    return {k: int(v) for k, v in reasons.items() if v}


def has_blocking_reason(reasons: dict | None) -> bool:
    """严格模式判定：是否存在「检测没跑完」类原因（降级 → 阻断依据）。

    `cancelled` 等 info 类、`signed_blocks_skipped` 等 exempt 类不在此列——
    exempt 是协议契约的显式例外，阻断它等于把参考实现自己锁定的行为当故障。
    """
    if not reasons:
        return False
    return any(reason_category(k) in BLOCKING_CATEGORIES for k in reasons.keys() if reasons.get(k))


def completeness_of(reasons: dict | None, *, failed=False) -> str:
    """由本轮原因码集合派生完整度。

    failed 只在「事件本身就是阻断」时用（503/fail-closed 没有正常完成可言）；
    exempt 类原因不把 `complete` 降成 `partial`（那是契约内的显式不扫面，
    「所配置的检测」定义里就不含它——但调用方必须把数量放进 reason_codes 保持可见）。
    """
    if failed:
        return FAILED
    if not reasons:
        return COMPLETE
    if any(reason_category(k) in BLOCKING_CATEGORIES for k in reasons if reasons.get(k)):
        return PARTIAL
    return COMPLETE


def decision_of(*, changed: bool, blocked: bool = False, passthrough: bool = False) -> str:
    """处置结论：阻断 > 直通 > 已脱敏 > 扫描未命中（同一请求只可能落在其中一类）。"""
    if blocked:
        return DECISION_BLOCKED
    if passthrough:
        return DECISION_PASSTHROUGH
    return DECISION_MASKED if changed else DECISION_SCANNED_CLEAN


def report_for_mask(*, changed: bool, ner_skips: dict | None = None, signed_skipped: int = 0) -> dict:
    """MASK 事件 / `/api/ext/mask` 响应的统一上报口径。

    `signed_skipped` 是「签名思考块整块未扫描」的块数（exempt 类）：它不把完整度降成
    `partial`（属协议契约内的显式不扫面），但必须出现在 `reason_codes` 里保持可见。
    """
    reasons = dict(ner_skips or {})
    if signed_skipped:
        reasons["signed_blocks_skipped"] = int(signed_skipped)
    return build_report(decision=decision_of(changed=changed), reasons=reasons)


def report_for_skip(*, reason: str, blocked: bool = False) -> dict:
    """SKIP / PASS / BLOCK 事件的上报口径：区分「明确直通」与「主动阻断」。"""
    reasons = {reason: 1} if reason else None
    return build_report(
        decision=decision_of(changed=False, blocked=blocked, passthrough=not blocked),
        reasons=reasons,
        failed=blocked,
    )


def report_for_restore(*, unresolved: int = 0) -> dict:
    """RESTORE 侧：只把「未还原的占位符」计入完整度，不伪造其它结论。

    还原不是扫描，所以不带 `decision`；`reason_codes` 里的 `unresolved_tokens` 已能
    表达“这条回复里还有东西没还原”，UI 据此提示用户。
    """
    reasons = {"unresolved_tokens": int(unresolved)} if unresolved else None
    return {"completeness": completeness_of(reasons), **({"reason_codes": reasons} if reasons else {})}


def build_report(*, decision: str, reasons: dict | None = None, failed: bool = False, completeness: str | None = None) -> dict:
    """组装对外上报的三元组（空原因时省略字段，避免常态噪声）。"""
    out = {"decision": decision}
    out["completeness"] = completeness or completeness_of(reasons, failed=failed)
    codes = summary_of(reasons)
    if codes:
        out["reason_codes"] = codes
    return out