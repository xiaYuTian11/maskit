"""一键自检：让程序自己说出「哪里不对」。

定位（与既有「诊断包」的分工）：
  · 诊断包（`panel._diagnostics_payload`）= **原始证据**，给维护者看；
  · 本模块 = **结论**（问题 + 证据 + 下一步动作），给用户自己看。
自检结论会嵌进诊断包（schema 2），所以入口只有一个，不重复造导出。

为什么规则引擎要独立成模块：
  ① 纯函数、不 import 引擎其余部分、不碰网络、**永不抛异常** —— 可以脱离
     mitmdump / Flask 直接单测（`tests/test_selfcheck.py`）；
  ② 每一条判据都能被"喂构造输入 → 断言结论"覆盖，包括"取数失败不许误报"。

输入由调用方（panel 的 `/api/selfcheck`）组装，见 `build_inputs` 的字段说明。
"""
from __future__ import annotations

import contextvars
import os
import platform
import shutil
import sys
import time
from pathlib import Path

SCHEMA = 1


# ── 双语（英文界面不该出现中文结论） ─────────────────────────────────────
# 为什么放在引擎而不是前端字典：22 条规则的 evidence 里嵌着**动态值**
# （端口号、毫秒、计数），搬到前端就得为每条规则再造一套结构化参数契约
# （params 提取 + 模板插值 + 渲染改造）。这里让每条规则自己给出英文分支，
# 输入仍是同一份 ctx、仍在同一个函数里，中英文案**相邻可对照**，
# 漏译一处也一眼能看出来。语言由调用方（panel 的 /api/selfcheck）传入。
_LANG = contextvars.ContextVar("selfcheck_lang", default="zh")


def _is_en():
    return str(_LANG.get() or "zh").lower().startswith("en")


def _en(fid, severity, title, evidence, action, verified=True):
    """英文结论：与 `_finding` 同构，只在 lang=en 时被各规则返回。"""
    return {"id": fid, "severity": severity, "title": title, "evidence": evidence,
            "action": action, "verified": bool(verified)}


def _en_detail(text, empty=""):
    """英文结论里的**叙述性中文**兜底。

    引擎自己的错误串是中文（模型缺失、权限不足…），英文分支直接插值就会冒出中文结论
    （实测：S04/S21 把 `ner.last_error` 原样带出）。命中 CJK 就换成英文定述 —— 原文没丢，
    它仍在诊断包与事件库里，中文界面照常显示。
    """
    s = str(text or "")
    if not s:
        return empty
    if any("\u4e00" <= ch <= "\u9fff" for ch in s):
        return "(Chinese error text; see the diagnostics bundle)"
    return s


def _dig(data, path, default=None):
    """按点号路径取值（自检规则里的字段引用很多，写成一串 get 太啰嗦）。"""
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
        if cur is None:
            return default
    return cur


def _num(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


# ══════════════════════════════════════════════════════════════════════════
# 环境探测（纯 stdlib、永不抛异常）
# ══════════════════════════════════════════════════════════════════════════
# 上一次采样的 cgroup 限流计数：S26 要看"窗口内增长"，没有基线就只能报绝对值
# （并标记 verified=False —— 宁可说"未验证"，也不能把绝对值说成"正在被限流"）。
_LAST_THROTTLE = {"ts": 0.0, "nr": None}


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def _cgroup_cpu():
    """返回 (配额核数 | None, 累计被限流次数 | None, cgroup 版本)。"""
    # v2：cpu.max = "quota period"（quota 为 max 表示不限）
    raw = _read_text("/sys/fs/cgroup/cpu.max")
    if raw:
        parts = raw.split()
        quota = _num(parts[0], 0.0) if parts and parts[0] != "max" else 0.0
        period = _num(parts[1], 100000.0) if len(parts) > 1 else 100000.0
        nr = None
        for line in _read_text("/sys/fs/cgroup/cpu.stat").splitlines():
            if line.startswith("nr_throttled "):
                nr = int(_num(line.split()[1], 0))
        cores = round(quota / period, 2) if quota > 0 and period > 0 else None
        return cores, nr, "v2"
    # v1：cpu.cfs_quota_us / cpu.cfs_period_us
    quota = _num(_read_text("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"), -1.0)
    period = _num(_read_text("/sys/fs/cgroup/cpu/cpu.cfs_period_us"), 0.0)
    nr = None
    for line in _read_text("/sys/fs/cgroup/cpu/cpu.stat").splitlines():
        if line.startswith("nr_throttled "):
            nr = int(_num(line.split()[1], 0))
    cores = round(quota / period, 2) if quota > 0 and period > 0 else None
    return cores, nr, "v1" if (cores is not None or nr is not None) else ""


def _cgroup_mem_mb():
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        raw = _read_text(path)
        if raw and raw != "max":
            mb = _num(raw, 0.0) / (1024 * 1024)
            if 1 <= mb < 1024 * 1024 * 4:      # 排除"实际等于无限制"的哨兵值
                return round(mb, 1)
    return None


def _effective_cpu_count():
    """本进程实际可用核数；拿不到 ner_engine（拆包运行）就回落到宿主核数。

    判据本体在 `ner_engine.effective_cpu_count()`，这里只做一次带兵底的转发：
    自检进程（panel）与引擎进程可能不同，不能假设模块一定在。
    不要 import transparent —— panel 不装 mitmproxy，一 import 就把自检打死了。
    """
    try:
        import ner_engine
        return max(1, int(ner_engine.effective_cpu_count()))
    except Exception:
        return max(1, int(os.cpu_count() or 2))


def probe_environment(data_root=None):
    """环境探测：容器 / CPU 配额 / 限流计数 / 内存上限 / 磁盘 / 版本。

    `verified` 语义见 S26：只有拿到**窗口内增量**才敢说"正在被限流"。
    """
    out = {
        "cpu_count": os.cpu_count(),
        # 实际可用核数（cgroup 配额 ∩ 亲和性掩码）：进程内所有池宽 / ONNX 线程数 /
        # 预算容量都是按它算的。报上去才能回答「为什么 2 核机器上 CPU 百分百」。
        "effective_cpu_count": _effective_cpu_count(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "arch": platform.machine(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "in_container": Path("/.dockerenv").exists() or bool(_read_text("/proc/1/cgroup")),
    }
    try:
        cores, nr, ver = _cgroup_cpu()
        out["cgroup_version"] = ver
        out["cgroup_cpu_quota"] = cores
        out["cgroup_nr_throttled"] = nr
        now = time.time()
        prev_nr, prev_ts = _LAST_THROTTLE["nr"], _LAST_THROTTLE["ts"]
        if nr is not None and prev_nr is not None and now > prev_ts:
            out["nr_throttled_delta"] = max(0, nr - prev_nr)
            out["nr_throttled_window_s"] = round(now - prev_ts, 1)
        else:
            out["nr_throttled_delta"] = None
        if nr is not None:
            _LAST_THROTTLE["nr"] = nr
            _LAST_THROTTLE["ts"] = now
    except Exception as e:
        out["cgroup_error"] = f"{type(e).__name__}: {e}"
    try:
        out["mem_limit_mb"] = _cgroup_mem_mb()
    except Exception:
        out["mem_limit_mb"] = None
    try:
        usage = shutil.disk_usage(str(data_root) if data_root else ".")
        out["disk_free_mb"] = round(usage.free / (1024 * 1024), 1)
        out["disk_total_mb"] = round(usage.total / (1024 * 1024), 1)
        out["disk_path"] = str(data_root or ".")
    except Exception as e:
        out["disk_error"] = f"{type(e).__name__}: {e}"
    return out


# ══════════════════════════════════════════════════════════════════════════
# 规则
# ══════════════════════════════════════════════════════════════════════════
def _finding(fid, severity, title, evidence, action, verified=True):
    """一条结论。`verified=False` = 数据不足，**必须**在界面上标出来。

    刻意不给"文档链接"这类字段留位：留着就会有人填一个指向 README 的泛泛链接，
    而结论页真正需要的是"现在该点哪里"，不是"再读一遍手册"。
    """
    return {"id": fid, "severity": severity, "title": title, "evidence": evidence,
            "action": action, "verified": bool(verified)}


def _s01(ctx):
    if _dig(ctx, "proxy.running", False):
        return None
    if _is_en():
        return _en("S01", "high", "Proxy is not running: requests are not masked",
                   "proxy.running=false" + ("; fallback_mode=%s" % _dig(ctx, "proxy.fallback_mode", ""))
                   if _dig(ctx, "proxy.fallback_mode") else "proxy.running=false",
                   "Start the proxy in the panel; if it just crashed, check the last error reported by S04")
    return _finding("S01", "high", "代理未运行：当前请求不会被脱敏",
                    "proxy.running=false" + ("；fallback_mode=%s" % _dig(ctx, "proxy.fallback_mode", ""))
                    if _dig(ctx, "proxy.fallback_mode") else "proxy.running=false",
                    "在面板点「启动代理」；若刚崩溃过，先看 S04 的最近错误")


def _s02(ctx):
    mode = str(_dig(ctx, "proxy.fallback_mode", "") or "")
    if _dig(ctx, "proxy.running", False) or mode != "error":
        return None
    if _is_en():
        return _en("S02", "high", "Fallback listener is answering 503 (shield_unavailable)",
                   "stop_mode=error: the port is still listening but rejects every request",
                   "Start the proxy, or set stop_mode to passthrough (availability first)")
    return _finding("S02", "high", "兜底层正在回 503（shield_unavailable）",
                    "stop_mode=error，端口仍在监听但拒绝一切请求",
                    "启动代理；或把 stop_mode 改为 passthrough（可用性优先）")


def _s03(ctx):
    ports = _dig(ctx, "proxy.ports", []) or []
    bad = [p for p in ports if isinstance(p, dict) and p.get("listening") and p.get("holder") not in ("mitmdump", "panel")]
    if not bad:
        return None
    if _is_en():
        return _en("S03", "high", "Port held by another process",
                   "; ".join("port %s held by %s" % (x.get("port"), x.get("holder") or "unknown")
                             for x in bad),
                   "Close the program holding the port (often another proxy or VPN), or change Maskit's listen port")
    return _finding("S03", "high", "端口被其他进程占用",
                    "; ".join("端口 %s 被 %s 占用" % (p.get("port"), p.get("holder") or "未知进程") for p in bad),
                    "关掉占用该端口的程序（常见是另一个代理/VPN），或改 Maskit 的监听端口")


def _s04(ctx):
    restarts = int(_num(_dig(ctx, "proxy.restarts", 0)))
    last_err = str(_dig(ctx, "proxy.last_error", "") or "")
    if restarts < 3 and not last_err:
        return None
    if _is_en():
        return _en("S04", "high", "Engine restarted repeatedly or reported errors",
                   "restarts=%d; last_error=%s" % (restarts, _en_detail(last_err[:200], "(empty)")),
                   "Export the diagnostics bundle to inspect the crash site; verify the data dir is writable and dependencies are complete")
    return _finding("S04", "high", "引擎反复重启或最近报错",
                    "restarts=%d；last_error=%s" % (restarts, last_err[:200] or "（空）"),
                    "导出诊断包查看崩溃现场；确认数据目录可写、依赖完整")


def _s10(ctx):
    n503 = int(_num(_dig(ctx, "events.by_status.503", 0)))
    if n503 <= 0:
        return None
    src = _dig(ctx, "events.by_block_source", {}) or {}
    up = int(_num(src.get("upstream"), 0))
    eng = int(_num(src.get("engine"), 0))
    fb = int(_num(src.get("fallback"), 0))
    known = up + eng + fb
    window = int(_num(_dig(ctx, "events.window_s", 3600)) / 60)
    parts = []
    if up:
        parts.append("上游返回 %d" % up)
    if eng:
        parts.append("本机拦截 %d" % eng)
    if fb:
        # 兜底监听把同类事件节流到 30s 一条：这里的"兜底占位 N"是**事件条数**而非请求数，
        # 写清口径免得被当成精确比例（真实压力看引擎的 busy/timeout 指标）。
        parts.append("兜底占位 %d 条（该来源事件按 30s 节流，条数≠请求数）" % fb)
    evidence = "最近 %d 分钟共 %d 次 503" % (window, n503)
    if known:
        evidence += "（" + " / ".join(parts) + "）"
    else:
        evidence += "（缺少来源字段，无法拆分：多为旧版本写入的历史事件）"
    if eng or fb:
        action = ("本机拦截属于 fail-closed 命中：看事件详情里的 reason 与规则名，"
                  "确认是误伤还是真的拦截（reason=engine_busy 表示队列满，"
                  "engine_timeout 表示超过端到端上限）")
    elif up:
        action = ("这些 503 由上游/中转返回，Maskit 只是如实记录；多个智能体共用同一个 "
                  "key 时通常是上游限流或并发上限，建议降低并发、增大客户端重试退避，或换 key")
    else:
        action = "先确认来源：升级到 0.6.0 后事件会带 block_source 字段"
    # 兜底来源的事件是**按 30s 节流**写入的，所以当它参与计数时，`n503` 只是**下界**
    # （10 分钟的兜底风暴可能只记 20 条）。这时结论不能标"已验证"：数字本身是保守的，
    # 用户不该据此判断"量级不大"。
    if _is_en():
        en_parts = []
        if up:
            en_parts.append("upstream %d" % up)
        if eng:
            en_parts.append("local blocks %d" % eng)
        if fb:
            en_parts.append("fallback %d (throttled to one event per 30s, so count != requests)" % fb)
        if known:
            en_ev = "%d 503s in the last %d min (%s)" % (n503, window, " / ".join(en_parts))
        else:
            en_ev = ("%d 503s in the last %d min (no source field: written by an older version)"
                     % (n503, window))
        if eng or fb:
            en_act = ("Local blocks are fail-closed hits: read reason and rule in the event detail "
                      "(engine_busy = queue full, engine_timeout = past the deadline)")
        elif up:
            en_act = ("These 503s come from the upstream provider; with several agents sharing one key "
                      "it is usually rate limiting - lower concurrency, back off more, or change the key")
        else:
            en_act = "Confirm the source: events carry block_source since 0.6.0"
        return _en("S10", "high" if n503 >= 3 else "medium", "503 responses detected",
                   en_ev, en_act, verified=bool(known) and fb == 0)
    return _finding("S10", "high" if n503 >= 3 else "medium",
                    "检测到 503 响应", evidence, action,
                    verified=bool(known) and fb == 0)


def _s11(ctx):
    up_p50 = _dig(ctx, "events.upstream_ms.p50")
    errs = int(_num(_dig(ctx, "events.by_status.5xx", 0)))
    # 口径必须写出来：p50 取自**最新 N 条**样本（N = events.upstream_ms.n），而 5xx
    # 是**全窗口**计数。两者不是同一个集合，混着读会把“样本里很快”当成“整体很快”。
    #
    # ⚠️ `n <= 0` 必须先判：`aggregate_recent` 的默认值是 `{"p50": 0.0, "n": 0}`，
    # 零样本时 p50 恒为 0 → `0 ≤ 300` 成立 → 会凭“没有数据”断言“上游秒拒”，
    # 并给出“核对限流/配额”这种指向错误的建议。没采到样本就不该下这个结论。
    n = int(_num(_dig(ctx, "events.upstream_ms.n", 0)))
    if errs <= 0 or n <= 0 or up_p50 is None or _num(up_p50) > 300:
        return None
    if _is_en():
        return _en("S11", "medium", "Upstream fails fast (rejection rather than timeout)",
                   "5xx %d in the whole window; upstream_ms p50=%.0fms over the latest %d samples"
                   % (errs, _num(up_p50), n),
                   "Usually rate limit, quota or auth: check the provider concurrency and quota, then back off and retry")
    return _finding("S11", "medium", "上游很快返回错误（不像超时，更像被网关直接拒绝）",
                    "5xx %d 次（全窗口计数），样本内 upstream_ms p50=%.0fms（基于最新 %d 条）"
                    % (errs, _num(up_p50), n),
                    "多为限流/配额/鉴权被拒：核对供应商的并发与额度，必要时退避重试")


def _s12(ctx):
    storms = _dig(ctx, "events.retry_storms", []) or []
    if not storms:
        return None
    top = storms[0]
    if _is_en():
        return _en("S12", "medium", "Client is retrying automatically (amplifies load)",
                   "%s was requested %d times within 60s (%d other paths look similar)"
                   % (top.get("path") or "?", int(_num(top.get("count"))), max(0, len(storms) - 1)),
                   "Turn off client/plugin auto-retry or raise the retry interval - duplicates multiply upstream and masking pressure")
    return _finding("S12", "medium", "客户端在自动重试（会放大负载）",
                    "%s 在 60 秒内被请求 %d 次（其余 %d 个路径也有类似形态）"
                    % (top.get("path") or "?", int(_num(top.get("count"))), max(0, len(storms) - 1)),
                    "关掉客户端/插件的自动重试，或把重试间隔调大（重复请求会成倍放大上游与脱敏压力）")


def _s20(ctx):
    if not _dig(ctx, "ner.enabled", False):
        return None
    cores = (_dig(ctx, "env.effective_cpu_count")
             or _dig(ctx, "env.cgroup_cpu_quota") or _dig(ctx, "env.cpu_count"))
    # 取不到核数就**不判**：把"没数据"当成"核少"会误报一次高危，而自检的高危
    # 是要用户立刻动手的（宁可少报一条，也不要让结论页失去可信度）。
    if cores is None or _num(cores) <= 0 or _num(cores) > 2:
        return None
    if _is_en():
        return _en("S20", "high", "Semantic recognition (NER) is on but usable CPU is very low",
                   "%s usable cores (cgroup quota wins over physical cores); NER is pure CPU inference and on "
                   "so few cores is usually this process's biggest CPU consumer (inferred, not measured)"
                   % (cores,),
                   "Turn semantic recognition off in Settings, or give the container/machine more CPU "
                   "(1-2 cores will noticeably slow every request)")
    return _finding("S20", "high", "语义识别（NER）开启，但可用 CPU 很少",
                    "可用核数 %s（cgroup 配额优先于物理核数）；语义识别是纯 CPU 推理，"
                    "在这么少的核数上通常是本进程最大的 CPU 消耗方（推断，未实测）"
                    % (cores,),
                    "在设置页关闭「语义识别」，或给容器/机器更多 CPU（1~2 核跑 NER 会明显拖慢全部请求）")


def _s21(ctx):
    if not _dig(ctx, "ner.enabled", False):
        return None
    available = bool(_dig(ctx, "ner.available", False))
    initialized = bool(_dig(ctx, "ner.initialized", False))
    failed = bool(_dig(ctx, "ner.failed", False))
    if available and initialized and not failed:
        return None
    if _is_en():
        return _en("S21", "high",
                   "Semantic recognition looks enabled but is not running: model unavailable",
                   "available=%s initialized=%s failed=%s last_error=%s"
                   % (available, initialized, failed,
                      _en_detail(str(_dig(ctx, "ner.last_error", "") or "")[:160])),
                   "Verify models/ner_mini_zh has all three files and onnxruntime/tokenizers are installed; "
                   "container images must be built with the model (local builds ship no model)")
    return _finding("S21", "high",
                    "语义识别「看起来开了、其实没做」：模型不可用",
                    "available=%s initialized=%s failed=%s last_error=%s"
                    % (available, initialized, failed, str(_dig(ctx, "ner.last_error", "") or "")[:160]),
                    "确认引擎目录下 models/ner_mini_zh 三个文件齐全、onnxruntime/tokenizers 已安装；"
                    "容器镜像需使用带模型的构建（本地构建默认不含模型）")


def _s22(ctx):
    skips = _dig(ctx, "ner.skips", {}) or {}
    if not skips:
        return None
    owned = {k: int(_num(v)) for k, v in skips.items() if _num(v) > 0}
    if not owned:
        return None
    if _is_en():
        return _en("S22", "medium", "Semantic recognition degraded (some text was not recognized)",
                   "; ".join("%s x%d" % (k, v) for k, v in sorted(owned.items())),
                   "global_throttled/sem_timeout: concurrency is too high (rate protection) - lower concurrency or "
                   "raise MASKIT_NER_BUDGET / MASKIT_NER_WAIT_MS knowingly; "
                   "budget_exhausted/deadline: the per-request NER budget ran out (big body or over-long text) - "
                   "expected degradation; raise ner_req_budget_s only if you accept the added latency")
    return _finding("S22", "medium", "语义识别有降级（部分文本未做识别）",
                    "；".join("%s×%d" % (k, v) for k, v in sorted(owned.items())),
                    "若为 global_throttled/sem_timeout：并发太高，属于限流保护，"
                    "可降并发或（明确知道代价时）调大 MASKIT_NER_BUDGET；"
                    "若为 budget_exhausted/deadline：单请求语义识别预算用尽（大 body 或超长文本），"
                    "属预期降级；确认可接受后再调 ner_req_budget_s，"
                    "调大等于把脱敏时长推向客户端的解包超时窗口")


def _engine_fresh(ctx):
    """引擎指标是不是**当下**的（缺失或过期都算不新鲜）。

    这些计数器来自引擎写出的 `engine-runtime.json`（过期阈值 180s）。拿一份几小时前的
    快照断言"现在正在排队"，结论页就变成误导 —— 所以要么标未验证，要么别报。
    """
    return not bool(_dig(ctx, "engine.metrics_stale", True))


def _s23(ctx):
    busy = int(_num(_dig(ctx, "engine.mask_pool.busy_total", 0)))
    peak_wait = _num(_dig(ctx, "engine.mask_pool.peak_wait_ms", 0))
    depth = _num(_dig(ctx, "engine.mask_pool.queue_depth", 0))
    if busy <= 0 and peak_wait < 2000 and depth <= 0:
        return None
    if _is_en():
        return _en("S23", "high" if busy > 0 else "medium",
                   "Mask queue is backing up (requests wait for a free mask worker)",
                   "%d backpressure rejections; peak wait %.0fms; current queue depth %.0f; pool width %s"
                   % (busy, peak_wait, depth, _dig(ctx, "engine.mask_pool.workers")),
                   "Lower concurrency (most visible with several agents); raise MASKIT_MASK_WORKERS only with spare cores; "
                   "busy means backpressure fired - clients should back off",
                   verified=_engine_fresh(ctx))
    return _finding("S23", "high" if busy > 0 else "medium",
                    "脱敏队列出现排队（请求在等空闲的脱敏线程）",
                    "busy 拒服务 %d 次；峰值排队 %.0fms；当前队列深度 %.0f；池宽 %s"
                    % (busy, peak_wait, depth, _dig(ctx, "engine.mask_pool.workers")),
                    "降低并发（多智能体同时跑时最明显）；确有多核余量可调大 MASKIT_MASK_WORKERS；"
                    "busy 说明已触发背压保护，客户端应退避重试",
                    verified=_engine_fresh(ctx))


def _s24(ctx):
    trunc = int(_num(_dig(ctx, "engine.audit.truncated", 0)))
    skipped = int(_num(_dig(ctx, "engine.audit.parse_skipped", 0)))
    p95 = _num(_dig(ctx, "engine.audit.p95_ms", 0))
    if trunc <= 0 and skipped <= 0 and p95 < 150:
        return None
    if _is_en():
        return _en("S24", "medium", "Audit scan truncated by budget, or a large response was not parsed",
                   "truncated %d; parse skipped %d; audit p95=%.0fms (window %sKB; engine-lifetime counters, not windowed)"
                   % (trunc, skipped, p95, int(_num(_dig(ctx, "engine.audit.scan_max", 0)) / 1024)),
                   "Truncation means very large responses: scanning only the head is a deliberate trade-off. "
                   "Edit audit.scan_max in config.json for full coverage (no Settings control; 16KB-512KB, linear CPU cost)",
                   verified=_engine_fresh(ctx))
    return _finding("S24", "medium", "审计扫描被预算截断或有超长响应未被解析",
                    "截断 %d 次；跳过解析 %d 次；审计耗时 p95=%.0fms（窗口 %sKB，"
                    "均为引擎累计计数而非窗口内）"
                    % (trunc, skipped, p95, int(_num(_dig(ctx, "engine.audit.scan_max", 0)) / 1024)),
                    "出现截断说明有超大响应体：审计只扫前段属预期取舍；"
                    "如需完整覆盖可手改 config.json 的 audit.scan_max（设置页没有该控件；"
                    "键会被保留，范围 16KB~512KB，调大线性增加 CPU）",
                    verified=_engine_fresh(ctx))


def _s25(ctx):
    per_min = _num(_dig(ctx, "events.per_minute", 0))
    if per_min <= 50:
        return None
    if _is_en():
        return _en("S25", "medium", "Unusual event rate (possible storm)",
                   "%.1f events/min in the recent window" % per_min,
                   "Read together with S12: usually client retries or a process hammering the proxy; "
                   "confirm it is not your own script looping")
    return _finding("S25", "medium", "事件速率异常（疑似风暴）",
                    "最近窗口平均 %.1f 事件/分钟" % per_min,
                    "结合 S12 一起看：多为客户端重试或某个进程在刷请求；确认不是自己脚本在打循环")


def _s26(ctx):
    delta = _dig(ctx, "env.nr_throttled_delta")
    if delta is None:
        nr = _dig(ctx, "env.cgroup_nr_throttled")
        if nr is None:
            return None
        if _is_en():
            return _en("S26", "low", "Host CPU was throttled before (window delta unavailable)",
                       "%s total throttling events (a first run has no baseline, so it cannot tell whether it is still happening)"
                       % nr,
                       "Run the self-check again to get the window delta; if it keeps growing the CPU quota is too small",
                       verified=False)
        return _finding("S26", "low", "本机 CPU 曾触发 cgroup 限流（未能计算窗口内增量）",
                        "累计被限流 %s 次（首次自检没有基线，无法判断是否仍在发生）" % nr,
                        "再跑一次自检即可得到窗口内增量；若持续增长，说明 CPU 配额不够",
                        verified=False)
    if _num(delta) <= 0:
        return None
    if _is_en():
        return _en("S26", "high", "CPU is saturated and throttled by the container",
                   "%d new throttling events in the window (quota %s cores)"
                   % (int(_num(delta)), _dig(ctx, "env.cgroup_cpu_quota")),
                   "Give the container more CPU, lower concurrency, or turn semantic recognition off in Settings")
    return _finding("S26", "high", "CPU 已被打满并被容器限流",
                    "窗口内新增被限流 %d 次（配额 %s 核）——这就是「CPU 100%% 降不下来」的直接证据"
                    % (int(_num(delta)), _dig(ctx, "env.cgroup_cpu_quota")),
                    "给容器更多 CPU、降低并发、或在设置页关闭语义识别")


def _s30(ctx):
    if _dig(ctx, "settings.fail_closed", True):
        return None
    if _is_en():
        return _en("S30", "medium", "Fail-closed on masking failure is disabled (fail_closed=false)",
                   "Pipeline errors are logged and the request is forwarded: plaintext may leave the machine",
                   "Re-enable fail-closed unless you are debugging an issue")
    return _finding("S30", "medium", "脱敏失败熔断已关闭（fail_closed=false）",
                    "管线异常时会记录错误后继续转发，存在明文上行风险",
                    "除非在排查问题，否则建议重新打开「脱敏失败熔断」")


def _s31(ctx):
    n = int(_num(_dig(ctx, "events.unresolved", 0)))
    if n <= 0:
        return None
    if _is_en():
        return _en("S31", "medium", "Some placeholders were not restored (clients may see {{...}})",
                   "%d unresolved in the window" % n,
                   "Usually caused by engine restarts, expired reuse tables, or a model rewriting placeholder shapes; "
                   "the event dialog shows the exact tokens")
    return _finding("S31", "medium", "有占位符没能还原（客户端可能看到 {{...}}）",
                    "窗口内 unresolved 合计 %d" % n,
                    "多因引擎重启/复用表过期或模型改写了占位符形态；详情弹窗可看到具体 token")


def _s32(ctx):
    # 键名/层级必须与 `event_store.writer_stats()` 的真实形状一致：
    #   {event_writer_alive, event_writer:{restarts,dead_letters,drops,last_err},
    #    audit_writer:{...}, ...}
    # 此前读 `storage.writer.dropped`（键名少个 s、层级少一层）→ 永远取到 0，
    # 写线程丢几千条事件时自检照样显示“事件库写入正常”（该功能最不可容忍的失败形态）。
    writer = _dig(ctx, "storage.writer", {}) or {}
    if not isinstance(writer, dict):
        writer = {}
    drops = 0
    dead = 0
    for key in ("event_writer", "audit_writer"):
        stats = writer.get(key) or {}
        if isinstance(stats, dict):
            drops += int(_num(stats.get("drops", 0)))
            dead += int(_num(stats.get("dead_letters", 0)))
    # 写线程死亡也属于“日志会丢”：队列会一直涨到满再丢，最终只体现在 drops 上
    stopped = [k for k in ("event_writer_alive", "audit_writer_alive")
               if k in writer and not writer.get(k)]
    if drops <= 0 and dead <= 0 and not stopped:
        return None
    evidence = "丢弃 %d 条；死信 %d 条" % (drops, dead)
    if stopped:
        evidence += "；写线程未存活：%s" % "、".join(stopped)
    if _is_en():
        en_ev = "dropped %d; dead letters %d" % (drops, dead)
        if stopped:
            en_ev += "; writer threads not alive: %s" % ", ".join(stopped)
        return _en("S32", "medium", "Event DB writes are failing (logs will be lost)",
                   en_ev,
                   "Verify the data dir is writable and the disk is not full; restart the engine if needed")
    return _finding("S32", "medium", "事件库写入异常（日志会丢）",
                    evidence,
                    "确认数据目录可写、磁盘未满；必要时重启引擎")


def _s33(ctx):
    free = _dig(ctx, "env.disk_free_mb")
    quarantined = bool(_dig(ctx, "storage.db_quarantined", False))
    if quarantined:
        if _is_en():
            return _en("S33", "medium", "Event DB was corrupted and recreated",
                       "Corruption was detected at startup; the old DB was renamed and its history is not in the current DB",
                       "Look at the *.corrupt files in the data dir; a one-off is fine, report it if it repeats")
        return _finding("S33", "medium", "事件库曾损坏并被隔离重建",
                        "启动时检测到损坏，旧库已改名保留，历史日志不在当前库中",
                        "查看数据目录下的 *.corrupt 文件；偶发一次可忽略，反复出现请反馈")
    if free is None or _num(free) > 200:
        return None
    if _is_en():
        return _en("S33", "medium", "Data directory is low on disk space",
                   "%.0fMB free (%s)" % (_num(free), _dig(ctx, "env.disk_path", "")),
                   "Free up disk space or move the data dir to a larger volume")
    return _finding("S33", "medium", "数据目录磁盘空间不足",
                    "可用 %.0fMB（路径 %s）" % (_num(free), _dig(ctx, "env.disk_path", "")),
                    "清理磁盘或把数据目录挪到空间更大的分区")


def _s34(ctx):
    if not _dig(ctx, "proxy.running", False):
        return None
    last_ts = _num(_dig(ctx, "events.last_event_ts", 0))
    if last_ts and (time.time() - last_ts) < 600:
        return None
    if int(_num(_dig(ctx, "proxy.uptime_s", 0))) < 600:
        return None
    if _is_en():
        return _en("S34", "low", "Proxy is running but has seen no traffic for 10 minutes",
                   "The bound listen address may not be the one clients target (Host=%s)"
                   % (_dig(ctx, "proxy.panel_host", "127.0.0.1"),),
                   "Check the client/IDE proxy address; under Docker set MASKIT_BIND_HOST=0.0.0.0 and map the port")
    return _finding("S34", "low", "代理在运行，但最近 10 分钟没有任何流量",
                    "绑定的监听地址可能不是客户端指向的那个（Host=%s）"
                    % (_dig(ctx, "proxy.panel_host", "127.0.0.1"),),
                    "检查客户端/IDE 的代理地址是否指向本机端口；Docker 下需要 MASKIT_BIND_HOST=0.0.0.0 并映射端口")


def _s35(ctx):
    """敏感词表生效性（2026-09-30 事故）：词被跳过 / 整表没生效时必须说出来。

    为什么值得单列一条规则：这类故障在面板上**完全看不出来** —— 词库页面显示得好好的、
    代理照常 200，只是整张词表（自定义词 + 内置敏感词组）一个都不命中。用户唯一的
    结论只能是「脱敏坏了」，而根因往往只是一个词的写法（例如 `re:(?i)(Beijing)`
    的内联全局开关会让整条合并正则编译失败）。
    """
    issues = _dig(ctx, "words.issues", {}) or {}
    configured = int(_num(_dig(ctx, "words.configured", 0)))
    engine_count = _dig(ctx, "words.engine_count", None)
    stale = bool(_dig(ctx, "words.engine_stale", True))
    detail = ""
    if isinstance(issues, dict) and issues:
        detail = "；".join("%s -> %s" % (k, str(v)[:80]) for k, v in list(issues.items())[:3])
    elif (not stale) and configured > 0 and engine_count == 0:
        detail = "配置里有 %d 个词，但引擎报告的生效词数为 0" % configured
    if not detail:
        return None
    if _is_en():
        return _en("S35", "high", "Some sensitive words are not taking effect",
                   detail,
                   "Fix the listed words under Settings -> Word list (each re: pattern must compile on its own); saving hot-reloads immediately")
    return _finding("S35", "high", "敏感词表有词未生效（可能漏脱敏）",
                    detail,
                    "在 设置 -> 敏感词库 修正列出的词（re: 正则必须能单独编译通过）；保存即热重载生效")


def _s36(ctx):
    """事件库死空间：删掉的明细只进 freelist，文件不会自己变小。

    实测线上库 249MB 里 84MB 是这种"已删除但仍占盘"的空页（33%）—— 保留策略每天
    都在删行，但此前全仓没有一处执行 VACUUM，所以体积只涨不落。只在确实浪费得多时提示；
    引擎拿不到写锁时压缩会失败（`reclaim_space` 返回 ok=False），那种情况更需要让人看见。
    """
    db = _dig(ctx, "storage.db", {}) or {}
    if not isinstance(db, dict) or not db.get("ok"):
        return None
    size_mb = _num(db.get("bytes")) / 1048576.0
    free_mb = _num(db.get("free_bytes")) / 1048576.0
    ratio = _num(db.get("free_ratio"))
    if size_mb < 64 or ratio < 0.25:
        return None
    if _is_en():
        return _en("S36", "low", "Event log file is holding dead space",
                   "%.0fMB on disk, %.0fMB of it is free pages left by deleted rows (%.0f%%)"
                   % (size_mb, free_mb, ratio * 100),
                   "The next retention pass compacts it automatically; if it never drops, the engine rarely idles long enough to take the write lock")
    return _finding("S36", "low", "事件库有死空间未回收",
                    "磁盘占用 %.0fMB，其中 %.0fMB 是已删除行为空页（%.0f%%）"
                    % (size_mb, free_mb, ratio * 100),
                    "下一轮保留策略会自动压缩；若长期不下降，说明引擎长时间占用写锁、没有空隙可压")


RULES = (_s01, _s02, _s03, _s04, _s10, _s11, _s12, _s20, _s21, _s22, _s23,
         _s24, _s25, _s26, _s30, _s31, _s32, _s33, _s34, _s35, _s36)

# 「检查过且正常」的项：结论页要能告诉用户"这些都没问题"，否则一片空白会让人
# 以为自检没跑。每项 = (id, 对应的规则集合, 正常时的一句话)。
#
# ⚠️ **必须绑定规则集合**：正常项只能来自“那条规则确实没触发”。此前是一个与
# RULES 完全无关的静态列表（有 findings 时固定显示第 1 条），于是 S01「代理未
# 运行」会和「代理运行中且端口 / 兜底层正常」同屏出现 —— 自相矛盾的结论比没有
# 结论更份信任（而本功能的全部价值就是让人信）。
OK_NOTES = (
    ("A", ("S01", "S02", "S03", "S04"),
     "代理运行中且端口 / 兜底层正常",
     "Proxy running; ports and fallback listener normal"),
    ("B", ("S10", "S11", "S12"),
     "最近窗口内没有 503",
     "No 503 responses in the recent window"),
    ("C", ("S23", "S24", "S25"),
     "脱敏队列无排队、无背压拒服务",
     "Mask queue idle; no backpressure rejections"),
    ("D", ("S20", "S21", "S22", "S26"),
     "语义识别与 CPU 状态正常（或未开启）",
     "Semantic recognition and CPU look normal (or NER is off)"),
    ("E", ("S32", "S33", "S34", "S36"),
     "事件库写入正常、磁盘充足",
     "Event DB writes healthy; disk space sufficient"),
    ("F", ("S35",),
     "敏感词表全部词均已生效",
     "All sensitive words are in effect"),
)


def _assemble(findings, errors, ctx):
    """排序 + 组装结论（与规则执行分开，便于给装配阶段单独加守卫）。"""
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (rank.get(f.get("severity"), 9), str(f.get("id"))))
    fired = {str(f.get("id")) for f in findings}
    # 只显示“对应规则确实没触发”的正常项：静态列表会让「代理未运行」与
    # 「代理运行中」同屏出现（见 OK_NOTES 注释）。
    ok_items = [{"id": oid, "note": (note_en if _is_en() else note_zh)}
                for oid, related, note_zh, note_en in OK_NOTES
                if not (fired & set(related))]
    highs = [f for f in findings if f.get("severity") == "high"]
    overall = "high" if highs else ("medium" if findings else "ok")
    summary = _summary_line(findings, ctx)
    return {
        "schema": SCHEMA,
        "generated_at": int(time.time()),
        "overall": overall,
        "summary_line": summary,
        "findings": findings,
        "fired_ids": sorted(fired),
        "ok_items": ok_items,
        "input_errors": errors,
    }


def run_selfcheck(ctx, lang="zh"):
    """跑规则集，返回结论对象。**永不抛异常**：单条规则出错只记 input_errors。

    `lang` 决定结论文案的语言（"en" 走英文分支）：英文界面不该出现中文结论。
    只接受 zh/en，其余一律按 zh 处理。
    

    规则执行与结论装配**各自**有兜底：规则里出错只丢那一条；装配阶段（排序/求和这类
    一崩就"整份报告都没了"的位置）出错也必须给出一份可读结论 —— 否则 `/api/selfcheck`
    回一个裸 500，而自检恰恰是在系统半死不活时才会被点开的功能。
    """
    _LANG.set("en" if str(lang or "").lower().startswith("en") else "zh")
    findings = []
    errors = []
    for rule in RULES:
        try:
            out = rule(ctx)
        except Exception as e:                       # pragma: no cover
            errors.append({"rule": getattr(rule, "__name__", "?"),
                           "error": "%s: %s" % (type(e).__name__, e)})
            continue
        if out:
            findings.extend(out if isinstance(out, list) else [out])
    try:
        return _assemble(findings, errors, ctx)
    except Exception as e:                           # pragma: no cover
        return {
            "schema": SCHEMA,
            "generated_at": int(time.time()),
            "overall": "medium",
            "summary_line": ("Self-check assembly failed (%s); export the diagnostics bundle for details."
                             % type(e).__name__) if _is_en() else
                            "自检结论组装失败（%s）：请导出诊断包进一步排查。"
                            % type(e).__name__,
            "findings": [],
            "fired_ids": [],
            "ok_items": [],
            "input_errors": errors + [{"rule": "_assemble",
                                       "error": "%s: %s" % (type(e).__name__, e)}],
        }


def _summary_line(findings, ctx):
    """一句话结论（用户可以直接复制粘贴给别人看）。"""
    if not findings:
        return ("Self-check found no issues: proxy state, queue, audit and event DB are all within normal range."
                if _is_en() else "自检未发现异常：代理状态、队列、审计与事件库均在正常范围。")
    highs = [f for f in findings if f.get("severity") == "high"]
    head = (highs or findings)[0]
    detail = head.get("evidence") or ""
    extra = ""
    if len(findings) > 1:
        extra = ("; plus %d more item(s) to review" % (len(findings) - 1)
                 if _is_en() else "；另有 %d 项需要注意（见结论列表）" % (len(findings) - 1))
    return "%s%s%s" % (head.get("title"), ". " if _is_en() else "。", detail + extra)
