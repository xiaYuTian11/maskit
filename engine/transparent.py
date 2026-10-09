"""
mitmproxy 本地显式代理 - 只拦目标站点聊天接口，脱敏请求 + 还原响应。
被 panel.py 以子进程方式启动：
    mitmdump -s transparent.py --listen-host 127.0.0.1 -p 5802 --mode ...

配置读同目录 config.json（panel.py 维护）。
日志输出结构化行供面板解析：SHIELD\\tTYPE\\t...
"""
# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import asyncio
import codecs
import copy
from types import SimpleNamespace
import collections
import concurrent.futures
import threading
import contextlib
import datetime
import ipaddress
import json
import logging
import os
import random
import re
import time
import secrets
import uuid
from pathlib import Path
from mitmproxy import http, ctx, exceptions
from connection_policy import ConnectionGovernance, validate_connection_policy
from body_buffer import decode_body
import inspection
import onboarding
import protocol_contracts as _contracts
from urllib.parse import urlparse
from shield_defaults import (
    DEFAULT_DOMAINS,
    DEFAULT_PATHS,
    DEFAULT_SECRET_PREFIXES,
    DEFAULT_TTL,
    DEFAULT_UPSTREAMS,
    DEFAULT_BUILTIN_RULES,
    DEFAULT_COMMAND_BLOCK,
    KNOWN_PUBLIC_DNS,
    validate_command_regex,
    parse_egress_proxy,
    extract_usage as _extract_usage,
)
from event_store import enqueue_event
from event_store import enqueue_audit_event
from event_store import project_event_for_log, stop_log_trace as _stop_log_trace
from credential_labels import CREDENTIAL_LABELS
import audit_signals as _audit
import base64
import hashlib
from typing import NamedTuple

# Transport evidence is event-loop owned; workers only read frozen metadata.
_CONNECTIONS = ConnectionGovernance()
_CONNECTION_STATS = {}
_HEARTBEAT = {}
_HEARTBEAT_TASK = None
_METRICS_POOL = None
_CONNECT_STALL = {}
_CONNECT_KILL_TOTAL = {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0}
_MASK_CANCEL_BY_CLIENT = {}
_MASK_WORK_CONTEXT = threading.local()


class _ClientFlowCancelled(asyncio.CancelledError):
    """Client stream ended: return normally from the mitmproxy hook, not its task."""


def _cancel_signal(flow):
    signal = getattr(flow, "_shield_cancel_wakeup", None)
    if signal is None:
        signal = asyncio.Event()
        flow._shield_cancel_wakeup = signal
    return signal


def _dispose_stream(flow):
    stream = getattr(getattr(flow, "response", None), "stream", None)
    dispose = getattr(stream, "_maskit_dispose", None)
    if callable(dispose):
        dispose()


def _on_stream_cancel(flow, reason):
    _dispose_stream(flow)
    flow._shield_cancel_reason = reason
    _cancel_signal(flow).set()
    event = getattr(flow, "_shield_mask_cancel", None)
    if event is not None:
        event.set()
    token = _aux_token(flow)
    owned = token.session_ref if token is not None else None
    _aux_abandon(flow)
    if (owned is not None and not token.submitted
            and not flow.metadata.get("shield_mask_pending")):
        _drop(flow.metadata.get("session_id"), expect=owned)


# 响应「已交付完毕」的标记值。只有流式收尾回调（`_sse_stream_factory` 里的 `_finish`）
# 会写它——那是唯一能证明「整条流已交给 mitmproxy」的时刻。整包路径的
# `_transport_complete` 在响应钩子**一开始**就调，不能拿来当「已交付」的判据，
# 两者刻意不共用（见 `_record_client_cancel` 的取舍说明）。
_RESPONSE_CONCLUDED_STREAM_DONE = "stream_done"


def _response_concluded(flow):
    """整条响应是否已交付完毕（判据只此一处，见 `_RESPONSE_CONCLUDED_STREAM_DONE`）。"""
    try:
        metadata = getattr(flow, "metadata", None) or {}
        return metadata.get("shield_response_concluded") == _RESPONSE_CONCLUDED_STREAM_DONE
    except Exception:
        return False


def _flow_error_detail(flow):
    """错误/取消事件的统一诊断串；返回 `(detail, raw)`。

    `error()` 与 `_record_client_cancel` **必须共用同一份**：2026-10-02 实测事故正是
    「先落地的薄记录（只有 reason/failure_phase）把后到的富记录挡掉」，用户拿到一整屏
    没有 bytes/耗时/上游的 CANCEL 行，既分不清真中断与收尾断开，也无从归因。
    `raw` 是 flow.error 的截断文本，供调用方判定事件类型（Client disconnected / DNS）。
    """
    err = getattr(flow, "error", None)
    raw = ""
    try:
        raw = str(err)[:160]
    except Exception:
        pass
    metadata = getattr(flow, "metadata", None) or {}
    request = getattr(flow, "request", None)
    # resp 仅记录是否存在 response 对象；耗时与缺失响应都不能单独证明
    # 复用了坏连接、请求已写出，或上游应用已经处理。
    try:
        elapsed_ms = int((time.time() - float(getattr(request, "timestamp_start", 0) or 0)) * 1000)
    except Exception:
        elapsed_ms = -1
    try:
        req_len = len(request.raw_content or b"")
    except Exception:
        req_len = -1
    err_name = type(err).__name__ if err is not None else "?"
    has_resp = 1 if getattr(flow, "response", None) is not None else 0
    detail = f"[err={err_name} resp={has_resp} req={req_len}B ms={elapsed_ms}] " + raw
    # P0-b：脱敏耗时与「脱敏完成到出错之间等了多久」必须进事件 —— 否则
    # 「卡在脱敏」与「卡在上游」在事件行上长得一模一样（2026-09-28 实测就因此
    # 把 58.5s 的冷缓存脱敏误读成上游问题、又把纯上游慢误判成脱敏问题，来回两次）。
    # upstream_wait 仅为脱敏完成后的累计等待，不代表请求已到达上游。
    # upstream_wait=-1 表示拿不到脱敏完成时刻（例如脱敏未跑完就出错）。
    mask_ms = metadata.get("shield_mask_ms")
    if mask_ms is not None:
        try:
            done_at = metadata.get("shield_mask_done_at")
            upstream_wait = int((time.time() - float(done_at)) * 1000) if done_at else -1
        except Exception:
            upstream_wait = -1
        detail = f"[mask={mask_ms}ms upstream_wait={upstream_wait}ms] " + detail
    # 流式接管中途被切断时 _finish() 不执行，没有 RESTORE 事件可对照，
    # 光看 ERR 无法判断断在哪。带上回调次数/字节数还原现场。
    if metadata.get("shield_streamed"):
        detail = (f"[stream calls={metadata.get('shield_stream_calls')} "
                  f"bytes={metadata.get('shield_stream_bytes')}] " + detail)
    # 走了出口代理的请求，失败时必须标出来：代理不通与上游不通的现象一样
    # （连接超时/被拒），不标注就分不清该查代理还是查上游。
    if metadata.get("shield_via_proxy"):
        detail = "[via egress_proxy] " + detail
    return detail, raw


# ── 失败归因（批次 8 / P0-5）──────────────────────────────────────────────
# 现象层全是「连接断开 / 超时」，但几类成因的处置完全不同，不判就只能靠猜：
#   · client   —— SDK 超时或用户取消（改我们这边没用）；
#   · dns      —— 上游域名解析失败；
#   · proxy    —— 走了出口代理（代理不通与上游不通现象完全一样）；
#   · engine   —— 请求**还没出网**就断了（脱敏未跑完/排队被拒），责任在本机引擎；
#   · upstream —— 其余：脱敏已完成、请求已写出，断在上游或链路上。
# 2026-09-28 实测就因事件行上区分不了后两者，把 58.5s 的冷缓存脱敏误读成上游问题、
# 又把纯上游慢误判成脱敏问题，来回两次。
_CLIENT_FAILURE_HINTS = ("client disconnected", "violation of protocol")
_DNS_FAILURE_HINTS = ("getaddrinfo", "name or service not known",
                      "nodename nor servname", "temporary failure in name resolution")
_FAILURE_OWNERS = frozenset({"client", "dns", "proxy", "engine", "upstream"})


def _flow_failure_owner(flow, raw):
    """判一次失败的**责任方**（见上方 `_FAILURE_OWNERS`）。只取已有事实，不猜。

    拿不准时宁可返回 upstream：既不要把自己的问题说成上游的，也不要把上游的
    问题揽成自己的——两种误判都会把排查引向错误的方向。
    """
    low = (raw or "").lower()
    if any(h in low for h in _CLIENT_FAILURE_HINTS):
        return "client"
    if any(h in low for h in _DNS_FAILURE_HINTS):
        return "dns"
    metadata = getattr(flow, "metadata", None) or {}
    if metadata.get("shield_via_proxy"):
        return "proxy"
    # 脱敏完成时刻是「请求即将出网」的唯一里程碑：没落就说明还没走到那一步。
    # 只对真的走过脱敏链路的请求（有 session_id）下这个结论，否则非匹配域名的
    # 透传请求超时也会被算成引擎问题。
    if metadata.get("session_id") and metadata.get("shield_mask_done_at") is None:
        return "engine"
    return "upstream"


def _flow_error_type(flow):
    """异常的**类名**（结构化字段，便于在日志里按类型聚合）。

    `_flow_error_detail` 里已经有 `err=<类名>` 的文字形态，但那是拼进 msg 的字符串，
    筛选/聚合都得正则抠；单独落一个字段才能直接按类型统计（如全部 `ReadTimeout`
    指向上游、全部 `ConnectionResetError` 指向链路）。
    """
    err = getattr(flow, "error", None)
    return type(err).__name__ if err is not None else ""


def _record_client_cancel(flow, phase):
    """记录一次客户端断开。

    **事件层面的取舍**（2026-10-02）：整条响应已交付完毕（流式收尾回调执行过）后客户端
    才关连接时，**不落 CANCEL 事件**。那只是「客户端读完关连接」，不是取消：实测 10-02
    这类记录与 MASK 达到 1:1（1334 / 1450），而带诊断的每一条都伴随已下发内容
    （bytes 最小 951、中位 7.1 KB），纯属噪声。真·未完成的中断照旧记录。

    **但取消信号照旧发出**（`_on_stream_cancel` 的唤醒、`_shield_cancel_recorded` 的置位
    都不改）：AUX 任务与脱敏池的等待者仍要被唤醒，否则就是拿日志噪声换资源泄漏；
    置位还能避免 `error()` 紧接着补发一条同样的记录。

    判据与「是否已完成」用 `_response_concluded`，不在本函数里另写一遍——两条路径各判
    一次必然漂移。范围保守：整包（非流式）响应写出途中被掐断**仍照旧记录**，因为那种
    情况拿不到「body 已写完」的证据。
    """
    if getattr(flow, "_shield_cancel_recorded", False):
        return
    flow._shield_cancel_recorded = True
    _transport_event("error", flow)
    flow.metadata["transport"] = _safe_transport_snapshot(flow)
    if _response_concluded(flow):
        return
    req = getattr(flow, "request", None)
    sid = flow.metadata.get("session_id", "")
    session = _session_get(sid) if sid else None
    source = (session or {}).get("source") or {}
    detail, _raw = _flow_error_detail(flow)
    up_name = flow.metadata.get("shield_upstream") or (session or {}).get("upstream_name") or ""
    model = flow.metadata.get("shield_model") or (session or {}).get("model") or ""
    _emit("CANCEL", sid=sid,
          host=getattr(req, "host", ""), method=getattr(req, "method", ""),
          path=str(getattr(req, "path", "")).split("?", 1)[0],
          reason=getattr(flow, "_shield_cancel_reason", "client_disconnected"),
          failure_phase=phase, transport=_transport_snapshot(flow),
          # CANCEL 的归因恒为 client（事件本身就是客户端断开）；`error_type` 仍然带上，
          # 好把「SDK 超时」与「协议错」分开统计。
          failure_owner="client", error_type=_flow_error_type(flow),
          msg="flow_error:" + detail, upstream=up_name, model=model, **source)


_CONNECTIONS.on_cancel = _on_stream_cancel


def _transport_event(name, *args):
    try:
        getattr(_CONNECTIONS, name)(*args)
    except Exception:
        _CONNECTIONS.observation_errors += 1


def _safe_transport_snapshot(flow):
    try:
        return _CONNECTIONS.snapshot(flow)
    except Exception:
        # Diagnostic failures (including non-weakrefable test flows) cannot affect traffic.
        _CONNECTIONS.observation_errors += 1
        return {"phase": "unknown", "evidence_complete": False}


def _transport_snapshot(flow):
    return dict((getattr(flow, "metadata", None) or {}).get("transport") or {})


def _transport_complete(flow):
    _transport_event("response_complete", flow)
    flow.metadata["transport"] = _safe_transport_snapshot(flow)


def requestheaders(flow):
    # Also guard live option changes: rejection must precede any body forwarding.
    if getattr(getattr(ctx, "options", None), "stream_large_bodies", None) is not None:
        flow.response = http.Response.make(
            503, b'{"error":{"code":"unsafe_request_streaming"}}',
            {"content-type": "application/json"})


def configure(updated):
    # Automatic body streaming can send plaintext before request() masks it.
    if getattr(getattr(ctx, "options", None), "stream_large_bodies", None) is not None:
        raise exceptions.OptionsError("Maskit requires stream_large_bodies to remain unset")


def _hop_task_candidates(tasks, address, peername):
    """The mitmproxy task(s) establishing exactly this hop.

    mitmproxy names them ``server connection handler <address>`` and tags the task with
    the owning client peername (`utils/asyncio_utils.set_task_debug_info`), so this
    resolves the hop from outside without holding any mitmproxy object. Anything but
    exactly one hit is left alone: a *second* handshake to the same address from the
    same client connection is a fact we do not have, and guessing would kill a healthy
    request. A rename upstream degrades to "no match" = today's behaviour, not to a
    wrong cancel.
    """
    want = f"server connection handler {address}"
    return [task for task in tasks
            if task.get_name() == want and getattr(task, "client", None) == peername
            and not task.done()]


def _act_handshake_kills(stalled):
    """Bound a pre-send handshake by cancelling exactly the task that owns that hop.

    mitmproxy's `open_connection` catches the resulting CancelledError, records
    `connection.error`, fires `server_connect_error` and completes the command with the
    error, so the flow dies through mitmproxy's own path and the client gets a clean 502
    instead of a 127 s silence. We never fabricate a response here: nothing was sent
    upstream, so nothing unscanned or un-restored is being passed on.

    `stalled` is per hop (see `ConnectionGovernance.stalled_before_send`), which is also
    how the flows sharing a pending connection die: together, via mitmproxy, once.
    """
    counters = {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0}
    if not _CONNECT_KILL or not stalled:
        return counters
    tasks = list(asyncio.all_tasks())
    for conn_id, _phase, address, peer in stalled:
        if not address or not peer:
            counters["no_conn"] += 1
            continue
        if not _CONNECTIONS.claim_handshake_kill(conn_id):
            continue
        hits = _hop_task_candidates(tasks, address, peer)
        if len(hits) > 1:
            counters["ambiguous"] += 1
        elif not hits:
            counters["no_task"] += 1
        else:
            hits[0].cancel()
            _CONNECTIONS.confirm_handshake_kill(conn_id)
            counters["killed"] += 1
    return counters


async def _heartbeat_loop():
    global _CONNECTION_STATS, _HEARTBEAT, _CONNECT_STALL
    loop = asyncio.get_running_loop()
    expected = loop.time()
    while True:
        _CONNECTION_STATS = _CONNECTIONS.stats()
        # 只能在事件循环上算：_flows/_connections 由循环独占，metrics 线程读它会竞态。
        stalled = _CONNECTIONS.stalled_before_send(_CONNECT_STALL_S)
        for key, value in _act_handshake_kills(stalled).items():
            _CONNECT_KILL_TOTAL[key] += value
        _CONNECT_STALL = {
            "stalled": len(stalled),
            "phases": sorted({phase for _conn, phase, _addr, _peer in stalled}),
        }
        _HEARTBEAT = {"generated_at": int(time.time()),
                      "loop_lag_ms": round(max(0, loop.time() - expected) * 1000, 2)}
        # Only one queued write; never use the DNS/default executor or block the loop.
        await loop.run_in_executor(_METRICS_POOL, write_runtime_metrics, True)
        expected = loop.time() + 2.0
        await asyncio.sleep(2.0)


def running():
    global _HEARTBEAT_TASK, _METRICS_POOL
    configure(set())
    if _HEARTBEAT_TASK is not None and not _HEARTBEAT_TASK.done():
        return
    _transport_event("running")
    _METRICS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="maskit-metrics")
    _HEARTBEAT_TASK = asyncio.get_running_loop().create_task(_heartbeat_loop())


def done():
    global _HEARTBEAT_TASK, _METRICS_POOL
    if _HEARTBEAT_TASK is not None:
        _HEARTBEAT_TASK.cancel()
        _HEARTBEAT_TASK = None
    if _METRICS_POOL is not None:
        _METRICS_POOL.shutdown(wait=False, cancel_futures=True)
        _METRICS_POOL = None
    for events in _MASK_CANCEL_BY_CLIENT.values():
        for event in events:
            event.set()
    _MASK_CANCEL_BY_CLIENT.clear()
    _transport_event("done")


def client_disconnected(client):
    for event in _MASK_CANCEL_BY_CLIENT.get(str(client.id), ()):
        event.set()


def server_connect(data):
    _transport_event("server_connect", data)


def server_connected(data):
    _transport_event("server_connected", data)


def server_connect_error(data):
    _transport_event("server_connect_error", data)


def server_disconnected(data):
    _transport_event("server_disconnected", data)


def tls_start_server(data):
    _transport_event("tls_start_server", data)


def tls_established_server(data):
    _transport_event("tls_established_server", data)


def tls_failed_server(data):
    _transport_event("tls_failed_server", data)


# 内置正则规则（敏感词字面在 config.json，正则规则固定，避免 UI 误改）
ID_BOUND_L = r"(?<![A-Za-z0-9])"
ID_BOUND_R = r"(?![A-Za-z0-9])"
# IP 专用右边界：额外挡掉「后面还跟着 .数字」的情况。
# 原来只用 ID_BOUND_R，`编号 192.168.1.1.1` 会把前 4 段当 IP 打码、剩个孤零零的
# `.1` 在后面，用户看到的是被截半的编号。5 段以上不是 IPv4，直接放过。
IP_BOUND_R = r"(?![A-Za-z0-9]|\.\d)"

# 公网 IPv4 专用边界：强防误伤定宽断言
# 左边界：挡住字母数字、字母数字连字符/下划线（lib-1.2.3.4/app_1.2.3.4）、包名域名点号前缀与多段版本截断
IP_PUBLIC_BOUND_L = r"(?<![A-Za-z0-9][-_])(?<![A-Za-z0-9]\.)(?<![A-Za-z0-9])"
# 右边界：挡住字母数字、点号文件后缀（.jar/.tar.gz/.js）与连字符标签/构建号后缀（-beta/-SNAPSHOT/-5）
IP_PUBLIC_BOUND_R = r"(?![A-Za-z0-9]|\.[A-Za-z0-9]|[-_][A-Za-z0-9])"
RULES = [
    # PEM 私钥整块替换（最高危凭据，形态固定零误报）——审计规则专项 P0。
    # 多行匹配：-----BEGIN ... PRIVATE KEY----- 到 -----END ... PRIVATE KEY-----
    # 整块替换成单个占位符，不逐行扫描。
    #
    # ⚠️ 中间段绝不能写成 `[\s\S]{20,}?`（2026-09-24 修）：没有 END 时惰性量词会从
    # **每一个** BEGIN 位置一路尝试到字符串末尾，实测 1.49MB + 200 个未闭合私钥头
    # 耗 870ms（典型 O(n²)，且这段跑在脱敏管线上，等于把请求拖慢）。
    # 换成「不跨 `--`」的定长字符类后，每个起点扫到下一个 `--` 就失败：真实 PEM
    # 正文是 base64（字母表里没有 `-`），所以语义不变，代价降为线性。
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----(?:[^-]|-(?!-)){20,}?-----END[^-]*PRIVATE KEY-----"), "PRIVATE_KEY", 0),
    (re.compile(r"(?<![A-Za-z0-9_-])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # GitHub fine-grained PAT: github_pat_<22>_<59+>（2022 GA，现为 GitHub 推荐默认形态）。
    # 老的 ghp_ 规则匹配不到它（前缀不同），实测 github_pat_... 整串漏检。
    # 前缀极其独特，无误报风险。
    (re.compile(r"(?<![A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{50,}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # 云厂商 AK 家族（审计规则专项 P1）：形态固定零误报。
    # Google API Key: AIza[0-9A-Za-z_-]{35,38}（实际长度 39-42，AIza + 35~38）
    (re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35,38}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # 阿里云 AK: LTAI[A-Za-z0-9]{12,20}
    (re.compile(r"(?<![A-Za-z0-9_-])LTAI[A-Za-z0-9]{12,20}(?![A-Za-z0-9_-])"), "ACCESS_KEY", 0),
    # 腾讯云 SecretId: AKID + 32 位。上界原为 20，比真实长度短一截，
    # 后缀 (?![A-Za-z0-9_-]) 又要求整串吃完 → 真实 36 位 SecretId 恒不命中
    # （实测 36 位示例串完全漏检）。放宽到 32。
    (re.compile(r"(?<![A-Za-z0-9_-])AKID[A-Za-z0-9]{13,32}(?![A-Za-z0-9_-])"), "ACCESS_KEY", 0),
    # Slack Token: xox[baprs]-[0-9A-Za-z-]{10,}
    (re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[0-9A-Za-z-]{10,}(?![A-Za-z0-9-])"), "API_KEY", 0),
    # Stripe Key: [sr]k_(live|test)_[0-9A-Za-z]{20,}
    (re.compile(r"(?<![A-Za-z0-9_-])[sr]k_(?:live|test)_[0-9A-Za-z]{20,}(?![A-Za-z0-9])"), "API_KEY", 0),
    # 飞书 app: cli_[a-z0-9]{16,} / 钉钉: ding[a-z0-9]{6,}
    (re.compile(r"(?<![A-Za-z0-9_-])cli_[a-z0-9]{16,}(?![a-z0-9])"), "API_KEY", 0),
    (re.compile(r"(?<![A-Za-z0-9_-])ding[a-z0-9]{6,}(?![a-z0-9])"), "API_KEY", 0),
    (re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), "ACCESS_KEY", 0),
    # AWS SecretAccessKey：40 位 base64（含 / 和 +）。裸串不敢匹配——任何 40 位
    # base64 摘要都会中招（误报优先级高于覆盖率），所以只认「键名 = 值」形态。
    # 这半边才是能直接花钱的：AKIA 泄漏本身无害，配上 SK 才能签请求。
    # 现有 SECRET 规则救不了它：值字符类不含 / 且有 (?!/) 前瞻，实测整串漏检。
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "ACCESS_KEY", 1),
    (re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"), "JWT", 0),
    (re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{20,})"), "TOKEN", 1),
    # SECRET 值排除 {}：占位符 {{LABEL_hex}} 不再被当值二次替换（曾把
    # api_key=sk-xxx → 前缀规则先换占位符 → SECRET 再把占位符包一层，
    # 响应还原时嵌套占位符残留）。
    # 值：ASCII 无空白、不以 / 开头（/token=/api_key= 说明文案误报源）、
    # 不含换行/引号/中文/括号、且不含 .（曾把代码方法名/成员访问
    # ModelUtils.toStringSafe、getSecret 当凭据脱敏——真实凭据无点）。
    # 值还须含数字或特殊符号（(?=.*[0-9!@#$%^&*])）：纯字母标识符
    # （CamelCase 方法名/变量名）不再误报，真实凭据几乎必含数字/符号。
    # 键名与值两侧的引号都要吃掉：真实泄漏面大量来自用户直接粘 .env / JSON / YAML
    # 配置块（{"api_key": "sk..."} / password="hunter2000"），只认裸 key=value 会整块漏。
    # 引号只作可选边界、不进捕获组（组 2 仍是纯值），还原时不会把引号一起吞掉。
    # 关键词必须同时覆盖中英文、分隔符必须同时覆盖半角与全角：本产品面向中文用户，
    # 提示词里写的是「安装令牌：xxx」「数据库密码：xxx」，而原规则只认英文关键词 +
    # 半角 [:=]，实测 5/7 的中文凭据场景整条原文上行（SHIELD-CRED-CJK-001）。
    # 中文关键词不需要英文那种 (?<![A-Za-z0-9_.]) 边界：汉字本就不在该字符类里。
    # 值的字符类不含汉字，所以「密码：请联系管理员」这类正常中文句子不会误报。
    (re.compile(
        r"(?i)(?:(?<![A-Za-z0-9_.])(?:password|passwd|pwd|secret|token|api[_-]?key"
        r"|access[_-]?key|private[_-]?key)(?![A-Za-z0-9_.])"
        r"|(?:密码|口令|令牌|密钥|秘钥|密匙|凭据|凭证|私钥|授权码|访问密钥|接口密钥))"
        r"[\"'“”「」]?\s*[:=：＝]\s*[\"'“”「」]?(?!/)"
        r"(?=[A-Za-z0-9!@#$%^&*_~+=-]*[0-9!@#$%^&*])"
        r"([A-Za-z0-9!@#$%^&*_~+=-]{6,64})(?![A-Za-z0-9!@#$%^&*_~+=-])"
    ), "SECRET", 1),
    # 连接串密码：scheme://user:pass@host 形态，只脱密码组（第2组），
    # 保留 scheme/user/host——模型仍能理解这是连接串（审计规则专项 P0）。
    # EMAIL 规则的注释里曾提到 postgres://user:secret123@db.internal 被误当邮箱，
    # 修了误报但没补漏检。
    # scheme 段必须封顶 {0,63}：`[a-z0-9+.-]*` 无上限时，在「大量词起始位置 +
    # 长 [a-z0-9+.-] 连续段」的文本上是 O(N²)——实测 8/16/32KB 为 82/335/1345ms
    # （每次翻倍 ≈4x），同步阻塞 event loop。封顶后 32KB 降到 7.4ms、倍率 2.0。
    # 真实 scheme 最长不到 40 字符，封顶不损失任何匹配。
    # 注意：`_smoke_data/_rxstress.py` 对这个模式是**假阴性**（它的对抗串
    # `"x://" + "a"*n + ":"` 只有 2 个 \b 起点，形不成乘积），语料已补齐。
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,63}://[^\s:@/]+:([^\s@/]{4,})@"), "CONNSTR", 1),
    # 手机号：连续 11 位，或 138-1234-5678 / 138 1234 5678（分隔符仅 - 或空白）；
    # +86 前缀整体脱敏（曾只脱 138... 部分，国家码原文残留）。
    # 加号可省（8613812345678 是国内表单/短信网关最常见写法）：国家码后紧跟
    # 1[3-9] 且两侧有非字母数字边界，与时间戳（17xxxxxxxxxxx）、订单号形态不冲突，
    # 实测 commit 8613812345678abcdef 因右边界含字母仍不命中。
    # 手机号：连续 11 位，或 138-1234-5678 / 138 1234 5678（分隔符仅 - 或空白）；
    # +86 / 0086 / (86) 前缀整体脱敏。
    # 分组分隔符必须前后一致（反向引用），或整体无分隔。
    (re.compile(ID_BOUND_L + r"(?:(?:\+?86|0086|[\(（]\+?86[\)）])[\s-]?)?1[3-9]\d(?:([-\s])\d{4}\1\d{4}|\d{8})" + ID_BOUND_R), "PHONE", 0),
    # 邮箱：本地部分首字符须为字母/数字/下划线/中文（排除 +- 等符号，防止 Git diff 的 +
    # 符号或列表 - 符号被当成用户名一部分吞噬）。
    # 本地部分前不能是 :（连接串 user:pass@host 形态防误伤），亦不能紧跟在其他词法字符后。
    # 下划线必须留在首字符类里：它同时在负向断言集合内，两边都排除会让 `某个邮箱字面量`
    # 整段不匹配（首字符不是 `_`、从 `s` 起又被断言挡住）→ 明文漏检（2026-09 复审）。
    (re.compile(r"(?<!:)(?<![A-Za-z0-9._\u4e00-\u9fff])[a-zA-Z0-9_\u4e00-\u9fff][\u4e00-\u9fffA-Za-z0-9._%+-]{0,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z\u4e00-\u9fff]{2,}(?![A-Za-z0-9._%+-])"), "EMAIL", 0),
    # 座机：3位区号(010/02x)或4位区号(03xx-09xx) + 分隔符/括号 + 7-8位本地号 + 可选分机号。
    (re.compile(
        ID_BOUND_L +
        r"(?:(?:\+?86|0086|[\(（]\+?86[\)）])[\s-]?)?"
        r"(?:"
          r"[\(（]0(?:10|2\d|[3-9]\d{2})[\)）][\s-]?[2-9]\d{6,7}"
          r"|"
          r"0(?:10|2\d|[3-9]\d{2})[-\s][2-9]\d{6,7}"
        r")"
        r"(?:[-\s]?(?:转|分机|ext|x|#)[-\s]?\d{1,5})?" +
        ID_BOUND_R,
        re.IGNORECASE
    ), "LANDLINE", 0),
    # 车牌：汉字省份 + 字母 + 5 位普通 / 6 位新能源
    # 车牌：省份简称 + 发牌机关字母 + 5-6 位车身。
    # **车身必须含至少一个数字**（0.1.15 修，实测误报 233 次）：左边界
    # `(?<![A-Za-z0-9])` 只挡 ASCII、挡不住汉字，而「新」是新疆简称——
    # 于是 `更新README.md` 里的「新README」被整段当成车牌脱掉，
    # 用户看到自己的文档名变成 {{PLATE_xxx}}。真车牌车身几乎必有数字，
    # README / ABCDEF 这类全字母串没有，一个前瞻就能分开，不必枚举词表。
    # 代价：全字母的个性化车牌会漏——那种在国内不发牌，可接受。
    (re.compile(r"(?<![A-Za-z0-9])[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z](?=[A-Z0-9]{0,5}\d)[A-Z0-9]{5,6}(?![A-Z0-9])"), "PLATE", 0),
    # 港澳通行证：仅 H 开头 8 位（曾含 M——M+8 位数字与日期/变量名
    # M20260805 无法区分，误伤面大；规则默认关，用户真需要可在敏感词页开启）
    (re.compile(ID_BOUND_L + r"H\d{8}" + ID_BOUND_R), "HKID", 0),
    # 身份证（0.1.18 合并为单一开关 IDCARD，覆盖 15 位旧证 + 18 位二代证；
    # 两条正则同 label，校验按匹配长度分发：
    #   15 位：省份 + 真实公历出生日期（_idcard15_ok）；
    #   18 位：省份 + 出生日期 + ISO 7064 MOD 11-2 校验位（_idcard18_ok）。
    # 历史占位符 {{IDCARD18_xxx}} 的还原不受影响——还原靠 token 查复用表，
    # 与签发时的 label 无关；新签发的 18 位证统一用 {{IDCARD_xxx}}。
    # 旧配置的 IDCARD18 键由 panel.load_config 一次性迁移合并（meta.idcard_merged）。
    (re.compile(ID_BOUND_L + r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])\d{13}" + ID_BOUND_R), "IDCARD", 0),
    (re.compile(ID_BOUND_L + r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])\d{15}[\dXx]" + ID_BOUND_R), "IDCARD", 0),
    # 内网 IP 拆两个 label：IP_PRIVATE（192.168/链路本地，默认开——不会当版本号）、
    # IP_INTERNAL（10.x/172.16-31，默认关——10.x 是最常见版本号格式，
    # 曾把 version 10.2.3.4 脱敏成占位符，用户问版本号时模型看不到数字）
    # IP 规则同 label 合并为一条（交替分支），减少全文扫描次数（性能优化：
    # 每条规则独立 finditer 全文，18 条规则 = 18 次 O(长度) 扫描；同 label
    # 合并语义完全一致（同一占位符 label），仅省扫描次数）
    (re.compile(ID_BOUND_L + r"(?:192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})" + IP_BOUND_R), "IP_PRIVATE", 0),
    # 100.64.0.0/10（CGNAT 段）：Tailscale / ZeroTier / 运营商大内网全用这一段。
    # 归 IP_PRIVATE 而不是 IP_INTERNAL（默认关）——这段地址只可能是内网基础设施，
    # 不像 10.x 那样会跟版本号撞形。实测缺口：ssh tanmw@100.118.224.56 原文直出。
    # 第二段限定 64-127，避免把 100.0.x / 100.200.x 这类普通数字串卷进来。
    (re.compile(ID_BOUND_L + r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}" + IP_BOUND_R), "IP_PRIVATE", 0),
    (re.compile(ID_BOUND_L + r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})" + IP_BOUND_R), "IP_INTERNAL", 0),
    # IPv6 私网地址（fe80:: 链路本地 / fc00::/7 ULA，默认关——IP 系规则全部
    # 默认关，防含冒号 hex 串误伤）：宽正则抓候选（≥2 个冒号的 hex 串），
    # 语义校验 _ipv6_private_ok 保证只脱私网段。公网 IPv6（2001:... 等）不做
    # ——误伤面与 IP_PUBLIC 同源（版本号/UUID 形态），有真实需求再评估。
    # UUID 含 4 个连字符无冒号，不会进候选。
    # 前视断言不得排除 `:`：`gateway:fd00::5`、`IPV6:fe80::1` 这类「键:值」写法里
    # 地址紧跟冒号，排除 `:` 会让整段一个起点都匹配不上（IPv4 的 ID_BOUND_L 只排除
    # 字母数字，两类规则的边界本就不该不一致）。hex 与 `.` 仍排除，防止从长 hex 串
    # 中间起匹配；更长的地址会被贪婪吃成一条候选，再由语义校验否掉。
    (re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f:]{2,45}(?![0-9A-Fa-f:])"), "IPV6_PRIVATE", 0),
    # 公网 IPv4：放 network 规则末尾（IP_INTERNAL 之后），作为泛化规则兜底。
    # 严格限定各段 0-255，语义校验由 _ip_public_ok 剔除私网保留段、组播与知名公共 DNS。
    (re.compile(IP_PUBLIC_BOUND_L + r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|[1-9])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})" + IP_PUBLIC_BOUND_R), "IP_PUBLIC", 0),
    # 银行卡：13-19 位数字，必须以 3-6 开头（真卡 BIN：3=Amex/JCB，4=Visa，
    # 5=MasterCard，6=银联/Discover），且过 Luhn。位数范围按 ISO/IEC 7812——
    # 旧版只匹配 16 位，把国内主流的 19 位银联借记卡（62 开头）整类漏掉。
    #
    # **分隔符不能用 `[\s-]?` 逐位可选**（0.1.15 修，实测误报）：那样写等于允许
    # 每一位数字前插一个空格，匹配会跨过空格把两个不相干的数字接起来。
    # 生产实测把文件列表里的「大小 + 年份」当成了卡号：
    #   313524224 2023  → 拼成 3135242242023（13 位）→ Luhn 恰好通过
    #   4983554048 2025 → 拼成 49835540482025（14 位）→ Luhn 恰好通过
    # Luhn 只能挡掉 90%（随机数 1/10 概率通过），拦不住这类。而脱敏侧误报
    # = 破坏用户请求：模型收到的是 {{CARD_xxx}} 而不是那个文件大小。
    #
    # 现在分两支，都不允许「一位一空格」：
    #   1) 无分隔：连续 13-19 位数字；
    #   2) 分组：分隔符用反向引用强制**前后一致**（同 MAC 的修法），每组 1-6 位，
    #      首组 3-6 位。真卡分组是 4-4-4-4 / 4-6-5 / 4-4-4-4-3 / 4-4-4-1，
    #      没有哪种会出现 9 位一组——误报样本正是栽在这。
    # 位数由 _card_ok 显式校验（组数可变，正则不再隐式保证 13-19 位）。
    (re.compile(ID_BOUND_L + r"(?:[3-6]\d{12,18}|[3-6]\d{2,5}(?:([ -])\d{1,6}){1,4})" + ID_BOUND_R), "CARD", 0),
    # IBAN：2 字母 + 2 数字 + ≥11 位字母数字，需过 mod-97（欧洲银行账号，中文场景少见，校验严格防误伤）
    (re.compile(ID_BOUND_L + r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}" + ID_BOUND_R), "IBAN", 0),
    # 统一社会信用代码（审计规则专项 P2）：18 位，[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}
    # 排除 I/O/S/V/Z 避免与普通字母数字串混淆。默认关——形态与普通字母数字串相近，
    # 政企场景用户需要时在敏感词页开启。
    (re.compile(ID_BOUND_L + r"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}" + ID_BOUND_R), "USCC", 0),
    # MAC 地址：xx:xx:xx:xx:xx:xx 或 xx-xx-xx-xx-xx-xx（审计 P1：
    # 分隔符用反向引用强制一致 + 去掉空格——曾用 [: -] 字符类，空格会让匹配
    # 从正文 'AC' 开始跨空格接上 MAC 片段，真 MAC 被切碎还吃掉周围文本）
    (re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"), "MAC", 0),
]

# 特征预检（性能优化，审计 P1 尾延迟）：每条规则配一个廉价必含特征
# （memchr 级子串查找，比 finditer 快一个数量级）。文本不含特征直接跳过
# 整条规则扫描——典型长对话（代码+中文）可跳过 JWT/TOKEN/API_KEY/IP 等
# 5-6 条规则，18 条全文扫描降到 ~12 条。特征必须保守（宁可漏检不误跳）：
# 只选规则"必须出现"的稳定片段；无可靠特征的规则（PLATE 汉字前缀、
# IDCARD/CARD 纯数字）不加，保留原扫描。
_RULE_MARKERS = {
    "PRIVATE_KEY": ("PRIVATE KEY",),  # PEM 私钥固定标记
    "CONNSTR": ("://",),      # 连接串必含 ://
    "API_KEY": ("gh", "AIza", "xox", "sk_", "rk_", "cli_", "ding"),  # GitHub/Google/Slack/Stripe/飞书/钉钉前缀
    # AWS/阿里云/腾讯云前缀。"aws"/"AWS" 是给 aws_secret_access_key= 那条规则用的：
    # 它整条是小写键名，不含 AK/LTAI/AKID 任何一个，不加就会被预检直接跳过。
    "ACCESS_KEY": ("AK", "LTAI", "AKID", "aws", "AWS"),
    "JWT": ("eyJ",),             # JWT 头固定
    # (?i)\bBearer\s+ 值。marker 是大小写敏感子串，三种常见大小写都要列：
    # 只列 Bearer/bearer 时全大写 "BEARER abc..." 连正则都跑不到（实测漏检）。
    "TOKEN": ("Bearer", "bearer", "BEARER"),
    # 规则要求 \s*[:=：＝]\s*。全角冒号/等号必须一并列出：预检命不中就整条规则跳过，
    # 中文用户写的「令牌：xxx」会连正则都跑不到（与 CGNAT 那次同一个坑）。
    "SECRET": ("=", ":", "：", "＝"),
    "PHONE": ("1",),             # 手机号 1[3-9] 开头
    "EMAIL": ("@",),             # 邮箱必含 @
    "LANDLINE": ("0",),          # 座机区号 0 开头
    # 加 "100."：CGNAT 段（Tailscale/ZeroTier）规则并进 IP_PRIVATE 后，
    # 预检特征也必须跟着加，否则整条规则被跳过、新规则等于没写（实测踩过）。
    "IP_PRIVATE": ("192.", "169.", "100."),
    "IP_INTERNAL": ("10.", "172."),
    # IPv6 私网首组必是 fe80-febf（fe8/fe9/fea/feb）或 fc00-fdff（fc/fd），
    # 用前缀做特征比 ":" 保守得多——':' 在任何 URL/JSON 里都命中，启用该规则
    # 后等于每条消息全量跑宽正则 + 海量 ipaddress 异常（31KB 文本实测 ~3400 次）。
    # 只列小写：该规则按大小写不敏感比对（见 _RULE_MARKERS_CI）。此前只列全小写与
    # 全大写，`Fe80::1` / `fE80::1` 这种混合大小写在预检处就被整条跳过且不留痕迹。
    "IPV6_PRIVATE": ("fe8", "fe9", "fea", "feb", "fc", "fd"),
}


# 预检必须大小写不敏感的规则（marker 是小写形态，比对前把文本降一次大小写）。
# 只对已启用该规则的文本生效（_rule_enabled 在调用点先短路），开销可忽略。
_RULE_MARKERS_CI = frozenset({"IPV6_PRIVATE"})

def _rule_may_hit(text, label):
    """特征预检：文本不含规则必含特征时跳过该规则扫描（性能）。"""
    markers = _RULE_MARKERS.get(label)
    if not markers:
        return True
    if label in _RULE_MARKERS_CI:
        # marker 只列了小写形态，比对前统一降一次大小写。不这么做的话，
        # `Fe80::1` / `fE80::1` 这类混合大小写在预检处就被判「不命中」，
        # 整条规则被静默跳过且不留痕（CGNAT 的 marker 漏加踩过同一个坑）。
        text = text.lower()
    return any(m in text for m in markers)


# 运行期配置（load 时从 config.json 读入）
TARGET_DOMAINS = list(DEFAULT_DOMAINS)
API_PATHS = list(DEFAULT_PATHS)
CUSTOM_WORDS = {}
# 自定义标签组禁用（组名仍保留在 config，只是 mask 时跳过）
SENSITIVE_DISABLED = set()
# 词级禁用：{label: set(words)}
SENSITIVE_WORD_DISABLED = {}
# 整词匹配开关：set(words) —— 开启后该词两侧加边界（不为字母数字/汉字），
# 避免「机要」打中「机要害」。默认对 2-3 字词不开（靠词长区分），用户显式开启（审计规则专项 P2）。
SENSITIVE_WORD_WHOLE = set()
# 内置规则开关（按 label；False 则 mask/scan 跳过该标签全部正则）
BUILTIN_RULES = dict(DEFAULT_BUILTIN_RULES)
SESSION_TTL = DEFAULT_TTL
DEBUG = False  # 调试：写完整 body（含真实原文）到 debug-日期.log
DIAGNOSTIC_UNMATCHED = False  # 诊断：只记录未命中请求元数据，不记录 body
DOMAINS_DISABLED = set()  # 被禁用的站点（不拦截，流量直连）
SECRET_PREFIXES = list(DEFAULT_SECRET_PREFIXES)
CAPTURE_MODE = "reverse"  # reverse | explicit | local
UPSTREAMS = list(DEFAULT_UPSTREAMS)  # 反向代理路由表
# 出口代理（Shield → 上游方向）：mitmproxy ServerSpec `(scheme, (host, port))`，None=不启用。
# 逐 flow 生效（`flow.server_conn.via`），所以同一个进程里可以「anyrouter 直连 +
# 官方 API 走代理」并存。实测走的是 CONNECT 隧道（即便目标是明文 http），
# 因此上游代理必须支持 CONNECT；socks5 不支持（mitmproxy 的 via 只认 http/https）。
EGRESS_PROXY = None
# 凭据类标签：唯一定义源在 credential_labels.py（panel / event_store 共用同一份，
# 前端 TS 侧由测试守同步）。以前这里各写一份，event_store 那份少两个标签 →
# 读路径会把 CONNSTR 密码与 PEM 私钥当普通 PII 返回。
# 凭据原文精确清洗的长度下限：内置规则最短的凭据捕获是 CONNSTR 的 {4,}，
# 自定义前缀规则要求前缀后 ≥8 位，SECRET 是 6-64 —— 真实凭据不会短于 4。
_MIN_SCRUB_LEN = 4
# 过滤开关：True=脱敏还原（默认），False=透明转发（不脱敏，流量原样到上游）。
# 代理仍运行、端口仍监听、路由仍生效，仅跳过脱敏/还原逻辑。客户端 base_url 不用改。
FILTER_ENABLED = True
# fail-closed（默认开）：脱敏管线异常时阻断请求返回 503，绝不放行含原文的 body 上行。
# 关闭 = 异常时记录 ERR 后仍继续转发（可能泄露原文，仅排查问题时临时关闭）。
FAIL_CLOSED = True
# 响应侧扫描（默认开）：还原后检查模型回复中不在本会话映射里的 PII（幻觉/训练数据泄漏），只记录事件不阻断。
RESPONSE_SCAN = True
# SSE 实时转发（默认开）：逐事件还原后立即下发，流末再做完整审计/扫描收尾。
STREAM_RESPONSE = True
# 字节级精确替换（默认开）：命中敏感词时只替换被脱敏的那个字符串字面量，
# 不再整棵 `json.dumps` 重序列化，从而保住客户端 body 的原始排版 —— 上游按前缀
# 做的 Prompt Cache 只会从真正的敏感值处失效，而不是从 body 开头附近就失效
# （实测一条带空格 + `\u` 转义的请求：敏感值在 byte 74，旧实现的差异位在 byte 9）。
# 结果必须通过 `json.loads(结果) == 脱敏后的树` 等价校验才会被采用，不过就自动
# 退回重序列化，所以它**不改变发往上游的内容**，只改变排版。
# 排查用的一键退路：环境变量 MASKIT_BYTE_SPLICE=0 即回到整棵重序列化的旧行为。
BYTE_SPLICE = os.environ.get("MASKIT_BYTE_SPLICE", "1") not in ("0", "false", "False")
# 流式接管黑名单：确认某上游接管后断连时，把 host 加进来保持整包路径。
# 仅在配置里**没有** stream_exclude_hosts 键时作为回落默认（老配置兼容）；
# 键存在即以配置为准，空列表 = 用户显式清空 = 不排除任何 host。
#
# 默认已清空。此前的 opencode.ai 条目是误判：断连并非上游限制，而是
# _sse_stream_factory 在「本次无完整 SSE 事件可发」时返回 b""，被 mitmproxy 的
# ResponseData 分支按 chunked 语法写成 b"0\r\n\r\n"（终止块），客户端据此判定
# 响应结束并关连接。改为返回空列表后，opencode.ai 实测 112 chunk / 11 个到达
# 时刻 / 1.09s 出字窗口，与直连同量级。是否复现只取决于上游的 TCP 分片是否
# 切开事件边界，与 host 无关，故不再预置任何 host。
_DEFAULT_STREAM_EXCLUDE_HOSTS = set()
STREAM_EXCLUDE_HOSTS = set(_DEFAULT_STREAM_EXCLUDE_HOSTS)
# 2.0 审计配置（默认开启被动检测，零影响脱敏还原）
AUDIT_ENABLED = True
AUDIT_PASSIVE = True
AUDIT_ACTIVE_PROBES = False
AUDIT_SEVERITY_FLOOR = "MEDIUM"
# 审计信号默认开关。这是信号清单的唯一来源：_read_settings 按本表的键遍历
# config.json，新增信号只改这里。曾在 _read_settings 里另写一份硬编码键列表，
# 加 S8/S9 时忘了同步 —— 结果第一次热重载就把 AUDIT_SIGNALS 换成 7 键字典，
# 两个信号在生产里静默失效而单测全绿（SHIELD-RELOAD-SIGNALS-001）。
DEFAULT_AUDIT_SIGNALS = {
    "error_leak": True,
    "identity_swap": True,
    "tool_call_rewrite": True,
    "sse_anomaly": True,
    "response_poison": True,
    "cross_request_pollution": True,
    "dangerous_action": True,  # S9 模型下发破坏性命令（只告警，不阻断）
}
AUDIT_SIGNALS = dict(DEFAULT_AUDIT_SIGNALS)
# 审计严重信号触发时的**响应级**熔断（默认关，用户自选；前端「审计阻断」开关）。
# 触发条件：某条 finding 的 severity >= CRITICAL（当前只有 S1 error_leak 的四类会到 CRITICAL）。
# 行为（D1 纠偏，2026-09-22）：**只把本次响应改成 503**，
#   ① 不写任何配置、**不会自动停用 upstream**（旧注释说「停用该 upstream」，与实现不符）；
#   ② 发生在**响应阶段**，请求体早已发往上游 → **不能阻止数据外泄**，
#      只能阻止已污染的响应内容进入客户端；
#   ③ 与脱敏主线的同名 `fail_closed`（请求级，默认 true，见 _read_settings 里的两条注释）
#      是**两层不同的东西**，不要混读。
AUDIT_FAIL_CLOSED = False
# 恒落库的信号：不受 `severity_floor` 拦截（W2-1 G1 契约 / Q6「默认就做审计记录」）。
# S9 dangerous_action 信 LOW，而全局默认 floor=MEDIUM——没有这条例外，
# 「默认只记录、不改写、不阻断」的承诺在默认配置下根本不成立（LOW 连写都不写，
# 「高风险操作时间线」会是空壳）。**只改成落库、不改档位**：severity 仍 LOW，
# 因此首页/统计页的告警数（只数 HIGH/CRITICAL）不受影响。
AUDIT_ALWAYS_RECORD = frozenset({"dangerous_action"})
# 审计自身的异常只警告一次：既让"审计坏了"可见，又不至于每个响应刷一行日志。
_AUDIT_WARNED = set()


def _audit_warn_once(key, msg):
    if key in _AUDIT_WARNED:
        return
    _AUDIT_WARNED.add(key)
    _log(f"[audit] {msg}")

# ---- A-1：审计扫描窗口 / 体积闸 / 时间预算（0.6.0，可用环境变量覆盖）----
# 为什么**不**直接改 `_SCAN_BODY_MAX`：那个常量同时喂给请求侧命令拦截窗口
# （`_cmd_find` 的 `cmd_req_window`，见本文件 :3779 与 :5894），动它等于缩小
# 「危险命令拦截」的可见范围——安全判据不许被性能优化顺手削弱（设计文档 §3.2）。
# 所以审计单独一个常数，两者互不影响。
AUDIT_SCAN_MAX = 128 * 1024
# 结构化解析（`_parse_response_payload` / 请求体 json.loads）的体积闸：
# 实测 512KB ≈ 0.7ms（scripts/bench_mask.py），成本远低于正则扫描，但 32MB
# 畸形体会变成几十毫秒 + 大对象分配，故设 2MB 上限并留痕。
AUDIT_PARSE_MAX = 2 * 1024 * 1024
# 单次响应审计的墙钟预算：只能在**步骤之间**检查（单个正则调用不可中断），
# 因此最坏情况是「一步的过冲」。默认 250ms 远高于实测值（128KB 三段扫描
# p50 ≈ 20ms），它兜的是正则灾难性回溯这类病态回归。
AUDIT_TIME_BUDGET_S = 0.25


def _env_int(name, default):
    """读一个整数环境变量；非法值回落默认（不抛异常、不刷屏）。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name, default):
    """读浮点环境变量；非法值回落默认。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return float(default)
    try:
        return float(raw)
    except ValueError:
        return float(default)


def _connect_budget(value):
    """握手预算的口径：`0`（或负数）= 关闸只观测，正数夹到 5 s 下限。

    下限的存在是因为这条预算会真的落刀：设成 1 s 会把「健康但慢」的握手（家里实测
    最坏一次成功 13.1 s）一起掐掉，等于自己造故障。
    """
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        seconds = 20.0
    if seconds != seconds:  # NaN
        seconds = 20.0
    return 0.0 if seconds <= 0 else max(5.0, seconds)


# 环境变量兜底（容器场景无法开面板时用）；config.json 里的值优先于它们。
_ENV_AUDIT_SCAN_MAX = _env_int("MASKIT_AUDIT_SCAN_MAX", AUDIT_SCAN_MAX)
_ENV_AUDIT_PARSE_MAX = _env_int("MASKIT_AUDIT_PARSE_MAX", AUDIT_PARSE_MAX)
_ENV_AUDIT_TIME_BUDGET = _env_float("MASKIT_AUDIT_TIME_BUDGET_MS", AUDIT_TIME_BUDGET_S * 1000.0) / 1000.0


def _clamp_int(value, default, lo, hi):
    """整数取值 + 范围钳制：非法值回落默认（配置写坏了不能让引擎起不来）。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return int(default)
    return max(int(lo), min(int(hi), n))


def _clamp_float(value, default, lo, hi):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return float(default)
    return max(float(lo), min(float(hi), n))
# A-2：同 body 的扫描结果复用。key 必须含 status 与 req_hash：
#   · S1 error_leak 只在 status>=400 时跑；
#   · S6/S9 有「请求里本来就有 → 不算上游注入」的回声抑制；
#   · S2 identity_swap 拿请求 model 当基准真相。
# 只用 response_hash 会把这些请求侧差异串味成错误结论。
_AUDIT_FINDINGS_CACHE = collections.OrderedDict()
_AUDIT_CACHE_TTL_S = 30.0
_AUDIT_CACHE_MAX = 256
_AUDIT_CACHE_LOCK = threading.Lock()
# 运行时指标（C-1 的 /api/engine/metrics 从这里取数；只统计、不影响判定）
_AUDIT_RUNTIME = {
    "count": 0, "truncated": 0, "parse_skipped": 0,
    "cache_hit": 0, "cache_miss": 0, "cache_store": 0,
    # ⚠️ 必须**预置**：这个键由 aux 线程在跑审计时插入，而读侧
    # `audit_runtime_stats()` 跑在 mask 池线程上做 Python 层 `.items()` 遍历 ——
    # 首次插入会改变 dict 大小 → 读侧 RuntimeError → 被 write_runtime_metrics 吞掉
    # （表现为"指标文件偶发不更新"，属静默丢数据）。预置 + 下面那把锁一起解决。
    "cache_disabled": 0,
    "total_ms": 0.0, "samples_ms": collections.deque(maxlen=200),
}
# 审计运行时计数器的读写锁：计数由 2 个 aux 线程 `+=`，快照由 mask 池线程读。
# 叶子锁（只护 dict/deque 操作，不嵌套任何其他锁），不影响既有锁序。
_AUDIT_STATS_LOCK = threading.Lock()


# 缓存指纹：findings 是「body + 状态码 + 请求体 + **信号开关**」的函数。
# 少了最后一项就会在用户刚关掉某个信号后，仍把 30s 内旧配置的结论端上来
# （实测：测试里改开关后立刻读缓存，返回的是上一个开关组合的结果）。
# `_maybe_reload` 每次都是整表换对象（不是就地改），所以拿对象 id 就能
# 精确判断"配置换代了"，不必每次深比较。
#
# ⚠️ 指纹**刻意不包含扫描函数的 id()**：想过用它来"实现换了就失效"，但
# `id()` 会被回收复用——临时函数（单测桩、热补丁 lambda）释放后下一个对象
# 可能拿到同一地址，键看起来没变、结论却是上一个实现的（实测被这个坑咬过一次）。
# 这里依赖的是**扫描器纯函数**这条不变式：findings 只由 (扫描文本, 开关, 上限)
# 决定。谁要往扫描器里塞会话态/随机态，就得连带改这个键。
_AUDIT_CFG_FP = [None, None]
# 指纹是"检查-写两格"的读改写：审计跑在 aux 池（多线程）上，两个线程同时进来
# 可能把 [0] 与 [1] 交叉写成"新签名 + 旧指纹"。后果不是崩溃，而是**键错配**
# （按 A 配置的指纹命中 B 配置的结论），属静默错误，所以加锁。
_AUDIT_CFG_FP_LOCK = threading.Lock()


def _audit_config_fingerprint():
    sig = AUDIT_SIGNALS
    with _AUDIT_CFG_FP_LOCK:
        if _AUDIT_CFG_FP[0] is not sig:
            _AUDIT_CFG_FP[0] = sig
            _AUDIT_CFG_FP[1] = (
                tuple(sorted(k for k, v in (sig or {}).items() if v)),
                int(AUDIT_SCAN_MAX), int(AUDIT_PARSE_MAX),
            )
        return _AUDIT_CFG_FP[1]


def _audit_cache_get(key):
    """取缓存的扫描结果（返回副本的副本语义由调用方保证：列表浅拷贝即可，
    findings 元素本身不被就地改写）。过期条目顺手清掉。"""
    now = time.time()
    with _AUDIT_CACHE_LOCK:
        rec = _AUDIT_FINDINGS_CACHE.get(key)
        if not rec:
            return None
        ts, findings = rec
        if now - ts > _AUDIT_CACHE_TTL_S:
            _AUDIT_FINDINGS_CACHE.pop(key, None)
            return None
        _AUDIT_FINDINGS_CACHE.move_to_end(key)
        return list(findings)


def _audit_cache_put(key, findings):
    with _AUDIT_CACHE_LOCK:
        _AUDIT_FINDINGS_CACHE[key] = (time.time(), list(findings))
        _AUDIT_FINDINGS_CACHE.move_to_end(key)
        while len(_AUDIT_FINDINGS_CACHE) > _AUDIT_CACHE_MAX:
            _AUDIT_FINDINGS_CACHE.popitem(last=False)


def audit_runtime_stats():
    """审计运行时指标快照（只读；供面板 /api/engine/metrics 使用）。"""
    with _AUDIT_CACHE_LOCK:
        cache_size = len(_AUDIT_FINDINGS_CACHE)
    with _AUDIT_STATS_LOCK:
        samples = list(_AUDIT_RUNTIME["samples_ms"])
    p50 = p95 = 0.0
    if samples:
        ordered = sorted(samples)
        p50 = ordered[len(ordered) // 2]
        p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    with _AUDIT_STATS_LOCK:
        out = {k: v for k, v in _AUDIT_RUNTIME.items() if k != "samples_ms"}
    out.update({
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "last_ms": round(samples[-1], 2) if samples else 0.0,
        "cache_size": cache_size,
        "scan_max": AUDIT_SCAN_MAX,
        "parse_max": AUDIT_PARSE_MAX,
        "time_budget_s": AUDIT_TIME_BUDGET_S,
    })
    return out


def _audit_record_timing(t_start, stats):
    """把一次审计的耗时与截断情况记进运行时指标（永不影响流量）。"""
    try:
        ms = (time.perf_counter() - t_start) * 1000
        # 计数是读改写：两个 aux 线程并发时会丢更新（用户看到的"审计被削过几次"
        # 因此偏小）。整段放进锁里 —— 只护内存自增，纳秒级，不构成竞争点。
        with _AUDIT_STATS_LOCK:
            _AUDIT_RUNTIME["count"] += 1
            _AUDIT_RUNTIME["total_ms"] += ms
            _AUDIT_RUNTIME["samples_ms"].append(ms)
            stats["ms"] = ms
            if stats.get("truncated"):
                _AUDIT_RUNTIME["truncated"] += 1
            if stats.get("parse_skipped"):
                _AUDIT_RUNTIME["parse_skipped"] += 1
            if stats.get("cache_hit"):
                _AUDIT_RUNTIME["cache_hit"] += 1
            else:
                _AUDIT_RUNTIME["cache_miss"] += 1
    except Exception:
        pass


def _audit_mark(stats, stage):
    """标记本次审计被预算截断，并记下截断发生在哪一段（排障要看得见）。"""
    stats["truncated"] = True
    stats.setdefault("truncated_at", stage)


def _audit_scan_signals(flow, status_code, ct, scan_text, scan_req_text, body_text,
                        hdrs_text, deadline, stats, body_oversize=False):
    """跑 S1/S6/S9/S2/S4/S7 扫描（A-1：每段之间检查时间预算，超限即截断留痕）。

    **只做 body 派生的判定**：会话作用域的合并（S9 槽位级命中、回声抑制）留在
    调用方，这样 A-2 的缓存不会把 A 会话的命令证据串到 B 会话（见 §4.2）。
    """
    findings = []

    if time.perf_counter() >= deadline:
        _audit_mark(stats, "before_scan")
        return findings

    # S1 error_leak（被动+主动）
    if AUDIT_SIGNALS.get("error_leak") and status_code >= 400:
        # 上游域名检测已移除（2026-08-18）：错误页出现用户**已配置**的上游地址
        # 是诊断信息而不是面向客户端的信息泄露，改由普通 ERR/状态日志排障；
        # 留在这里只会把审计中心刷成上游错误页的噪音场。
        findings.extend(_audit.scan_error_leak(status_code, scan_text, hdrs_text))

    if time.perf_counter() >= deadline:
        _audit_mark(stats, "after_s1")
        return findings

    # S6 response_poison（被动+主动，200/4xx 都扫）
    if AUDIT_SIGNALS.get("response_poison") and scan_text:
        findings.extend(_audit.scan_response_poison(scan_text, scan_req_text))

    # S9 dangerous_action：模型下发的破坏性命令（rm -rf / / DROP DATABASE / 强推…）
    # 必须扫**还原后**的文本：占位符状态下路径和主机名都是假的，判不准也没意义。
    # 只告警不阻断——设计取舍见 audit_signals.scan_dangerous_action 的注释。
    if AUDIT_SIGNALS.get("dangerous_action") and scan_text:
        findings.extend(_audit.scan_dangerous_action(scan_text, scan_req_text))

    if time.perf_counter() >= deadline:
        _audit_mark(stats, "after_scan")
        return findings

    # S2 identity_swap + S4 sse_anomaly：需解析 body
    if body_text and ("json" in ct or "event-stream" in ct):
        # 单次解析产出 (text_chunks, model_field, events) — 避免三重解析
        # A-1：结构化解析吃**全量** body，给它一个体积闸。超限则跳过并留痕
        # （identity_swap 需要 model_field、sse_anomaly 需要 events，两者随之停摆；
        #  这是刻意取舍：宁可少一项被动检测，也不让 32MB 畸形体吃满事件循环）。
        text_chunks, model_field, events = ((), "", ())
        # `body_oversize`：调用方已按体积闸只解了前缀，此时"文本很短"是**假象**，
        # 不能因此就去做结构化解析（会解析一份截断的 JSON）——判定口径与
        # "文本超 AUDIT_PARSE_MAX"完全一致。
        if not body_oversize and len(body_text) <= AUDIT_PARSE_MAX:
            text_chunks, model_field, events = _parse_response_payload(body_text, ct)
        else:
            stats["parse_skipped"] = True
        if AUDIT_SIGNALS.get("identity_swap"):
            # 对比式检测（借鉴 LiteLLM requested_model vs response_model）：
            # 请求 model 是基准真相，响应 model 与之对比，不一致才是换芯——
            # 零知识库、零硬编码，模型迭代/新厂商自动适配。
            # A-1：优先复用请求阶段已解析出的 model（`request` 钩子里写进
            # `flow.metadata["shield_model"]`），省掉一次全量 json.loads；
            # 只有在 metadata 缺失、且请求体不超体积闸时才回退解析。
            req_model = str(flow.metadata.get("shield_model") or "")
            if not req_model:
                _raw_req = getattr(flow.request, "content", None) or b""
                if len(_raw_req) <= AUDIT_PARSE_MAX:
                    try:
                        req_model = _extract_model(json.loads(_raw_req))
                    except Exception:
                        pass
                else:
                    stats["parse_skipped"] = True
            # ⚠️ 必须**只调一次**，不能放在 `for chunk in text_chunks` 里（审计 B4）。
            # `scan_identity_swap` 的判据只有 `model_field` + `req_model`，第一个
            # 参数（文本）完全不参与判定（见 audit_signals.scan_identity_swap）。
            # 放进循环的后果是：tool_use-only / reasoning-only / 空文本响应
            # （Anthropic 非流式 tool_use、流式 delta.partial_json、OpenAI
            # content:null 拒答）的 `text_chunks` 为空 → 整段跳过 → 换芯检测
            # 在编程助手最主流的响应形态上完全失效，而 `model_field` 明明已解析出来。
            # 传第一个非空 chunk 只是为了将来若该参数被启用时仍有上下文。
            findings.extend(_audit.scan_identity_swap(
                text_chunks[0] if text_chunks else "", model_field, req_model))
        # S4 sse_anomaly（仅 SSE）
        if AUDIT_SIGNALS.get("sse_anomaly") and "event-stream" in ct:
            findings.extend(_audit.scan_sse_anomaly(events))

    if time.perf_counter() >= deadline:
        _audit_mark(stats, "after_parse")
        return findings

    # S7 cross_request_pollution：仅主动探针模式。
    # 当前请求自身携带的 nonce（current）不算「前序」；只有**没有携带任何
    # nonce 的独立请求**响应里出现前序 nonce，才证明 relay 跨请求存了数据。
    # S5「当前请求回显」已于 2026-08-18 移除：nonce 经 X-Shield-Canaries 头
    # 注入且转发前被剥离，模型本看不到它；若探针还要求模型回显，正常模型
    # 也会回显，不能证明泄漏。
    if AUDIT_ACTIVE_PROBES and body_text:
        # A-1：跨请求污染扫描同样按体积闸截断（主动探针默认关，影响面更小）
        if body_oversize or len(body_text) > AUDIT_PARSE_MAX:
            stats["parse_skipped"] = True
        else:
            current = set(flow.metadata.get("audit_canaries") or set())
            # registry 是 dict {nonce: ts}，取 key 集合做 prior。
            # 必须持锁快照：注册/清理在别的线程上跑（见 _AUDIT_CANARY_LOCK 注释）。
            with _AUDIT_CANARY_LOCK:
                prior = set(_AUDIT_CANARY_REGISTRY.keys()) - current
            if AUDIT_SIGNALS.get("cross_request_pollution") and prior:
                findings.extend(_audit.scan_cross_request_pollution(body_text, prior))

    # S3 tool_call_rewrite：仅主动探针模式，由 audit_engine 直接判定（需 expected 对照）
    # 此处被动模式跳过（无法区分正常 tool_call 与被改写的）
    return findings


# ========== 命令拦截（config.command_block）运行时状态 ==========
# 结构：{"mode": "observe"|"rewrite"|"block", "channels": set, "patterns": [(id,label,rx)],
#        "allow": [rx], "disabled": set(id)}
# 与审计 S9（只记录、恒 LOW）是**两套**东西：S9 的判据不被用户配置改写；这里可读可改
# （用户要求「开箱即用 + 可改 + 删除不复活」）。由 `_read_settings` 热重载刷新。
COMMAND_BLOCK = {
    "mode": "observe",
    "channels": {"tool"},
    "patterns": [],
    "allow": [],
    "disabled": set(),
}
# 命令拦截的扫描上限与防 ReDoS 预算：
#   · CMD_SCAN_MAX：单次只扫前 N 字节。人写的命令不会藏在 8KB 之后，
#     而把不设限的文本喂给用户正则就是把事件循环交给对方。
#   · CMD_MATCH_BUDGET_MS：单条规则单次匹配耗时上限，超限即**停用该条**并告警。
#     ⚠️ 诚实说明：Python 的 `re` 无法中途打断，所以这是「下次不再付这个代价」，
#     不是「这次不卡」。真正的第一道防线是 panel 侧的长度上限 + 嵌套量词拒绝
#     （见 panel._normalize_command_block），这里只是运行时的例外兜底。
CMD_SCAN_MAX = 8192
CMD_MATCH_BUDGET_MS = 60
# 改写文本（W2-2）。**固定字符串，绝不拼入任何变量**：
#   · 它会被插进工具参数（可执行面），拼入被拦命令原文等于用我们自己的改写文本
#     把命令重新引入——原文里的 `'` 一闭一开就能构造出 `echo '…' ; <危险命令> #`，
#     即「我方的改写反而成了注入的载体」。
#   · 固定形态也是无害 no-op：真被当 shell 跑，只往 stdout 打一行说明；
#     Agent 能读到这句「已阻止」，从而不再重试同一条命令。
#   · **刻意不带命令名/规则名**（方案初稿曾写 `（rm -rf /）`）：① 任何拼接都可能带进原文里的引号
#     而破坏 no-op 形态；② 这个常量对**全部 7 条内置规则**都一样生效，写具体命令名反而不如实。
#     命中详情走时间线 evidence 与 UI，不进 shell 字符串。
CMD_BLOCK_NOTICE = "echo '[Maskit] 已阻止高危删除命令，本条为占位说明，未执行任何操作'"
# 有界前瞻缓冲的尾巴上限（chunk 1-8）：命令可能被切成 `rm -r` + `f /`，
# 必须把「可能是模式前缀」的尾巴暂留到下一块。只取模式源长度上界截断（≤ 本值）。
CMD_HOLD_MAX = 64
# AI 实体识别开关（默认关闭，需用户显式开启，避免概率模型干扰确定性规则）
NER_ENABLED = False
# 严格模式（§B3，默认关闭）：开启后要求「本次语义检测必须完整成功」，命中降级类原因
# 码即在**出网前**阻断（503）。老配置保持 best-effort 行为；开启后不会自动取消，
# 只能由用户显式关掉开关（不允许回滚把它静默降级）。
NER_REQUIRE_COMPLETE = False
# 主动探针注入的 canary nonce 注册表（跨请求污染检测用）
# 结构：{nonce: ts}，按 ts 清理过期 nonce，避免无界增长
#
# ⚠️ 这个 dict 是**跳线程**的：注册在 request()（事件循环线程），读取在
# `_audit_response`（可能跑在 aux 线程），清理在 `_sweep`（另一个时机）。
# 无锁时 `set(dict.keys())` 与并发插入/删除会撞出
# `RuntimeError: dictionary changed size during iteration` —— 而它被上层的宽
# except 吞掉，表现为“这条响应没做审计”（静默少一层安全检测）。
_AUDIT_CANARY_LOCK = threading.Lock()
_AUDIT_CANARY_REGISTRY = {}
_AUDIT_REGISTRY_TTL = 3600  # nonce 保留 1 小时
_AUDIT_REGISTRY_MAX = 500   # 上限 500 nonce，超则清最早
_ROOT = Path(__file__).parent.resolve()
# 流式响应留存上限：只为审计/响应侧扫描保留还原后文本，超过即不再累积（防大响应吃内存）
_SSE_KEEP_MAX = 256 * 1024
# 流式半事件/半行缓冲上限：buf 只暂存「没凑齐分隔符的半个事件」，正常上游事件远小于此值。
# 恶意/异常上游若持续推送不含分隔符的数据（非标准实现），buf 会无限增长吃光内存——
# 超限时把整个缓冲按最终事件强制还原下发并清空，宁多一次事件边界也不让内存失控。
_SSE_BUF_MAX = 4 * 1024 * 1024
# 响应侧扫描体长上限：几 MB 文本 × 全量规则正则会霸占事件循环，扫描是防御性功能，
# 超长只扫前段（代价：超长响应的尾部命中可能漏，属刻意取舍）。
_SCAN_BODY_MAX = 512 * 1024
# 扩展链路单会话的 stream_id 缓冲条目上限（审计 M2）。stream_id 由页面提供、
# 完全可控，而 `ext_frames` 是会话内的一个普通 dict：启用站点上的任意脚本都能在
# 会话 TTL 内不断换 id 把引擎内存撑大。超限按插入序淘汰最老的一条 ——
# 淘汰只丢「半帧缓冲」，被淘汰的流下次调用从空缓冲重来，最差结果是该条流上
# 跨帧切开的占位符拼不回来，而那是没有这套缓冲时的本来行为。
_EXT_FRAMES_MAX = 64
# 流式逐回调调试日志开关（SHIELD_STREAM_DEBUG=1）。默认关：SSE 每秒几十次回调，
# 常开会把日志刷爆并拖慢转发。断流排障时临时打开。
_STREAM_DEBUG = (os.environ.get("SHIELD_STREAM_DEBUG") or "").strip() not in ("", "0", "false", "False")
# in-flight 会话的硬回收上限：ts 静默超过此值即认为连接已死（上游断连／被中间
# 设备静默丢弃，流回调收不到空块、error 钩子也未必上报），强制回收避免会话与
# 脱敏原文映射永久驻留。取 15 分钟：远大于正常长生成的块间隔（有数据就 _touch
# 刷新 ts），又能兜住死连接。
_INFLIGHT_MAX_IDLE = 900
# 请求体脱敏上限（默认 32MB，**可配置**：`config.max_request_body_mb`，§H4a）。
# **别再按旧文说"脱敏全部跑在 event loop 上同步执行"**：
# 脱敏自重 2026-09-24 起 offload 到 `_MASK_POOL` 专职线程（见 `_mask_pipeline_worker`），
# 超大 body 不再直接冻结事件循环。闸门真正拦的是三件事：
#   1) `_mask_tree` 是纯 Python + `re`，受 GIL 串行化——实测 ≈112 ms/MiB，一条 32 MiB
#      请求会占住 GIL 约 3.7s，把同池其它连接的脱敏/还原一起拖慢；
#   2) 内存上界 = 单条上限 × 池宽（最坏 ≈ workers×32MiB 在跑 + workers×8MiB 排队）；
#   3) `_ENGINE_DEADLINE_S=120s` 是端到端预算，单条无界会让它自己 `engine_timeout`。
# 并发不足是另一条路径（503 `engine_busy`）。**严禁为了放行大请求而少扫字节。**
_DEFAULT_MAX_REQUEST_BODY = 32 * 1024 * 1024
_MAX_REQUEST_BODY = _DEFAULT_MAX_REQUEST_BODY
# 响应体还原上限（32MB）：json.loads + 全树遍历同样是同步 CPU 操作，几十 MB 的响应
# 足以把 event loop 占住数秒，期间**同进程内所有会话**的脱敏/还原一起停摆。
# 请求侧上一行早有这道闸，响应侧原先只受上游返回体大小间接限制。
# 超限时的处置：跳过还原 + 留痕（事件页可见），而不是默默卡死代理。
_MAX_RESPONSE_RESTORE_BODY = 32 * 1024 * 1024
# 数据目录：打包后从 LLM_SHIELD_DATA_DIR 环境变量读（panel.py 启动子进程时设置）；开发时回退到脚本目录
_DATA_ROOT = Path(os.environ.get("LLM_SHIELD_DATA_DIR") or str(_ROOT)).resolve()
_skip_seen = {}
_skip_seen_last_purge = 0.0

# ========== 引擎 ==========
sessions: dict = {}


def _debug(tag, sid, text):
    """调试日志：含真实敏感数据，仅排障用。

    受日志写入模式约束（§D1）：只有 detailed 才写原文。最小模式与限时排障
    都不能绕过新策略——「显式打开了 debug 开关」不是把未脱敏原文落盘的合法
    理由，否则最小模式就形同虚设（明文仍在数据目录里）。取模式失败时
    一律不写（fail-closed）。
    """
    if not DEBUG:
        return
    try:
        import event_store as _es
        if _es.effective_log_mode() != _es.LOG_MODE_DETAILED:
            return
    except Exception:
        return
    try:
        fn = _DATA_ROOT / f"debug-{time.strftime('%Y%m%d')}.log"
        head = f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} {tag} sid={sid} ====\n"
        with open(fn, "a", encoding="utf-8") as f:
            f.write(head)
            f.write(onboarding.scrub(text if isinstance(text, str) else str(text)))
            f.write("\n")
    except Exception:
        pass


def _touch(sid):
    s = _session_get(sid)
    if s:
        s["ts"] = time.time()


def _new_session(sid, source=None):
    sessions[sid] = {
        "fwd": {},
        "rev": {},
        "labels": {},
        # pending: {通道 -> 半截占位符}。流式响应里每个 delta 字段一个通道，
        # 避免上一个字段没闭合的占位符被拼进下一个字段（会把内容错位/吞字段）。
        "pending": {},
        # flush_tmpl: {通道 -> 最后一个该通道事件的 JSON}，收尾补发残留文本时做模板
        "flush_tmpl": {},
        "restored": 0,
        "restored_tokens": set(),
        "restored_origs": set(),
        "unresolved": 0,
        # 靠宽松兜底修回来的占位符数（模型把 {{}} 剥掉/写残，_LOOSE_PLACEHOLDER_RX
        # 捞回来的那些）。是成功路径，但值得看见：它说明模型在改写输出格式，
        # 是「哪天彻底还原不回来」的前兆。在这里显式初始化——原来只在
        # _loose_sub 里 s.get("degraded", 0)+1 隐式创建，没在会话结构里登记过，
        # 读的人不知道有这个字段（而且它压根没被发进事件，见 _restore_emit）。
        "degraded": 0,
        "last_hits": set(),
        "new_orig": set(),
        # 本次请求签发的占位符里，有没有「沿用复用表旧 token」的。
        # 只用于 MASK 事件的诊断字段（suffix_reused），不参与任何决策：
        # 全为 True 说明占位符后缀长期稳定，上游前缀缓存仍有机会命中；
        # 全为 False 的长会话说明每轮都在重签，缓存必然逐轮失效。
        "suffix_reused": False,
        # inflight: 请求已发出、响应未到。长生成（>SESSION_TTL）期间
        # 不能让 _sweep 按 ts 误删会话，否则整包路径响应到达时查不到 rev，
        # 占位符全部泄漏且不报错（P1-2）。
        "inflight": False,
        # 耗时统计：req_ts=请求到达（wall clock，事件展示用）；req_t0=perf_counter
        # 基准点（耗时计算用，精度 μs——time.time() 秒级，毫秒级请求会算成 0）；
        # mask_ms=脱敏管线；resp_ts=响应到达；first_byte_ms=流式首字节
        "req_ts": time.time(),
        "req_t0": time.perf_counter(),
        "mask_ms": 0.0,
        "resp_ts": None,
        "first_byte_ms": None,
        "ext_frames": {},
        "ts": time.time(),
        "source": source or {},
    }


def _drop(sid, expect=None):
    """丢弃会话。

    `expect` 给定时**只在当前会话仍是同一个对象时才丢**。必要性来自延迟调用方：
    aux 池里的流式收尾（`_stream_finish_offload`）投递即返回，等它跑 `_drop` 时，
    同一个 sid 上可能已经有**新会话**了（同一 sid 的连续两次流，测试与生产都可能），
    无条件 pop 会把新会话连同 rev 表一起抹掉 —— 表现为"占位符还原不回来"，
    且成败取决于 GIL 调度（实测同一用例连跑时随机红/绿）。
    返回 True 表示确实丢了。
    """
    if expect is not None and sessions.get(sid) is not expect:
        return False
    sessions.pop(sid, None)
    return True


def _luhn_ok(num: str) -> bool:
    """Luhn 校验（银行卡）。"""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 12:
        return False
    s, dbl = 0, False
    for d in reversed(digits):
        if dbl:
            d = d * 2 - 9 if d > 4 else d * 2
        s += d
        dbl = not dbl
    return s % 10 == 0


def _card_ok(orig: str) -> bool:
    """银行卡最终判据：去掉分隔符后必须是 13-19 位纯数字，且过 Luhn。

    位数校验以前是靠正则形状隐式保证的（`[3-6]\\d{3}(?:[\\s-]?\\d){9,15}`
    恰好 13-19 位）。0.1.15 把正则改成「无分隔 | 一致分隔符分组」两支之后，
    分组那支的组数可变、位数不再由正则锁死，必须在这里显式验——
    漏了它就会把 `554048 2025` 这种 10 位串当卡号。
    """
    digits = re.sub(r"[ -]", "", str(orig or ""))
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    return _luhn_ok(digits)


_IDCARD_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_IDCARD_CODE = "10X98765432"

_PROVINCES = {
    "11", "12", "13", "14", "15",
    "21", "22", "23",
    "31", "32", "33", "34", "35", "36", "37",
    "41", "42", "43", "44", "45", "46",
    "50", "51", "52", "53", "54",
    "61", "62", "63", "64", "65",
    "71", "81", "82",
}


def _idcard18_ok(num: str) -> bool:
    """GB 11643-1999 身份证 18 位多重严格校验：
    1. 省份行政区划代码合法（11-82）；
    2. 出生年月日真实性检验（1880 ~ 当前年份，含闰年 2 月 29 日与各月真实天数）；
    3. ISO 7064:1983.MOD 11-2 加权求模校验码匹配。
    """
    if not isinstance(num, str) or len(num) != 18 or not num[:17].isdigit():
        return False
    if num[:2] not in _PROVINCES:
        return False
    try:
        y, m, d = int(num[6:10]), int(num[10:12]), int(num[12:14])
        birth = datetime.date(y, m, d)
        now_year = datetime.datetime.now().year
        if not (1880 <= birth.year <= now_year):
            return False
    except ValueError:
        return False
    total = sum(int(d) * w for d, w in zip(num[:17], _IDCARD_W))
    return num[17].upper() == _IDCARD_CODE[total % 11]


def _idcard15_ok(num: str) -> bool:
    """GB 11643-1989 身份证 15 位综合有效性校验：
    1. 省份行政区划代码合法（11-82）；
    2. 出生年月日（YYMMDD -> 19YY-MM-DD）必须构成 1900~1999 年间真实的公历日期（含平闰年与月天数）。
    过滤掉时间戳、雪花 ID、订单号等任意非日期 15 位数字串。
    """
    if not isinstance(num, str) or len(num) != 15 or not num.isdigit():
        return False
    if num[:2] not in _PROVINCES:
        return False
    yy = int(num[6:8])
    mm = int(num[8:10])
    dd = int(num[10:12])
    try:
        birth = datetime.date(1900 + yy, mm, dd)
        if not (1900 <= birth.year <= 1999):
            return False
    except ValueError:
        return False
    return True


def _idcard_ok(num: str) -> bool:
    """身份证统一校验（0.1.18 合并开关后）：按匹配长度分发。
    15 位 → _idcard15_ok（省份 + 19YY 真实日期）；
    18 位 → _idcard18_ok（省份 + 真实日期 + ISO 7064 校验位）。
    正则已分别锁定位数，这里只做长度分发，避免误用。
    """
    if not isinstance(num, str):
        return False
    if len(num) == 18:
        return _idcard18_ok(num)
    if len(num) == 15:
        return _idcard15_ok(num)
    return False


def _phone_ok(num_str: str) -> bool:
    """国内手机号校验：
    1. 提取核心 11 位纯数字；
    2. 严格 1[3-9] 开头；
    3. 排除全同重复数字（如 11111111111）。

    只挡 set==1 的全同号：set<=2 会误杀 手机号（131 联通，set={1,3}=2）
    等真实在用号段。全同号 11111111111 的特征是 set==1，正则 1[3-9] 已挡住
    其第二位，这里只是双保险，不该误伤任何 2 种数字以上的合法号。
    """
    digits = re.sub(r"\D", "", str(num_str or ""))
    if digits.startswith("86") and len(digits) == 13:
        digits = digits[2:]
    elif digits.startswith("0086") and len(digits) == 15:
        digits = digits[4:]
    if len(digits) != 11:
        return False
    if not (digits[0] == "1" and digits[1] in "3456789"):
        return False
    if len(set(digits)) == 1:
        return False
    return True


def _landline_ok(num_str: str) -> bool:
    """国内固定电话号码校验：
    1. 必须以 0 开头（支持 3 位区号 010/02x 及 4 位区号 03xx~09xx）；
    2. 本地号码 7~8 位，首位 2~9（排除 0/1 开头非法本地号——国内普通座机
       无 1 开头号段，9 为付费/特殊号保守放行）；
    3. 带可选分机号。
    """
    digits = re.sub(r"\D", "", str(num_str or ""))
    if digits.startswith("86"):
        digits = digits[2:]
    elif digits.startswith("0086"):
        digits = digits[4:]
    if not (10 <= len(digits) <= 17):
        return False
    if not digits.startswith("0"):
        return False
    # 本地号首位：010/02x 是 3 位区号，本地号从第 4 位起；03xx-09xx 是 4 位区号，从第 5 位起。
    # 国内本地号首位 2-9（1 开头无此号段，0 开头非法）。正则已用 [2-9] 挡住首位 0/1，
    # 这里做双保险，防正则后续放宽后漏校验。
    if len(digits) >= 4 and digits[1] in "12":
        # 3 位区号 01x/02x
        local_first = digits[3]
    elif len(digits) >= 5 and digits[1] in "3456789":
        # 4 位区号 0xxx
        local_first = digits[4]
    else:
        return False
    if local_first not in "23456789":
        return False
    return True


def _email_ok(email_str: str) -> bool:
    """邮箱地址校验：
    1. 包含合法用户名与域名；
    2. 排除连续双点及冒号前缀连接串；
    3. 顶级域名至少 2 位。
    """
    s = str(email_str or "").strip()
    if "@" not in s or s.startswith("@") or s.endswith("@"):
        return False
    parts = s.split("@")
    if len(parts) != 2:
        return False
    local, domain = parts[0], parts[1]
    if len(local) < 1 or len(domain) < 3 or "." not in domain:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local or ".." in domain:
        return False
    tld = domain.split(".")[-1]
    if len(tld) < 2:
        return False
    return True


def _iban_ok(iban: str) -> bool:
    """IBAN mod-97 校验：字母 A=10..Z=35，前 4 位移尾后整体 mod 97 余 1。"""
    s = iban.strip()
    if len(s) < 15 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    reordered = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in reordered)
    try:
        return int(digits) % 97 == 1
    except Exception:
        return False


def _jwt_ok(token: str) -> bool:
    """JWT 真伪校验：第一段（eyJ...）base64url 解码后必须是含 alg 的 JSON header。
    只按三段形态匹配会把长 base64 串误判为 JWT（曾无校验直接脱敏）。"""
    try:
        head = token.split(".")[0]
        pad = "=" * (-len(head) % 4)
        decoded = base64.urlsafe_b64decode(head + pad).decode("utf-8", errors="replace")
        return '"alg"' in decoded
    except Exception:
        return False


# ---- CONNSTR 误报豁免的形态常量 ----
# 全部提到模块级：mask() 是热路径，一次请求可能命中上万条连接串，
# 函数内每次调用重建 set / 编译正则纯属浪费（审计 2026-09 复审）。
# 判据一律「锚定整体形态」，**绝不**用字符类判「密码里含模板符号」——
# 曾用 `re.search(r"[{<\[\$%]", orig)`，结果 `Xk9$mQ2p`、`p%40ssw0rd` 这类
# 真实口令被判成模板而豁免，明文直接上行（详见 _connstr_ok 注释）。
_CONNSTR_TPL_RXS = (
    re.compile(r"^\$?\{[A-Za-z_][A-Za-z0-9_]*\}$"),   # {password} / ${PORT}
    re.compile(r"^<[A-Za-z_][A-Za-z0-9_]*>$"),        # <password>
    re.compile(r"^\[[A-Za-z_][A-Za-z0-9_]*\]$"),      # [password]
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),        # $PORT
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),        # %PWD%
)
# 通配占位：**** / ... / xxxx
_CONNSTR_WILDCARD_RX = re.compile(r"^[xX*.]+$")
# 文档保留 / 占位主机（RFC 2606 的 example.* 与常见教程主机名）
_CONNSTR_DUMMY_HOSTS = frozenset({
    "host", "hostname", "myhost", "server", "myserver",
    "example.com", "example.org", "example.net",
    "test.com", "sample.com", "your-host", "yourhost", "yourdomain.com",
})
_CONNSTR_DUMMY_HOST_SUFFIXES = (".example", ".invalid")
# 经典教学占位凭据对
_CONNSTR_PLACEHOLDER_USERS = frozenset({"user", "username", "your_username", "yourusername", "usr", "guest"})
_CONNSTR_PLACEHOLDER_PASSWORDS = frozenset({
    "pass", "password", "passwd", "your_password", "yourpassword", "changeme", "change_me", "guest",
})
# 一次请求里最多记录多少条「被豁免的连接串原文」供下游规则避让。
# 上界只为防病态输入：集合是去重的，文档模板反复出现只会留 1 条；
# 超过上界后不再记录，最坏结果是下游规则照常脱敏（安全方向）。
_CONNSTR_EXEMPT_MAX = 512

# `@` 之后的 authority（host[:port]）。IPv6 字面量必须整体吃进 `[...]`：
# 按 `split(":", 1)` 拆 `[::1]:5432` 会得到 host=`[`、port=`::1`，
# 非数字端口判定随即把它当模板豁免 —— 真实口令明文上行（复审实测漏检）。
_CONNSTR_AUTH_RX = re.compile(r"^(?:\[[^\]\s]*\](?::[^\s/?#\"'`)>},;]*)?|[^\s/?#\"'`)>\]},;]*)")


def _connstr_authority(text: str, pos: int):
    """取 pos 处的 authority，返回 (host, port)；port 无端口时为空串。"""
    tail = text[pos:pos + 256] if text else ""
    m = _CONNSTR_AUTH_RX.match(tail)
    auth = m.group(0) if m else ""
    if auth.startswith("["):
        host, _, rest = auth.partition("]")
        return host, (rest[1:] if rest.startswith(":") else "")
    host, sep, port = auth.partition(":")
    return host, (port if sep else "")


def _connstr_ok(orig: str, m=None, text: str = "") -> bool:
    """连接串密码真伪校验：只豁免「一眼是文档/代码模板」的形态，其余照常脱敏。

    判据分四档，任一档成立才豁免（**fail-closed：拿不准就脱敏**）：

      1. 端口非数字（`:port` / `:<port>` / `:{port}` / `:$PORT`）**且**用户名或密码是
         占位形态 —— RFC 3986 规定端口必须是纯数字，非数字端口是模板；但「端口是模板」
         推不出「密码是假的」，单凭端口豁免会把 `https://svc:secret123@db.internal:port/x`
         的真实口令原样放行。
         ⚠️ 佐证项**不含占位主机**：主机像模板同样是「端口是模板」的同类信号，拿它当
         佐证等于循环论证，会把 `postgres://admin:S3cret99@host:port/db` 整体豁免
         （实测 12 个占位主机名全部漏检，2026-09 复审）。主机只在第 3 档与「密码是占位词」
         **同时**成立时才算证据。
         另外要求端口里一个数字都没有：`:5432x` 这种带数字的照常脱敏。
      2. 密码整体是锚定模板形态：`{password}` / `<password>` / `[password]` /
         `$PORT` / `%PWD%` / `****` / `xxxx`。
      3. 主机是文档保留域名或占位词（host / example.com / test.com …）**且**密码也是
         占位词 —— 只查主机不查密码，会把 `admin:S3cret99@host:5432` 这类真实口令放行。
      4. 用户名与密码是经典教学组合（user:pass / username:password）。

    历史教训（2026-09 复审，两处必须记住的坑）：
      · 用字符类 `[{<\\[\\$%]` 判「密码含模板符号」会把真实口令判成模板而豁免，
        `mysql://root:p%40ssw0rd@…` 直接全明文上行。
      · 豁免本身还会**放走下游规则**：CONNSTR 让路后排在后面的 EMAIL 规则会把
        「口令尾@host」整段当邮箱吃掉，输出 `postgres://app:Xk9${{EMAIL_x}}:5432/prod`
        —— 看着有占位符、实际口令前半截明文上行，最危险的一类。
        由 mask() / 扫描路径里的 `exempt_conn` 区间列表负责避让，两处必须成对修改
        （判据见 `_overlaps_exempt_conn`：只跳过**与豁免区间重叠**的 EMAIL 命中）。
    """
    if not isinstance(orig, str) or not orig:
        return False
    if _CONNSTR_WILDCARD_RX.match(orig):
        return False
    if any(rx.match(orig) for rx in _CONNSTR_TPL_RXS):
        return False
    if m is None:
        return True

    try:
        # 从 `scheme://user:pass@` 里回推 username
        prefix = m.group(0)
        user_part = ""
        if "://" in prefix:
            _scheme, rest = prefix.split("://", 1)
            idx = rest.rfind(":" + orig + "@")
            user_part = rest[:idx] if idx != -1 else rest.split(":", 1)[0]

        host, port = _connstr_authority(text, m.end())
        host_lower = host.lower().strip("[]")
        user_lower = user_part.lower()
        pass_lower = orig.lower()
        host_dummy = (host_lower in _CONNSTR_DUMMY_HOSTS
                      or host_lower.endswith(_CONNSTR_DUMMY_HOST_SUFFIXES))
        user_dummy = user_lower in _CONNSTR_PLACEHOLDER_USERS
        pass_dummy = pass_lower in _CONNSTR_PLACEHOLDER_PASSWORDS

        # 1. 非数字端口。注意：端口是模板 ≠ 密码是假的，我们决定的是「要不要脱密码」，
        #    所以还要一个弱信号佐证 —— 但佐证只能是**用户名或密码**是占位词。
        #    曾把 host_dummy 也算进来，等于「端口像模板 + 主机像模板 ⇒ 密码是假的」：
        #    主机像模板和端口像模板是同一类信号，循环论证，实测
        #    `postgres://admin:S3cret99@{host|example.com|db.example|…}:port/db` 12/12 全漏，
        #    真实口令原样上行（2026-09 复审）。主机要到第 3 档、与占位密码同时成立才算数。
        #    端口里不含任何数字才认（`:5432x` 这种带数字的照常脱敏）。
        if port and not any(ch.isdigit() for ch in port):
            if user_dummy or pass_dummy:
                return False

        # 2. 占位主机：必须「主机 + 密码」同时像占位才豁免。
        #    只查主机不查密码，会把 `admin:S3cret99@host:5432` 这类真实口令放行。
        if host_dummy and pass_dummy:
            return False

        # 3. 经典教学凭据对（user:pass / username:password）
        if user_dummy and pass_dummy:
            return False
    except Exception:
        # 校验自身出错时保守脱敏（绝不把疑似凭据放明文出网）
        return True

    return True


def _overlaps_exempt_conn(start: int, end: int, spans) -> bool:
    """EMAIL 命中 [start, end) 是否与被豁免的连接串**重叠**。

    为什么判「重叠」而不是「紧接其后」（2026-09-13 修正）：
    连接串的 CONNSTR 命中止于 userinfo 结尾的 `@`（host/port 在 `m.end()` 之后由
    `_connstr_authority` 单独解析），所以真正需要避让的 EMAIL 命中是**起点落在豁免
    串内部**的那些——它们才是「口令尾@host」，脱掉一半会留半截口令明文。
    而「起点正好在豁免串之后」的 EMAIL 命中是**独立的真实邮箱**（例如
    `redis://default:{password}@zhang.san@example.com:6379` 里那个 `@example.com`
    主机名形式的邮箱），把它一起跳掉等于新增一条漏检：实测 guard 开着时该邮箱
    明文上行，关掉才被正常脱敏。

    ⚠️ 判据必须是重叠、不能只看「前一个字符是不是 `@`」：后者既挡不住口令尾
    （口令在 `@` 之前，前一个是 `:`），又会误伤紧跟其后的真实邮箱。
    把本函数整体改成 `return False` 时 660 个用例仍全过 —— 说明它此前**没有任何
    用例保护**，改这里务必同步补用例。

    `spans` 由 finditer 顺序追加，天然按 start 递增且互不重叠，故一旦
    `s_start >= end` 即可提前结束。
    """
    if not spans:
        return False
    for s_start, s_end in spans:
        if s_start >= end:
            break
        if start < s_end and end > s_start:
            return True
    return False


_prefix_rx_cache = None
_prefix_rx_key = None
# 记忆化是"检查-写两格"：`key == old_key` 与两个 global 的写入不是原子的。
# 多线程可达（脱敏池 1~4 + aux 池 2，`_scan_response` 也会调本函数），交叉写会得到
# "新键 + 旧正则" 或反过来的错配 —— 最坏后果是**用上一次的前缀配置扫凭据**
# （API-key 掩码是安全路径，静默错配不可接受）。与我已修的 `_AUDIT_CFG_FP_LOCK` 同类。
_prefix_rx_lock = threading.Lock()


def _ip_public_ok(orig: str) -> bool:
    """公网 IPv4 校验：排除已知公共 DNS、版本号形态、私网、环回、组播及保留段。

    两层版本号启发式（规则默认关，宁漏勿误伤）：
    1. 四段全个位数（1.2.3.4 / 2.0.1.0）：开发文本里压倒性偏向版本号与教学
       示例；真实公网主机的全个位数地址只有知名 anycast DNS，已全部枚举进白名单。
    2. 构建号形态（首段个位 + 第三段为 0 + 末段三位数，如 Java 1.8.0.202 /
       2.4.0.101）：Java/构建号版本的标准形状。第三段必须为 0——不加这条的
       话 5.189.128.100 这类真实公网主机（AWS/Level3 的 3.x/5.x/8.x 段常见）
       会被放行（复审实测）。
    漏检面（fail-open，已知取舍）：全个位数非白名单段（8.8.8.1）、构建号形态
    真实主机（5.189.0.100）不脱；由默认关闭 + 元数据标注兜底。
    """
    if not isinstance(orig, str) or orig in KNOWN_PUBLIC_DNS:
        return False
    try:
        parts = orig.split(".")
        # 四段全个位数：视为版本号/教学示例放行（白名单已在上面先判）
        if all(len(part) == 1 for part in parts):
            return False
        # 构建号形态：首段个位 + 第三段为 0 + 末段三位数（100-255）
        if len(parts[0]) == 1 and parts[2] == "0" and len(parts[-1]) == 3:
            return False
        addr = ipaddress.IPv4Address(orig)
        return addr.is_global and not addr.is_multicast
    except ValueError:
        return False


# USCC（统一社会信用代码）字符集与 MOD31 权重：GB 32100-2015。
# 权重因子 31^i mod 31 不会循环出 0（31 是素数），官方即用 1..31 直接乘。
_USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


def _ipv6_private_ok(orig: str) -> bool:
    """IPv6 私网校验：仅 fe80::/10（链路本地）与 fc00::/7（ULA）算命中。

    宽正则抓来的候选绝大多数不是 IPv6（MAC、时间、端口号串），先靠
    ipaddress 解析剔除；解析成功的再看是否私网段。注意不能用
    IPv6Address.is_private——它把 2001:db8::/32（文档段）、::1（环回）等
    全算 private，公网讨论文本里的这些地址会被误脱（实测 2001:db8::1
    被 is_private 放行进打码）。只认 ULA 与链路本地两段，其余一律放行。
    带 zone id（fe80::1%eth0）的解析会失败——剥掉 % 后缀再试一次，
    链路本地地址带 zone 是 Linux 网络配置的常态写法。
    """
    if not isinstance(orig, str) or orig.count(":") < 2:
        return False
    candidate = orig.split("%", 1)[0]
    try:
        addr = ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return addr.is_link_local or (addr in ipaddress.IPv6Network("fc00::/7"))


def _uscc_ok(orig: str) -> bool:
    """USCC 校验位验证（GB 32100-2015 MOD31）。

    18 位 = 登记管理部门(1) + 机构类别(1) + 登记管理机关(6) + 主体标识(9) +
    校验位(1)。前 17 位加权求和 mod 31，映射到字符集取校验位比对。
    规则默认关；开启后校验位把随机字母数字串的误伤率压到 1/31 以下。
    """
    if not isinstance(orig, str) or len(orig) != 18:
        return False
    try:
        total = sum(_USCC_WEIGHTS[i] * _USCC_CHARS.index(orig[i]) for i in range(17))
        check = (31 - total % 31) % 31
        return _USCC_CHARS[check] == orig[17]
    except ValueError:
        return False


def _prefix_secret_regex():
    global _prefix_rx_cache, _prefix_rx_key
    key = tuple(SECRET_PREFIXES)
    if key == _prefix_rx_key and _prefix_rx_cache is not None:
        return _prefix_rx_cache
    with _prefix_rx_lock:
        # 双检：并发首次调用只编译一次，且键与值成对写
        if key == _prefix_rx_key and _prefix_rx_cache is not None:
            return _prefix_rx_cache
        return _prefix_secret_regex_locked(key)


def _prefix_secret_regex_locked(key):
    """编译前缀正则（调用方持 `_prefix_rx_lock`）。"""
    global _prefix_rx_cache, _prefix_rx_key
    # - / _ 视为等价（审计规则专项 P2）：用户配 sk- 不会漏掉 sk_live_，配 ghp_ 也兼容 ghp-。
    # 把前缀中的 - 和 _ 都展开成 [-_] 字符类。逐字符安全转义，防二次替换嵌套。
    prefixes = ["".join("[-_]" if ch in ("-", "_") else re.escape(ch) for ch in p) for p in SECRET_PREFIXES if p]
    if not prefixes:
        _prefix_rx_cache = None
        _prefix_rx_key = key
        return None
    # 凭据后缀阈值：前缀匹配后跟随至少 8 位无空格密文字符（1+7 位）。
    # 之前硬编码 19 位（1+18）导致自建平台、内部鉴权或测试环境的 8~16 位自定义短 Key 严重漏判。
    # 设为 8 位既能彻底避开 sk-demo/sk-test 等极短日常词误伤，又能全面覆盖自定义短凭据。
    _prefix_rx_cache = re.compile(r"(?<![A-Za-z0-9_-])(?:" + "|".join(prefixes) + r")[A-Za-z0-9][A-Za-z0-9_-]{7,}(?![A-Za-z0-9_-])")
    _prefix_rx_key = key
    return _prefix_rx_cache


# ========== 占位符 ==========
# 格式：{{LABEL_后缀6位}}，纯 ASCII。后缀自 0.1.13 起是纯辅音（见下方 _TOKEN_ALPHABET），
# 存量 hex6 后缀仍继续识别（见 _SUFFIX_PAT）。
# 旧格式 ⟦X·hex⟧ 用生僻 Unicode 且不带语义：主流 tokenizer 会切成多个罕见 token，
# 模型复述时容易变形（少一个括号就还原失败），且模型不知道占位符代表什么，回答质量下降。
# 新格式保留业务标签（PHONE / EMAIL / TERM…），模型能理解"这里原本是个电话号"。
_LABEL_SAFE_RX = re.compile(r"[^A-Z0-9]+")

# 凭据标签互通族（大模型在写代码/生成命令时，对 CONNSTR/SECRET/PASSWORD/TOKEN 容易混用）
_CREDENTIAL_SYNONYMS = frozenset({
    "CONNSTR", "SECRET", "PASSWORD", "PASSWD", "PWD", "TOKEN",
    "APIKEY", "ACCESSKEY", "PRIVATEKEY",
})

# IP 标签互通族（大模型常把 IPPRIVATE / IPINTERNAL 缩写为 IP）
_IP_SYNONYMS = frozenset({
    "IPPRIVATE", "IPINTERNAL", "IP",
})


def _labels_compatible(lab_a, lab_b):
    """判定两个归一化标签是否语义兼容（用于后缀反查容错）。"""
    if lab_a == lab_b:
        return True
    if lab_a in _CREDENTIAL_SYNONYMS and lab_b in _CREDENTIAL_SYNONYMS:
        return True
    if lab_a in _IP_SYNONYMS and lab_b in _IP_SYNONYMS:
        return True
    return False


def _safe_label(label):
    """标签 ASCII 化。内置规则标签本身是 ASCII；自定义中文标签统一归 TERM。"""
    up = _LABEL_SAFE_RX.sub("", str(label or "").upper())
    return up[:12] or "TERM"


def _rand_suffix():
    """占位符后缀：6 位纯辅音（字符集与理由见 _TOKEN_ALPHABET）。

    用 secrets.choice 而不是 random：这个后缀是会话内实体的唯一标识，
    可预测的后缀会让上游能够枚举、关联同一实体。
    """
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(6))


def _new_token(label):
    """生成不与近期占位符冲突的新占位符。

    冲突判定同时看**完整 token** 与**6 位后缀**：后缀索引按后缀反查，若两个
    存活 token 共用一个后缀，标签被改写时就会把 A 的原文替换到 B 的位置上。
    后缀空间 19^6≈4700 万、表内至多 _RECENT_MAX=2000 条，多一次后缀检查
    换来「索引永远无歧义」，这个代价是值的。
    """
    lab = _safe_label(label)
    tables = _tables()
    for _ in range(20):
        token = "{{%s_%s}}" % (lab, _rand_suffix())
        # 冲突判定按**当前表组**：演示仓是真实复用窗口的快照副本，所以查它同时
        # 覆盖了两边——演示里签出的 token 不会与真实 token 抢同一个后缀。
        if token not in tables.rev and _token_suffix(token) not in tables.suffix:
            return token
    # 兜底仍用 6 位：长度必须落在 _SUFFIX_PAT 认得的范围内。
    # 原来这里返回 secrets.token_hex(6)（12 个字符），而正则只认 6 个——
    # 一旦触发，该 token 永远匹配不到、还原永久失败，且失败得毫无声响。
    # 实际不可达：19^6≈4700 万，表里至多 _RECENT_MAX=2000 条，
    # 单次撞上约 4.3e-5，连撞 20 次约 1e-88。
    return "{{%s_%s}}" % (lab, _rand_suffix())


# ===================== 共享态互斥锁（2026-09-24）=====================
# 为什么需要：脱敏不再是「只有 mitmproxy 事件循环一个线程」在跑。代理链路的脱敏
# 现在跑在 `_MASK_POOL` 专职线程，panel 的扩展桥接另有 Flask 线程，它们都会走到
# `_recall_token` / `mask`，即都在改本文件级的全局表：`_RECENT_FWD/_REV`、
# `_RECENT_SUFFIX`、`_CUSTOM_WORD_FWD/_REV`、`_CUSTOM_WORDS_SORTED`。
#
# 单条 dict 操作靠 GIL 是原子的，真正危险的是**多步序列**与**遍历**：
#   1) `_recall_token` 的「查后缀占用 → 生成 token → 登记三张表」不是原子的：
#      两个线程可能签出同一后缀，于是同一个 token 指向两个原文，还原时把 A 的
#      原文填到 B 的位置（`_suffix_index_add` 的注释已写明「替换错值比不替换
#      危险得多」）。
#   2) `_prune_recent` / `_sync_custom_word_mappings` 会遍历并成批删改这些表，
#      与并发写入相撞会抛 `RuntimeError: dictionary changed size`（请求直接失败）。
#
# 配置项（词表 / 规则开关 / 上游表等）不走本锁：`_maybe_reload` 一律**整体换对象**
# 发布，读者只会看到上一代或新一代。曾经对 `CUSTOM_WORDS` 用就地 `clear()+update()`，
# 读者可能看到半填充词表并把它当当前词表发布 —— 那一轮少脱敏用户自定义词，明文出网。
#
# 锁序（**必须遵守**）：`panel._EXT_LOCK` → 本文件的 `_SYNC_LOCK` → `_STATE_LOCK`。

# ── B-1a：`sessions[sid]` 的并发契约（0.6.0 定稿）────────────────────────────
# 背景（必须写清楚，否则下一个人会照抄过时注释）：`sessions` 及会话内的字段
# **不是**"已经由 _STATE_LOCK 保护好了"的——`_STATE_LOCK` 原本只护
# `_RECENT_*` / `_CUSTOM_WORD_*` 的签发与清理。0.6.0 之前，代理链路恰好只有
# 一个脱敏线程（`_MASK_POOL(max_workers=1)`），会话态才"事实上"没出问题；
# 放开并发宽度 + 把还原搬进 `_AUX_POOL` 之后，同一个 `sessions[sid]` 会同时被
# N 个 worker、aux 池与事件循环读写。因此逐字段定下契约：
#
#   ① 只读 / 单次赋值（ts、source、model、scan_scope、upstream_name、resp_ts、
#      stream_mode…）：并发只会读到旧值或新值，语义无害，**不加锁**。
#   ② 计数与映射的读改写（restored / degraded / unresolved / restored_tokens /
#      restored_origs / rev / fwd / labels）：**必须持 `_STATE_LOCK`**。
#      少加一处的后果不是崩溃而是"数字对不上"——比崩溃更难查，所以宁可多拿锁。
#   ③ 去重式追加（先判断再 append/add）：判断与写入是两步 → 持 `_STATE_LOCK`。
#   ④ 字典本身的插入/删除（新会话、sweep）：靠 GIL 原子；**遍历一律 `list()` 快照**。
#
# `_STATE_LOCK` 是 RLock：签发路径已经在持它，这里再用不会自锁；
# 也不引入新的锁序边（不新开锁层级）。
# panel 侧先持 `_EXT_LOCK` 再进 transparent；本文件绝不持锁回调 panel 或做任何 I/O，
# 因此不存在反向路径，没有死锁环。临界区必须保持微秒级：**严禁**在持锁期间做 NER
# 推理、读写文件、发网络请求或遍历长会话。
_STATE_LOCK = threading.RLock()

# 自定义词映射重建的串行锁。
# 重建分三段：① 锁内取快照（微秒级）→ ② **锁外**派生（SHA-256 + 避让探测，逐词
# 计算，千词表就是百毫秒级）→ ③ 锁内换表。派生必须与落表同锁串行，否则两次并发
# 重建各基于同一份旧快照、可能派生出同一个后缀（撞车即张冠李戴）；但它不该占着
# `_STATE_LOCK`，那样配置保存时在途脱敏只能干等。
# 锁序上它必须排在 `_STATE_LOCK` **外**（先 `_SYNC_LOCK` 再 `_STATE_LOCK`），
# 所以 `_custom_words_sorted` / `_refresh_custom_words_sorted` 都在释放 `_STATE_LOCK`
# 之后才调重建。
_SYNC_LOCK = threading.Lock()

# 跨请求占位符复用表（仅内存，TTL = session_ttl，带条数上限）。
# 解决两个真实问题：
# 1) 多轮对话里同一实体每轮拿到不同占位符，模型会当成不同的人；
# 2) 上一轮响应里没还原干净的占位符留在客户端历史里，下一轮请求带上来时无从还原，
#    会话被污染且永远不会自愈。复用表让历史占位符仍能查到原文（见 _lookup / _seed_known）。
# 代价：原文在内存中的保留窗口从"单请求"延长到 session_ttl，且同一原文在 TTL 内
# 对上游呈现同一占位符（可被关联）。TTL 到期即失效，不落盘。
_RECENT_FWD = {}   # orig -> [token, label, ts]
_RECENT_REV = {}   # token -> [orig, label, ts]
_RECENT_MAX = 2000

# 自定义敏感词持久化映射表（仅内存常驻，不随 TTL/LRU 淘汰）：
# 解决长任务、Agent 工具调用时因超过复用表 TTL 或引擎重启导致无法还原的问题。
# 自定义敏感词来自用户明确配置的 CUSTOM_WORDS，其原文已在配置文件中受控持久化，
# 因此其内存映射在运行时永久常驻，且通过确定性派生算法保证跨重启后缀一致。
_CUSTOM_WORD_FWD = {}  # orig -> token
_CUSTOM_WORD_REV = {}  # token -> [orig, label, ts]


def _deterministic_suffix(orig, used_suffixes=None):
    """为自定义敏感词生成确定性的 6 位纯辅音后缀。

    使用 SHA-256 确定性派生，在词表内发生碰撞时递增计数器避让。
    保证相同的敏感词在多次重启、跨会话中始终获得稳定相同的占位符，
    最大化上游 Prompt Cache 命中率并保证长任务工具调用可靠还原。
    """
    counter = 0
    while True:
        seed = f"maskit_cw:{counter}:{orig}".encode("utf-8")
        h = hashlib.sha256(seed).digest()
        suffix = "".join(_TOKEN_ALPHABET[b % len(_TOKEN_ALPHABET)] for b in h[:6])
        if used_suffixes is None or suffix not in used_suffixes:
            return suffix
        counter += 1


def _is_custom_word_orig(orig):
    """该原文是否属于**当前启用**的自定义敏感词（决定是否永久豁免 TTL/LRU）。

    必须连启用状态一起判：词或整组被禁用后仍返回 True 的话，它的映射会绕过
    TTL 与 LRU 永久驻留，与「复用表到期即失效」的原文驻留窗口契约冲突
    （见 SECURITY.md）。label 优先取已签发的 REV 记录，退回配置里的 label。
    """
    tables = _tables()
    tok = tables.cw_fwd.get(orig)
    if tok is not None:
        rec = tables.cw_rev.get(tok)
        return _custom_word_enabled(orig, (rec[1] if rec else None) or CUSTOM_WORDS.get(orig, ""))
    if orig in CUSTOM_WORDS:
        return _custom_word_enabled(orig, CUSTOM_WORDS.get(orig, ""))
    return False


def _is_custom_word_token(tok):
    return tok in _tables().cw_rev
# 启动预热时最多回读的事件条数（见 _warmup_recent_from_db）。复用表本来就有
# _RECENT_MAX 封顶，读再多也留不住，这个上限只是防止重度使用下几万条事件
# 逐条 json.loads 把引擎启动拖慢。
_WARMUP_MAX_EVENTS = 5000

# 后缀索引：6 位后缀 -> 完整 token。**只是 _RECENT_REV 的指针，不存原文**，
# 所以它不会延长原文在内存里的存活窗口，也不需要独立的 TTL。
#
# 解决什么：模型会把占位符的标签改写掉——`{{IPPRIVATE_x}}` 写成
# `{{IP_PRIVATE_x}}`（自己补回下划线）或 `{{ipprivate_x}}`（整段小写）。
# 标签一变，按完整 token 查表必然落空，而 6 位后缀是随机指纹、模型改不动它，
# 于是「按后缀反查」就能把它们救回来。
#
# 三条硬约束（都来自实测，不是保守起见）：
# 1. **只收录纯辅音后缀**。给正则加 IGNORECASE 之后，`config_abc123` /
#    `sha_abcdef` 这类「小写标识符 + `_hex6`」会命中宽松形态（实测）。今天
#    只是白查一次表，可一旦后缀索引介入就会把整段替换成明文，直接改坏用户
#    代码。hex6 后缀是存量格式、且在代码里天然常见，所以一律不进索引，
#    继续只走完整 token 精确匹配。
# 2. **只在带花括号的调用点使用**（restore 的严格遍与转义遍）。流式响应里
#    裸 token 被 chunk 切开后，残片（实测 `ATE_zwndfk`）会被宽松正则命中；
#    后缀索引一旦介入就会把残片替换成明文，拼出一条错的命令。
# 3. **标签归一化后必须相等，或属于同一凭据互通族**（见 _suffix_real_token 与 _labels_compatible）。
#    后缀只有 47M 分之一的碰撞概率，但一旦碰撞就是静默替换错值（把 A 的内网 IP 填到 B 的位置）。
#    普通标签如 `{{HOST_x}}` 这种整段换名不认，走 unresolved；但凭据族内部（大模型把 CONNSTR
#    改写为 PASSWORD / SECRET）属于同义互通族，且撞车后缀会被 _SUFFIX_AMBIGUOUS 剔除，
#    允许语义兼容反查。
#
# 维护：_suffix_index_add / _suffix_index_del 是唯一入口，必须与
# _RECENT_FWD / _RECENT_REV 的写入、淘汰**成对出现**（见 _prune_recent、
# _warmup_recent_from_db、_recall_token 三处）。
_RECENT_SUFFIX = {}
# 后缀撞车标记：同一个后缀被两个存活 token 占用时写进索引值。
# 撞车后**永不参与兜底匹配**——「保留先来的那个」会把 A 的原文答给 B，
# 属于静默替换错值；拒答的代价只是这个后缀不再兜底，退化成改动前的行为。
_SUFFIX_AMBIGUOUS = object()


class _TokenTables:
    """一组占位符映射表（复用窗口 FWD/REV/后缀索引 + 自定义词永久映射）。

    存在的唯一理由是**演示隔离**：`/api/demo/lab` 要在不给真实会话留痕的前提下
    回答「同样的原文会得到什么占位符」。只靠 sid 做不到这件事——sid 只隔离
    `sessions`，而签发 token 用的复用表是进程级全局的，演示样本一旦写进去就会
    进入真实请求的复用窗口（反过来，真实请求也会复用演示的 token）。

    所以参数化的是「表」而不是「sid」：默认表组（`_GlobalTables`）动态读模块
    全局，演示作用域（`demo_store_scope`）注入本类的独立实例；本文件的脱敏/还原
    路径一律经 `_tables()` 取表，不再直接引用全局名（预热与词表重载两条全局
    生命周期路径除外，它们有意写全局表）。
    """

    __slots__ = ("fwd", "rev", "suffix", "cw_fwd", "cw_rev")

    def __init__(self, fwd, rev, suffix, cw_fwd, cw_rev):
        self.fwd = fwd
        self.rev = rev
        self.suffix = suffix
        self.cw_fwd = cw_fwd
        self.cw_rev = cw_rev


class _GlobalTables:
    """默认表组：字段在**每次访问时**读模块全局，不持引用。

    持引用会在两处静默出错：
    - `_sync_custom_words` 在词表/标签变更时**整体换对象**
      （`_CUSTOM_WORD_FWD = new_fwd`），持引用会让访问器继续看上一代表 ——
      词表改了却识别不到；
    - 测试与压测会整体替换 `_RECENT_FWD`（如 `_IterationWindowDict` 探并发遍历），
      持引用等于把它们替换的那张表绕过。
    一次属性读只是一次模块字典查找，相比热点路径上的正则扫描可以忽略。
    """

    __slots__ = ()

    @property
    def fwd(self):
        return _RECENT_FWD

    @property
    def rev(self):
        return _RECENT_REV

    @property
    def suffix(self):
        return _RECENT_SUFFIX

    @property
    def cw_fwd(self):
        return _CUSTOM_WORD_FWD

    @property
    def cw_rev(self):
        return _CUSTOM_WORD_REV


_DEFAULT_TABLES = _GlobalTables()
# 线程本地覆盖：**只对设置了它的线程生效**。脱敏工作线程（_MASK_POOL）、代理
# 事件循环、事件库写入线程从不设置它，因此一律看到全局表 —— 演示作用域不会
# 把它们拽进来（这正是选线程本地而不是「临时换模块全局名」的理由：后者是
# 进程级的，演示那段窗口里并发的真实请求会把 token 签进演示仓，换回后全部丢失）。
_TABLES_TLS = threading.local()


def _tables():
    """当前线程生效的表组；未设置覆盖时为全局表。"""
    cur = _TABLES_TLS.__dict__.get("cur")
    return cur if cur is not None else _DEFAULT_TABLES


@contextlib.contextmanager
def demo_store_scope(seed_recent=True):
    """把**当前线程**的表组切到演示专用仓（退出时必然还原，异常也一样）。

    种子策略（默认 `seed_recent=True`）：复用窗口与后缀索引取只读快照，自定义词
    永久映射取独立拷贝。为什么不是空表：演示的意义是「真实请求会得到什么」，
    而同一原文若本机已有存活 token，真实请求会沿用它 —— 空表会让演示显示一个
    现实中不会出现的后缀，这个功能就失去了意义。而演示期间的**所有写入只落在
    副本上**：真实复用窗口一条不增、一条不减、时间戳一点都不动。

    快照必须在 `_STATE_LOCK` 内做：别的线程正在签发/淘汰时遍历这些 dict 会抛
    `RuntimeError: dictionary changed size during iteration`。拷贝很快，脱敏
    （慢的那段）留在锁外。
    """
    with _STATE_LOCK:
        tables = _TokenTables(
            fwd={k: list(v) for k, v in _RECENT_FWD.items()},
            rev={k: list(v) for k, v in _RECENT_REV.items()},
            suffix=dict(_RECENT_SUFFIX),
            cw_fwd=dict(_CUSTOM_WORD_FWD),
            cw_rev={k: list(v) for k, v in _CUSTOM_WORD_REV.items()},
        )
    prev = _TABLES_TLS.__dict__.get("cur")
    _TABLES_TLS.cur = tables
    try:
        yield tables
    finally:
        # 还原而不是直接删属性：demo 作用域可以嵌套（回归测试会连续进入），
        # 删掉会把外层那一层一起扯掉。
        if prev is None:
            _TABLES_TLS.__dict__.pop("cur", None)
        else:
            _TABLES_TLS.cur = prev

# 复用表用独立 TTL，不跟着 SESSION_TTL（默认 600s）走。
#
# 起因（实测）：agent 类客户端一个任务动辄跑几十分钟，上下文里始终带着几十轮前
# 的占位符。SESSION_TTL 一到，_RECENT_REV 里的映射就被清掉，之后模型回复里的
# 占位符查不到原文 → 原样透传给客户端 → 用户看到裸露的 {{IPPRIVATE_c81792}}，
# agent 把它当成真值去执行，命令直接失败。表现出来就是「还原功能坏了」，
# 实际是映射过期。
#
# 为什么不干脆调大 SESSION_TTL：那个值同时管 sessions 的回收，长对话的 fwd/rev
# 可能几千条且无上限，调大它是拿内存换命中率。复用表本身有 _RECENT_MAX=2000 封顶，
# 单独放宽到 24h 的内存代价是有界的（2000 条 × 两个方向）。
#
# 这张表本身仍不落盘：里面是原文明文，主动写盘等于把凭据写进磁盘，与
# 「凭据永不落库」直接冲突。
#
# 但 0.1.12 起启动时会从**事件库**做一次只读预热（_warmup_recent_from_db）：
# 那些 original 是用户明确要求落的日志（约束 5），本来就在盘上，读它不产生
# 任何新的磁盘写入，凭据类在库里也只有 digest 没有原文。所以
# 「引擎重启后历史占位符不可还原」这句自 0.1.12 起不再成立——
# 48h 内的普通 PII 映射能恢复，更早的仍然丢。
RECENT_TTL = 24 * 3600


def _recent_ttl():
    """复用表 TTL：至少 24h，用户把 session_ttl 调得更大时跟随。"""
    return max(RECENT_TTL, SESSION_TTL)


def _prune_recent(now=None):
    """清理复用表（持 `_STATE_LOCK` 后交给实体）。

    任一链路线程都可能调到，成批删改三张全局表，必须与并发签发/登记互斥。
    """
    with _STATE_LOCK:
        return _prune_recent_locked(now)


# TTL 清理的节流窗口（秒）。
#
# `_recall_token` 每签发一个**新**占位符就调一次清理，而清理是全表扫描：表满
# _RECENT_MAX=2000 条时实测 **154µs/次**，一个 300 个新实体的请求光这项就约 46ms
# （对照 `mask_ms` p50≈230ms）。节流后代价降到「每个窗口一次」。
#
# 注意不能只写 `len <= _RECENT_MAX` 就跳：表**正好等于**上限时那个条件为真，
# 于是每次插入都跨过上限、每次签发都全集扫一遍（实测反而变成 143ms/300 次）。
# 所以窗口内允许小幅超出，到 `_PRUNE_SLACK` 倍才强制回收：内存上界仍是
# 「2000 × 1.25 条」（几十 KB 量级），代价从 O(1) 次全集扫变成每窗口一次。
#
# TTL 语义只放宽 ≤ 该窗口：过期条目最多多驻留 1 秒内存。这不影响正确性 ——
# `_recall_token` / `_lookup` 本来就按 ts 自行判过期，清理只负责回收内存与 PII 驻留；
# 且超出幅度到 `_PRUNE_SLACK` 时**不等窗口**，立刻回收。
_PRUNE_INTERVAL_S = 1.0
_PRUNE_SLACK = 1.25
_prune_last = [0.0]  # time.monotonic()，不受系统时钟回拨影响


def _prune_recent_throttled(now):
    """按窗口节流调用 `_prune_recent`（**热路径专用**）。

    调用方必须已持 `_STATE_LOCK`：读 `len(_tables().fwd)` 与写 `_prune_last` 要和签发
    同处一个临界区，否则节流窗口自身就变成了竞态。

    节流的只是**调用频率**，不是清理语义：`_prune_recent()` 本身逐字不变（含 TTL
    与超容量两条判据），启动预热等一次性路径仍直接调它。
    """
    mono = time.monotonic()
    if (mono - _prune_last[0] < _PRUNE_INTERVAL_S
            and len(_tables().fwd) <= int(_RECENT_MAX * _PRUNE_SLACK)):
        return
    _prune_last[0] = mono
    _prune_recent(now)


def _prune_recent_locked(now=None):
    """按 TTL + 条数上限清理复用表，防止无界增长。

    后缀索引必须跟着一起删：它是指向 _tables().rev 的指针，留着指向已淘汰
    token 的条目虽然不会答错（_lookup_by_suffix 还会回查 _tables().rev），
    但会让 _new_token 白白避开一个已经空出来的后缀。
    """
    now = now or time.time()
    tables = _tables()
    ttl = _recent_ttl()
    stale = [
        k for k, v in list(tables.fwd.items())
        if not _is_custom_word_orig(k) and now - v[2] > ttl
    ]
    for k in stale:
        tok = tables.fwd.pop(k, [None])[0]
        tables.rev.pop(tok, None)
        _suffix_index_del(tok)
    if len(tables.fwd) > _RECENT_MAX:
        evictable = [
            (k, v) for k, v in list(tables.fwd.items())
            if not _is_custom_word_orig(k)
        ]
        # 配额只按**可淘汰**条数算：自定义词的规模由词表封顶，不该挤占普通条目的额度。
        # 拿总长度算欠额，词表越大就越先清掉普通 PII 的复用条目——词表接近
        # _RECENT_MAX 时，刚签发的普通占位符会被当场淘汰（复用与后缀容错一起失效）。
        over = len(evictable) - _RECENT_MAX
        if over > 0:
            oldest = sorted(evictable, key=lambda kv: kv[1][2])
            for k, v in oldest[:over]:
                tables.fwd.pop(k, None)
                tables.rev.pop(v[0], None)
                _suffix_index_del(v[0])


def reset_mappings(reason="") -> dict:
    """清空「占位符 ↔ 原文」内存映射：会话表 + 复用窗口 + 后缀索引。

    这是 §D3.3 要求的**独立动作**（与清日志/清审计/清数字统计并列）：以前想清掉
    内存里的映射只能重启代理，而重启会一并断掉在飞请求与全部会话状态——
    比用户想要的东西重得多。

    清哪些：
      · `sessions`：每会话的 fwd/rev/labels 与流式收尾状态；
      · 复用窗口 `_RECENT_FWD` / `_RECENT_REV` / `_RECENT_SUFFIX`。
    不清哪些：
      · 自定义词永久映射（`_CUSTOM_WORD_*`）：它由用户自己的词表派生，词表本来就
        明文存在 config.json 里，且它的存在意义就是「词不被删就一直稳定」；
      · 事件库（历史日志）与统计——想清那些请用各自的独立动作。

    锁：`sessions` 的插入/删除靠 GIL 原子（见 B-1a 契约④），但 `_RECENT_*` 会被
    `_prune_recent_locked` 与词表重建遍历并成批删改，**必须持 `_STATE_LOCK`**，
    否则并发遍历会抛 `RuntimeError: dictionary changed size` 把在途请求直接打死。

    代价必须对用户说清楚（面板端点的确认文案会写）：清掉之后**当前对话里携带的
    历史占位符会全部还原不了**（原样透传给客户端），直到它们被重新扫描到；
    正在流式传输的响应也会因会话消失而停止还原。

    与在途请求的关系（下一个人必问）：本函数**不会**打断已经在跑的请求——
    持锁期与它们互斥，而锁外的单次读取（`sessions.get(sid)`）可能拿到一个
    已被从字典里移除的会话对象。那个请求自己的还原照样会完成（它拿着对象引用），
    但它的映射不会再被后续请求复用 —— 这正是本动作的语义，不是残留。
    """
    with _STATE_LOCK:
        n_sessions = len(sessions)
        sessions.clear()
        n_recent = len(_RECENT_FWD)
        _RECENT_FWD.clear()
        _RECENT_REV.clear()
        _RECENT_SUFFIX.clear()
    # 叶子缓存也一并清掉：它的命中判据就是「占位符还能在 rev 里查到」，
    # 映射清空后整张表必然全部未命中，留着只是白占内存（不清也不会有错值）。
    _leaf_cache_clear()
    _log("[LLM Shield] 内存映射已清空: 会话=%d 复用条目=%d%s"
         % (n_sessions, n_recent, (" reason=" + str(reason)) if reason else ""))
    return {"ok": True, "sessions": n_sessions, "recent_entries": n_recent}


# 已处理的「清空映射」代号（None = 还没看过，首次只看不重置）。
# 用列表而不是裸全局：_maybe_apply_mapping_reset 要**写入**它，
# 而模块级全局在函数里必须 global 声明——列表让这条热路径少一个 global 噪音。
_MAPPING_RESET_SEEN = [None]


def ack_mapping_reset(gen) -> None:
    """把本进程已处理的「清空映射」代号登记为 `gen`，不触发清空。

    存在的理由：**面板也是消费方**（扩展桥接链路会把它的 `transparent` 副本清一次）。
    面板端点自己已经调过 `reset_mappings()` 了，如果不同步登记代号，面板进程会在
    下一个 `/api/ext/mask` 时把同一个代号再消费一次 —— 那时表里已经是**清空之后
    新产生**的映射，用户视角就是「刚清完又莫名少了一次」。

    引擎进程**不**需要、也不应该调这个：它必须靠代号变化来触发清空。
    """
    try:
        _MAPPING_RESET_SEEN[0] = int(gen or 0)
    except Exception:
        pass


def _maybe_apply_mapping_reset():
    """在请求路径上捕获「面板要求清空映射」的信号（跨进程，见 event_store）。

    面板与引擎是两个进程，面板清不到引擎的表，所以信号走数据目录的小文件；
    本函数只在代号**变化**时清一次。首次调用只记下当前代号而不清：否则引擎
    启动时 `load()` 刚用 `_warmup_recent_from_db()` 预热完的映射会被立刻抹掉。

    读盘由 `event_store._read_signals` 做 5s 节流，所以这里热路径只是一次
    缓存查找 + 整数比较，不新增 syscall（§G3：不在热路径加同步写盘/查库）。
    """
    try:
        import event_store as _es
        gen = _es.mapping_reset_generation()
    except Exception:
        return
    seen = _MAPPING_RESET_SEEN[0]
    if seen is None:
        _MAPPING_RESET_SEEN[0] = gen
        return
    if gen == seen:
        return
    _MAPPING_RESET_SEEN[0] = gen
    try:
        reset_mappings(reason="panel")
    except Exception as e:
        _log(f"[LLM Shield] 内存映射清空失败: {type(e).__name__}: {e}")


def _warmup_recent_from_db():
    """引擎启动时从本地 SQLite 事件库预热恢复历史占位符映射。

    **有意直写模块全局表**（不走 `_tables()`）：这是进程启动路径，与请求无关，
    永远不会在演示作用域内执行。
    解决：引擎发版升级、重启或进程崩溃后，客户端长对话里携带的历史占位符
    因内存表清空而 100% 还原不了。

    与「复用表不落盘」那条取舍的关系：它指的是
    **不新增落盘**。这里读的是事件库里**本来就有**的 `items[].original`
    （日志含脱敏明文是产品既定行为），不产生任何新的磁盘写入，
    所以不与该取舍冲突。「引擎重启后历史占位符不可还原」那句
    自 0.1.12 起不再成立，已同步改文档。

    安全保证：
    - 凭据类（API_KEY/TOKEN/SECRET/JWT/ACCESS_KEY/CONNSTR/PRIVATE_KEY）在库里
      本来就只有 digest+preview、没有 original，双重过滤后绝不会被预热；
    - 只读，不写库；
    - **数据目录严格隔离**：设了 LLM_SHIELD_DATA_DIR 就只认该目录，
      库不存在就什么都不预热。0.1.12 曾在该目录无库时静默回落
      %APPDATA%\\Maskit，导致隔离测试实例把用户生产库的真实 PII
      （实测 420 条，含身份证/银行卡/手机号）载入内存——违反「隔离实例绝不读生产库」这条约定。
    """
    try:
        import sqlite3
        # 数据目录只认一处，不做候选回落：回落等于隔离环境读生产库。
        env_dir = os.environ.get("LLM_SHIELD_DATA_DIR")
        if env_dir:
            db_path = os.path.join(env_dir, "shield-events.sqlite3")
        else:
            appdata = os.environ.get("APPDATA")
            db_path = (os.path.join(appdata, "Maskit", "shield-events.sqlite3")
                       if appdata else "shield-events.sqlite3")
        if not os.path.isfile(db_path):
            return

        now = time.time()
        cutoff = now - 48 * 3600  # 恢复最近 48 小时内的映射
        # LIMIT 兜底：重度使用下 48h 可能有几万条事件，逐条 json.loads 会把
        # 引擎启动拖慢。倒序取最近的 _WARMUP_MAX_EVENTS 条足够覆盖活跃会话，
        # 而复用表本来就有 _RECENT_MAX 上限，多读也留不住。
        # 注意：sqlite3 的 with 只管事务不关连接，句柄不释放会锁住数据目录
        # （Windows 下隔离测试实例 cleanup 直接 PermissionError）。
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT payload FROM events WHERE ts >= ? ORDER BY id DESC LIMIT ?",
                (cutoff, _WARMUP_MAX_EVENTS),
            ).fetchall()
        finally:
            conn.close()

        # 先按「最新事件优先」收集（rows 为 id 倒序），同一原文只留最新 token：
        # 旧 token 直接不登记，天然不产生 REV/后缀索引孤儿。
        seen_orig = set()
        collected = []
        for (payload_str,) in rows:
            try:
                p = json.loads(payload_str)
                for it in p.get("items", []) or []:
                    tok = it.get("tok")
                    orig = it.get("original")
                    label = it.get("label") or ""
                    if not tok or not orig or not _PLACEHOLDER_RX.match(tok):
                        continue
                    # 过滤凭据类与占位符自身
                    if label in CREDENTIAL_LABELS or _PLACEHOLDER_RX.match(orig):
                        continue
                    if orig in seen_orig:
                        continue
                    seen_orig.add(orig)
                    collected.append((tok, orig, label))
            except Exception:
                pass
        # 再按时间正序（旧→新）写入：所有条目的 ts 都是同一个 now，_prune_recent
        # 超容量时的稳定排序按插入序删——正序插入保证先删**最旧**映射。
        # 曾按倒序直接写入：恢复 >2000 条时反而把最新的映射先删掉，重启后
        # 活跃会话最需要的占位符还原命中率倒挂（审计 P2）。
        with _STATE_LOCK:
            for tok, orig, label in reversed(collected):
                _RECENT_FWD[orig] = [tok, label, now]
                _RECENT_REV[tok] = [orig, label, now]
                _suffix_index_add(tok)
        count = len(collected)
        if count > 0:
            _prune_recent(now)
            _log(f"[shield-warmup] 从本地事件库预热 {count} 条占位符映射"
                 f"（复用表现有 {len(_RECENT_REV)} 条）")
    except Exception as e:
        _log(f"[shield-warmup] 预热映射失败 (静默跳过): {e}")


def _recall_token(orig, label):
    """取该原文的占位符：TTL 内复用旧的，否则新建并登记。

    整体持 `_STATE_LOCK`：本函数是**签发占位符的唯一入口**，内部「查后缀占用 →
    生成 token → 登记三张表」是多步序列，不原子会让两个线程签出同一后缀。
    """
    with _STATE_LOCK:
        return _recall_token_locked(orig, label)


def _recall_token_locked(orig, label):
    """`_recall_token` 的实体；调用方必须已持 `_STATE_LOCK`。"""
    tables = _tables()
    # 安全防套娃：如果 orig 自身就是占位符，严禁为其分配新 token！
    if isinstance(orig, str) and _PLACEHOLDER_RX.match(orig):
        # 尝试反查其真实明文
        rec = tables.rev.get(orig) or tables.cw_rev.get(orig)
        if rec and not _PLACEHOLDER_RX.match(rec[0]):
            orig = rec[0]
            label = rec[1] or label
        else:
            # 查不到真实明文，直接原样返回自身，绝不套娃生成新占位符
            return orig

    # 自定义敏感词优先使用稳定永久映射
    perm_token = tables.cw_fwd.get(orig)
    if perm_token:
        _touch_recent(perm_token, orig)
        _suffix_index_add(perm_token)
        return perm_token

    now = time.time()
    hit = tables.fwd.get(orig)
    if hit and (_is_custom_word_orig(orig) or now - hit[2] <= _recent_ttl()):
        hit[2] = now
        rev = tables.rev.get(hit[0])
        if rev:
            rev[2] = now
        # 幂等补登记：复用表里可能因预热撞车而没进索引（见 _suffix_index_add）
        _suffix_index_add(hit[0])
        return hit[0]
    token = _new_token(label)
    # 旧映射已过期：注销旧 token 的 REV / 后缀索引再覆盖 FWD。
    # 不注销的话旧条目成孤儿——_prune_recent 只扫 FWD 的值发现待删 token，
    # REV / _RECENT_SUFFIX 里的旧条目两个清理路径都碰不到，长驻进程缓慢泄漏。
    prev = tables.fwd.get(orig)
    if prev and prev[0] != token:
        tables.rev.pop(prev[0], None)
        _suffix_index_del(prev[0])
    tables.fwd[orig] = [token, label, now]
    tables.rev[token] = [orig, label, now]
    _suffix_index_add(token)
    _prune_recent_throttled(now)
    return token


def _remember(fwd, labels, orig, label):
    """登记原文→占位符映射；返回 True 表示沿用了复用表里的旧 token。

    返回值只用于诊断（MASK 事件的 `suffix_reused`）：沿用旧 token 说明占位符
    后缀与前缀都没变，上游按前缀做的 Prompt Cache 仍有机会命中；本次全新签发
    则意味着缓存必然从这个位置起失效。
    """
    if orig not in fwd:
        tables = _tables()
        perm_token = tables.cw_fwd.get(orig)
        if perm_token:
            fwd[orig] = perm_token
            labels[orig] = label
            _touch_recent(perm_token, orig)
            return True
        hit = tables.fwd.get(orig)
        reused = bool(hit) and (_is_custom_word_orig(orig) or time.time() - hit[2] <= _recent_ttl())
        fwd[orig] = _recall_token(orig, label)
        labels[orig] = label
        return reused
    return False


# 按长度降序的敏感词表（长词优先匹配，保证同一位置长词先命中）。
# 唯一消费者是 _custom_words_plan，而它只在执行计划缓存未命中时才会走到这里，
# 所以下面的排序不进 mask 热路径。
_CUSTOM_WORDS_SORTED = ()


def _sorted_custom_words():
    """CUSTOM_WORDS 按词长降序的元组（长词优先）。

    ⚠️ 本函数**遍历** `CUSTOM_WORDS`。生产路径一律「整体换对象」发布该变量
    （见 `_maybe_reload`），遍历时不会被并发改写；而直接就地 `clear()/update()`
    一旦与并发脱敏同时发生就会抛 `RuntimeError: dictionary changed size during
    iteration`（实测）。测试里改词表请直接赋新 dict。
    """
    return tuple(sorted(CUSTOM_WORDS.items(), key=lambda kv: len(kv[0]), reverse=True))


def _refresh_custom_words_sorted():
    """显式重建排序词表（热重载与测试直改词表后调用，用于预热）。"""
    global _CUSTOM_WORDS_SORTED
    with _STATE_LOCK:
        _CUSTOM_WORDS_SORTED = _sorted_custom_words()
    # 重建映射必须在**释放** `_STATE_LOCK` 之后调（锁序：_SYNC_LOCK → _STATE_LOCK）。
    _sync_custom_word_mappings()


def _custom_words_sorted():
    """取排序词表；**内容**变了才重建。

    曾只比长度（`len(cache) != len(CUSTOM_WORDS)`）：等长换词——例如把
    {张三, 李四} 换成 {密, 王五}——长度不变就不重建，于是继续沿用旧词表，
    新词不生效、旧词继续命中；现象还随用例/请求顺序漂移（曾让单字边界用例随机失败）。

    生产路径 reload_config 会显式重建，但把正确性寄托在「每个调用方都记得刷新」上
    太脆——任何绕过 reload 直改 CUSTOM_WORDS 的路径（主要是测试）都会中招。
    这里改成比内容，谁改词表都自动正确，不再依赖调用方纪律。
    """
    global _CUSTOM_WORDS_SORTED
    cur = _sorted_custom_words()
    # 比较与赋值必须原子：两个线程同时发现内容变了会各自发布一代，先发布的那代
    # 可能随即被覆盖，而 `_sync_custom_word_mappings` 已经按它登记过映射。
    with _STATE_LOCK:
        changed = cur != _CUSTOM_WORDS_SORTED
        if changed:
            _CUSTOM_WORDS_SORTED = cur
        out = _CUSTOM_WORDS_SORTED
    # 重建映射在锁外调（它自己先拿 `_SYNC_LOCK` 再拿 `_STATE_LOCK`，不能反过来）。
    if changed:
        _sync_custom_word_mappings()
    return out


# 凭据的「结构前缀」——这部分不是秘密，是各家公开的格式标记（sk-proj- 就是
# OpenAI 项目密钥，ghp_ 就是 GitHub PAT）。原样显示零风险，却是排查时最有用的信息。
_CRED_PREFIX_RX = re.compile(
    r"^(?:sk-proj-|sk-ant-[a-z0-9]{2,10}-|sk-|gh[pousr]_|github_pat_|AIza|AKIA|ASIA"
    r"|AKID|LTAI|xox[baprs]-|[sr]k_(?:live|test)_|cli_|ding|eyJ)"
)
# 机器生成的高熵凭据：给「前缀 + 末 4 位」足够定位是哪一把，剩余熵仍在天文数字级。
# 人选的低熵口令（SECRET/CONNSTR）不在此列——一个 10 位口令露首尾就等于露了大半。
_HIGH_ENTROPY_LABELS = {"API_KEY", "ACCESS_KEY", "TOKEN", "JWT"}


def _cred_preview(orig, label):
    """凭据预览：可识别，不可用。

    产品红线是「日志被人拿走也拿不到你的 key」，但一律打成 **** 走到了另一个极端——
    用户看到告警却不知道是哪一把泄露了，没法去吊销，安全能力等于零。
    折中按凭据类型分档：

      PRIVATE_KEY  只给密钥类型（RSA/EC/OPENSSH）。私钥任何一段都不能露。
      高熵凭据      结构前缀 + 末 4 位。前缀是公开格式标记，末 4 位与各家控制台
                   列表里的显示方式一致（GitHub/Stripe/AWS 都这么做），够你对上号。
      低熵口令      一个字符都不给，只给长度。数据库密码常常只有 8-12 位，
                   露首尾就是露大半。靠 digest 做同一性比对。

    精确定位始终可以用 digest（sha256 前 16 位）：本地对你手上的 key 算一次
    sha256 一比就知道是不是它，而 digest 本身不可逆。
    """
    s = str(orig or "")
    n = len(s)
    if label == "PRIVATE_KEY":
        m = re.search(r"BEGIN (?:(RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY", s)
        kind = (m.group(1) if m and m.group(1) else "PEM") if m else "PEM"
        return f"<{kind} 私钥 {n} 字节>"
    if label in _HIGH_ENTROPY_LABELS and n >= 20:
        m = _CRED_PREFIX_RX.match(s)
        head = m.group(0) if m else s[:4]
        return f"{head}…{s[-4:]}"
    # 低熵口令 / 太短的凭据：不给任何字符
    return f"<{label} {n} 位>"


def _preview(orig, label):
    """生成脱敏预览：凭据类不泄露可用信息，其他类型保留少量上下文。"""
    if label in CREDENTIAL_LABELS:
        return _cred_preview(orig, label)
    n = len(orig)
    if n <= 2:
        return orig[0] + "*" if n else ""
    if n <= 5:
        return orig[0] + "*" * (n - 1)
    if n <= 12:
        return orig[:1] + "*" * (n - 2) + orig[-1:]
    return orig[:2] + "**" + orig[-2:]


def _cred_digest(orig):
    """凭据的不可逆摘要（sha256 前 16 位）：日志/导出里可做同一性对照，不落明文。"""
    try:
        return hashlib.sha256(str(orig).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _redact_credentials(text):
    """把文本里所有凭据形态的值抹成 [REDACTED]（日志 dialog/preview 落库前清洗）。

    还原后的响应文本可能复述了模型见到的 api_key/token 原文，直接进事件库等于
    凭据明文落盘。这里用内置凭据规则 + 用户前缀规则过一遍，命中即抹掉。
    """
    if not isinstance(text, str) or not text:
        return text
    try:
        for rx, label, _g in RULES:
            if label in CREDENTIAL_LABELS:
                text = rx.sub("[REDACTED]", text)
        pref = _prefix_secret_regex()
        if pref:
            text = pref.sub("[REDACTED]", text)
    except Exception:
        pass
    return text


def _redact_session_credentials(text, s):
    """把**本会话脱敏过的凭据原文**从文本里精确抹掉（与 `_redact_credentials` 互补）。

    `_redact_credentials` 只按「凭据形态」跑正则，防的是「用户自己贴的、本会话没
    脱敏过的凭据」。它防不住另一种：还原后的响应里模型**只复述了值本身**——
    CONNSTR 的规则要求完整 `scheme://user:pass@host`，PRIVATE_KEY 要求 PEM 头，
    裸值都不命中形态正则，于是明文跟着 resp_dialog / resp_preview 落进 SQLite。

    引擎本来就知道原文（`s["fwd"]` 的 key 就是原文），所以这里做精确串替换。

    长度下限 `_MIN_SCRUB_LEN`：内置规则里最短的凭据捕获是 CONNSTR 的 `{4,}`，自定义
    前缀规则要求前缀后至少 8 位，SECRET 是 6-64——即**任何真实凭据原文都不会短于 4**。
    更短的只可能是「用户把 1-3 字符短词放进凭据类分类」这种配置，无法安全定位，
    整段不下发（见下方取舍说明）。
    """
    if not isinstance(text, str) or not text:
        return text
    try:
        labels = s.get("labels") or {}
        unsafe_short = False
        # 收集所有已知凭据原文：
        # 1. 本会话请求阶段自身脱敏的凭据（s["fwd"]）
        # 2. 跨请求从 _RECENT_REV 还原出来的历史凭据（s["restored_tokens"]）
        candidate_origs = set()
        for orig in (s.get("fwd") or {}):
            if labels.get(orig, "") in CREDENTIAL_LABELS:
                candidate_origs.add(orig)
        for tok in (s.get("restored_tokens") or set()):
            rec = _RECENT_REV.get(tok)
            if rec and len(rec) >= 2:
                orig, label = rec[0], rec[1]
                if label in CREDENTIAL_LABELS and orig:
                    candidate_origs.add(orig)

        for orig in candidate_origs:
            if orig not in text:
                continue
            if len(orig) < _MIN_SCRUB_LEN:
                unsafe_short = True
                continue
            text = text.replace(orig, "[REDACTED]")
        if unsafe_short:
            # 1-3 字符的原文无法安全定位：全局替换会把整段文本打成筛子（每个 "id"
            # 都变 [REDACTED]）。内置规则里最短的凭据捕获是 CONNSTR 的 {4,}、自定义
            # 前缀要求前缀后 ≥8 位，所以走到这里只可能是「用户把 1-3 字符的短词放进
            # 了凭据类分类」这种配置。与 `_scrub_legacy_event` 同一取舍：拿不准就整段
            # 不下发——放行原文是最坏结果。
            return "[REDACTED]"
    except Exception:
        pass
    return text


def _label_for_orig(s, orig):
    return s.get("labels", {}).get(orig, "")


def _host_matches(host, domain):
    host = (host or "").lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _path_matches(path, prefix):
    path = (path or "").split("?", 1)[0]
    prefix = prefix or ""
    return bool(prefix) and (path == prefix or path.startswith(prefix.rstrip("/") + "/"))


def is_target(host, path):
    if not any(_path_matches(path, p) for p in API_PATHS):
        return False
    for d in TARGET_DOMAINS:
        if _host_matches(host, d) and not any(_host_matches(host, off) for off in DOMAINS_DISABLED):
            return True
    return False


# ========== 反向代理路由 ==========

def _parse_upstream_target(target):
    """'https://api.openai.com' -> ('api.openai.com', 443, 'https', '', '')
    'https://api.example.com/v1?api-version=2024-02-15' -> (host, 443, 'https', '/v1', 'api-version=2024-02-15')

    target 带路径时（如 /v1、/zen/go/v1），透传层（panel）会拼回路径前缀；
    这里同样返回 path_prefix 与 query_prefix，反向代理路由转发时拼回，
    保证 Azure OpenAI、Gemini 或带版本号的上游 query 参数不丢失。
    """
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "https"
    path_prefix = parsed.path.rstrip("/")
    query_prefix = parsed.query or ""
    return host, port, scheme, path_prefix, query_prefix


def _merge_path_and_query(path_prefix, target_query, client_path):
    """合并上游 target 前缀/query 与客户端请求路径/query，保证 api-version 等参数绝不丢失。"""
    if "?" in (client_path or ""):
        client_pure, client_q = client_path.split("?", 1)
    else:
        client_pure, client_q = client_path or "", ""

    if path_prefix:
        merged_path = path_prefix + (client_pure if client_pure.startswith("/") else "/" + client_pure)
    else:
        merged_path = client_pure or "/"

    queries = [q for q in (target_query, client_q) if q]
    merged_q = "&".join(queries)
    return merged_path + ("?" + merged_q if merged_q else "")


def _listener_port(flow):
    """获取 mitmproxy 本地监听端口（用于多端口模式路由）。"""
    conn = getattr(flow, "client_conn", None)
    if not conn:
        return None
    # mitmproxy 12.x: client_conn.sockname 是本地监听地址（含端口）
    for attr in ("sockname", "address"):
        sock = getattr(conn, attr, None)
        if callable(sock):
            try:
                sock = sock()
            except Exception:
                sock = None
        if not sock:
            continue
        try:
            # Address 可能是 tuple/list (host, port) 或对象
            if isinstance(sock, (list, tuple)) and len(sock) >= 2:
                return int(sock[1])
            # mitmproxy.net.http.Address 或类似对象，尝试 .port 属性
            port = getattr(sock, "port", None)
            if port is not None:
                return int(port)
            text = str(sock)
            if ":" in text:
                return int(text.rsplit(":", 1)[1])
        except Exception:
            continue
    return None


def _match_upstream_by_port(port):
    """多端口模式：按入站端口匹配 upstream。"""
    if not port:
        return None
    for up in UPSTREAMS:
        if int(up.get("port") or 0) == port:
            return up
    return None


def _match_upstream(path):
    """单端口前缀模式：按请求路径前缀匹配反向代理 upstream。
    返回 (upstream_dict, stripped_path) 或 (None, path)。
    base_path=/openai, 请求 /openai/v1/chat/completions?api-version=1 -> 剩余 /v1/chat/completions?api-version=1
    """
    clean = (path or "").split("?", 1)[0]
    query = ("?" + (path or "").split("?", 1)[1]) if "?" in (path or "") else ""
    for up in UPSTREAMS:
        base = (up.get("base_path") or "").rstrip("/")
        if not base:
            continue
        if clean == base:
            return up, "/" + query
        if clean.startswith(base + "/"):
            return up, (clean[len(base):] or "/") + query
    return None, path


def _upstream_path_ok(upstream, stripped_path, final_path=None):
    """检查路径是否在该 upstream 的 paths 白名单。

    target 带路径前缀时（如 /v1），白名单命中最终路径（带前缀）或剥前缀后的
    路径任一即可——上游配置的 paths 是 API 真实路径（如 /v1/chat/completions）。
    """
    paths = upstream.get("paths") or API_PATHS
    candidates = [final_path, stripped_path] if final_path else [stripped_path]
    for cand in candidates:
        sp = (cand or "").split("?", 1)[0]
        if any(_path_matches(sp, p) for p in paths):
            return True
    return False


def apply_reverse_routing(flow):
    """反向代理模式路由。优先多端口（按入站端口），回退单端口前缀（按 base_path）。
    多端口模式：客户端 base_url=http://127.0.0.1:<port>，不剥前缀，直接转发。
    单端口模式：客户端 base_url=http://127.0.0.1:5802/<base_path>，剥前缀后转发。
    返回 (matched_upstream_or_None, final_path)。未匹配时不动 flow。
    """
    path = getattr(flow.request, "path", "") or ""
    # 1. 多端口模式：按入站端口匹配
    port = _listener_port(flow)
    up = _match_upstream_by_port(port)
    if up:
        host, up_port, scheme, path_prefix, query_prefix = _parse_upstream_target(up["target"])
        try:
            flow.request.host = host
            flow.request.port = up_port
            flow.request.scheme = scheme
            flow.request.headers["Host"] = host
        except Exception:
            pass
        final = _merge_path_and_query(path_prefix, query_prefix, path)
        try:
            flow.request.path = final
        except Exception:
            pass
        return up, final
    # 2. 单端口前缀模式回退：按 base_path 匹配并剥前缀
    up, stripped = _match_upstream(path)
    if not up:
        return None, path
    host, up_port, scheme, path_prefix, query_prefix = _parse_upstream_target(up["target"])
    try:
        flow.request.host = host
        flow.request.port = up_port
        flow.request.scheme = scheme
        flow.request.headers["Host"] = host
        flow.request.path = stripped
    except Exception:
        # 测试用 SimpleNamespace 可能没有可写属性，退回只改 path
        try:
            flow.request.path = stripped
        except Exception:
            pass
    final = _merge_path_and_query(path_prefix, query_prefix, stripped)
    try:
        flow.request.path = final
    except Exception:
        pass
    return up, final


# 注入请求头的占位符形态：**整个值**就是 <...>（可带 Bearer 前缀）。
# 只匹配「整体就是占位符」，不做子串匹配——真实 header 值（application/json、
# 真 key、URL）里不会整值长这样，所以不会误伤正常配置。
_EXTRA_HEADER_PLACEHOLDER_RX = re.compile(r"^\s*(?:Bearer\s+)?<[^<>]{1,64}>\s*$", re.IGNORECASE)

# 凭据类请求头：语义就是「承载身份凭据」，一律禁止通过 extra_headers 注入。
#
# 为什么单列一份名单：Maskit 的定位是**只配 URL 的透明转发网关**，凭据归客户端所有
# （Claude Code / Cursor 等都会自带）。在这个字段里填凭据没有任何正当场景，只会把
# 客户端自带的真 key 覆盖成配置里的值——填错就是必然 401，而用户从上游看到的只有
# 「无效的令牌」，根本联想不到是自己的配置造成的（实测 anyrouter 中转站报障即此因）。
#
# 与凭据无关的协议头不受影响，例如 anthropic-version、anthropic-beta
# （实测 claude-sonnet-4-5 必须带 anthropic-beta: context-1m-2025-08-07 才能用 1M 上下文）。
#
# 比对方式：头名转小写后精确匹配（HTTP 头名大小写不敏感），不做子串匹配，
# 所以 x-api-key-version 这类自造头不会被误伤。
_CREDENTIAL_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-goog-api-key",
    "x-auth-token",
    "x-access-token",
    "x-token",
    "x-session-token",
    "private-token",
    "x-gitlab-token",
    "x-github-token",
    "x-amz-security-token",
    "x-amz-credential",
    "x-client-secret",
    "client-secret",
})

# 同一 (客户端, 头名) 只告警一次，避免每个请求刷一行日志；config reload 时清空。
_EXTRA_HEADER_SKIP_WARNED = set()


def _apply_extra_headers(flow, upstream):
    """按 upstream 配置注入静态请求头（extra_headers）。

    场景：上游要求某个**与凭据无关**的协议头，但客户端根本不发
    （典型：anthropic-beta: context-1m-2025-08-07），在转发前注入。
    仅 reverse 模式（客户端流量必经本钩子）；值含敏感信息只进内存配置，不落日志。

    **三类值一律跳过注入**：

      1. 凭据头（authorization / x-api-key / cookie …，见 `_CREDENTIAL_HEADER_NAMES`）：
         凭据属于客户端，Maskit 只做 URL 转发。在这里填凭据只会覆盖客户端自带的真 key，
         换回一个必然 401——而上游报的只是「无效的令牌」，用户看不出是自己配置造成的。
      2. 占位符值（整个值就是 `<...>`，可带 Bearer 前缀，如 `<YOUR_API_KEY>`）：
         永远不可能是真实凭据，注入等于用一个假 key 顶掉真 key。
      3. 空值：空字符串不是凭据，注入等于把客户端的头清掉，比不注入更糟。

    三者都跳过之后，请求退回「客户端自带凭据」的正常路径：用户即使没填也不会挂，
    真要注入的协议头照常按真实值覆盖。
    """
    try:
        extra = (upstream or {}).get("extra_headers") or {}
        if not isinstance(extra, dict) or not extra:
            return
        up_name = str((upstream or {}).get("name") or "")
        for key, value in extra.items():
            k = str(key or "").strip()
            if not k:
                continue
            v = str(value)
            if k.lower() in _CREDENTIAL_HEADER_NAMES:
                if (up_name, k) not in _EXTRA_HEADER_SKIP_WARNED:
                    _EXTRA_HEADER_SKIP_WARNED.add((up_name, k))
                    _log(f"[mask] 客户端「{up_name}」的注入请求头 {k} 属于凭据头，已跳过注入"
                         f"（凭据请配在客户端里，Maskit 只做透明转发；"
                         f"此处填凭据会覆盖客户端自带的真凭据并导致上游 401）")
                continue
            if not v.strip() or _EXTRA_HEADER_PLACEHOLDER_RX.match(v):
                if (up_name, k) not in _EXTRA_HEADER_SKIP_WARNED:
                    _EXTRA_HEADER_SKIP_WARNED.add((up_name, k))
                    why = "值为空" if not v.strip() else f"仍是占位符 {v}"
                    _log(f"[mask] 客户端「{up_name}」的注入请求头 {k} {why}，已跳过注入"
                         f"（请在设置页填入真实值或删除该行；跳过不会影响客户端自带的凭据）")
                continue
            try:
                flow.request.headers[k] = v
            except Exception:
                pass
    except Exception:
        pass


def _apply_egress_proxy(flow, upstream):
    """按 upstream 配置决定本次转发是否经由出口代理（Shield → 上游方向）。

    机制：mitmproxy 的 `flow.server_conn.via` 是**按连接**的上游代理指定，
    `make_server_connection()` 建连时读取（本项目用 `connection_strategy=lazy`，
    连接在 request 钩子之后才建，时机正好）。因此同一个 mitmdump 进程里可以
    「境内中转直连 + 境外官方 API 走代理」并存，不必像环境变量方案那样一刀切。

    **必须在 request() 里所有 return 分支之前调用**：`/v1/models`、健康检查这类
    「路由命中但不脱敏、提前 return」的请求同样要走代理，漏掉就会直连境外上游，
    表现为「聊天能用但客户端初始化失败」这种极难归因的半残状态。

    实测注意：即便目标是明文 http，mitmproxy 也通过 CONNECT 隧道走代理，
    所以上游代理必须支持 CONNECT（Clash/v2ray 的 http 端口都支持）。
    仅 reverse 模式生效；explicit 模式另有 `--mode upstream:` 机制，不在此处理。
    """
    if not EGRESS_PROXY or not isinstance(upstream, dict) or not upstream.get("use_proxy"):
        return
    try:
        flow.server_conn.via = EGRESS_PROXY
        flow.metadata["shield_via_proxy"] = True
    except Exception as e:
        # 设不上就照常直连，绝不因此打断转发；但要留痕，否则「代理没生效」无从发现
        _log(f"[egress] 设置出口代理失败 {EGRESS_PROXY}: {type(e).__name__}: {e}")


def _target_miss_reason(host, path):
    path_ok = any(_path_matches(path, p) for p in API_PATHS)
    domain_ok = any(_host_matches(host, d) for d in TARGET_DOMAINS)
    disabled = any(_host_matches(host, off) for off in DOMAINS_DISABLED)
    if disabled:
        return "domain_disabled"
    if not domain_ok:
        return "host_not_configured"
    if not path_ok:
        return "path_not_configured"
    return ""


# 无请求体的方法：直接转发（/v1/models 之类）
_READONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
# LLM 请求体特征键（判断一个 POST 是否值得走脱敏管线）。
# 前 6 个是 OpenAI/Anthropic/Gemini/Responses/Ollama 的标准键；后面几个来自实测漏检：
# Cohere v1 chat 用 message（单数）、Bedrock Titan 用 inputText、讯飞星火用 payload、
# HuggingFace Inference 用 inputs —— 都不在原名单里，整包原文透传
# （SHIELD-SHAPE-WHITELIST-001）。名单只是快速路径，真正的兜底见 request() 里
# 「已配置上游 + fail_closed 一律脱敏」的分支：白名单追不上新协议，不能只靠它。
_LLM_BODY_KEYS = (
    "messages", "prompt", "input", "instructions", "system", "contents",
    "message", "inputText", "inputs", "payload", "chat_history", "query",
    "documents",
)


_NO_BODY = object()          # 哨兵：区分"没传 body"与"解析结果就是 None/False"


def _looks_like_llm_request(flow, body=_NO_BODY):
    """请求体是否像 LLM 补全请求。用于放行非白名单路径上的非 LLM 调用。

    `body` 传入**已解析**的请求体时跳过解析：主管线在调用本函数之前已经解析过一次
    （`_load_json_pairs`），再解一次就是纯粹的重复开销 —— 实测 1MB 请求体
    `json.loads` 约 1.2ms，**在事件循环上是白付的**（B-3 的真实形态：不是"解析该不该
    下池"，而是"同一份 body 被解析了两遍"）。必须用哨兵而不是 `None` 作默认值：
    `json.loads("null")` 的合法结果就是 None，用它表意会把"解析成功但为 null"误判成
    "没传 body"。
    """
    ct = flow.request.headers.get("content-type", "") or ""
    if "json" not in ct:
        return False
    if body is _NO_BODY:
        try:
            raw = flow.request.content or b""
        except Exception:
            return True
        # 超大 body 不在事件循环上解析。闸门用 `AUDIT_PARSE_MAX`（2MB）而**不是**
        # 请求体积闸（32MB）：这条调用点在 32MB 闸门之前（未列入白名单的路径要先问
        # "像不像 LLM 请求"），拿 32MB 当闸等于放行"2~32MB 的 JSON 在循环上解析"
        # —— `json.loads` 在 1MB 级 JSON 上的实测约 90~95µs/KB（本机 3.13，
        # 见 scripts/bench_mask.py 的 parse 段），30MB 约 2.8s，正是 A-1/A-3 要
        # 消灭的冻结类。⚠️ 别拿它跟下面 29µs/KB（逐规则正则）、0.11ms/KB（三信号扫描）
        # 比大小：三者量的是**不同**的东西（解析 vs 单规则正则 vs 三信号正则）。
        # 返回 True 是**安全侧**默认：主管线随后按体积闸判定，非 LLM 形态在
        # fail_closed 下同样会脱敏，不会因这里返回 True 而放行原文。
        if len(raw) > AUDIT_PARSE_MAX:
            return True
        try:
            body = json.loads(raw)
        except Exception:
            return True  # 声明 JSON 却解析失败，交给主管线按 fail-closed 处理
    return isinstance(body, dict) and any(k in body for k in _LLM_BODY_KEYS)


def _emit_skip(host, method, path, reason, content_type="", source=None, force=False, upstream=""):
    """记录未脱敏/透传类事件。

    规则：
    - 已命中配置的客户端端口（upstream 非空）：每条都记，绝不去重 —— 用户要「过网关必有日志」
    - 未命中路由（no_reverse_route / not_target）：10s 去重，避免乱扫端口刷屏
    - force=True：强制记一条
    """
    global _skip_seen_last_purge
    clean_path = (path or "").split("?", 1)[0]
    src = dict(source or {})
    # 已配置客户端的流量：不去重
    hit_client = bool(upstream) or force
    dedupe = (not hit_client) and reason in {
        "no_reverse_route", "not_target", "host_not_configured", "path_not_configured",
    }
    key = (host, method, clean_path, reason)
    now = time.time()
    if dedupe:
        if now - _skip_seen.get(key, 0) < 10:
            return
        _skip_seen[key] = now
        if now - _skip_seen_last_purge > 30:
            stale = [k for k, ts in _skip_seen.items() if now - ts > 60]
            for k in stale:
                del _skip_seen[k]
            _skip_seen_last_purge = now
    _emit(
        "SKIP" if not hit_client else "PASS",
        host=host,
        method=method,
        path=clean_path,
        reason=reason,
        content_type=str(content_type or "")[:80],
        count=0,
        upstream=upstream or "",
        # 统一检测口径（§B1）：明确直通不是「0 命中」，要能与「扫了没命中」区分开。
        **inspection.report_for_skip(reason=reason, blocked=False),
        **src,
    )


def _body_preview(raw, limit=1200, total_len=None):
    """请求/响应体预览（截断、去空白）。绝不包含敏感原文。
    先截断再正则：2MB body 全文空白折叠曾耗时 23ms/请求，截断后只剩 limit 字符。
    截断前必须先存原长，否则折叠后算 len-text 会得到负数（曾显示 …(+N字) 负数）。

    `total_len`：调用方已经只给了**前缀**时，用真实总长计算 "+N字" 尾巴，
    避免显示成"前缀长度"（否则 4MB 响应的预览会写 …(+261344字) 这种假数字）。
    """
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    raw_len = len(text) if total_len is None else int(total_len)
    if raw_len > limit:
        text = re.sub(r"\s+", " ", text[:limit]).strip()
        return text + f"…(+{raw_len - limit}字)"
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _msg_text(content):
    """把 message.content（str 或 content blocks）抽成纯文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for blk in content:
            if isinstance(blk, str):
                parts.append(blk)
            elif isinstance(blk, dict):
                t = blk.get("text") or blk.get("content") or ""
                if isinstance(t, str) and t:
                    parts.append(t)
        return "\n".join(parts)
    return str(content)


def _extract_chat_dialog(raw, limit=4000):
    """从请求/响应 body 抽出「对话内容」便于日志阅读。

    请求：只保留 user/assistant 消息（跳过 system 长指令）。
    响应：JSON choices 或 SSE data 行里的 assistant 文本。
    返回可读纯文本，不是整包 JSON。
    """
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    text = text.strip()
    if not text:
        return ""

    def _assistant_sections(reasoning_parts=None, content_parts=None):
        """Keep model thinking and final answer separate in the event dialog."""
        sections = []
        thinking = "".join(x for x in (reasoning_parts or []) if isinstance(x, str))
        answer = "".join(x for x in (content_parts or []) if isinstance(x, str))
        if thinking.strip():
            sections.append(f"【助手思考】\n{thinking.strip()}")
        if answer.strip():
            sections.append(f"【助手】\n{answer.strip()}")
        return sections

    # 1) 尝试 JSON 请求/非流式响应
    try:
        body = json.loads(text)
        if isinstance(body, dict):
            lines = []
            # Chat Completions / Messages 请求：按顺序展示全部用户消息。
            # OpenCode 会携带 system prompt 和整段历史：system 指令跳过；
            # 曾只取末条 user——命中常在 system/更早历史，用户看不到自己发送的
            # 内容（SHIELD-DIALOG-001）。总量仍受 limit 截断。
            msgs = body.get("messages")
            if isinstance(msgs, list):
                for m in msgs:
                    if not isinstance(m, dict):
                        continue
                    role = str(m.get("role") or "")
                    if role != "user":
                        continue
                    content = _msg_text(m.get("content"))
                    if content:
                        lines.append(f"【用户】\n{content.strip()}")
            # 非流式响应
            ch = body.get("choices")
            if isinstance(ch, list) and ch:
                c0 = ch[0] if isinstance(ch[0], dict) else {}
                msg = c0.get("message") if isinstance(c0.get("message"), dict) else {}
                content = _msg_text(msg.get("content") if msg else None) or str(c0.get("text") or "")
                reasoning = msg.get("reasoning_content") if msg else None
                if not isinstance(reasoning, str) or not reasoning.strip():
                    reasoning = msg.get("reasoning") if msg else None
                lines.extend(_assistant_sections([reasoning], [content]))
            # Anthropic content
            cont = body.get("content")
            if isinstance(cont, list) and not lines:
                thinking = [b.get("thinking") for b in cont
                            if isinstance(b, dict) and isinstance(b.get("thinking"), str)]
                answer = [b.get("text") for b in cont
                          if isinstance(b, dict) and isinstance(b.get("text"), str)]
                lines.extend(_assistant_sections(thinking, answer))
            if lines:
                out = "\n\n".join(lines)
                if len(out) > limit:
                    return out[:limit] + f"…(+{len(out) - limit}字)"
                return out
    except Exception:
        pass

    # 2) SSE 流式：拼 delta.content
    if "data:" in text or "\ndata:" in text:
        reasoning_buf = []
        content_buf = []
        # 早退：输出最终只保留 limit 字，但原实现把**整段**流逐行 `json.loads`
        # （256KB SSE ≈ 40ms/次，且这条路径在请求与响应收尾时都会被调用）。
        # 助手正文攒够 limit 就够；思考段通常先于正文下发，此时也已到手。
        _content_chars = 0
        for line in text.splitlines():
            if _content_chars >= limit:
                break
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            ch = obj.get("choices")
            if isinstance(ch, list) and ch and isinstance(ch[0], dict):
                delta = ch[0].get("delta") if isinstance(ch[0].get("delta"), dict) else {}
                c = delta.get("content") if delta else None
                if isinstance(c, str) and c:
                    content_buf.append(c)
                    _content_chars += len(c)
                rc = delta.get("reasoning_content") if delta else None
                if not isinstance(rc, str) or not rc:
                    rc = delta.get("reasoning") if delta else None
                if isinstance(rc, str) and rc:
                    reasoning_buf.append(rc)
                msg = ch[0].get("message") if isinstance(ch[0].get("message"), dict) else {}
                if msg:
                    mc = _msg_text(msg.get("content"))
                    if mc:
                        content_buf.append(mc)
                        _content_chars += len(mc)
            # Anthropic SSE
            if obj.get("type") == "content_block_delta":
                delta_obj = obj.get("delta")
                delta = delta_obj if isinstance(delta_obj, dict) else {}
                if isinstance(delta.get("thinking"), str):
                    reasoning_buf.append(delta["thinking"])
                if isinstance(delta.get("text"), str):
                    content_buf.append(delta["text"])
                    _content_chars += len(delta["text"])
            # OpenAI Responses API SSE
            et = obj.get("type")
            if et == "response.output_text.delta" and isinstance(obj.get("delta"), str):
                content_buf.append(obj["delta"])
                _content_chars += len(obj["delta"])
            elif et == "response.reasoning_text.delta" and isinstance(obj.get("delta"), str):
                reasoning_buf.append(obj["delta"])
        sections = _assistant_sections(reasoning_buf, content_buf)
        if sections:
            out = "\n\n".join(sections)
            if len(out) > limit:
                return out[:limit] + f"…(+{len(out) - limit}字)"
            return out

    # JSON/SSE 能解析但没有对话正文时保持为空；原始协议内容另存 req/resp_preview。
    # 详情默认只展示对话，不能再把 system prompt/整包 SSE 当作对话回退显示。
    if text.startswith("{") or text.startswith("[") or "data:" in text:
        return ""
    return _body_preview(text, min(limit, 800))


def _extract_model(body):
    if not isinstance(body, dict):
        return ""
    m = body.get("model")
    return str(m)[:120] if m else ""


def _rule_enabled(label):
    """内置规则是否启用；缺省 True。"""
    return bool(BUILTIN_RULES.get(label, True))


def _custom_word_enabled(word, label):
    if label in SENSITIVE_DISABLED:
        return False
    disabled_words = SENSITIVE_WORD_DISABLED.get(label) or set()
    if word in disabled_words:
        return False
    return True


# 单字词两侧不能是 CJK/字母数字，避免「密」打中「密码」、「加」打中「加密」。
# 两字及以上仍子串匹配（「张三」左右常是汉字，加 CJK 边界会漏）；两字高频词靠 UI 禁用/默认关控制。
_SINGLE_WORD_BOUND = r"A-Za-z0-9_\u4e00-\u9fff"
# 整词开关用的边界**不含汉字**：汉字之间不存在词边界，`手机` 两侧几乎永远是汉字，
# 用 CJK 做边界等于该词永不命中——实测「开关整词匹配」会把中文词的脱敏整个关掉，
# 且界面上毫无提示（漏脱敏，不是误伤）。无分词器时中文词的「整词」无法表达，
# 退化回子串匹配（宁可多打码，不可漏打码）；ASCII 词边界照旧，Acme 不会命中 AcmeCorp。
_WHOLE_WORD_BOUND = r"A-Za-z0-9_"
_CUSTOM_WORD_RX_CACHE = {}
# 词表执行计划缓存：把全部启用词编译成一份**有序**执行计划。
# 500 词 × 10 万字符从 O(词数×长度) 降到 O(长度)（审计性能项）。
# 词表/禁用状态变化时 key 失效重建；key 计算是 O(词数) 的元组比较，微秒级。
#
# 计划元素（顺序即执行顺序，按词长降序 = 长词优先，与逐词替换语义一致）：
#   ("literal", rx, index)           连续普通词合并成的一条 alternation
#   ("regex",   rx, (word, label))   单个 re: 词，**独立编译**
#
# ⚠️ 为什么 re: 词必须独立编译、绝不能拼进同一条 alternation（2026-09-30 实测事故）：
# 用户写的 `re:(?i)(Beijing)` 单看合法（面板保存也是逐词编译 -> 放行），但只要词表里
# 存在比它更长的词，它就会落到 alternation 的非首位，整条编译抛
# `global flags not at the start of the expression`；旧实现把该异常兜成「词表降级为
# 空」-> **自定义词 + 内置敏感词组一起静默失效**，代理照常 200，只留一行进程日志。
# 用户看到的现象是「关掉 NER 后什么都不脱敏了」，而根因与 NER 毫无关系。
# 被隔离掉的同类问题还有：跨词同名命名组（redefinition of group name）、反向引用 \1
# 因别的词插进来导致组号漂移而指错组。隔离后这些写法各自独立成立，坏词只毁它自己。
#
# `key` 槽位与旧实现同名同义（None = 失效重建）：测试夹具直接改它来清缓存。
# （旧实现还有个 `rx` 槽位，执行计划上线后没有消费者了，已直接删除。）
_CUSTOM_COMBINED_CACHE = {"key": None, "plan": None}


# 词表问题登记表（词 -> 原因）。容量有限、同词只记首次，配置换代时清空。
# 存在的理由：这些问题以前**只在进程日志里留一行**，面板、事件、一键自检全看不见，
# 用户唯一能得出的结论是「脱敏坏了」。现在由 /api/status、一键自检与 MASK/RESTORE
# 事件详情共用它，把「哪个词、什么原因、怎么改」直接摆到用户面前。
_WORD_TABLE_ISSUES = {}
_WORD_TABLE_ISSUES_LOCK = threading.Lock()
_WORD_TABLE_ISSUES_MAX = 20


def _note_word_table_issue(word, reason):
    """登记一条词表问题（线程安全；同词只记首次，最多留 `_WORD_TABLE_ISSUES_MAX` 条）。"""
    try:
        key = str(word or "")[:200]
        with _WORD_TABLE_ISSUES_LOCK:
            if key in _WORD_TABLE_ISSUES or len(_WORD_TABLE_ISSUES) >= _WORD_TABLE_ISSUES_MAX:
                return
            _WORD_TABLE_ISSUES[key] = str(reason or "")[:200]
        _log(f"[mask] 词表问题：{key} —— {reason}")
    except Exception:
        pass


def word_table_issues():
    """当前词表问题快照（词 -> 原因）。空 dict = 全部词都能用。

    出口三处：`/api/status`（面板设置页）、一键自检、MASK/RESTORE 事件详情。
    """
    with _WORD_TABLE_ISSUES_LOCK:
        return dict(_WORD_TABLE_ISSUES)


def _clear_word_table_issues():
    """配置换代后清空：上一代词表的问题不该挂在新一代上（新词表会在下次构建计划时重评）。"""
    with _WORD_TABLE_ISSUES_LOCK:
        _WORD_TABLE_ISSUES.clear()


def _custom_word_regex(word):
    """自定义词匹配：≥2 字子串；单字带边界，降低误伤。

    大小写不敏感（审计规则专项 P2）：加 IGNORECASE，Acme 匹配 ACME/acme。
    防御：超长词（>200 字符）直接返回 None 跳过——
    面板保存时已限长，但 config 可能被手工写入/旧版本遗留，超长词 escape 后
    拖慢合并正则重建与扫描（审计 P1）。
    """
    if not word or len(word) > 200:
        return None
    cached = _CUSTOM_WORD_RX_CACHE.get(word)
    if cached is not None:
        return cached
    esc = re.escape(word)
    if len(word) == 1:
        rx = re.compile(rf"(?<![{_SINGLE_WORD_BOUND}]){esc}(?![{_SINGLE_WORD_BOUND}])", re.IGNORECASE)
    else:
        rx = re.compile(esc, re.IGNORECASE)
    _CUSTOM_WORD_RX_CACHE[word] = rx
    return rx


def _literal_word_pattern(word):
    """普通词 -> 一条**纯字面量**片段（escaped，永不编译失败）。

    边界规则与旧的合并实现完全一致（勿改）：
      · 单字词用 `_SINGLE_WORD_BOUND`（含汉字，避免「密」打中「密码」）；
      · 显式「整词匹配」的词用 `_WHOLE_WORD_BOUND`（不含汉字，否则中文词永不命中）；
      · 其余（>=2 字）无边界，子串匹配 —— 宁可多打码，不可漏打码。
    """
    esc = re.escape(word)
    if len(word) == 1 or word in SENSITIVE_WORD_WHOLE:
        bound = _SINGLE_WORD_BOUND if len(word) == 1 else _WHOLE_WORD_BOUND
        return rf"(?<![{bound}]){esc}(?![{bound}])"
    return esc


def _custom_words_plan_key():
    """计划缓存键：完整覆盖词表内容与禁用状态（`_custom_word_enabled` 只读这两个集合）。"""
    return (
        tuple(CUSTOM_WORDS.items()),
        tuple(sorted(SENSITIVE_DISABLED)),
        tuple(sorted((l, w) for l, ws in SENSITIVE_WORD_DISABLED.items() for w in ws)),
        tuple(sorted(SENSITIVE_WORD_WHOLE)),
    )


def _custom_words_plan():
    """构建（或取缓存）词表执行计划，语义见 `_CUSTOM_COMBINED_CACHE` 的注释。

    两遍：① 按长词优先顺序把启用词摊成 `word` / `regex` 两种条目（`re:` 词在此单独
    编译，坏词只跳过它自己并登记原因）；② 把**连续**的 `word` 条目合并成一条
    alternation（`re:` 词天然成为分界线），逐字面量段编译。

    任何编译失败都**只影响它自己**：段编译失败退化为逐词 pattern，单词失败只跳过该词。
    旧实现在这一步失败时把**整张词表**置空（自定义词 + 内置敏感词组一起失效），
    是本轮修复的核心缺陷。
    """
    key = _custom_words_plan_key()
    cache = _CUSTOM_COMBINED_CACHE
    if cache["key"] == key and cache["plan"] is not None:
        return cache["plan"]

    items = []          # ("word", word, label) | ("regex", compiled_rx, word, label)
    for word, label in _custom_words_sorted():
        if not word or not _custom_word_enabled(word, label):
            continue
        if word.startswith("re:"):
            try:
                rx = re.compile(word[3:], re.IGNORECASE)
            except re.error as e:
                # 非法正则只跳过它自己（旧行为），但必须留痕给面板/自检/事件
                _note_word_table_issue(word, f"正则无效，已跳过该词：{e}")
                continue
            items.append(("regex", rx, word, label))
        else:
            items.append(("word", word, label))

    # 大小写索引：命中文本 -> (词表里的原始 key, 标签)，让 ACME/acme 复用同一个原词与
    # 占位符。旧实现是**每次命中**都对 CUSTOM_WORDS 做一次 O(词数) 的 `next()` 线性
    # 扫描（5000 词表 + 上千命中 = 百万级比较），这里只建一次。冲突时取词表中**首个**
    # 匹配（与旧实现 `next(...)` 同义）。
    index = {}
    for it in items:
        if it[0] == "word":
            index.setdefault(it[1].lower(), (it[1], it[2]))

    plan = []
    batch = []

    def _flush():
        if not batch:
            return
        try:
            rx = re.compile("|".join(_literal_word_pattern(w) for w, _l in batch),
                            re.IGNORECASE)
        except re.error as e:                       # 纯 escaped 字面量，理论上不可达
            rx = None
            _note_word_table_issue(batch[0][0],
                                   f"普通词合并编译失败，已改为逐词匹配：{e}")
        if rx is not None:
            plan.append(("literal", rx, index))
        else:
            # 兜底：逐词独立 pattern。**绝不整表置空** —— 那等于把用户整张词表废掉
            plan.extend(("literal", re.compile(_literal_word_pattern(w), re.IGNORECASE), index)
                        for w, _l in batch)
        del batch[:]

    for it in items:
        if it[0] == "word":
            batch.append((it[1], it[2]))
        else:
            _flush()
            plan.append(("regex", it[1], it[3]))
    _flush()

    cache["key"] = key
    cache["plan"] = plan
    # 词表执行计划换代 ⇒ 叶子结果缓存整体作废（计划变了，同一段文本的命中结果
    # 可能不同）。不能指望每个改词表的路径都记得清缓存，所以在“计划真的重建”
    # 这个唯一出口上挂钩。
    _leaf_cache_bump()
    return plan


def _sync_custom_word_mappings():
    """同步自定义敏感词的永久映射表（持 `_SYNC_LOCK` 后交给实体）。

    这里拿的是 `_SYNC_LOCK` 而不是 `_STATE_LOCK`：整表重建里最贵的是**逐词派生**
    （SHA-256 + 避让探测），词表上千时持 `_STATE_LOCK` 就是百毫秒级，配置保存时
    在途脱敏只能干等（压测实测 2.4~5.1s 的最坏值就是这类长持锁群众贡献的）。
    现在只有「取快照」与「换表 + 补登记」两段微秒级临界区碰 `_STATE_LOCK`。

    并发重建由 `_SYNC_LOCK` 串行化：两次重建若并发派生，各自基于同一份旧快照可能
    派生出同一个后缀 —— 后缀撞车就是把 A 的原文填到 B 的位置，所以派生与落表必须
    在同一把锁内完成。
    """
    with _SYNC_LOCK:
        return _sync_custom_word_mappings_inner()


def _sync_custom_word_mappings_inner():
    """同步自定义敏感词的永久映射表（调用方必须已持 `_SYNC_LOCK`）。

    在启动、热重载或 CUSTOM_WORDS 变动时调用。
    为启用的自定义敏感词生成稳定、跨会话确定性的 6 位纯辅音占位符并永久常驻，
    永不被 TTL 清理或超量淘汰，确保多轮会话或长任务调用工具时稳定还原。

    三阶段：① 锁内取快照 → ② 锁外派生目标映射 → ③ 锁内换表并补 `_RECENT_*`。
    """
    global _CUSTOM_WORD_FWD, _CUSTOM_WORD_REV
    now = time.time()
    # ⚠️ 这里必须用纯函数 `_sorted_custom_words()`，**不能**用带缓存的
    # `_custom_words_sorted()`：后者在发现词表变化时会回调 `_sync_custom_word_mappings()`，
    # 而 `_SYNC_LOCK` 是不可重入的 `Lock` —— 同线程二次获取直接自锁死
    # （实测：单测套件卡在 CustomWordSuffixCollisionTests，整个门禁被超时杀掉）。
    # 我们就是同步本身，不需要（也不应该）再触发一次同步。
    active_words = {}
    for word, label in _sorted_custom_words():
        if word and _custom_word_enabled(word, label):
            active_words[word] = label

    # ① 快照。避让集合必须并入**全局后缀索引**（_RECENT_SUFFIX，含规则/NER/历史已签发的
    #    活跃 token），不能只避让自定义词自己的后缀：否则新词一旦撞上某个活跃 token 的
    #    后缀（标签相同时 = 完整 token 相同），下面 `_RECENT_REV[tok] = ...` 会把那个
    #    token 静默改指向新词——换会话 / 会话过期后 restore 会把 A 的原文填到 B 的位置上。
    #    后缀空间 19^6≈4700 万、活跃至多 2000 条，实测约 4.3e-5/词，撞上即静默错值。
    with _STATE_LOCK:
        prev_fwd = dict(_CUSTOM_WORD_FWD)                              # word -> token
        prev_labels = {tok: rec[1] for tok, rec in _CUSTOM_WORD_REV.items()}
        used_suffixes = {
            _token_suffix(tok) for tok in _CUSTOM_WORD_REV
        } | set(_RECENT_SUFFIX)

    # ② 锁外派生：只有「新增词」与「标签变更词」要真的算后缀，未变词直接沿用。
    new_fwd, new_rev, reissued = {}, {}, []
    for word, label in active_words.items():
        tok = prev_fwd.get(word)
        if tok is not None and prev_labels.get(tok) == label:
            new_fwd[word] = tok
            new_rev[tok] = [word, label, now]
            continue
        # 旧 token 的后缀**故意不**从 used_suffixes 释放：释放后新词可能复用刚被
        # 换掉的 token 形态（标签相同时就是同一个 token），客户端历史里那条旧
        # 占位符会被还原成新词的原文 —— 替换错值比不替换危险得多。
        suffix = _deterministic_suffix(word, used_suffixes)
        used_suffixes.add(suffix)
        tok = "{{%s_%s}}" % (_safe_label(label), suffix)
        new_fwd[word] = tok
        new_rev[tok] = [word, label, now]
        reissued.append((word, tok, label))

    # ③ 锁内换表（整体换对象发布，读者只会看到上一代或新一代）。
    with _STATE_LOCK:
        for word, prev_tok in prev_fwd.items():
            tok = new_fwd.get(word)
            if tok is None:
                # 词被移除 / 禁用：只从**永久映射**里摘掉（下面的换表已经做到），
                # `_RECENT_FWD/_REV` 里那条必须留着 —— 客户端历史里已签发的占位符
                # 还得靠复用表还原，TTL 到期由 `_prune_recent` 回收。
                # 曾在这里连 `_RECENT_REV` 一起 pop，直接让 FWD/REV 不互逆
                # （压测实测 30 例），且旧占位符再也还原不出来。
                continue
            if tok != prev_tok:
                # 标签变更 → 换了 token：旧 token 要连 `_RECENT_REV` 与后缀索引
                # 一起注销，否则它会带着旧标签长驻成孤儿（`_prune_recent` 只按 FWD
                # 扫，碰不到）。
                _CUSTOM_WORD_REV.pop(prev_tok, None)
                _RECENT_REV.pop(prev_tok, None)
                _suffix_index_del(prev_tok)
        _CUSTOM_WORD_FWD = new_fwd
        _CUSTOM_WORD_REV = new_rev
        for word, tok, label in reissued:
            prev = _RECENT_FWD.get(word)
            if prev and prev[0] != tok:
                # 预热/历史带进来的旧 token：换新 token 后必须注销，否则它会留在
                # REV 与后缀索引里长驻成孤儿（_prune_recent 只按 FWD 扫，碰不到）
                _RECENT_REV.pop(prev[0], None)
                _suffix_index_del(prev[0])
            _RECENT_FWD[word] = [tok, label, now]
            _RECENT_REV[tok] = [word, label, now]
            # 步②可能与并发签发抢同一后缀（快照到落表之间新签出的 token）：
            # `_suffix_index_add` 撞车时把该后缀标为歧义、退出兜底匹配 —— 只会少还原，
            # 不会还原成错值。
            _suffix_index_add(tok)


def _request_scope(body):
    """请求扫描范围摘要（只含计数，不落原文）。说明日志 dialog 为何可能远少于 count。"""
    scope = {
        "msg_count": 0,
        "roles": {},
        "has_system": False,
        "has_tools": False,
        "latest_user_len": 0,
        "scan": "full_body",  # 当前策略：messages/system/tools 等全量递归脱敏
    }
    if not isinstance(body, dict):
        return scope
    msgs = body.get("messages")
    if isinstance(msgs, list):
        scope["msg_count"] = len(msgs)
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "other") or "other"
            scope["roles"][role] = scope["roles"].get(role, 0) + 1
            if role == "system":
                scope["has_system"] = True
            if role in ("tool", "function"):
                scope["has_tools"] = True
        for m in reversed(msgs):
            if isinstance(m, dict) and str(m.get("role") or "") == "user":
                t = _msg_text(m.get("content")) or ""
                scope["latest_user_len"] = len(t)
                break
    if body.get("system"):
        scope["has_system"] = True
        scope["roles"]["system"] = scope["roles"].get("system", 0) + 1
    if body.get("tools") or body.get("functions"):
        scope["has_tools"] = True
    for key in ("prompt", "input", "instructions", "contents"):
        if key in body and body[key] not in (None, "", [], {}):
            scope["roles"][key] = scope["roles"].get(key, 0) + 1
    return scope


def _collect_role_texts(body):
    """脱敏前各角色/字段文本，用于命中归因（仅内存，不写日志原文）。

    用 list 累积再 join，避免 += 字符串拼接的 O(n²) 复制（大 body 会话历史可上百 KB）。
    """
    bags = {}

    def add(role, text):
        if not isinstance(text, str) or not text:
            return
        bags.setdefault(role, []).append(text)

    if not isinstance(body, dict):
        return {k: "\n".join(v) for k, v in bags.items()}
    msgs = body.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "other") or "other"
            add(role, _msg_text(m.get("content")))
            # tool_calls / function_call 参数常带历史真实值
            for tc in m.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                args = fn.get("arguments")
                if isinstance(args, str):
                    add("tool", args)
            fc = m.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
                add("tool", fc["arguments"])
    for key in ("system", "prompt", "instructions"):
        v = body.get(key)
        if isinstance(v, str):
            add(key if key != "system" else "system", v)
        elif isinstance(v, list):
            add(key, _msg_text(v))
    inp = body.get("input")
    if isinstance(inp, str):
        add("input", inp)
    elif isinstance(inp, list):
        for part in inp:
            if isinstance(part, str):
                add("input", part)
            elif isinstance(part, dict):
                add(str(part.get("role") or "input"), _msg_text(part.get("content")))
    return {k: "\n".join(v) for k, v in bags.items()}


def _hit_roles_for(orig, role_texts):
    if not orig or not role_texts:
        return []
    hit = []
    for role, text in role_texts.items():
        if orig in text:
            hit.append(role)
    return hit


# ===== 占位符后缀字符集（0.1.13 起改用纯辅音，旧的 hex6 仍然认） =====
#
# 起因：模型会把 hex 后缀当成可以做算术的数。实测生产库 8798 条 RESTORE 里
# 36 条（0.41%）有占位符没还原，其中 92/97 是 IPPRIVATE——模型看到
# {{IPPRIVATE_83fc6a}}（对应 192.168.119.5），把 83fc 当网段前缀、6a 当主机位，
# 于是自己造出 {{IPPRIVATE_83fc00}} 表示子网、{{IPPRIVATE_83fc02}} 表示网关。
# 这两个 token 我们从没签发过，还原不了，也绝不许猜（见 _lookup 的长注释）。
#
# 六位十六进制**长得就是一个能拆开计算的数**，这是诱因本身。换成纯辅音后
# 后缀没有任何数值可读性，模型没有「改后缀」这个动作可做。
# 注意这只降低诱因，不构成保证——真出现了仍然走 unresolved 如实上报。
#
# 为什么是辅音而不是全字母：
# - _LOOSE_PLACEHOLDER_RX 是**不带花括号**匹配的（模型常把 {{}} 剥掉）。若放宽成
#   [0-9a-z]{6}，`HTTP_status` / `MAX_buffer` 这类代码标识符会命中，每次白查一次表。
#   辅音表不含 aeiou，天然与英文单词不相交（status 含 a、u，匹配不上）。
# - 去掉 l/i/o 是因为与 1/0 形近，模型复述时容易串。
# 熵：19^6 ≈ 4700 万 > hex6 的 1677 万，冲突概率反而更低。
_TOKEN_ALPHABET = "bcdfghjkmnpqrstvwxz"
# 新旧后缀的并集。写并集而不是放宽字符类：存量占位符（客户端历史对话里、
# 事件库预热回来的）全是 hex6 必须继续认，同时不把匹配面扩到英文单词。
_SUFFIX_PAT = r"(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})"

# 完整占位符 / 行尾半截占位符（流式时可能被切在两个 chunk 之间）
_PLACEHOLDER_RX = re.compile(r"\{\{[A-Z0-9]{1,12}_" + _SUFFIX_PAT + r"\}\}")
# 兼容内部空白与标签改写的双花括号占位符（用于还原时的容错第一遍）
# 覆盖模型习惯在 {{ 与标签之间加空格（如 Jinja 语法风格 `{{ APIKEY_xxxx }}`），
# 避免原先按宽松正则替换导致留下 `{{ ` 和 ` }}` 破坏工具命令。
_BRACED_PLACEHOLDER_RX = re.compile(
    r"\{\{\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*\}\}"
)
# 「裸露 / 半残」占位符：模型经常把 {{ }} 剥掉或只剩一半再吐回来。
#
# 实测（deepseek-v4-flash，真实调用）：让它把脱敏后的 token 拼进一条 curl，
# 输出是 `X-Setup-Token: SECRET_b5a53c` —— 花括号没了。原因很直白：
# {{...}} 在 Jinja/Handlebars/Vue 里就是模板语法，模型写命令时会顺手"整理"掉。
# 严格正则匹配不到 → 整个还原被跳过 → 用户拿到一个假 token 去执行。
#
# 这条只做兜底修复，且**只替换我们自己发过的 token**（必须能在会话/复用表里查到），
# 所以不存在误伤：LABEL_后缀 这种组合（6 位纯辅音或存量 hex6）正常文本里不会自然出现，何况还要求查得到。
_LOOSE_PLACEHOLDER_RX = re.compile(
    r"\{{1,2}\s*([A-Za-z0-9_]{1,12}_" + _SUFFIX_PAT + r")\s*\}{0,2}|([A-Z0-9]{1,12}_" + _SUFFIX_PAT + r")"
)
# 行尾半截占位符（流式时可能被切在两个 chunk 之间），需要扣住等下一块拼。
#
# 反斜杠必须进入缓冲范围：模型输出 `\{\{X\}\}` 时，chunk 边界可能正好落在
# 反斜杠与花括号之间（实测：不认反斜杠时 32 个切点里有 23 个会漏出 `\{\` 残渣，
# 因为第一个 chunk 只被扣下 `{`、反斜杠已经发出去了）。反斜杠必须和花括号
# 一起扣住才拼得回来。
#
# 花括号那一段必须写成 `(?:\\{0,3}\{){1,3}`，与 _ESCAPED_PLACEHOLDER_RX 同构：
# 两个花括号之间也夹着反斜杠（`\ { \ {`），写成 `\{\{?` 只能从内层花括号开始
# 匹配，外层反斜杠照样漏出去。
#
# **无上限的反斜杠量词必须封顶**（`\\*`→`\\{0,3}`、`\\+`→`\\{1,3}`）：否则本正则
# 在「连续反斜杠、末尾又不是反斜杠」的文本上会退化成 O(N²) 回溯。实测 8192 个
# 反斜杠：第一分支 `(?:\\*\{){1,3}...` 耗时 20ms，封顶后 0.12ms；`\\+$` 分支
# 耗时 133ms，封顶后 0.14ms —— **`\\+$` 才是主因**（无上限的 `\\+` 在每个非末尾
# 位置都要逐次回吐，每位置 O(N)）。封顶后整条正则为线性。
# 真实转义形态最多 3 个反斜杠（`\\\{\\\{`），3 够用；`\\{1,3}$` 与 `\\+$` 语义
# 等价（search 从最左成功位置开始），只是扣留范围由「全部反斜杠」收窄为
# 「末尾 1~3 个」—— 4 层以上转义不存在，收窄无影响。
#
# 末尾那个 `\\{1,3}$` 分支单独列出，是为了「切点正好落在反斜杠与花括号之间」：
# 此时 chunk 以裸反斜杠结尾，看不出来它后面要跟花括号，只能先扣住。代价是
# 普通文本里以反斜杠结尾的 chunk（Windows 路径 `C:\Users\`、行继续符）也会
# 多扣一个 chunk —— 内容不会丢，下一块或收尾时照常发出，只是晚一个 chunk。
# 换来的是转义形态在**全部 32 个切点**上都还原干净（不扣反斜杠时实测 23 个
# 切点会漏残渣，扣了之后为 0）。
#
# `{` 本身仍然是必需的——所以不含花括号的普通文本（`C:\Users\` 之外，
# 比如「今天天气」）不会被扣住。
_PARTIAL_RX = re.compile(r"(?:\\{0,3}\{){1,3}\s{0,4}[A-Za-z0-9_]{0,20}\s{0,4}\\{0,3}\}?\\{0,3}$|\\{1,3}$")
# 扣留上限：必须 ≥ _PARTIAL_RX 能匹配出的最长片段，否则「扣不下」会退化成
# 「就地处理半截占位符」——比如此前是 24，而二次转义的完整片段长 25，
# 于是它总是不被扣留、还原后留下 `\\}` 残渣。
# 反斜杠与空白都封顶后，模式的理论上限 = 3 单元×4 + 4 + 20 + 4 + (3+1+3) = 47，
# 故放到 48。空白原是无界 `\s*`，那样「理论最长」根本无从计算，扣留上限也就
# 失去依据（`{{` 后跟 40+ 空白的半截块扣不下，退化成留残渣）。
# 保持小而具体：只是「一段疑似半截占位符」，不是缓冲任意文本。
_PARTIAL_MAX = 48
# 从完整占位符里拆出 label 与后缀。多处要用，别再各写各的正则——
# 0.1.12 就有三处各自写死 [0-9a-f]{6}，改格式时漏一处就是静默失效。
_PLACEHOLDER_PARTS_RX = re.compile(r"^\{\{([A-Z0-9]{1,12})_(" + _SUFFIX_PAT + r")\}\}$")
# 转义形态：模型把 {{ }} 当成需要转义的字符，输出 \{\{X\}\}。
#
# 反斜杠要允许「每个花括号前后都有、且不止一个」，两个原因都是实测/推演出来的：
# - 反斜杠在**每个**花括号前后都要允许：真实输入是 `\ { \ { X \ } \ }`，两个
#   花括号**之间也夹着反斜杠**，`(?:\\)?\{\{(?:\\)?(...)` 这种写法连门都进不去；
# - 模型还会二次转义（`\\{\\{X\\}\\}`，它在按 JSON 的规则思考），只允许一个
#   反斜杠会剩下 `\\{\\` 残渣 —— 与不修没区别。
#
# 量词写成 `\\{0,3}` 而不是 `\\*`：**上限本身就是性能要求**。`\\*` 无上限时，
# 在「连续反斜杠、后面并没有花括号」的文本上，每个起始位置都要把剩余的反斜杠
# 全部回吐一遍才失败 → O(N²)。实测（N 个反斜杠 + 一个下划线）：
# 1024→0.30ms、4096→4.57ms、8192→18.2ms、16384→72.9ms、32768→293ms；
# 封顶后 0.013 / 0.052 / 0.105 / 0.224 / 0.405ms，线性。
# 3 足够（真实转义最多两层 `\\{\\{`），且 _PARTIAL_RX 取同一个上限，
# 两遍对同一形态的判定才不会错位。
#
# 花括号组写成 `{1,3}` 而不是 `{1,2}`：流式还原时 _PARTIAL_RX 会把行尾的裸
# 反斜杠也扣住（否则切点落在反斜杠与花括号之间就漏残渣），于是下一块拼起来的
# 文本可能多带一层反斜杠/花括号，这里要能容忍。
#
# 已知代价（写在这里以免日后当成 bug 追）：反斜杠紧贴在占位符左侧时会被一并
# 吃掉，所以「Windows 路径分隔符 + 标签被改写过的占位符」这种组合会少一个 `\`。
# 常规形态（标签完好）由严格遍先处理，走不到这里，所以暴露面很窄；而且一旦
# 查不到原文就原样放回，不会误吃。
#
# 与 _LOOSE_PLACEHOLDER_RX 的分工：这一条**必须带花括号**，因此只用在严格遍
# 与转义遍；不带花括号的形态仍交给宽松正则，且宽松正则不许走后缀索引
# （理由见 _RECENT_SUFFIX 的注释）。
_ESCAPED_PLACEHOLDER_RX = re.compile(
    r"(?:\\{0,3}\{){1,3}(?:\\{0,3})\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*(?:\\{0,3}\}){1,3}",
    re.IGNORECASE,
)
# 从「带花括号但标签可能被改写」的形态里取后缀。标签允许含下划线：
# 模型会自己把 `IPPRIVATE` 补成 `IP_PRIVATE`，用 _PLACEHOLDER_PARTS_RX
# （标签字符类不含下划线）解析不了这种。
_ANY_BRACED_SUFFIX_RX = re.compile(
    r"^\{\{\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*\}\}$", re.IGNORECASE
)


def _token_suffix(token):
    """取 token 的 6 位后缀（小写）；形态不对返回空串。

    用字符串切分而不是正则：`{{LABEL_suffix}}` 里 label 由 _safe_label 保证
    不含下划线，所以最后一个下划线之后就是后缀；对模型改写过的
    `{{IP_PRIVATE_x}}` 同样成立。
    """
    if not isinstance(token, str) or not token.startswith("{{") or not token.endswith("}}"):
        return ""
    body = token[2:-2].strip()
    if "_" not in body:
        return ""
    return body.rsplit("_", 1)[1].lower()


def _token_label(token):
    """取 token 的标签部分（原样，未归一化）；形态不对返回空串。"""
    if not isinstance(token, str) or not token.startswith("{{") or not token.endswith("}}"):
        return ""
    body = token[2:-2].strip()
    if "_" not in body:
        return ""
    return body.rsplit("_", 1)[0]


def _suffix_indexable(suffix):
    """该后缀是否允许进索引：必须 6 位纯辅音。

    hex6 后缀不进索引，原因见 _RECENT_SUFFIX 注释（代码里 `_abc123` 太常见，
    进索引就会误替换）。
    """
    return len(suffix) == 6 and all(c in _TOKEN_ALPHABET for c in suffix)


def _suffix_index_add(token):
    """登记后缀索引。**撞车即置为不可用，绝不覆盖、也绝不保留其一。**

    新 token 由 _new_token 保证后缀不与索引冲突，所以撞车只可能来自事件库
    预热/客户端历史带进来的历史 token。无论保留哪一个，都会让「按后缀反查」
    把 A 的原文答到 B 的位置上，所以撞车后该后缀直接退出兜底匹配——代价只是
    这个后缀不参与兜底，退化成改动前的行为。**替换错值比不替换危险得多。**

    **必须值比较（!=），不能对象身份比较（is not）**：预热走 json.loads、
    客户端历史走 sqlite 取出，拿到的 token 与索引里已存的那个**值相等但对象
    不同**。用 `is not` 会让「同一个 token 被登记两次」被误判成撞车，后缀
    永久退出兜底（且运行时补登记救不回来，见 _recall_token）。实测：预热里
    同一 token 出现 ≥2 条事件是常态（复用表的设计目的就是跨请求复用），
    于是大面积静默失效、用户只看到占位符没被还原。
    """
    sfx = _token_suffix(token)
    if not _suffix_indexable(sfx):
        return
    tables = _tables()
    with _STATE_LOCK:
        cur = tables.suffix.get(sfx)
        if cur is None:
            tables.suffix[sfx] = token
        elif cur != token:
            # _SUFFIX_AMBIGUOUS 是 object()，与任何字符串 != 恒真 -> 撞车标记不会被
            # 后续登记抹掉；真撞车（两个不同 token 抢同一后缀）的语义不变。
            tables.suffix[sfx] = _SUFFIX_AMBIGUOUS


def _suffix_index_del(token):
    """注销后缀索引。只删「确实指向本 token」的条目。

    撞车标记不会被删：它本来就不指向任何具体 token，而恢复成「指向剩下的那个」
    又会重新引入歧义。撞车只在预热历史数据时可能发生（新 token 已保证后缀唯一），
    条数极少，留着不影响内存。
    """
    sfx = _token_suffix(token)
    tables = _tables()
    with _STATE_LOCK:
        if sfx and tables.suffix.get(sfx) == token:
            tables.suffix.pop(sfx, None)


def _suffix_real_token(token):
    """按后缀反查出**真实签发的 token**；不满足全部条件返回 None。

    与 _lookup_by_suffix 拆开，是为了让调用方能拿到真实 token 去做记账
    （restored_tokens 里存的是签发时的原 token，不是模型改写后的形态）。

    调用点必须**已经保证 token 带花括号**（严格遍与转义遍）。裸 token 不许
    走这里：流式响应里它可能只是被 chunk 切开的残片（实测 `ATE_zwndfk`），
    按后缀命中后会把残片替换成明文，拼出一条错的命令。

    **标签必须归一化后相等，或属于同一凭据互通族**（`_safe_label` 去大小写、去下划线）：
    - `{{IP_PRIVATE_x}}` / `{{ipprivate_x}}` → 归一到 `IPPRIVATE`，命中；
    - `{{PASSWORD_x}}` / `{{SECRET_x}}` 与 `CONNSTR` → 同属凭据互通族，命中；
    - `{{HOST_x}}` → `HOST` != `IPPRIVATE` 且不属同族，**拒绝**，原样放回并计入 unresolved。

    为什么不做「只看后缀、标签随便」的完全宽松匹配：后缀虽然只有 47M 分之一
    的碰撞概率，但一旦碰撞就是**把 A 的原文（真实内网 IP、手机号）替换到 B 的
    位置上**，属于静默替换错值。凭据族同义互通安全是因为撞车后缀已被剔除且
    同属凭据范畴；其他标签仍坚持相等校验。
    """
    m = _ANY_BRACED_SUFFIX_RX.match(token)
    if not m:
        return None
    real = _tables().suffix.get(m.group(2).lower())
    if not isinstance(real, str) or real == token:
        # None = 没登记过；_SUFFIX_AMBIGUOUS = 该后缀撞车、已退出兜底；
        # real == token 说明精确路径刚查过且落空，再查一次没意义
        return None
    lab_in = _safe_label(m.group(1))
    lab_real = _safe_label(_token_label(real))
    if not _labels_compatible(lab_in, lab_real):
        return None
    return real


def _lookup_by_suffix(token, sid):
    """按后缀反查原文（容错路径）。判定逻辑见 _suffix_real_token。"""
    real = _suffix_real_token(token)
    if real is None:
        return None
    return _lookup(real, sid)


class Edit(NamedTuple):
    """一次「原文 → 占位符」替换，坐标为**该次替换发生时**的文本坐标系。"""
    start: int      # 闭
    end: int        # 开
    token: str      # 替换后的占位符（部分替换时仅为替换捕获组的占位符）


def _mask_excluding_placeholders_ed(text, rx, sub_fn, group_idx=0):
    """同 _mask_excluding_placeholders，额外返回本次替换产生的 Edit 列表。

    Edit 坐标为**入参 text 的坐标系**（即本趟开始时的坐标系）。
    对 text 做正则替换，但跳过已有的占位符片段（防污染）。
    """
    if not text:
        return text, []

    edits = []
    result = []
    last_end = 0

    def _process_chunk(chunk, base):
        chunk_out = []
        c_last = 0
        for m in rx.finditer(chunk):
            repl = sub_fn(m)
            chunk_out.append(chunk[c_last:m.start()])
            chunk_out.append(repl)
            c_last = m.end()
            if repl != m.group(0):
                if group_idx == 0:
                    edits.append(Edit(base + m.start(), base + m.end(), repl))
                else:
                    gs, ge = m.span(group_idx)
                    prefix_len = gs - m.start()
                    suffix_len = m.end() - ge
                    tok = repl[prefix_len:len(repl) - suffix_len] if suffix_len else repl[prefix_len:]
                    edits.append(Edit(base + gs, base + ge, tok))
        chunk_out.append(chunk[c_last:])
        return "".join(chunk_out)

    for m in _PLACEHOLDER_RX.finditer(text):
        before = text[last_end:m.start()]
        if before:
            result.append(_process_chunk(before, last_end))
        result.append(m.group())
        last_end = m.end()

    tail = text[last_end:]
    if tail:
        result.append(_process_chunk(tail, last_end))

    if not edits and last_end == 0:
        return text, []

    return "".join(result), edits


def _mask_excluding_placeholders(text, rx, sub_fn, group_idx=0):
    """对 text 做正则替换，但跳过已有的占位符片段（防污染）。

    薄封装：转调 _mask_excluding_placeholders_ed 并丢弃 edits。
    """
    new_text, _ = _mask_excluding_placeholders_ed(text, rx, sub_fn, group_idx=group_idx)
    return new_text


# ── NER（语义实体识别）辅助 ───────────────────────────────────────────────────
# NER 是概率模型，与上面那套确定性规则之间有三条硬边界：
#   1. 必须排在确定性规则之后跑，同一原文以确定性命中为准；
#   2. 只能**按区间**替换，且与已有占位符相交时只脱敏「非占位符片段」；
#   3. 长度上限 / 时间预算 / 失败可见性由 ner_engine 负责（见该模块头部成本模型）。
# 先前的实现在这里踩了两个坑（均实测复现，2026-09-19）：
#   - `not _PLACEHOLDER_RX.search(orig)` 守卫是**整段丢弃**：多轮历史带回的占位符
#     会把同一实体（含其中的明文）整段放过；
#   - 用 `re.compile(re.escape(orig))` 做**全文子串替换**：实体在长文本里出现 N 次
#     就扫 N 遍全文（10 万字符实测 69 秒），而这段跑在 mitmproxy 的 asyncio 事件
#     循环上，会冻结全部 upstream 端口的连接。
_NER_WARNED = set()


def _ner_warn_once(key, msg):
    """NER 的失败必须可见（静默降级等于「以为开了、其实没脱」），但同类只记一次。"""
    try:
        import ner_engine
        if hasattr(ner_engine, "record_skip"):
            ner_engine.record_skip(key, msg)
    except Exception:
        pass
    if key in _NER_WARNED:
        return
    _NER_WARNED.add(key)
    try:
        _log(f"[transparent] {msg}")
    except Exception:
        pass


@contextlib.contextmanager
def _ner_doc_budget(seconds, *, deadline=None, cancel_event=None):
    """给一段连续调用（如整份 Office 文档逐 run 脱敏）设 NER 总预算。

    单条短文本实测约 10ms，几千个 run 会线性堆到分钟级，而扩展侧 HTTP 超时更短，
    用户看到的就是「文件没脱敏」。超预算后只停用语义识别，确定性规则照常生效。
    """
    try:
        import ner_engine
    except Exception:
        yield
        return
    if deadline is None and cancel_event is None:
        ner_engine.begin_budget(seconds)
    else:
        ner_engine.begin_budget(seconds, deadline=deadline, cancel_event=cancel_event)
    try:
        yield
    finally:
        ner_engine.end_budget()


def _mask_by_spans(text, spans):
    """按 [start, end, repl) 区间一次性重建文本（spans 须已按 start 排序）。

    重叠区间安全契约：
    - 若出现区间重叠（start < cursor），后续重叠区间必须整段丢弃（continue）。
    - 绝不能将重叠区间截断为 [cursor, end) 替换，因为 repl 绑定的完整原文在还原
      (restore) 时会将前序已覆盖的明文重复吐出，导致文本严重错位与破坏性重复。
    - 上游实体抽取层（ner_engine / _ner_entity_spans）负责确保实体区间两两不交。
    """
    if not spans:
        return text
    out = []
    cursor = 0
    for start, end, repl in spans:
        if start < cursor:
            continue          # 与已接受区间重叠：整段跳过，防错位且防还原重复吐字
        out.append(text[cursor:start])
        out.append(repl)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


class OffsetMap:
    """由有序、互不重叠的 Edit 序列构造的单调坐标映射。

    记录「存活区间」：src 上未被替换的区间 → 目标上的对应起点。
    kept = [(src_start, src_end, dst_start), ...]，按 src_start 升序。
    """

    def __init__(self, edits=None, src_len=0, kept=None, dst_len=None):
        self.src_len = src_len
        if kept is not None:
            self.kept = kept
            self.dst_len = dst_len if dst_len is not None else (
                kept[-1][2] + (kept[-1][1] - kept[-1][0]) if kept else 0
            )
            self.edits = edits or []
            return

        self.edits = sorted(edits, key=lambda x: x[0]) if edits else []
        kept = []
        cs = cd = 0
        for s, e, tok in self.edits:
            if s < 0 or e < s:
                raise ValueError(f"Edit 区间非法: [{s}, {e}) 必须满足 0 <= start <= end")
            if s < cs:
                raise ValueError(f"Edit 重叠: [{s}, {e}) 与前序边界 {cs} 冲突")
            if s > cs:
                kept.append((cs, s, cd))
                cd += s - cs
            cd += len(tok)
            cs = e
        if cs > src_len:
            raise ValueError(f"Edit 越界: 结束位置 {cs} 超过 src_len {src_len}")
        if cs < src_len:
            kept.append((cs, src_len, cd))
            cd += src_len - cs
        self.kept = kept
        self.dst_len = cd

    def _seg_of(self, i):
        """返回包含 i 的存活区间下标；i 落在被替换区间内则返回 None。"""
        lo, hi = 0, len(self.kept) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if i < a:
                hi = mid - 1
            elif i >= b:
                lo = mid + 1
            else:
                return mid
        return None

    def map_point(self, i):
        """i 落在存活区间内 → 返回目标坐标；落在被替换区间内 → 返回 None。"""
        seg = self._seg_of(i)
        if seg is None:
            return None
        a, b, d = self.kept[seg]
        return d + (i - a)

    def map_range(self, s, e):
        """区间映射：两端向内收敛到最近的可定位点。

        起点落在替换区间内 → 向右找到下一个存活区间的起点；
        终点落在替换区间内 → 向左找到上一个存活区间的终点。
        收敛后 s2 >= e2 表示该区间已被完全吃掉 → 返回 None。
        """
        if s >= e:
            return None
        # 起点：第一个 >= s 的存活字符
        lo, hi = 0, len(self.kept) - 1
        seg_s = None
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if b <= s:
                lo = mid + 1
            elif a >= e:
                hi = mid - 1
            else:
                seg_s = mid
                hi = mid - 1
        if seg_s is None:
            return None
        a, b, d = self.kept[seg_s]
        s2 = d + (max(s, a) - a)

        # 终点：最后一个 < e 的存活字符
        lo, hi = 0, len(self.kept) - 1
        seg_e = None
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if a >= e:
                hi = mid - 1
            elif b <= s:
                lo = mid + 1
            else:
                seg_e = mid
                lo = mid + 1
        if seg_e is None:
            return None
        a, b, d = self.kept[seg_e]
        e2 = d + (min(e, b) - a)
        if e2 <= s2:
            return None
        return s2, e2

    def compose(self, next_om):
        """合成 self (src->mid) 与 next_om (mid->dst)，返回总映射 (src->dst)。

        双指针扫描两者的存活区间交集，时间复杂度 O(len(self.kept) + len(next_om.kept))。
        """
        if self.dst_len != next_om.src_len:
            raise ValueError(f"OffsetMap 尺寸不匹配无法合成: {self.dst_len} vs {next_om.src_len}")
        kept1 = self.kept
        kept2 = next_om.kept
        new_kept = []
        i1 = i2 = 0
        while i1 < len(kept1) and i2 < len(kept2):
            s0, e0, d1 = kept1[i1]
            t1_start = d1
            t1_end = d1 + (e0 - s0)

            s1, e1, d2 = kept2[i2]
            t2_in_start = s1
            t2_in_end = e1

            inter_s = max(t1_start, t2_in_start)
            inter_e = min(t1_end, t2_in_end)

            if inter_s < inter_e:
                new_s0 = s0 + (inter_s - t1_start)
                new_e0 = s0 + (inter_e - t1_start)
                new_d2 = d2 + (inter_s - t2_in_start)
                new_kept.append((new_s0, new_e0, new_d2))

            if t1_end < t2_in_end:
                i1 += 1
            elif t2_in_end < t1_end:
                i2 += 1
            else:
                i1 += 1
                i2 += 1

        return OffsetMap(src_len=self.src_len, kept=new_kept, dst_len=next_om.dst_len)

    @classmethod
    def empty(cls, length):
        """构造恒等映射（无任何编辑）。"""
        return cls([], length)


def _ner_entity_spans(text, entities):
    """把 NER 实体转成可安全替换的区间列表 [(start, end, label), ...]。

    实体与已有占位符相交时，只取**不在占位符内**的片段，并按占位符边界切开：
    - 模型常把 `上海市浦东新区{{TERM_x}}世纪大道100号` 识别成一个地址。整段替换会把
      明文片段与既有占位符混成一个新 token；整段丢弃则明文照原样出网。
      切成两段分别打码，才既不丢保护、也不污染已有占位符。
    - 被占位符切碎的残渣（如 `{` / `}}`）不是实体：片段 strip 后不足 2 字即放弃。
    """
    ph = [(m.start(), m.end()) for m in _PLACEHOLDER_RX.finditer(text)]
    spans = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        try:
            start = int(ent["start"])
            end = int(ent["end"])
        except (KeyError, TypeError, ValueError):
            continue
        label = str(ent.get("type") or "TERM")
        if end - start < 2 or start < 0 or end > len(text):
            continue
        cursor = start
        for ps, pe in ph:
            if pe <= cursor:
                continue
            if ps >= end:
                break
            if ps > cursor:
                spans.append((cursor, min(ps, end), label))
            cursor = max(cursor, pe)
            if cursor >= end:
                break
        if cursor < end:
            spans.append((cursor, end, label))
    return spans


def mask(text, sid):
    # D5: reserve only exact verification markers. Split before *all* detectors,
    # including NER's original-text input/cache; every neighboring byte is scanned.
    if not text or onboarding.PREFIX not in text:
        return _mask_text(text, sid)
    matches = list(onboarding.MARKER_RE.finditer(text))
    if not matches:
        return _mask_text(text, sid)
    if _session_get(sid) is None:
        _new_session(sid)
    evidence = _session_get(sid).setdefault('verification', {})
    parts, offset = [], 0
    for match in matches:
        parts.append(_mask_text(text[offset:match.start()], sid))
        marker = match.group()
        parts.append(marker)
        if len(evidence) < 16:
            evidence[onboarding.digest(marker)] = True
        offset = match.end()
    parts.append(_mask_text(text[offset:], sid))
    return ''.join(parts)


# ── 叶子结果缓存（批次 8 / P1-6）─────────────────────────────────────────
# 长会话的形态是「客户端每轮重发整段历史」：几百条消息里**只有最后一条变了**，
# 其余字符串叶子逐字节相同。而 `_mask_text` 对每个叶子都要跑 20~50 遍正则
# （实测 135ms/MiB，长会话 4MB 请求体里约 70% 的脱敏耗时在这里），全是重复劳动。
#
# 缓存的是**整个叶子的脱敏结果**，命中判据是双重的：
#   1. 代号一致（配置热重载 / 词表换代 / NER 开关变化时整体作废）；
#   2. 缓存时登记的每一个**占位符**在当前会话 `rev` 里还能查到原文、且
#      `fwd[原文]` 仍然是同一个占位符。
# 第 2 条把「LRU 淘汰 / 面板清空映射 / 跨会话复用」全部挡在门外：映射一漂就当
# 未命中重跑。命中时逐条重放 `_hit()`，last_hits / new_orig 口径与重跑一致。
#
# ⚠️ 缓存里**不得出现原文**（§G1，与 ner_engine 的结果缓存同一口径）：键是进程密钥的
# 摘要，值是「脱敏后的文本 + 占位符清单」，原文一律经 `rev` 从会话表现取。
_LEAF_CACHE_MAX = max(256, _env_int("MASKIT_LEAF_CACHE_MAX", 8192))
_LEAF_CACHE_MAX_CHARS = max(1_000_000, _env_int("MASKIT_LEAF_CACHE_CHARS", 32_000_000))
_LEAF_CACHE_MAX_LEAF = max(4096, _env_int("MASKIT_LEAF_CACHE_MAX_LEAF", 262144))
# 抽样自检周期：每 N 次调用中有一次**故意不走缓存**，重算一遍与缓存比对。
# 命中路径不会重算，所以一个漏进代号的输入会永远静默地给出错误文本；
# 抽样是唯一的网，命中即整体关闭缓存（宁可不要这个优化，不能给错文本）。
_LEAF_CACHE_VERIFY_EVERY = max(16, _env_int("MASKIT_LEAF_CACHE_VERIFY", 256))
_LEAF_CACHE_KEY = os.urandom(32)
_LEAF_CACHE = collections.OrderedDict()   # 摘要 -> (代号, 原长, 脱敏文本, [(占位符, 标签, 原文摘要)])
_LEAF_CACHE_CHARS = 0
_LEAF_CACHE_LOCK = threading.Lock()
_LEAF_CACHE_STATS = {"hit": 0, "miss": 0, "verify": 0, "poison": 0}
_LEAF_CACHE_GEN = [0]


def _leaf_cache_env_enabled() -> bool:
    """叶子缓存总开关（`MASKIT_LEAF_CACHE=0` 关）。

    与「抽样自检发现不一致→整位关断」用的是同一个闸（`_LEAF_CACHE_OK[0]`），
    区别只在于这个能主动、立即停：缓存只是加速手段，怀疑它算错了就该能当场停掉，
    而不是等下一次抽中或回滚版本。单测见 `tests/test_leaf_cache.py`。
    """
    return _env_int("MASKIT_LEAF_CACHE", 1) != 0


# 总开关兼故障闸：关掉即"一条也不缓存"（全部当未命中 → 走完整扫描路径）。
_LEAF_CACHE_OK = [_leaf_cache_env_enabled()]
_LEAF_CACHE_TICK = [0]


def _leaf_cache_key(text):
    """缓存键：进程密钥的 blake2b 摘要（**不留原文**，与 §G1 同口径）。"""
    return hashlib.blake2b(text.encode("utf-8", "surrogatepass"),
                           key=_LEAF_CACHE_KEY, digest_size=16).hexdigest()


def _orig_digest(orig):
    """原文的进程密钥摘要：缓存**把「代号」与「它当时代表哪个原文」钉在一起**。

    为什么光有代号不够（2026-10-04 评审发现）：代号不是**原始值的身份**。
    全局复用窗口（`_RECENT_SUFFIX`，上限 2000）满了之后，一个旧后缀可能被
    重新签发给**另一个原文**；此时同一条代号在两个会话里各自指向不同的原文，
    「代号在两个会话里都对得上」这条校验就会放行一段指向错原文的旧结果 ——
    后果是上游拿到的占位符会在客户端被还原成**另一个值**（跨会话串扰）。
    摘要用同一个进程密钥，不落盘、不可反推；碰撞需知道密钥，8 字节已远超所需。
    """
    return hashlib.blake2b(orig.encode("utf-8", "surrogatepass"),
                           key=_LEAF_CACHE_KEY, digest_size=8).hexdigest()


def _leaf_cache_gen():
    """缓存代号：**任何**能改变脱敏输出的进程内配置都要在它里面。

    漏一项 = 那个配置改了之后旧结果继续命中（静默给错文本）。三道保险：
      · `_LEAF_CACHE_GEN`：配置热重载、词表执行计划重建、显式清空时自增；
      · `NER_ENABLED`：语义识别开关（它直接改变输出）；
      · `id(BUILTIN_RULES)`：规则开关表是**整体换对象**发布的，换对象即换代
        （测试里直接赋值也能被抓住；原地改 key 不会被抓，生产路径不存在这种写法）。
    """
    return (_LEAF_CACHE_GEN[0], bool(NER_ENABLED), id(BUILTIN_RULES))


def _leaf_cache_bump():
    """配置/词表换代：代号一变，旧条目在下次查找时整体作废。"""
    _LEAF_CACHE_GEN[0] += 1


def _leaf_cache_clear():
    global _LEAF_CACHE_CHARS
    with _LEAF_CACHE_LOCK:
        _LEAF_CACHE.clear()
        _LEAF_CACHE_CHARS = 0


def _leaf_cache_lookup(text, fwd, rev):
    """查缓存；命中返回 `(脱敏文本, [(占位符, 标签)])`，未命中返回 None。

    代号不符、长度不符、或任一个占位符在当前会话里**对不上原文**，都算未命中。
    校验必须真的查一遍映射，不能只看代号 —— 占位符是**会话级**的，同一段文本
    在不同会话/被淘汰后指向的占位符不同，拿旧文本直接返回会把 A 会话的占位符
    发给 B 会话。

    三道校验缺一不可：`rev[tok]` 存在、`fwd[rev[tok]] == tok`、且
    `_orig_digest(rev[tok])` 等于存缓存时那个原文的摘要。前两道只证明「这个代号
    在当前会话里指向某个原文」，第三道才证明「指向的就是当初那个原文」。
    """
    global _LEAF_CACHE_CHARS
    key = _leaf_cache_key(text)
    with _LEAF_CACHE_LOCK:
        ent = _LEAF_CACHE.get(key)
        if ent is None:
            _LEAF_CACHE_STATS["miss"] += 1
            return None
        if ent[0] != _leaf_cache_gen() or ent[1] != len(text):
            _LEAF_CACHE.pop(key, None)
            _LEAF_CACHE_CHARS -= ent[1]
            _LEAF_CACHE_STATS["miss"] += 1
            return None
        _LEAF_CACHE.move_to_end(key)
    with _STATE_LOCK:
        for token, _label, want in ent[3]:
            orig = rev.get(token)
            if orig is None or fwd.get(orig) != token or _orig_digest(orig) != want:
                with _LEAF_CACHE_LOCK:
                    _LEAF_CACHE_STATS["miss"] += 1
                return None
    with _LEAF_CACHE_LOCK:
        _LEAF_CACHE_STATS["hit"] += 1
    return ent[2], ent[3]


def _leaf_cache_verify(expect, masked):
    """抽样自检：`expect` 是本次命中到的旧文本，`masked` 是重算结果。

    不一致 = 缓存给错了文本（漏进代号的输入、或命中校验有洞）。命中路径上的错误
    是**静默**的，宁可丢掉这个优化，也不能让用户拿到错的脱敏结果 —— 所以直接整体关闭。
    """
    if expect is None:
        return
    _LEAF_CACHE_STATS["verify"] += 1
    if expect == masked:
        return
    _LEAF_CACHE_OK[0] = False
    _LEAF_CACHE_STATS["poison"] += 1
    _leaf_cache_clear()
    _log("[transparent] 叶子缓存自检发现不一致，已整体关闭叶子缓存")


def _leaf_cache_store(text, masked, tokens):
    """存一条结果（调用方负责先跑 `_leaf_cache_verify`）。"""
    global _LEAF_CACHE_CHARS
    if not _LEAF_CACHE_OK[0]:
        return
    size = len(text)
    if size > _LEAF_CACHE_MAX_LEAF:
        return                      # 单条超大叶子不入库（一条就顶掉小半张表）
    key = _leaf_cache_key(text)
    with _LEAF_CACHE_LOCK:
        old = _LEAF_CACHE.pop(key, None)
        if old is not None:
            _LEAF_CACHE_CHARS -= old[1]
        _LEAF_CACHE[key] = (_leaf_cache_gen(), size, masked, tokens)
        _LEAF_CACHE_CHARS += size
        while _LEAF_CACHE and (_LEAF_CACHE_CHARS > _LEAF_CACHE_MAX_CHARS
                               or len(_LEAF_CACHE) > _LEAF_CACHE_MAX):
            _k, _v = _LEAF_CACHE.popitem(last=False)
            _LEAF_CACHE_CHARS -= _v[1]


def _ner_skip_epoch():
    """NER「结果残缺」计数（拿不到模块时返回 None，两边相等 → 允许入库）。"""
    try:
        import ner_engine
        return ner_engine.skip_epoch()
    except Exception:
        return None


def _mask_text(text, sid):
    """脱敏文本。返回脱敏后的文本。

    命中明细通过会话的 last_hits 暴露（本次实际替换的唯一原文，含复用项），
    供 MASK 事件的 count/new_count 统计——count 是会话累计 fwd 大小，会随历史
    增长到几千，直接当「本次脱敏数」展示会误导（用户曾质疑脱敏几千还原几十）。
    """
    if not text:
        return text
    original = text
    om = OffsetMap.empty(len(original)) if NER_ENABLED else None
    om_broken = False

    def _update_om(edits, curr_len):
        nonlocal om, om_broken
        if om is None or om_broken or not edits:
            return
        try:
            om = om.compose(OffsetMap(edits, curr_len))
        except Exception as e:
            om_broken = True
            om = None
            _ner_warn_once("om_compose",
                           "OffsetMap 坐标合成降级，本次跳过 NER 识别: %s: %s"
                           % (type(e).__name__, e))

    s = _session_get(sid)
    if s is None:
        _new_session(sid)
        s = sessions[sid]
    fwd = s["fwd"]
    labels = s["labels"]
    rev = s["rev"]
    hit_orig = set()
    # 本次真正登记过的命中（占位符 -> (标签, 原文摘要)，按首次出现保序）。叶子缓存
    # 只存这份**清单**（不含原文，见 §G1），命中时再经 rev 把原文取回来重放 `_hit()`。
    # 摘要不是可选项：代号本身不是原始值的身份（见 `_orig_digest`）。
    hit_tokens = {}
    # 本次请求新增的原文（_remember 之前 fwd 里没有的）；用于 new_count 统计。
    # 注意必须在 _remember 之前判断，否则恒为 0（曾因先写 fwd 再判导致死代码）
    new_orig = set()

    def _hit(orig, label="API_KEY"):
        if orig not in fwd:
            new_orig.add(orig)
            if _remember(fwd, labels, orig, label):
                s["suffix_reused"] = True
            # rev 增量维护：只有新增才补一条，避免每次 mask 全量重建（长会话 fwd 数千条）
            rev[fwd[orig]] = orig
        hit_orig.add(orig)
        tok = fwd.get(orig)
        if tok is not None:
            hit_tokens.setdefault(tok, (label, _orig_digest(orig)))

    # ── 叶子结果缓存命中路径（批次 8）───────────────────────────────────────
    # 抽样自检：每 _LEAF_CACHE_VERIFY_EVERY 次调用里有一次故意不用缓存，走完整
    # 重算，末尾由 `_leaf_cache_verify()` 比对（不一致即整体关闭缓存）。
    _lc_expect = None
    if _LEAF_CACHE_OK[0]:
        # 计数**取模回绕**：这是个永不重置的进程级计数器，没必要把它加到无穷
        # （大整数求模会随位数变慢，长期运行下纯属无谓开销）。
        _LEAF_CACHE_TICK[0] = (_LEAF_CACHE_TICK[0] + 1) % _LEAF_CACHE_VERIFY_EVERY
        _probe = _leaf_cache_lookup(text, fwd, rev)
        if _probe is not None:
            if _LEAF_CACHE_TICK[0] == 0:
                _lc_expect = _probe[0]
            else:
                with _STATE_LOCK:
                    for _tok, _lbl, _ in _probe[1]:
                        _orig = rev.get(_tok)
                        if _orig is not None:
                            _hit(_orig, _lbl)
                s.setdefault("last_hits", set()).update(hit_orig)
                s.setdefault("new_orig", set()).update(new_orig)
                return _probe[0]

    # Key 前缀命中归 API_KEY；可被 builtin_rules.API_KEY 关闭
    if _rule_enabled("API_KEY"):
        prefix_rx = _prefix_secret_regex()
        if prefix_rx:
            def _prefix_sub(m):
                orig = m.group()
                _hit(orig)
                return fwd.get(orig, orig)
            # 跳过已有占位符片段（防污染：多轮对话历史里带旧占位符）
            curr_len = len(text)
            text, edits = _mask_excluding_placeholders_ed(text, prefix_rx, _prefix_sub)
            _update_om(edits, curr_len)

    # 自定义词扫描。计划由 `_custom_words_plan()` 产出：普通词合并成一条 alternation
    # （O(长度)，长词优先），`re:` 词各自独立成项 —— 隔离用户正则的全局 flag、命名组
    # 与反向引用，坏词只毁它自己而不是整张词表（见该函数的注释）。
    # 跳过已有占位符片段（防污染：自定义词含 hex 子串会劈开占位符）。
    for _cw_kind, _cw_rx, _cw_meta in _custom_words_plan():
        def _cw_sub(m, _kind=_cw_kind, _meta=_cw_meta):
            word = m.group(0)
            if _kind == "literal":
                # 大小写变体统一用词表里的原始 key（ACME/acme 复用同一占位符）
                orig_key, label = _meta.get(word.lower()) or (word, "")
            else:
                # 正则型词：原文是**命中到的文本**（每个命中各自建映射，绝不把正则
                # 本身当原文 —— 那会让还原吐出 `re:...` 字面量），标签取词表里那个词的
                orig_key, label = word, _meta
            _hit(orig_key, label)
            return fwd.get(orig_key, word)
        curr_len = len(text)
        text, edits = _mask_excluding_placeholders_ed(text, _cw_rx, _cw_sub)
        _update_om(edits, curr_len)


    # 被豁免的连接串**区间** [start, end)（end 即 userinfo 结尾的 `@` 之后）：
    # RULES 里 CONNSTR 排在 EMAIL 之前，本列表用于让 EMAIL 避开与这些区间重叠的
    # 命中，否则「口令尾@host」会被当邮箱吃掉、留下口令半明文。
    exempt_conn = []

    for rx, label, group_idx in RULES:
        if not _rule_enabled(label):
            continue
        if not _rule_may_hit(text, label):
            continue  # 特征预检：不含必含特征，跳过整条规则扫描
        matched = []
        for m in rx.finditer(text):
            orig = m.group(group_idx)
            if label == "CARD" and not _card_ok(orig):
                continue
            if label == "IDCARD" and not _idcard_ok(orig):
                continue
            if label == "PHONE" and not _phone_ok(orig):
                continue
            if label == "LANDLINE" and not _landline_ok(orig):
                continue
            if label == "EMAIL" and not _email_ok(orig):
                continue
            if label == "IBAN" and not _iban_ok(orig):
                continue
            if label == "JWT" and not _jwt_ok(orig):
                continue
            if label == "IP_PUBLIC" and not _ip_public_ok(orig):
                continue
            if label == "IPV6_PRIVATE" and not _ipv6_private_ok(orig):
                continue
            if label == "USCC" and not _uscc_ok(orig):
                continue
            if label == "CONNSTR" and not _connstr_ok(orig, m, text):
                # 记下被豁免的区间：CONNSTR 排在 EMAIL 之前，下面必须让 EMAIL 避开
                # 与它重叠的命中，否则「口令尾@host」会被当邮箱吃掉留下半明文。
                if len(exempt_conn) < _CONNSTR_EXEMPT_MAX:
                    exempt_conn.append((m.start(), m.end()))
                continue
            if label == "EMAIL" and _overlaps_exempt_conn(m.start(), m.end(), exempt_conn):
                continue
            _hit(orig, label)
            matched.append(orig)
        # 按唯一原文替换（dict.fromkeys 去重且保序）。曾直接 `for orig in matched`：
        # matched 记的是命中「次数」而非唯一原文，同一个手机号在长上下文里出现上万次
        # 就对全文做上万次 str.replace，而 str.replace 本就是全局替换、第二次起纯属
        # 无用功 → 整条管线退化成 O(命中次数 × 文本长度)。
        # 实测 256KB 请求体：命中 11037 次、唯一原文仅 4 个，替换环节 930ms;
        # 512KB 达 3696ms（去重后 2.9ms，输出逐字节一致）。mitmproxy addon 跑在
        # asyncio event loop 上同步执行，这几秒会冻结全部 upstream 端口的所有连接，
        # 包括进行中的 SSE 流 —— 表现为「打字机卡死 + 其他客户端超时」。
        # 同时跳过已有占位符片段（防污染：内置规则如 hex 匹配会劈开占位符）
        if matched:
            unique_orig = list(dict.fromkeys(matched))
            repl_map = {orig: fwd[orig] for orig in unique_orig}
            def _rule_sub(m):
                orig = m.group(group_idx)
                if orig in repl_map:
                    if group_idx == 0:
                        return repl_map[orig]
                    # group_idx > 0：只替换捕获组部分，保留匹配的其他文本
                    # （如 Bearer 规则匹配「Bearer sk-xxx」，只替换「sk-xxx」）
                    gs, ge = m.span(group_idx)
                    return m.group(0)[:gs - m.start()] + repl_map[orig] + m.group(0)[ge - m.start():]
                return m.group(0)
            curr_len = len(text)
            text, edits = _mask_excluding_placeholders_ed(text, rx, _rule_sub, group_idx=group_idx)
            _update_om(edits, curr_len)

    # ── AI 实体识别（NER）：人名 (NAME) / 机构 (ORG) / 详细地址 (ADDR) ──
    # 排在全部确定性规则之后：同一原文以规则/自定义词为准，语义模型只补规则覆盖不到
    # 的自由文本。模型在干净的 original 上抽取上下文，抽出的区间经 om.map_range
    # 翻译至伤疤文本坐标系，再由 _ner_entity_spans 按占位符切分（测试验证见
    # tests/test_shield.py 中的 OffsetMapTests 与 tests/test_regressions.py）。
    # om_broken 或 om 为 None 时跳过 NER，严禁将 original 坐标作为回退直接用于伤疤文本。
    #
    # `_ner_clean`：本次 NER 是否**完整跑完**（没被预算/超时/失败降级）。只有完整跑完的
    # 结果才允许进叶子缓存 —— 残缺结果一旦入库就等于把漏检永久固化（与 NER 负缓存
    # 同一类坑）。判据是 `skip_epoch()` 前后是否变化：它只统计「结果残缺」类原因
    # （见 ner_engine._CACHE_POISON_SKIPS），`model_unavailable` 不在其中。
    _ner_clean = True
    _ner_epoch0 = None
    if NER_ENABLED:
        if om_broken or om is None:
            _ner_clean = False
        else:
            _ner_epoch0 = _ner_skip_epoch()
    if NER_ENABLED and not om_broken and om is not None:
        try:
            import ner_engine
            if not ner_engine.is_ner_available():
                _ner_warn_once("model_missing",
                               "NER 已开启但模型文件不可用（%s），本次未做实体识别"
                               % ner_engine.status().get("model_dir"))
            else:
                entities = ner_engine.extract_entities(original)
                translated_entities = []
                for ent in entities:
                    if not isinstance(ent, dict):
                        continue
                    try:
                        s_orig = int(ent["start"])
                        e_orig = int(ent["end"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    lbl = str(ent.get("type") or "TERM")
                    if e_orig - s_orig < 2 or s_orig < 0 or e_orig > len(original):
                        continue
                    mapped_range = om.map_range(s_orig, e_orig)
                    if mapped_range is None:
                        continue
                    s2, e2 = mapped_range
                    if e2 - s2 < 2:
                        continue
                    translated_entities.append({"start": s2, "end": e2, "type": lbl})

                planned = []
                for s0, e0, lbl in _ner_entity_spans(text, translated_entities):
                    raw_frag = text[s0:e0]
                    frag = raw_frag.strip()
                    if len(frag) < 2:
                        continue
                    # 实体区间两端可能带空白，收窄到 strip 后的边界，
                    # 免得把空格/换行一起换成占位符（还原后会丢排版）。
                    lead = len(raw_frag) - len(raw_frag.lstrip())
                    # 记账口径说明（易错，必须保留）：_hit() 必须传伤疤坐标系的残片 frag，
                    # 绝不能传原文实体。因为 restore() 会把占位符换回 fwd[TOKEN]，
                    # 出网文本在该位置只剩残片，注册成完整原文会导致还原时把占位符覆盖的部分重复吐出。
                    _hit(frag, lbl)
                    token = fwd.get(frag)
                    if token:
                        planned.append((s0 + lead, s0 + lead + len(frag), token))
                if planned:
                    # 起点相同时贪心优先覆盖更长的区间，防止短区间覆盖导致长区间残片明文泄漏
                    planned.sort(key=lambda x: (x[0], -x[1]))
                    text = _mask_by_spans(text, planned)
        except Exception as e:
            _ner_warn_once("runtime", "NER 识别降级，本次未做实体识别: %s: %s" % (type(e).__name__, e))
        _ner_clean = _ner_skip_epoch() == _ner_epoch0

    # last_hits / new_orig 累积而非覆盖：mask() 被 _mask_tree 对每个字符串叶子
    # 各调一次，覆盖会让 count 只反映最后一个叶子的命中（曾导致 MASK 行
    # 「脱敏列 0、明细 2 项」自相矛盾）。
    # new_orig 累积全部新增；上报时与 last_hits 交集算「本次命中且新增」。
    s.setdefault("last_hits", set()).update(hit_orig)
    s.setdefault("new_orig", set()).update(new_orig)
    # 抽样自检的比对必须排在 `_ner_clean` 判断**之前**：否则 NER 一降级这一轮就不比对，
    # 缓存里的错误内容要等到下一次「完整跑完」才被发现。
    if _LEAF_CACHE_OK[0]:
        _leaf_cache_verify(_lc_expect, text)
        # 只有「完整跑完」的结果才入库：NER 降级时这条叶子是残缺的，存进去等于把漏检
        # 永久固化。代价是 NER 开启时命中率取决于预算是否充足，方向是保守的。
        if _ner_clean:
            _leaf_cache_store(original, text, [(t, l, d) for t, (l, d) in hit_tokens.items()])
    return text


# _PLACEHOLDER_RX / _PARTIAL_RX 已在 mask() 前定义（防占位符污染辅助函数依赖）

def _touch_recent(token, orig, now=None):
    """命中即续期（滑动过期）。

    原来只有 mask 侧（_recall_token）会刷新时间戳，restore 侧只读不刷。
    后果：一个原文在对话开头出现一次之后就再没被 mask 过，但模型每轮都在复述
    它的占位符——这条映射明明一直在用，时间戳却停在第一次，24h 一到照样被清，
    之后整段历史的这个占位符全部还原不了。缓存该有的是「活跃就续命」，
    绝对时间只是兜底上界。

    两个方向都要刷：_prune_recent 是按 _RECENT_FWD 的时间戳扫的，
    只刷 REV 的话照样会被连带删掉。
    """
    now = now or time.time()
    tables = _tables()
    with _STATE_LOCK:
        rev = tables.rev.get(token)
        if rev is not None:
            rev[2] = now
        fwd = tables.fwd.get(orig)
        if fwd is not None and fwd[0] == token:
            fwd[2] = now


def _lookup(token, sid):
    """占位符 → 原文。先查本会话，再查跨请求复用表，最后做套娃解包。

    **不做模糊匹配、不猜、不推算。** 0.1.12 曾加过一段「幻觉 IP 智能自愈」：
    模型把 {{IPPRIVATE_83fc6a}} 自行改写成 {{IPPRIVATE_83fc00}} 时，
    拿前 3~4 位 hex 去匹配已知 IP，再把末两位 hex 当十进制主机位算出一个地址。
    该逻辑 0.1.13 已整体删除，原因是它的前提不成立：

    - hex6 来自 `_new_token` 的 `secrets.token_hex(3)`（该函数 docstring 原话：
      "never derive IDs from secrets"）。`83fc` 不是子网前缀、`6a` 不是主机位，
      它们与 192.168.119.5 之间没有任何数学关系。对随机数做算术得到的 IP，
      **是用户从未输入过的数据**。
    - 实测：6 个从未登记的幻觉占位符里 5 个被编出地址；前缀只比 3 位 hex
      （4096 桶），已知 200 个 IP 时随机幻觉 token 的编造率 4.53%，
      且多网段共存时落到哪个网段取决于 dict 遍历顺序。
    - 编造走的是 `s["restored"] += 1` 这条正常路径，日志里分辨不出真假。

    模型自造的占位符从来没被登记过，表里没有它、也没有能推出它的东西——
    还原它在信息论上就不可能。正确行为是**原样保留 + 计入 unresolved**，
    让用户看得见「模型这里编了个东西」。要根治的是模型为什么想改写
    （它需要表达「该网段的 .0」却只有不透明 token），那属于脱敏格式的设计，
    不是还原侧能补的。
    """
    s = _session_get(sid)
    hit = None
    if s:
        hit = s["rev"].get(token)
        if hit is not None:
            _touch_recent(token, hit)

    if hit is None:
        recent = _tables().rev.get(token)
        if recent:
            if _is_custom_word_orig(recent[0]) or _is_custom_word_token(token) or time.time() - recent[2] <= _recent_ttl():
                _touch_recent(token, recent[0])
                hit = recent[0]

    # 兜底：如果 _RECENT_REV 没命中（例如外部重置了复用表），直接查永久映射表
    if hit is None:
        c_rec = _tables().cw_rev.get(token)
        if c_rec:
            hit = c_rec[0]
            _touch_recent(token, hit)

    # 防占位符套娃解包（如 A 被误脱敏为 B，递归解包直到真实明文）
    depth = 0
    while hit is not None and isinstance(hit, str) and _PLACEHOLDER_RX.match(hit) and depth < 5:
        depth += 1
        inner = None
        if s:
            inner = s["rev"].get(hit)
        if inner is None:
            rec = _tables().rev.get(hit)
            # 内层同样校验 TTL：套娃解包走的是「外层校验过、内层没校验」的缝隙，
            # 会用一条早已过期的映射完成还原，突破 24h 原文保留窗口契约
            if rec:
                if _is_custom_word_orig(rec[0]) or _is_custom_word_token(hit) or time.time() - rec[2] <= _recent_ttl():
                    inner = rec[0]
            if inner is None:
                c_rec = _tables().cw_rev.get(hit)
                if c_rec:
                    inner = c_rec[0]
        if inner is not None and inner != hit:
            hit = inner
        else:
            break

    # 如果最终还是占位符自身，说明没有真实明文
    if hit is not None and isinstance(hit, str) and _PLACEHOLDER_RX.match(hit):
        return None

    return hit


def restore(text, sid, channel="", escape=False, final=False):
    """把占位符还原成原文。

    channel: 流式通道标识。半截占位符只在本通道缓冲，正文 delta 与 tool 参数 delta
             互不串扰（共用一个缓冲会把上一个字段的尾巴吐进下一个字段）。
    escape:  目标位置是 JSON 字符串内部（tool_calls.arguments / partial_json），
             原文里的引号、换行必须按 JSON 转义，否则客户端解析工具参数直接报错。
    final:   True = 不再等后续 chunk，缓冲区一次性吐出。
    """
    s = _session_get(sid)
    if not isinstance(text, str):
        return text
    if not s:
        # 会话不存在 → **原样返回，绝不还原**。这是安全门：替换流程会查全局复用表
        # `_RECENT_REV`，放行等于让任意自造 sid 都能借复用表还原占位符
        # （test_t7 守这条）。但必须如实计数，否则「页面上满屏未还原」在统计里是 0。
        _count_orphans_without_session(sid, text)
        return text
    pend = s["pending"]
    if not isinstance(pend, dict):  # 兼容旧结构
        pend = s["pending"] = {}
    buf = pend.get(channel, "") + text
    if final:
        pend.pop(channel, None)
        confirmed = buf
    else:
        m = _PARTIAL_RX.search(buf)
        if m and m.end() == len(buf) and len(m.group()) <= _PARTIAL_MAX:
            confirmed = buf[: m.start()]
            pend[channel] = m.group()
        else:
            confirmed = buf
            pend.pop(channel, None)
    if not confirmed:
        return ""

    def _sub(m):
        whole = m.group(0)
        lab_raw = m.group(1)
        suffix = m.group(2)
        canon = "{{%s_%s}}" % (lab_raw.upper(), suffix.lower())
        orig = _lookup(canon, sid)
        via_suffix = False
        real_token = canon if orig is not None else None
        if orig is None:
            # 标签被模型改写（补回下划线 / 全小写 / 变异）时按后缀反查。
            # 这里是双花括号形态，由 _BRACED_PLACEHOLDER_RX 保证带花括号，可以安全走后缀索引。
            real = _suffix_real_token(canon)
            if real is not None:
                orig = _lookup(real, sid)
                if orig is not None:
                    real_token = real
                    via_suffix = True
            if orig is None:
                orig = _lookup_by_suffix(canon, sid)
                if orig is not None:
                    via_suffix = True
                    real_token = canon
        if orig is None:
            # 占位符查不到原文（复用表被淘汰/会话被扫掉/引擎重启后没预热回来的
            # 凭据类/客户端历史带入的孤儿）：原样返回（不能猜），但**必须如实计数**。
            #
            # 计数面不能只认严格形态 `_PLACEHOLDER_RX`——它要求 `{{` 后**紧跟**
            # `[A-Z0-9]{1,12}_`，于是这两类真实出现的形态全被漏掉：
            #   `{{ EMAIL_abcdfg }}`（模型按 Jinja 习惯加空格）
            #   `{{email_abcdfg}}`（标签被小写化）
            # 它们能进本函数（外层就是 `_BRACED_PLACEHOLDER_RX`，允许内部空白与
            # 大小写），却匹配不上严格正则 → 页面上明明一堆没还原、事件页只报 1 个。
            # 用户真机实测报过这个漏报（Claude 侧「未还原 1」而屏幕上有多个）。
            #
            # 能走到这里说明外层**已判定为双花括号占位符形态**，计数不会误伤：
            # 后缀是 6 位 hex 或 6 位纯辅音，普通文本不会自然出现 `{{ word_abcdfg }}`。
            with _STATE_LOCK:      # B-1a ②
                s["unresolved"] = s.get("unresolved", 0) + 1
                _record_unresolved_sample(s, whole)
            return whole
        with _STATE_LOCK:          # B-1a ②：计数 + 集合去重追加必须一起进锁
            s["restored"] = s.get("restored", 0) + 1
            s["restored_tokens"].add(real_token or canon)
            s.setdefault("restored_origs", set()).add(orig)
            if via_suffix or whole != canon:
                # 靠空格容错或改写容错救回来的，计入 degraded
                s["degraded"] = s.get("degraded", 0) + 1
        return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig

    out = _BRACED_PLACEHOLDER_RX.sub(_sub, confirmed)

    # 第二遍：转义形态 `\{\{X\}\}` / `\\{\\{X\\}\\}`，含内部可选空白。
    #
    # 必须跑在宽松遍之前：宽松正则不带花括号匹配，在转义形态上只吃得到中间
    # 一段，替换完会留下 `\{\` 与 `\}\}` 残渣 —— IP 出来了但命令仍然是坏的，
    # 用户会误判成「还原成功」。这一遍把整个转义块（连同反斜杠与内部空白）一起替换掉。
    # 同样只认查得到原文的 token，查不到原样放回，绝不猜。
    if "_" in out:
        def _esc_sub(m):
            whole = m.group(0)
            canon = "{{%s_%s}}" % (m.group(1).upper(), m.group(2).lower())
            orig = _lookup(canon, sid)
            real = canon if orig is not None else None
            if orig is None:
                real = _suffix_real_token(canon)
                if real is not None:
                    orig = _lookup(real, sid)
            if orig is None:
                # ⚠️ 只对**真·转义形态**计数。`_ESCAPED_PLACEHOLDER_RX` 的反斜杠量词是
                # `\\{0,3}`（允许 0 个反斜杠），所以它**同样匹配** `{{EMAIL_x}}`、
                # `{EMAIL_x}` 这些非转义形态——那些形态第一遍/第三遍已经计过，
                # 这里再计一次会让计数整体**翻倍**（实测：3 个孤儿报成 6 个）。
                # 判据用「整段里有没有反斜杠」最直白，也与该遍的语义严格一致。
                if "\\" in whole:
                    with _STATE_LOCK:      # B-1a ②
                        s["unresolved"] = s.get("unresolved", 0) + 1
                        _record_unresolved_sample(s, whole)
                return whole
            with _STATE_LOCK:              # B-1a ②
                s["restored"] = s.get("restored", 0) + 1
                s["degraded"] = s.get("degraded", 0) + 1
                s.setdefault("restored_origs", set()).add(orig)
                # 记账用真实 token：RESTORE 明细按签发时的 token 比对 restored 标记，
                # 存模型改写后的形态会查不到，该项被误标成「未还原」（假阴性）。
                s["restored_tokens"].add(real)
            return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig
        out = _ESCAPED_PLACEHOLDER_RX.sub(_esc_sub, out)

    # 第三遍：捞回被模型剥了花括号 / 只剩单花括号的占位符。
    # 只在前面两遍之后跑，且只认「查得到原文」的 token——查不到就原样放回，绝不猜。
    # **这一遍不走后缀索引**：裸 token 可能只是被 chunk 切开的残片，按后缀命中
    # 就会把残片替换成明文（见 _RECENT_SUFFIX 注释）。
    # degraded 计数进 RESTORE 事件（`degraded=` 参数，见 _restore_emit），
    # 让用户看得见「这次是靠兜底修回来的」。这句注释曾在此、而 _emit 里根本没这个
    # 参数——计数只加在会话 dict 里，从没发出去过，于是这条信息永远查不到。
    # 实测生产库 8805 条 RESTORE 里该字段一条都不存在，正是因此。0.1.14 补上。
    if "_" in out:
        def _loose_sub(m):
            whole = m.group(0)
            if whole.startswith("{{") and whole.endswith("}}"):
                return whole  # 双花括号形态第一遍已处理
            tok_body = (m.group(1) or m.group(2) or "").strip()
            canon = "{{" + tok_body + "}}"
            orig = _lookup(canon, sid)
            real = canon if orig is not None else None
            if orig is None and whole.startswith("{"):
                real = _suffix_real_token(canon)
                if real is not None:
                    orig = _lookup(real, sid)
            if orig is None:
                # 这一遍的形态判据（`_LOOSE_PLACEHOLDER_RX`）本身就要求
                # `LABEL_` + 6 位 hex 或 6 位纯辅音后缀——注释里已论证过
                # 「这种组合正常文本里不会自然出现」，与替换判据同源，
                # 所以查不到时同样计数，不会因为「怕是残片」就把漏还原藏起来。
                #
                # ⚠️ 唯一例外：前一字符是反斜杠 → 这是 `\{\{X\}\}` 的**内部片段**
                # （本遍的 `\{{1,2}` 会从转义块的第 2 个 `{` 开始匹配），上一遍已
                # 处理并计数过；不排除就会把转义形态计两次（实测报成 2，样本里
                # 同时留下 `\{\{X\}\}` 与 `{X}` 两条）。
                # **只能在计数上排除，不能提前 return**：提前 return 会连
                # 「该片段其实查得到原文、本该被还原」的情况一起跳过——
                # 实测这一版直接把 test_t7 打红（响应里该有的还原没了）。
                if not (m.start() > 0 and m.string[m.start() - 1] == "\\"):
                    with _STATE_LOCK:      # B-1a ②
                        s["unresolved"] = s.get("unresolved", 0) + 1
                        _record_unresolved_sample(s, whole)
                return whole
            with _STATE_LOCK:              # B-1a ②
                s["restored"] = s.get("restored", 0) + 1
                s["degraded"] = s.get("degraded", 0) + 1
                s.setdefault("restored_origs", set()).add(orig)
                if real is not None:
                    s["restored_tokens"].add(real)
            return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig
        out = _LOOSE_PLACEHOLDER_RX.sub(_loose_sub, out)
    return out


# ===== 命令拦截：探测 / 改写 / 阻断（W2-1 ~ W2-4） =====
#
# 挂在**槽位层**而不是审计层：审计层（_audit_response）在流结束后才跑，那时
# 内容已经发给客户端了，除了 503 什么都做不了；而槽位层是逐 chunk 的，
# 能在下发前就地替换。四个挂点：`_restore_sse_data`、`_restore_ndjson_line`
# 的槽位循环，以及非流式的 `_restore_tree`（通道由 JSON 键名判定）与
# 收尾的 `_flush_pending`（前瞻缓冲不吞字）。
#
# ⚠️ 未覆盖的链路（如实声明，免得后来者以为全覆盖）：
#   · `_restore_ext_sse_event` 的豆包私有信封分支（直接调 restore，不走槽位）；
#   · panel 侧 `/api/ext/restore` 的扩展非流式还原（另一份实现，不 import 本模块）。
#   两条都是扩展链路，且豆包站点本身已因附件链路差异从推荐列表移除（W3-3 专项）。
#
# 思考通道**恒排除**：模型在思考里权衡「要不要 rm -rf /」不是下发命令；
# 正文通道可选 opt-in（AI 讲命令是家常便饭），默认只拦工具参数通道。
_CMD_REASON_MARKERS = (".reason", ".reason2", ".think", "thinking", "reasoning")
_CMD_TOOL_MARKERS = (".tool", ".fcall", ".pj", ".args", "arguments", "partial_json")
# 嵌套量词/长度的唯一校验源在 shield_defaults（panel 保存时也调它）
_CMD_LOGGED = set()


def _cmd_log_once(msg):
    """同一条告警只记一次（热重载/每个 chunk 重复记会把日志刷爆）。"""
    if msg in _CMD_LOGGED:
        return
    _CMD_LOGGED.add(msg)
    try:
        _log(msg)
    except Exception:
        pass


def _cmd_channel_kind(channel):
    """槽位通道名 / JSON 键名 → 命令拦截通道：`tool` / `text` / `reason`。

    未命中任何标记的通道**归到 `text`**（注释里写死口径，免得后人猜）：本函数的输入只有
    两类——槽位名（`c0.content` / `c0.tool0` / `a0.pj` / `o.message.content` …）与 JSON 键名
    （`content` / `arguments` / `thinking` …），落到这里的就是模型正文。
    `raw` / `ext:` 这类非槽位通道**到不了这里**（命令拦截的 4 个调用点全部按槽位/键名传入：
    `_restore_sse_data` / `_restore_ndjson_line` / `_restore_tree` / `_flush_pending`）；
    豆包私有信封内层 `text` 即使经 `_flush_pending` 走到这里，它本身就是模型正文，
    判为 `text` 也是对的。所以默认值**既不改成 `tool`、也不排除**。
    """
    ch = str(channel or "").lower()
    if any(m in ch for m in _CMD_REASON_MARKERS):
        return "reason"
    if any(m in ch for m in _CMD_TOOL_MARKERS):
        return "tool"
    return "text"


def _parse_command_block(raw):
    """把 config.command_block 解析成运行时结构（编译正则 + 边界校验）。

    panel 保存时已校验一次；这里是**第二道**（config.json 可被人手改，绕过 UI）。
    非法条目丢弃并记日志，不影响其余规则——一条坏正则不能让整个功能瘫。
    """
    out = {"mode": "observe", "channels": {"tool"}, "patterns": [], "allow": [],
           "disabled": set()}
    if not isinstance(raw, dict):
        raw = DEFAULT_COMMAND_BLOCK
    mode = str(raw.get("mode") or "observe").strip().lower()
    out["mode"] = mode if mode in ("observe", "rewrite", "block") else "observe"
    chans = raw.get("channels")
    chans = [c for c in chans if c in ("tool", "text")] if isinstance(chans, list) else []
    out["channels"] = set(chans) or {"tool"}
    items = raw.get("patterns")
    if not isinstance(items, list):
        items = DEFAULT_COMMAND_BLOCK["patterns"]
    for item in items:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        src = str(item.get("regex") or "")
        pid = str(item.get("id") or "")
        label = str(item.get("label") or "")
        ok, why = validate_command_regex(src)
        if not ok:
            _cmd_log_once(f"[cmd-block] 规则 {pid or src[:20]} {why}，已忽略")
            continue
        out["patterns"].append((pid, label, re.compile(src)))
    allow_src = raw.get("allow_patterns")
    for src in (allow_src if isinstance(allow_src, list) else []):
        src = str(src or "")
        ok, why = validate_command_regex(src)
        if not ok:
            if src:
                _cmd_log_once(f"[cmd-block] 白名单「{src[:20]}」{why}，已忽略")
            continue
        out["allow"].append(re.compile(src))
    return out


def _cmd_hold_len():
    """有界前瞻缓冲的尾巴长度（只在 rewrite/block 模式用）。

    上界取「最长启用模式源长度 − 1」，再截到 CMD_HOLD_MAX：命令被 TCP 切开的
    跨度过不了这个量级，而无限拖尾会把流式体验拖坏。
    """
    pats = COMMAND_BLOCK.get("patterns") or []
    if not pats:
        return 0
    longest = max((len(rx.pattern) for _pid, _lb, rx in pats), default=0)
    return max(0, min(longest - 1, CMD_HOLD_MAX))


def _cmd_find(text):
    """在 text 里找第一条命中的启用规则；命中白名单视为未命中。

    返回 (命中文本, 规则 id, 规则 label) 或 None。**只读**，不改 text。
    单次匹配耗时超预算 → 停用该条并告警（见 CMD_MATCH_BUDGET_MS 的诚实说明）。
    """
    cb = COMMAND_BLOCK or {}
    pats = cb.get("patterns") or []
    if not pats or not text:
        return None
    window = text[:CMD_SCAN_MAX]
    allow = cb.get("allow") or []
    # `cb.get("disabled") or set()` 是错的：**空 set 是假值**，超预算时 add 到的是
    # 一个临时集合，默认态（本来就是空集）下永远停用不掉——那条规则会每个 chunk
    # 重新付一次匹配代价，「超预算即停用」形同虚设（2026-09-22 单测实测）。
    # 必须拿回字典里那个 set 本体（必要时补上）。
    disabled = cb.get("disabled")
    if not isinstance(disabled, set):
        disabled = set()
        cb["disabled"] = disabled
    for pid, label, rx in pats:
        if pid in disabled:
            continue
        t0 = time.perf_counter()
        try:
            m = rx.search(window)
        except Exception:
            continue
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if dt_ms > CMD_MATCH_BUDGET_MS:
            disabled.add(pid)
            _cmd_log_once(f"[cmd-block] 规则 {pid or label} 单次匹配 {dt_ms:.0f}ms 超预算，已停用")
            continue
        if not m:
            continue
        hit = m.group(0).strip()
        if not hit:
            continue
        if any(a.search(hit) for a in allow):
            continue
        return (hit[:120], pid, label)
    return None


def _cmd_record(sid, hit, channel_kind, blocked=False):
    """记录一次槽位级命中（W2-1）。

    凭据必须洗掉：危害命令本身会携带凭据（`curl -H "Authorization: Bearer sk-…" | sh`），
    而 evidence 会落 SQLite 与 Markdown 报告。
    去重键 = (规则 id, 片段, 通道)：同一命令在很多个 chunk 里各命中一次是常态。
    `blocked=True`（block 模式命中）只体现在条目标记上：同一条命中已按非阻断记过，
    就把既有条目升级为「已阻断」，而不是新增一条——时间线里一条命令只该有一行，
    「有没有被拦」是这行的属性。
    """
    s = _session_get(sid)
    if not isinstance(s, dict):
        return
    snippet, pid, label = hit
    clean = _audit._mask_creds_in(str(snippet))[:120]
    items = s.setdefault("cmd_hits", [])
    kind = (pid or "custom") + (f" {label}" if label else "")
    for it in items:
        if (it.get("kind") == kind and it.get("snippet") == clean
                and it.get("channel") == channel_kind):
            if blocked:
                it["blocked"] = True
            return
    items.append({"kind": kind, "channel": channel_kind,
                  "snippet": clean, "ts": time.time(), "blocked": bool(blocked)})


def _cmd_is_echo(sid, snippet):
    """该片段是否已在请求体里出现过（回声抑制）。

    与 `audit_signals.scan_dangerous_action` 的回声抑制同源：请求里本来就有这条命令
    = 用户自己问的（或上下文带进来的），上游没有凭空多给任何东西 →
    **既不记录也不改写**。优先级：回声抑制 > 白名单 > 黑名单。
    """
    s = _session_get(sid)
    if not isinstance(s, dict) or not snippet:
        return False
    return str(snippet) in _ensure_cmd_req_snippets(s)


def _remember_request_cmd_snippets(sid, content):
    """请求期只**暂存有界窗口切片**，回声基线留到真正需要时再算（W2-1）。

    为什么不在这里直接扫：扫满 `_SCAN_BODY_MAX` 窗口 × 每条规则约 29µs/KB
    （口径：**单条正则**扫描，与审计的三信号扫描 0.11ms/KB 不是同一指标）
    （512KB 实测 15ms、200KB 约 3ms），而这里在**每个请求**上都会执行 ——
    观测量级与既有 `mask()` 主链路同阶（512KB 时约占其 4 成），等于给默认档位
    白加一笔延迟，而绝大多数请求根本不会命中任何命令。
    改法：请求期只留切片（不解析、不驻留整份请求体——上限 32MB 不能进会话），
    首次真要判定回声时由 `_ensure_cmd_req_snippets` 扫一次即丢。
    """
    try:
        s = _session_get(sid)
        if not isinstance(s, dict) or not content:
            return
        pats = (COMMAND_BLOCK or {}).get("patterns") or []
        if not pats:
            return
        s["cmd_req_window"] = content[:_SCAN_BODY_MAX]
    except Exception:
        # 回声基线建不起来不能影响请求（最坏是少一层抑制，多记一条而已）
        pass


def _ensure_cmd_req_snippets(s):
    """惰性构建回声基线（只算一次，算完丢窗口）。

    语义与「请求期先扫好」完全等价：窗口是同一段字节、规则是同一批规则，
    差别只在**算的时机**（从每请求挪到首次真命中）。返回集合恒非 None，
    以便用 `cmd_req_snippets` 是否存在区分「没算过」与「算过但为空」。
    """
    cached = s.get("cmd_req_snippets")
    if cached is not None:
        return cached
    found = set()
    win = s.pop("cmd_req_window", None)
    if win:
        try:
            text = win.decode("utf-8", errors="replace")
            for _pid, _label, rx in ((COMMAND_BLOCK or {}).get("patterns") or []):
                try:
                    for m in rx.finditer(text):
                        g = m.group(0).strip()
                        if g:
                            found.add(g[:120])
                except Exception:
                    continue
        except Exception:
            found = set()
    s["cmd_req_snippets"] = found
    return found


def _cmd_process(text, channel, sid, escape=False, final=False):
    """命令拦截统一入口：探测 + 按 mode 改写/阻断。返回（可能）改写后的文本。

    调用点（设计 §2.5 的 3 处槽位循环 + 非流式 `restore_final`）均已把**还原后**
    的文本交给它——占位符状态下路径是假的，判不准也没意义。

    mode 语义：
      · observe：只探测、只记录，**逐字节原样返回**（也不做前瞻缓冲——缓冲会把
        尾字符延后到下一块，一旦流被切断就可能丢字，而「响应字节零变化」是
        这个默认档位的硬承诺）；
      · rewrite：就地替换为 `CMD_BLOCK_NOTICE`（无害 no-op），保持流式不中断；
      · block：命中即停（本会话剩余内容不再下发），非流式整包换 503。

    ⚠️ 边界（诚实声明）：observe 不做缓冲 → 跨 chunk 切开的命令可能漏检（只少不多）；
    rewrite/block 的有界前瞻把最后 hold 个字符暂留到下一块，流末由 `final=True`
    或 `_cmd_flush_frames` 补发，**不吞字**。
    `escape` 参数保留只是因为调用点按槽位属性传入：改写文本是不可配置的固定常量
    （`CMD_BLOCK_NOTICE`），JSON 转义只处理双引号与反斜杠这两个字符，而它两者都不含
    （内含的单引号在 JSON 里无需转义），故不参与计算。若将来改成可配置文本，此处必须重新评估。
    """
    cb = COMMAND_BLOCK or {}
    mode = cb.get("mode") or "observe"
    if not isinstance(text, str):
        return text
    # 空文本**不能**直接早返回：final=True 时它正是「把缓冲一次性吐出来」的信号
    # （收尾帧的文本常常是空的，缓冲里却还压着上一块的尾巴）。
    if not text and not final:
        return text
    s = _session_get(sid)
    if not isinstance(s, dict):
        return text
    kind = _cmd_channel_kind(channel)
    patterns = cb.get("patterns") or []
    # 思考通道：既不记录（设计决定：思考里的权衡不是下发命令）也不改写，
    # 但要留下「这里出现过」的片段——供 _audit_response 把全量 S9 扫描里
    # 同片段的误报压掉（§6.4 记录的既有污染：S9 扫的是混了思考块的全量文本）。
    if kind == "reason":
        if patterns:
            h = _cmd_find(text)
            if h:
                s.setdefault("cmd_reason_snippets", set()).add(h[0])
        return text
    if kind not in (cb.get("channels") or {"tool"}):
        return text
    if not patterns:
        return text
    if s.get("cmd_blocked"):
        # block 模式已命中：本会话剩余内容不再下发（回复被截断是「阻断」的可见形态）
        return ""
    if mode == "observe":
        hit = _cmd_find(text)
        if hit and not _cmd_is_echo(sid, hit[0]):
            _cmd_record(sid, hit, kind)
        return text
    # rewrite / block：先把上一条尾巴拼回来再判定（命令可能被 chunk 切开，
    # 如 `rm -r` + `f /`——只看本块永远漏拦）
    pend = s.setdefault("cmd_pend", {})
    combined = pend.pop(channel, "") + text
    keep = ""
    hold = _cmd_hold_len()
    if hold > 0 and not final:
        if len(combined) <= hold:
            pend[channel] = combined
            return ""
        keep = combined[-hold:]
        combined = combined[:-hold]
    hit = _cmd_find(combined)
    if hit and _cmd_is_echo(sid, hit[0]):
        # 回声抑制：用户自己问过的命令，既不改写也不记录
        hit = None
    if hit:
        blocked = mode == "block"
        _cmd_record(sid, hit, kind, blocked=blocked)
        if blocked:
            s["cmd_blocked"] = True
            _log_cmd_block(channel, hit)
            return ""
        result = _cmd_rewrite_text(combined)
    else:
        result = combined
    if keep:
        pend[channel] = keep
    return result


def _cmd_rewrite_text(text):
    """把 text 里的命令片段换成无害 no-op 说明（W2-2）。

    逐条规则替换（不是只换第一条）：一次工具调用里可能含多条危害命令。
    用 lambda 而不是把文本当替换模板——`re.sub` 的替换串会解释反向引用（如 `\\1`、`\\g<0>`）
    这类反向引用，而规则本身可含捕获组，用字面量替换不会有这个问题。
    """
    out = text
    # 取字典里的 set 本体。**不要写 `or set()`**：空 set 是假值，那个写法会现场造一个临时集合——
    # 此处只读虽无后果，但同一个写法在 `_cmd_find` 里曾让「超预算即停用」静默失效（那条要 add），
    # 两处保持同一形态，避免后来者照抄走错的那一版。
    disabled = COMMAND_BLOCK.get("disabled")
    if not isinstance(disabled, set):
        disabled = set()
    for pid, _label, rx in (COMMAND_BLOCK.get("patterns") or []):
        if pid in disabled:
            continue
        try:
            out = rx.sub(lambda _m: CMD_BLOCK_NOTICE, out)
        except Exception:
            continue
    return out


def _log_cmd_block(channel, hit):
    """block 模式留痕：**只写日志**，不写 BLOCK 主事件（W2-4）。

    为什么不用 BLOCK 事件：`event_store` 的口径里 BLOCK 同时计入 `requests` 与
    `alerts`（见 event_store.py 的 `_ev("BLOCK")` 两处聚合），而 BLOCK 原本描述的
    是「请求压根没出去」的 fail-closed 场景（未脱敏不出网、体积闸）。响应侧命令阻断
    发生在请求**已脱敏发出之后**，再补一条 BLOCK 会把同一个请求计两次，首页「请求数」
    与「告警数」同时虚高。留痕统一走槽位级审计信号（`dangerous_action`，evidence 带
    `[已阻断]` 标记），与 observe/rewrite 同口径；时间线视图本就按 floor=LOW 单独取数，
    阻断照样看得见。

    与既有的 `audit_critical_signal` 阻断（审计 fail-closed）**故意不同**：那条是
    CRITICAL 级（上游确凿窃取数据）才触发，稀发且必须上首页告警，因此它发 BLOCK；
    命令阻断是用户自己开的日常机制，命中即上报会把首页告警刷成噪音。
    两条路径的差异是故意的，不是漏改。
    """
    _pid, label, _snippet = (list(hit) + ["", "", ""])[:3]
    _cmd_log_once(
        f"[cmd-block] block 模式命中 {_pid or label}（通道={_cmd_channel_kind(channel)}），"
        "已停止下发该会话剩余内容")


def restore_final(text, sid, escape=False):
    return restore(text, sid, escape=escape, final=True)


# 这些字段的字符串本身是 JSON 文本（tool 参数），还原时原文需转义
_JSON_STR_KEYS = {"arguments", "partial_json"}


_RESTORE_MAX_DEPTH = 24


def _count_unresolved(sid, n=1):
    """会话级 unresolved 计数（与 restore() 维护同一字段，只用于诊断展示）。"""
    s = _session_get(sid)
    if isinstance(s, dict):
        try:
            s["unresolved"] = int(s.get("unresolved") or 0) + n
        except Exception:
            pass


# 未还原占位符的样本留存上限。只留形态（token 本身是占位符，不含任何明文），
# 落库安全；上限压到 5 是为了不让长响应把 payload 撑大。
_UNRESOLVED_SAMPLES_MAX = 5


def _record_unresolved_sample(s, tok):
    """留存几个「查不到原文」的占位符样本，供事件详情弹窗定位。

    为什么必须留：`unresolved` 原先只有一个计数，用户看到「未还原 7」却无从知道
    是哪些 token、什么形态。而这两种情况的处置完全不同，光看计数分不出来：

    - 形态正常（`{{EMAIL_abcdfg}}`）→ 引擎表里真的没有它：引擎重启后
      **凭据类永远不会被 `_warmup_recent_from_db` 预热**（库里只有 digest+preview，
      红线 4），或是复用表 TTL 过期 / 会话被 sweep 掉；
    - 形态被改写（`{{ email_abcdfg }}`、小写标签、剥掉花括号）→ 模型在动输出格式，
      是「哪天彻底还原不回来」的前兆。

    只做诊断，不参与任何还原决策，异常一律吞掉。
    """
    try:
        lst = s.get("unresolved_samples")
        if not isinstance(lst, list):
            lst = s["unresolved_samples"] = []
        if len(lst) < _UNRESOLVED_SAMPLES_MAX and tok not in lst:
            lst.append(tok)
    except Exception:
        pass


# ── 会话不存在时的孤儿计数兜底表 ──────────────────────────────────────────
# sid -> [count, [样本...], ts]
#
# 为什么需要它：`restore()` / `restore_stream_chunk()` 在**会话不存在**时必须
# 原样返回——这不是偷懒，是安全门。替换流程会去查**全局**复用表 `_RECENT_REV`，
# 一旦放行，任意自造 sid（`ext:000…0`）都能借复用表把占位符还原出来
# （tests/test_ext_bridge.py::test_t7 守的就是这条，改动实测当场变红）。
#
# 但原样返回的副作用是：「页面上满屏 `{{...}}`」在统计里**一个数字都没有**，
# 用户只看到还原不了、查不到原因。真机报过——重启引擎后打开 Claude 历史对话，
# 屏幕上一堆未还原，事件页只有一条 `unresolved=1`，用户直接质疑统计造假。
#
# 于是这里**只计数、不还原**：数出文本里有几个占位符形态，留给
# `/api/ext/restore` 合并进 RESTORE 事件。样本只存占位符本身，不含任何明文。
_NO_SESSION_ORPHANS = {}
_NO_SESSION_ORPHANS_MAX = 256


def _count_orphans_without_session(sid, text):
    """会话不存在时只统计文本里的占位符形态（绝不还原、绝不猜原文）。

    只认 `_BRACED_PLACEHOLDER_RX`（双花括号，容错内部空白与大小写）：
    这是页面上最显眼、也是模型原样吐回时最常见的形态；裸 token / 单花括号
    在本遍不做统计，避免把正文里的普通标识符算进来（那属于宽松遍的判据，
    它需要会话上下文来区分残片）。
    """
    try:
        n = 0
        samples = []
        for m in _BRACED_PLACEHOLDER_RX.finditer(text):
            n += 1
            if len(samples) < _UNRESOLVED_SAMPLES_MAX:
                samples.append(m.group(0))
        if n <= 0:
            return
        if sid not in _NO_SESSION_ORPHANS and len(_NO_SESSION_ORPHANS) >= _NO_SESSION_ORPHANS_MAX:
            # 超上限淘汰最老的一条（与 _EXT_FRAMES_MAX 同思路，防止内存被顶上去）
            oldest = min(_NO_SESSION_ORPHANS.items(), key=lambda kv: kv[1][2])[0]
            _NO_SESSION_ORPHANS.pop(oldest, None)
        rec = _NO_SESSION_ORPHANS.get(sid)
        if rec is None:
            _NO_SESSION_ORPHANS[sid] = [n, samples, time.time()]
        else:
            rec[0] += n
            for x in samples:
                if len(rec[1]) < _UNRESOLVED_SAMPLES_MAX and x not in rec[1]:
                    rec[1].append(x)
            rec[2] = time.time()
    except Exception:
        pass


def _take_orphans_without_session(sid):
    """取走并清零（同一 sid 只应被一条 RESTORE 事件消费）。返回 (count, samples)。"""
    try:
        rec = _NO_SESSION_ORPHANS.pop(sid, None)
        if not rec:
            return 0, []
        return int(rec[0] or 0), [str(x) for x in (rec[1] or [])][:_UNRESOLVED_SAMPLES_MAX]
    except Exception:
        return 0, []



def _restore_tree(obj, sid, key=None, depth=0):
    """递归还原 JSON 里所有字符串叶子。

    响应结构五花八门（choices[].message、Anthropic content[].tool_use.input、
    Responses output[]…），逐个格式硬编码必然漏。占位符只可能出现在我们脱敏过的
    位置，整树扫一遍是安全的，且天然覆盖 tool 调用参数。
    """
    if depth > _RESTORE_MAX_DEPTH:
        # 超深不再静默：请求侧同深度是 fail-closed（_mask_tree 抛 json_depth_exceeded），
        # 响应侧此前直接原样返回——占位符就此永久留在回复里，而会话计数毫无变化，
        # 排障时分不清「这里没还原」和「本来就没有占位符」。
        _count_unresolved(sid, 1)
        return obj
    if isinstance(obj, str):
        restored = restore_final(obj, sid, escape=key in _JSON_STR_KEYS)
        # 命令拦截的**非流式**挂点：通道由 JSON 键名判定（arguments/partial_json → tool），
        # 整包文本都在手里，故 final=True（无需前瞻缓冲）。
        return _cmd_process(restored, key or "", sid,
                            escape=key in _JSON_STR_KEYS, final=True)
    if isinstance(obj, list):
        return [_restore_tree(v, sid, key, depth + 1) for v in obj]
    if isinstance(obj, dict):
        # 签名/密文思考块（含流式增量形态）不还原：与 `_sse_text_slots` 同口径。
        # SSE 上思考增量事件会因"无槽位"改走本兜底，若不挡就会把明文还原回写入；
        # 整包/回退（`_restore_json_body`）与 NDJSON 同样靠这里。
        # 注意：挡的是**块**，不是字段名——同名业务字段仍照常还原。
        if obj.get("type") in _RESTORE_SKIP_BLOCK_TYPES:
            return obj
        return {k: _restore_tree(v, sid, k, depth + 1) for k, v in obj.items()}
    return obj


# ===== 递归脱敏的跳过策略（完整路径判定，v1.5.19 起） =====
# 审计实测：按字段名整体跳过 name/url/id/data/type/role，会让 tool 参数里的
# 业务字段（input_name 的姓名、input_url 里的手机号、input.type 里的号码）原文直出。
# 规则：
# - 业务区（tool_use.input / function.arguments 等参数容器）内一律照常扫描，
#   不应用任何字段名豁免——业务字段的敏感值必须脱敏；
# - 业务区外的跳过按「完整路径 + 协议位置」判定，禁止裸字段名豁免。
# model 全局跳过（模型名不是 PII 且扫描无害）；object/finish_reason 等响应侧枚举同理。
# ⚠️ 这个集合**只对字符串叶子生效**（判定点在 _mask_tree 的 str 分支）。
# 键的值若是对象/数组，写在这里也拦不住——递归会照常进到子树里。
# 2026-09 实测 `cache_control` 就是这种情况：它一直被列在本集合里，但
# `{"type": "ephemeral"}` 里的 "ephemeral" 仍会被自定义词表命中，写成
# `{"type": "{{TERM_xxxxxx}}"}`，Anthropic 侧缓存指令当场失效。
# **dict 值的键请用 _MASK_SKIP_SUBTREE_KEYS。**
_MASK_SKIP_SCALAR_KEYS = {
    "model", "object", "finish_reason", "stop_reason",
    "citations", "detail", "encoding_format", "media_type",
}
# 值恒为「协议元数据对象」的键：整棵子树跳过（判定点在 dict 分支开头）。
# 收录门槛很窄——只收结构固定、绝无业务载荷的键，因为整棵跳过 = 放弃该子树里
# 全部字符串的扫描，是一条实打实的漏检路径：
#   cache_control 形如 {"type": "ephemeral", "ttl": "1h"}，改写它只会让上游
#   判缓存指令非法，保护不了任何东西。
# 故意**不收** response_format 与 format（两者同为 dict 值，同样"死条目"）：
#   - OpenAI 的 response_format.json_schema.schema 可以带 enum 示例值；
#   - Ollama 的 format 可以是一整份 JSON Schema，其 enum 同样可能承载真实业务取值。
# 整棵跳过它们收益为零（里面本就没有 PII 以外的数据），风险却是新增漏检面。
# 见 tests/test_regressions.py::MaskPathAwarenessTests 的反向锁用例。
_MASK_SKIP_SUBTREE_KEYS = {"cache_control"}
# role/type 是判别字段，但只在其协议容器内跳过；出现在业务自定义对象里
# （如 {"type": "手机号"}）必须扫描——审计实测 input.type 原文上行即此类。
_MASK_ROLE_TYPE_PARENTS = {
    "message", "messages", "content", "contents", "parts", "block", "blocks",
    "tools", "tool", "tool_calls", "function", "response_format",
    "candidates", "choices", "output",
}
# id 只在协议容器位置跳过（消息/块级关联 ID，客户端靠它关联流内对象）；
# 业务对象里的 customer.id 等照常扫描（审计验收点）。
_MASK_PROTOCOL_ID_PARENTS = {
    "message", "messages", "content", "contents", "parts", "block", "blocks",
    "tool_calls", "tool_use", "response", "output", "data", "object",
    "candidates", "choices", "function_call",
}
# 只在这类父 key 下才豁免的字段（工具名/媒体容器）。
# 覆盖 OpenAI tools[].function / 旧式 functions[] / function_call（含响应侧）、
# Anthropic tool_use、Gemini functionCall，以及 image_url/inline_data 等媒体容器。
_MASK_PROTOCOL_PARENTS = {
    "function", "functions", "function_call", "functionCall", "tool_use", "tools", "tool",
    "image_url", "inline_data", "thumbnail", "input_image", "source", "file",
}
_MASK_SKIP_KEYS = {"id", "tool_call_id", "tool_use_id", "name", "url", "data", "b64_json"}
# 工具调用关联 ID：上游生成的不透明句柄，客户端靠它把工具结果连回上一轮函数调用。
# 这组**不分业务区一律豁免**（判定点在 _mask_tree 的 in_business 之前），
# 因为脱敏它必然断链且保护不了任何东西。call_id 是 OpenAI Responses API 的形式，
# tool_call_id 是 Chat Completions 的，tool_use_id 是 Anthropic 的。
_MASK_CORRELATION_ID_KEYS = {"tool_call_id", "tool_use_id", "call_id"}
# 业务区容器 key：进入后任何字段都照常扫描
_MASK_BUSINESS_KEYS = {"input", "arguments", "parameters", "partial_json", "documents"}
_MASK_MAX_DEPTH = 24

# ── 协议不可改写状态（签名/密文块，整块只读或只锁密文字段） ──────────────
# 判据是**结构**而不是字段名：上游要校验「签名 = 被签正文」「密文原样回放」，而工具参数里
# 的同名字段是业务数据（AstrLink `continuation_test.go:134` 锁定的反例）。
# 2026-10-02 实测（§A1 E2c）：默认规则下这些 base64 载体侥幸不改写，但用户加一个 2 字符
# 自定义词就能把它们打烂 —— 所以判定必须由契约表统一给出，不在这里写第二份。
# 载体表、两种作用域（block/slot）与来源引用见 `protocol_contracts.py`。
# 响应侧不还原的块类型由同一张表导出（请求/响应共用一套判据，§A2）；
# `thinking_delta` 只以 SSE 增量事件出现，只归响应侧（已在表里并入）。
_RESTORE_SKIP_BLOCK_TYPES = _contracts.restore_skip_types()

# 数值型协议字段：这些键的**数值**是协议参数（采样参数、用量计数、序号），
# 不是业务数据。{"seed": 1234567890123456} 这种随机大整数完全可能被 Luhn 校验
# 误判成卡号 —— 一旦改写，请求当场被上游拒绝。所以数值分支对它们一律豁免。
# ⚠️ 只对**数值**豁免，字符串形态照常扫描（`{"seed": "手机号"}` 仍会命中）。
_MASK_SKIP_NUMERIC_KEYS = {
    "max_tokens", "max_completion_tokens", "max_tokens_to_sample", "budget_tokens",
    "temperature", "top_p", "top_k", "n", "seed", "index", "created", "logprobs",
    "top_logprobs", "presence_penalty", "frequency_penalty", "best_of", "timeout",
    "prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens",
    "cache_creation_input_tokens", "cache_read_input_tokens", "reasoning_tokens",
    "status_code", "http_status", "retry", "attempt", "weight", "priority",
}

# 对象**键名**的白名单：集合内的键永不脱敏，集合外一律当「数据键」扫描。
#
# 为什么需要这个集合：旧实现「键名一律不脱敏」让 `{"手机号": "safe"}` 这种
# PII-as-key 形态整条明文上行（审计 B2 实测）。但直接放开又会踩另一个坑 ——
# 用户自定义短词（比如加个 "con"）会命中 `content`，把协议骨架打坏，
# 代价是**每个请求都坏**，比漏一个罕见载荷形状严重得多。
#
# 所以判据从「要不要扫」翻转成「哪些键是结构键」：这里穷举协议/角色/JSON Schema
# 词汇，命中即豁免；剩下的键才是数据键。新增协议字段时**必须同步加到这里**，
# 否则该字段名会被当数据脱敏（症状：上游报参数非法）。
_MASK_PROTECTED_KEY_NAMES = frozenset(
    set(_MASK_SKIP_SCALAR_KEYS)
    | set(_MASK_SKIP_SUBTREE_KEYS)
    | set(_MASK_SKIP_KEYS)
    | set(_MASK_CORRELATION_ID_KEYS)
    | set(_MASK_ROLE_TYPE_PARENTS)
    | set(_MASK_PROTOCOL_PARENTS)
    | set(_MASK_PROTOCOL_ID_PARENTS)
    | set(_MASK_BUSINESS_KEYS)
    | {
        # 对话协议骨架
        "role", "type", "content", "contents", "parts", "messages", "message",
        "system", "user", "assistant", "tool", "tools", "function", "functions",
        "prompt", "input", "output", "text", "delta", "choices", "candidates",
        "usage", "error", "code", "status", "version", "headers", "request",
        "response", "metadata", "stream", "stop", "stop_sequences", "logit_bias",
        "response_format", "stream_options", "parallel_tool_calls", "tool_choice",
        "system_instruction", "generationConfig", "safetySettings", "toolConfig",
        "functionDeclarations", "functionCall", "inline_data", "image_url", "source",
        "anthropic_version", "thinking", "signature",
        # JSON Schema 词汇（response_format / format 里可能是整份 schema）
        "schema", "json_schema", "format", "definitions", "$defs", "$ref", "$schema",
        "properties", "required", "items", "enum", "const", "description", "title",
        "additionalProperties", "anyOf", "oneOf", "allOf", "not", "if", "then", "else",
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
        "minLength", "maxLength", "minItems", "maxItems", "pattern", "default",
        "examples", "nullable", "strict", "name", "strict_mode",
        # 缓存 / 计费 / 诊断指令
        "cache_control", "ttl", "ephemeral",
        # 对话协议顶级控制参数（涵盖各大模型标准字段，对齐 PROTOCOL_TOP_KEYS）
        # ⚠️ 这一组是**协议骨架**，被改名等于上游 400。别漏 `n`（OpenAI 的
        # `n` = 生成几条候选，单字母键最容易在补白名单时被漏掉）。
        "temperature", "top_p", "top_k", "n", "max_tokens", "max_completion_tokens",
        "max_output_tokens", "presence_penalty", "frequency_penalty", "seed",
        "logprobs", "top_logprobs", "modalities", "audio", "prediction", "store",
        "service_tier", "reasoning", "reasoning_effort", "thinking_budget",
        "betas", "anthropic_beta", "context_management", "mcp_servers", "container",
        "generation_config", "safety_settings", "candidate_count", "systemInstruction",
        "session_id", "request_id", "keep_alive", "options", "api_key", "x_api_key",
        "authorization", "instructions", "tool_config",
    }
)
# 顶层非对象 JSON 的合成根键：只在 request() 内部存在，发往上游前一定会拆掉。
# 取一个绝不会与真实字段重名、且不落在任何跳过名单里的名字，保证叶子照常被扫描。
_ROOT_WRAP_KEY = "__shield_root__"


# 首个差异字节的扫描上限。超过就不算（记 -1）。
# 实测（二分 + 切片比较，差异位置越靠后越贵）：1MB 14.5ms、8MB 173ms、32MB 约 700ms。
# 这个值只用于「前缀有没有被改动」的诊断，而它在回写分支里**每次都调**
# （与 splice 成不成无关），不值得为它拖慢热路径。
# ⚠️ 别跟着 `_SPLICE_MAX`（8MB）一起放宽（见那里的注释）。
_FIRST_DIFF_MAX = 1 << 20


def _first_diff_byte(a, b):
    """返回 a、b 首个不同字节的下标；一方是另一方前缀时返回较短者的长度。

    只用于诊断（MASK 事件的 first_diff_byte），**不参与任何脱敏决策**。
    用途：判断「命中敏感词时，客户端原始 body 的排版是否被我们的重序列化改掉了」——
    差异位若正好落在第一个被脱敏的值上，说明客户端本来就在发紧凑体，
    当前的回写方式没有额外损失；差异位若远小于它（例如 byte 9 的
    `{"model": ` 空格），说明还有整段前缀被凭空改动，值得考虑字节级替换。

    实现用二分 + 切片相等比较：每次比较是 C 级 memcmp，整体 O(log n) 次，
    避免 Python 逐字节循环在 MB 级请求体上跑到几百毫秒。切片相等性对前缀长度
    单调（长度 m 的公共前缀 ⇒ 所有更短的也相等），所以二分成立。
    """
    if len(a) > _FIRST_DIFF_MAX or len(b) > _FIRST_DIFF_MAX:
        return -1
    n = min(len(a), len(b))
    if n == 0:
        return -1 if len(a) == len(b) else 0
    if a[:n] == b[:n]:
        return -1 if len(a) == len(b) else n
    lo, hi = 0, n - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[:mid + 1] == b[:mid + 1]:
            lo = mid + 1
        else:
            hi = mid
    return lo


# 字节级替换的体积与条目上限。超过就退回整棵重序列化。
#
# `_SPLICE_MAX` 取 8MB。早先取 1MB 的注释理由是「省下的前缀对齐收益抵不过 CPU
# 开销」，**实测不成立**——完整路径（`_splice_mask` + 调用方的 `json.loads` 等价校验）
# 对退路 `json.dumps` 的比值：1MB 3.2/2.4ms（1.34x）、8MB 28.0/23.9ms（1.17x），
# 最坏只多 4ms（敏感值 1→64 个耗时只差 2 倍，不是分支数的线性放大）。
# 而 1MB 恰好把**长会话**挡在了外面——那恰恰是上游 Prompt Cache 收益最大的场景，
# 上下文越长，前缀 miss 一次越贵。
#
# ⚠️ 别把它和 `_FIRST_DIFF_MAX`（1MB）联动放宽：后者是每次回写都要算的纯诊断值，
# 耗时随差异位置后移暴涨（1MB/最末 14.5ms、8MB 173ms），跟着放宽等于给热路径加
# 100ms+。后果：>1MB 的请求 splice 生效但 `first_diff_byte` 记 -1，仪表盘
# 「平均首个差异字节」样本数为 0 —— **已知口径，不是 bug**，别重复排查。
#
# `_SPLICE_MAX_FORMS = 128` 是**另一条独立的退回线**：本次请求里被脱敏的**唯一原文**
# 数上限（每个原文按「原字符 / \uXXXX」两种合法 JSON 写法各建一条交替分支，
# 所以 128 个原文 ≈ 256 个分支）。超了 `_splice_mask` 直接返回 None，同样退回整棵
# 重序列化 → 前缀又被改，首个差异位回到 body 开头附近。
#   · 为什么是 128 而不是 64：2026-09-13 在 8MB body 上复测了上限档位——splice 生效
#     的耗时与退路的 `json.dumps` **同价**（32 分支 21ms / 128 分支 23ms / 256 分支
#     27ms vs dumps 22ms），退回并没有省时间，只是白白丢掉前缀保真；而分支数在
#     64→256 区间内几乎不放大耗时（主成本在大 body 扫描本身）。取 128 是让日常长会
#     话（单请求几十个不同敏感值）不再踩线，同时保留体积上限做硬护栏。继续放宽的
#     代价仍是同价的，若未来感知到慢再回来复测档位——只要分支数仍在个位数毫秒级。
#   · 唯一副作用也附带测量过：splice 生效与否不影响脱敏/还原正确性（两端都是同一
#     棵已脱敏树，还原只看占位符→rev 表），只影响发往上游字节的前缀保真。
#   · 诊断方式：这类请求 `body_rewritten=true` 但 `first_diff_byte` **明显早于敏感值
#     在 body 里的真实位置**（客户端用带空格排版时约在 byte 9），而 splice 生效时
#     差异位正好落在敏感值上 —— 两者对照一眼可辨。
_SPLICE_MAX = 8 << 20
_SPLICE_MAX_FORMS = 128


def _splice_mask(raw, masked_root, pairs):
    """把 raw 里被脱敏的原文**就地**换成占位符，保住客户端 body 的原始排版。

    为什么值得多这一条路径：命中敏感词时旧实现用 `json.dumps` 整棵重序列化，
    客户端 body 的排版（冒号后空格、缩进、`1e-05` 这类数字写法）被一并抹掉，
    与客户端原始字节的首个差异位就从「真正的敏感值」前移到 body 开头附近
    （实测一条带空格 + `\\u` 转义的请求：敏感值在 byte 74，差异位却在 byte 9）。
    上游按前缀做的 Prompt Cache 从差异位起整段 miss，中间那 65 个字节被白白改掉。

    做法：对每个被脱敏的原文，按「原字符」与「\\uXXXX」两种合法 JSON 写法各建一条
    替换项，在原始字节上一次性替换 —— 客户端用哪种转义风格，占位符就用哪种写回去。
    不做结构解析，所以不动键名、不动数字字面量、不改排版。

    ⚠️ **正确性不由这个函数保证**：调用方必须校验
    `json.loads(结果) == masked_root`，不过就整条退回 `json.dumps`。
    所以这里可以粗暴 —— 多替换了（命中键名、命中 `_mask_tree` 有意跳过的位置、
    把历史里已有的占位符切碎）都会被等价校验拦下，退回**同一棵已经脱敏的树**。
    因此这条路径在任何情况下都不会放行原文，最差只是回到改动前的行为。

    pairs: {原文: 占位符}。返回替换后的字节；一个都没替换就返回 None。
    """
    if not pairs or not raw or len(raw) > _SPLICE_MAX:
        return None
    table = {}
    for orig, tok in pairs.items():
        if not orig or not tok or orig == tok:
            continue
        for ascii_esc in (False, True):
            lit = json.dumps(orig, ensure_ascii=ascii_esc)[1:-1]
            repl = json.dumps(tok, ensure_ascii=ascii_esc)[1:-1]
            if lit != repl:
                table[lit.encode("utf-8")] = repl.encode("utf-8")
    if not table or len(table) > _SPLICE_MAX_FORMS:
        return None
    # 长 form 优先：正则交替是「首个匹配胜出」，短原文若是长原文的子串，
    # 排在前面就会把长原文切碎。
    forms = sorted(table, key=len, reverse=True)
    pat = re.compile(b"|".join(re.escape(f) for f in forms))
    new, hits = pat.subn(lambda m: table[m.group(0)], raw)
    return new if hits else None


def _mask_hit(obj, sid, flag=None):
    """调 `mask()` 并记录「这个请求体真的被改写过」。

    flag 是调用方传进来的单元素 list（None = 调用方不关心）。用途见
    `_mask_tree` 的调用方：一个敏感词都没命中时**完全不回写**
    `flow.request.content`，让上游收到的字节与客户端发出的逐字节一致。

    为什么非要有这个标记：`json.dumps` 的默认分隔符是 `(", ", ": ")`，
    重序列化会在每个逗号/冒号后插空格；`ensure_ascii` 的取值还会决定非 ASCII
    是写成 `\\u5f20` 还是「张」。哪怕一个敏感词都没命中，这两点也足以让上游
    收到的字节与客户端发出的不同 —— 上游按前缀做 Prompt Cache，前缀一变就
    整段 miss（实测紧凑体 113 字节被改写成 123 字节）。
    """
    out = mask(obj, sid)
    if flag is not None and out != obj:
        flag[0] = True
    return out


def _note_signed_block_skip(sid):
    """记一次「协议不可改写状态未扫描」（本轮计数）。

    豁免是一条**漏检路径**，静默豁免等于用户以为扫了、其实没扫（与 NER 降级
    同一个理由），所以必须计数并随 MASK 事件上报（`signed_blocks_skipped`）。
    批次 3 起计数覆盖契约表里的全部载体（签名块 + 密文句柄），字段名保持不变，
    免得面板与事件库跟着改口径。

    累加在会话上、由 MASK 事件取走并清零，语义是「本次请求」；取不到会话时不记
    （探测/单测路径不能因此抛异常）。
    """
    s = _session_get(sid)
    if isinstance(s, dict):
        s["signed_skipped"] = int(s.get("signed_skipped") or 0) + 1


def _take_signed_skips(sid):
    """取走本轮「协议不可改写状态未扫描」计数并清零（MASK 事件用）。

    与 `_note_signed_block_skip` 成对：一个在 worker 线程累加，一个在事件循环侧
    取走。取走即清零，语义是「本次请求」，不让会话级累计值冒充本轮数字。
    """
    s = _session_get(sid) if sid else None
    if not isinstance(s, dict):
        return 0
    return int(s.pop("signed_skipped", 0) or 0)


def _state_carrier_match(obj, key, parent, path, in_business, role):
    """命中的协议不可改写状态载体（或 None），判据见 `protocol_contracts.py`。

    这里是**唯一**的请求侧判据入口：载体表、两种作用域（`block` = 签名覆盖兄弟明文、
    整块只读；`slot` = 自包含密文句柄、只锁该字段）与来源引用都在契约表里，
    本文件不再写第二份（写两份等于给"请求/响应集合漂移"留门）。

    为什么不能退回裸字段名豁免：工具参数里的同名业务字段必须照常扫描（AstrLink
    `continuation_test.go:134` 锁定的反例）；只看块类型不看角色，会让 user 轮、
    `tool_result` 里的同名块整块不受扫描 → 静默漏检。签名/密文缺失或为空的块上游
    无从校验，照常脱敏才不白丢一个漏检面。
    """
    return _contracts.match(obj, key, parent, path, role, in_business)


def _leaf_exempt(key, parent, in_business):
    """叶子（字符串 / 数值）是否落在「协议位置」从而豁免扫描。

    抽成独立函数是因为 str 与数值两个分支必须用**同一套**判据：数值型漏检
    （审计 B2）的根因之一就是数值分支压根没有判据、直接 `return obj`。

    判据细节（按优先级）：
    - 工具调用关联 ID：**不分业务区，一律豁免**。它是上游生成的不透明句柄
      （call_abc123），客户端要拿它把工具结果回连到上一轮函数调用。脱敏它必然断链，
      而且保护不了任何东西——里面没有用户原文，有也是上游必须逐字匹配的那份。
      所以这条判定必须在 in_business 之前。
      提前的原因（2026-08-17 外部审计）：OpenAI Responses API 把协议信封放进
      input[] 里 —— {"input":[{"type":"function_call_output","call_id":...}]}。
      而 input 是业务区容器，`if not in_business` 那一大块整个不进，
      于是 call_id 被当普通文本脱敏：call_ACME_9x → call_{{CUSTOMER_ed24da}}_9x。
      Chat Completions 的 tool_call_id 在 messages[] 里（非业务区）所以一直没事，
      两边行为不一致纯属遗漏，不是设计。
    - 业务区内一律不豁免（见 `_mask_tree` 的说明）。
    - 业务区外按「完整路径 + 协议位置」判定，禁止裸字段名豁免。
      只列关联 ID，不含 name/url/id 等——那些在业务对象里确实可能载有原文
      （customer.id、正文里的 url），维持按位置判定。
    """
    if key in _MASK_CORRELATION_ID_KEYS:
        return True
    if in_business:
        return False
    if key in _MASK_SKIP_SCALAR_KEYS:
        return True
    if key in ("role", "type") and (parent is None or parent in _MASK_ROLE_TYPE_PARENTS):
        return True
    if key in _MASK_SKIP_KEYS:
        # 协议位置判定（业务区内不豁免）：
        # - name：仅工具定义/调用位置的工具名（tools[].function.name / tool_use.name）
        # - url/data/b64_json：仅媒体容器里的图片 URL/base64（改了就破图）
        # - id：仅协议容器（messages/content/tool_calls/response/output 等）的关联 ID
        if key == "name" and parent not in _MASK_PROTOCOL_PARENTS:
            return False
        if key in ("url", "data", "b64_json", "image_url") and parent not in _MASK_PROTOCOL_PARENTS:
            return False
        if key == "id" and parent not in _MASK_PROTOCOL_ID_PARENTS:
            return False
        return True
    return False


def _mask_tree(obj, sid, key=None, parent=None, path=(), depth=0, flag=None, role=None):
    """递归脱敏 JSON 里的字符串叶子（完整路径判定 + 业务区强制扫描）。

    只处理 message.content 会整片漏掉多轮历史里的
    tool_calls[].function.arguments、Anthropic tool_use.input、tool_result.content —
    这些位置常年携带上一轮的真实值，是最容易被绕过的泄漏面。
    JSON 深度超过上限不再静默原文放行：抛异常走 fail-closed 阻断（fail-closed 关闭时
    记 ERR 跳过），杜绝"深到扫不到就直出"的泄漏路径。

    flag：可选单元素 list，任一叶子真的被替换过就置 True（见 `_mask_hit`）。
    调用方靠它决定「要不要回写请求体」——没命中就一个字都不改，保住上游前缀缓存。

    path：自根向下的真实路径，**数组下标也进 path**（契约表的"真实数组"判据要区分
    "数组元素"与"同名对象字段"）。注意两条入口的起点不同：整包入口从 `path=()` 递归，
    生产代理链路按顶层键逐个调用（顶层键留在 `key` 里）；契约表对此两种形态都认。

    role：当前所在 message 的角色（字符串），由 dict 分支向下传递。只服务于
    契约表的角色判据；旧调用方不传＝None，行为与之前一致。
    """
    control = getattr(_MASK_WORK_CONTEXT, "control", None)
    if control is not None:
        _check_mask_work(*control)
    if depth > _MASK_MAX_DEPTH:
        raise ValueError("json_depth_exceeded: 请求嵌套超过脱敏递归上限，拒绝透传")
    in_business = any(k in _MASK_BUSINESS_KEYS for k in path)
    if isinstance(obj, str):
        # 业务区（tool_use.input / function.arguments 等参数容器）内一律扫描：
        # 不应用任何全局字段名豁免——input 里的 type/role/model/id 都可能是业务数据
        # （审计实测：input.type 放手机号曾原文上行）。只有业务区外的协议位置才跳过。
        # 判据抽到 `_leaf_exempt`：数值分支必须用同一套，否则两边行为会漂。
        if _leaf_exempt(key, parent, in_business):
            return obj
        return _mask_hit(obj, sid, flag)
    # bool 是 int 的子类，必须先判掉：否则 True/False 会被 str() 成 "True"/"False"
    # 送去过规则（虽然默认词表不会命中，但自定义词表里加个 "True" 就会）。
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, (int, float)):
        # 数值型标量（审计 B2 阻断项）。规则全是文本正则，而旧实现到这里直接
        # `return obj` —— 于是 {"phone": 手机号} 这种形态**既不命中也不抛异常**，
        # changed 保持 False → 零改写分支把客户端原始字节原样放行，明文出网；
        # 而 fail-closed 只兜异常，兜不住「静默判定为无需改写」。
        # 修法：取字符串形态过一遍规则，命中才把整个值换成占位符（类型由 number
        # 变 string，上游读到的就是占位符，与字符串形态的脱敏结果一致）。
        if key in _MASK_SKIP_NUMERIC_KEYS or _leaf_exempt(key, parent, in_business):
            return obj
        s = repr(obj) if isinstance(obj, float) else str(obj)
        out = mask(s, sid)
        if out != s:
            if flag is not None:
                flag[0] = True
            return out
        return obj
    if isinstance(obj, list):
        # 数组下标必须进 path：契约表的"真实数组"判据要区分「数组元素」与
        # 「同名对象字段」（Responses 的 `input[]` vs 工具参数里的 `input` 对象）。
        return [_mask_tree(v, sid, key, parent, path + (i,), depth + 1, flag, role)
                for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        # 协议元数据对象整棵跳过。必须放在 dict 分支——str 分支的
        # _MASK_SKIP_SCALAR_KEYS 对对象值无效（见该集合上方的注释）。
        if not in_business and key in _MASK_SKIP_SUBTREE_KEYS:
            return obj
        # 协议不可改写状态（契约表）：`block` 作用域整块只读（正文与签名必须原样上行，
        # 改任一侧都让上游校验失败）；`slot` 作用域只锁住密文字段，兄弟字段照常扫描。
        # 必须在 dict 分支（`_MASK_SKIP_SCALAR_KEYS` 对对象值无效）。
        carrier = _state_carrier_match(obj, key, parent, path, in_business, role)
        locked = frozenset()
        if carrier is not None:
            _note_signed_block_skip(sid)
            if carrier.scope == "block":
                return obj
            locked = _contracts.protected_fields(carrier, obj)
        # 键名脱敏（2026-09 起，审计 B2）。旧实现是「键名一律不脱敏」，理由是
        # 键名承载结构语义、自定义短词误命中会把协议骨架打坏。这个顾虑成立，
        # 但它同时让 {"手机号": "safe"} 这种 PII-as-key 形态整条明文上行。
        #
        # 现在的判据翻转成**结构键白名单**：`_MASK_PROTECTED_KEY_NAMES` 内的键永不
        # 脱敏，集合外一律当数据键扫描。于是「用户加个 con 命中 content」这类误伤
        # 被白名单挡住，而手机号/身份证当键名时能被打上。
        # 注意 path 仍用**原键** k 推进：in_business 判定必须看客户端真实的键名，
        # 用脱敏后的占位符去判会让下游整棵子树丢失业务区语义。
        masked_obj = {}
        # 角色下传：契约表的角色判据要看「所在 message 的 role」，而 role 是 message
        # 的兄弟字段，只能在往下递归时带上下文（见 `_state_carrier_match`）。
        branch_role = obj.get("role") if isinstance(obj.get("role"), str) else role
        for k, v in obj.items():
            if k in locked:
                # 不可改写字段原样保留（键名也不动）：签名/密文串被改写就等于把状态打烂。
                masked_obj[k] = v
                continue
            new_key = k
            if isinstance(k, str) and k not in _MASK_PROTECTED_KEY_NAMES:
                masked_key = mask(k, sid)
                if masked_key != k:
                    new_key = masked_key
                    if flag is not None:
                        flag[0] = True
            masked_obj[new_key] = _mask_tree(v, sid, k, key, path + (k,), depth + 1, flag,
                                              branch_role)
        return masked_obj
    return obj


def _seed_known(text, sid):
    """把请求里出现的、属于复用表的历史占位符登记进本会话 rev。

    客户端历史里带上来的上一轮占位符，本轮响应若被模型复述，仍能正确还原。
    """
    s = _session_get(sid)
    if not s or not text:
        return
    for token in set(_PLACEHOLDER_RX.findall(text)):
        # B-1a ③：`in` 判断与写入是两步，多个 worker 同时处理同一会话时会重复写
        # （本身幂等，但 `_touch_recent` 的续期与 `_RECENT_*` 的淘汰语义要一致）。
        with _STATE_LOCK:
            if token in s["rev"]:
                continue
            recent = _tables().rev.get(token)
            if recent and time.time() - recent[2] <= _recent_ttl():
                s["rev"][token] = recent[0]
                _touch_recent(token, recent[0])


# ===================== 浏览器扩展桥接（Browser Bridge v1）专用入口 =====================
# 这两个 helper 是 panel 的 /api/ext/mask 端点复用的入口，**不经代理链路**。
# 它们都必须由调用方（panel 侧）持 `_EXT_LOCK` 调用。⚠️ 这条**不是**因为
# "`sessions` 由 `_STATE_LOCK` 保护好了"——0.6.0 起 `sessions[sid]` 内的计数与
# 映射才有 `_STATE_LOCK` 契约（见上方 B-1a），而**字典本身**的插入/删除仍靠
# `list()` 快照兜住遍历期；panel 侧再叠一层 `_EXT_LOCK` 是为了把
# "读配置 → 脱敏 → 写统计"当作一个整体串行化，避免与热重载互相踩。
#
# 代理链路自 2026-09-24 起也跑在自己的专职线程里（见 `_MASK_POOL`），与 panel 的
# Flask 线程仍不同锁。代理链路的会话由事件循环侧在派发前 `_new_session()` 建好，
# worker 里的 `mask()` 因此命中已有会话；刚建的会话 `ts` 是当前时刻，`_sweep()` 也不会
# 回收它（idle≈0 且尚未 inflight），所以 worker 不会插入 `sessions`。
# 但 `mask()` 里确实留着惰性 `_new_session()` 兜底，这条边界依赖「会话刚被创建」的
# 时序。因此本文件遍历全局字典一律用 `list()` 快照（见 `_sweep` / `_prune_recent`），
# 不去赌时序 —— 赌输的代价是 `RuntimeError: dictionary changed size` 把请求打成 502。

def _mask_event_items(sid, limit=30):
    """构造与代理路径**同构**的 MASK 事件明细（items），供 panel 的 ext 端点落库。

    字段结构与代理响应侧构造对齐（`tok/label/hash/length/preview` + 凭据类
    `cred/digest` 或非凭据 `original` + 短词 `short`），这样 `_warmup_recent_from_db`
    预热与前端明细弹窗对两条链路的行为一致（SPEC C11/T14）。

    **唯一少一个字段：`roles`**（代理侧由 `role_texts` 反查「命中在第几个角色块」，
    那个映射来自代理的请求解析过程，扩展链路拿不到）。前端对缺失的 `roles` 是
    「不渲染归因角标」，不报错——所以这里是**有意的缺省，不是漏写**，别照抄代理侧
    的构造列表去补（补不出来，只会拿到 `roles=None` 被静默跳过）。

    **假定会话已由调用方显式建立**（端点先 `_new_session`），不做缺会话兜底——
    端点显式建会话正是为了让 inflight 保护落在真会话上。
    凭据类标签恒只回 digest+preview（不落原文），与项目隐私红线一致。
    """
    s = _session_get(sid) or {}
    fwd = s.get("fwd") or {}
    labels = s.get("labels") or {}
    last_hits = s.get("last_hits") or set()
    # 本次命中的排前面，让事件的 count 与明细对得上（同代理路径口径）
    ordered = [o for o in last_hits if o in fwd] + [o for o in fwd if o not in last_hits]
    items = []
    for orig in ordered[:limit]:
        tok = fwd.get(orig, "")
        if not tok:
            continue
        m = _PLACEHOLDER_PARTS_RX.match(tok)
        label = labels.get(orig, "")
        item = {
            "tok": tok,
            "label": label,
            "hash": m.group(2) if m else "",
            "length": len(orig),
            "preview": _preview(orig, label),
        }
        if label in CREDENTIAL_LABELS:
            item["cred"] = True
            item["digest"] = _cred_digest(orig)
        else:
            item["original"] = orig
        if len(orig) <= 2:
            item["short"] = True
        items.append(item)
    return items


_DUP_KEY_WARNED = [False]


def _load_json_pairs(text):
    """解析 JSON，并同时报告**是否存在重复键**。返回 (obj, has_dupes)。

    为什么要单独判重复键：`json.loads` 对重复键取「后者覆盖前者」，解析结果无法
    代表原文。于是 `{"a":"手机号","a":"safe"}` 的树里只剩 "safe"，`_mask_tree`
    扫不到那个手机号 → changed 保持 False → 零改写分支把**原始字节**原样放行
    （审计 B2 实测）。命中其它字段时同样不能走 `_splice_mask`：丢掉的键不在替换表里，
    而等价校验又会因为「splice 结果解析回来仍等于脱敏树」而误判通过，明文照样出网。

    解析失败返回 (None, False) —— 由调用方走各自的「非 JSON 体」分支。
    """
    dupes = [False]

    def _pairs(pairs):
        d = dict(pairs)
        if not dupes[0] and len(d) != len(pairs):
            dupes[0] = True
        return d

    try:
        return json.loads(text, object_pairs_hook=_pairs), dupes[0]
    except Exception:
        return None, False


def mask_body(text, sid):
    """请求体脱敏（JSON 感知 + 就地替换），扩展链路的请求打码入口。

    与代理路径的三级回写同源，目标是**别把客户端 body 的前缀整体挪位**：
    1. `json.loads` 成对象 → `_mask_tree` 逐字符串叶子脱敏（协议位置跳过、业务区强制扫描）；
    2. 首选 `_splice_mask` 在**原始文本上就地替换**（保住排版/转义风格），
       并以 `json.loads(结果) == 脱敏后的树` 等价校验拦下过度替换；
    3. 校验不过（或未 splice）退回整棵重序列化，separators 用紧凑形态。
    解析失败（纯文本体）走 `mask()` 整段扫描。

    零命中时**逐字节原样返回**（省一次序列化，也让上游前缀缓存能命中）。
    例外是**含重复键**的体：树里已丢掉被覆盖的那个值，零改写会放行原文，
    所以强制走重序列化（见 `_load_json_pairs`）。

    深度超限等异常**向上抛**（端点转 (A) 阻断），绝不在这里静默放行明文。
    """
    if not text:
        return text
    obj, has_dupes = _load_json_pairs(text)
    if has_dupes and not _DUP_KEY_WARNED[0]:
        _DUP_KEY_WARNED[0] = True
        try:
            _log("[mask] 请求体存在重复键：该请求已改为整棵重序列化，"
                 "被覆盖的字段值不会明文上行（首次告警，后续静默）")
        except Exception:
            pass
    if not isinstance(obj, (dict, list)):
        # 非 JSON 体（含合法 JSON 标量）：整段当纯文本扫描
        out = mask(text, sid)
        _seed_known(out, sid)
        return out

    changed = [False]
    masked_root = _mask_tree(obj, sid, flag=changed)
    if not changed[0] and not has_dupes:
        # 零改写：一个字都不动（保住前缀），但仍登记历史遗留占位符供响应侧还原
        _seed_known(text, sid)
        return text

    masked_raw = None
    if not has_dupes:
        try:
            spliced = _splice_mask(
                text.encode("utf-8"), masked_root,
                {o: t for o, t in (_session_get(sid, {}).get("fwd") or {}).items() if t},
            )
        except Exception:
            spliced = None
        if spliced is not None:
            try:
                decoded = spliced.decode("utf-8")
                if json.loads(decoded) == masked_root:
                    masked_raw = decoded
            except Exception:
                masked_raw = None
    if masked_raw is None:
        masked_raw = json.dumps(masked_root,
                               ensure_ascii=("\\u" in text),
                               separators=(",", ":"))
    _seed_known(masked_raw, sid)
    return masked_raw


_logger = logging.getLogger("llm_shield")


def _log(msg):
    """引擎日志。

    mitmproxy 11 起移除了 `ctx.log`，addon 必须用标准 logging（mitmproxy 会把
    root logger 接到自己的日志输出）。此前这里调 `ctx.log.info` 抛 AttributeError
    被下面的 except 吞掉，导致「流式接管」「压缩退化」等全部诊断日志静默丢失，
    断流问题无法归因。异常仍然吞掉：日志失败不能影响代理转发。
    """
    try:
        _logger.info(msg)
    except Exception:
        pass


def _client_source(flow):
    conn = getattr(flow, "client_conn", None)
    peer = None
    for attr in ("peername", "address"):
        value = getattr(conn, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value:
            peer = value
            break
    if not peer:
        return {}
    if isinstance(peer, (list, tuple)) and len(peer) >= 2:
        host, port = str(peer[0]), peer[1]
    else:
        text = str(peer)
        if ":" not in text:
            return {"client": text}
        host, port = text.rsplit(":", 1)
    try:
        port = int(port)
    except Exception:
        return {"client": f"{host}:{port}", "client_host": host}
    return {"client": f"{host}:{port}", "client_host": host, "client_port": port}


def mapping_stats() -> dict:
    """内存映射规模快照（面板「清空内存映射」按钮与自检用；**不含任何原文**）。

    计数通过 `engine-runtime.json` 跨进程外发：面板进程只能看到它自己那份
    （扩展桥接链路），代理链路的真值在引擎进程，而用户想清的是**两者**。
    只报数量不报内容，所以这个消息面本身不引入新的泄露面。
    """
    try:
        with _STATE_LOCK:
            return {
                "sessions": len(sessions),
                "recent_entries": len(_RECENT_FWD),
                "suffix_index": len(_RECENT_SUFFIX),
                "custom_word_entries": len(_CUSTOM_WORD_FWD),
            }
    except Exception:
        return {}


def _emit(typ, **kw):
    if typ == 'MASK':
        session = _session_get(kw.get('sid'), {})
        verification = session.pop('verification', {})
        if verification:
            kw['verification'] = verification
    # 阻断事件的统一检测口径（§B1）：BLOCK 有十几处调用点，逐个加字段迟早漏一处
    # （而漏掉的那处恰好会在列表里显示成“什么都没发生”），因此在这里一次性补全。
    # 只在调用方没显式给 decision 时补，避免覆盖更精确的现场结论。
    if typ == "BLOCK" and "decision" not in kw:
        kw.update(inspection.report_for_skip(reason=str(kw.get("reason") or ""), blocked=True))
    rec = onboarding.scrub({"ts": time.time(), "type": typ, **kw})
    try:
        # 日志分级（§D1）在**写侧**投影，stdout 与事件库共用同一函数。
        # 为什么 stdout 也要：这一行会被桌面壳原样追加进 engine-stdout.log，
        # 那是磁盘上的第二份正文副本；只在 DB 侧裁剪的话，最小模式下
        # dialog/dialog_req/items[].original 照样躺在日志文件里。
        stdout_rec = dict(rec)
        stdout_rec.pop('verification', None)  # local DB only; never diagnostic log_tail
        line = "SHIELD\t" + typ + "\t" + json.dumps(project_event_for_log(stdout_rec), ensure_ascii=False)
    except Exception:
        # 事件字段含不可序列化值（理论上不出现）：降级为仅记类型，不让异常穿透代理主流程
        line = "SHIELD\t" + typ + "\t{}"
    _log(line)
    try:
        enqueue_event(rec)
    except Exception:
        pass


# ========== 2.0 审计钩子（隔离保证：永不改 body，永不抛异常，关时零开销） ==========
def _hash_body(content):
    try:
        if not content:
            return ""
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return ""


def _audit_response(flow, sid, host, method, path, source, streamed_text=None,
                    apply_block=True):
    """响应审计：在 restore 完成后调用。只读不改 body，异常静默。

    A-3：本函数会跑在 `_AUX_POOL` 线程里，因此**不得依赖 flow 的可写性**——
    需要正文时由调用方用 `streamed_text` 显式传入（非流式路径传还原后的文本）。
    `apply_block=False` 时只**构造**审计熔断的 503 响应对象并返回，由事件循环
    回写（`flow.response = ...` 是 mitmproxy 状态，统一在循环线程碰）。
    """
    if not AUDIT_ENABLED:
        return None
    block_resp = None
    t_start = time.perf_counter()
    try:
        resp = flow.response
        if resp is None:
            return
        status_code = getattr(resp, "status_code", None) or 0
        ct = resp.headers.get("content-type", "")
        # 流式接管时 flow.response.content 不可用（设置会破坏流），用回调累积文本
        if streamed_text is not None:
            content = streamed_text.encode("utf-8")
        else:
            content = resp.content or b""
        # 只解出**真会被用到的部分**：唯一需要全量文本的消费者是结构化解析
        # （`_parse_response_payload`），而它本身被 `AUDIT_PARSE_MAX` 闸住。
        # 所以超过该闸时全量 decode 纯属浪费 —— 4MB 实测 3.6ms、16MB 11.5ms，
        # 而且那份 str 会与 bytes 一起常驻（4MB 体多占数 MB 峰值，× 并发数）。
        # 等价性（不是"近似"）：超闸时结构化解析与跨请求污染两条路径**本来都不执行**
        # （下面用 `body_oversize` 保持同一判定，`parse_skipped` 照旧置位），
        # 而 128KB 扫描窗口取的就是前缀。前缀按"4 字节/字上限 +4 字节"取，
        # 保证窗口内不出现截断产生的替换符。
        if content and len(content) > AUDIT_PARSE_MAX:
            body_text = content[:_audit_text_probe_bytes()].decode("utf-8", errors="replace")
            _body_oversize = True
        else:
            body_text = content.decode("utf-8", errors="replace") if content else ""
            _body_oversize = False
        # 审计扫描的**输入上限**（审计 M1）。此前全量 body_text 直接喂给
        # `scan_error_leak` / `scan_response_poison` / `scan_dangerous_action`，
        # 而上游完全可以回一个 4xx + 几百 KB 的畸形 body：单是 PEM 正则的
        # 灾难性回溯就足以把 mitmproxy 事件循环 CPU 打满（实测 12KB 就要 3.4s）。
        # 响应侧扫描是**防御性**功能，前段命中已覆盖绝大多数幻觉/泄漏场景。
        # ⚠️ 只截断送给扫描器的副本：需要全量文本的 `_parse_response_payload`
        # （SSE/JSON 结构化解析）由上面的 decode 分支保证"要么拿到全量、要么明确知道
        # 自己超闸"（`body_oversize`），不会吃到一份被悄悄截断的文本。
        #
        # A-1（0.6.0）把窗口从 `_SCAN_BODY_MAX`(512KB) 收到 `AUDIT_SCAN_MAX`(128KB)：
        # 实测（scripts/bench_mask.py）三信号扫描约 0.11ms/KB（口径：error_leak +
        # response_poison + dangerous_action **三条**一起扫），512KB 就是 ~55ms
        # 纯事件循环 CPU，正是 503 重试风暴里被线性放大的那一块。
        # ⚠️ **必须如实披露的能力变化**：`scan_text` 同时喂给 S1 `error_leak`，
        # 而 `audit_fail_closed`（默认关）的熔断判据是「severity ≥ CRITICAL」，
        # 当前只有 S1 的四类凭据能到 CRITICAL（:384 / audit_signals.py:194）。
        # 所以用户打开「审计阻断」后，可检范围随窗口同步缩小——设置页与
        # CHANGELOG 都写了这句，别让它只活在注释里。
        # （危险命令拦截不受影响：它走还原侧 `_cmd_find`/`_cmd_record` 逐块扫全文。）
        scan_text = body_text[:AUDIT_SCAN_MAX] if body_text else ""
        # 回声抑制用的请求体文本：请求里本来就有的危险命令/凭据不算「上游注入」。
        # 生产库实测这是最有效的一条去噪规则——编程助手的对话里 rm、curl|sh
        # 天天出现，只有上游凭空多出来的那条才值得报。
        try:
            # 同上：请求文本只喂 128KB 窗口，全量 decode 是白烧（请求可达 32MB，
            # 一次 decode ≈ 20ms 且多占几十 MB）。哈希仍用**全量字节**（见下）。
            req_text = ((getattr(flow.request, "content", None) or b"")
                        [:_audit_text_probe_bytes()]).decode("utf-8", errors="replace")
        except Exception:
            req_text = ""
        scan_req_text = req_text[:AUDIT_SCAN_MAX] if req_text else ""
        req_hash = _hash_body(getattr(flow.request, "content", None))
        resp_hash = _hash_body(content)
        common = {
            "sid": sid, "host": host, "method": method, "path": path,
            "request_hash": req_hash, "response_hash": resp_hash,
        }
        # ---- A-1/A-2：预算 + 同 body 复用 ----
        deadline = t_start + AUDIT_TIME_BUDGET_S
        _stats = {"truncated": False, "parse_skipped": False, "cache_hit": False,
                  "cache_miss": False, "scan_bytes": len(scan_text)}
        # 响应头文本：S1 error_leak 用它识别「凭据出现在响应头里」。
        # 必须在**算缓存键之前**就取好 —— 它是扫描输入之一，不参与键就等于
        # "同 body 不同 header 回放 30s 的旧结论"（把 Set-Cookie/X-* 里的凭据漏掉）。
        _hdrs_text = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
        # 缓存键必须覆盖**全部**扫描输入：body 摘要、状态码、请求摘要、信号开关、
        # 以及下面这两个曾经漏掉的 —— `ct`（决定 S2/S4 是否走结构化解析分支）与
        # 响应头摘要（S1 的凭据在头里）。漏了它们就是"输入变了、结论没变"的静默漏检。
        _hdrs_sig = (hashlib.sha256(_hdrs_text.encode("utf-8", "replace")).hexdigest()[:16]
                     if _hdrs_text else "")
        _cache_key = (resp_hash, status_code, req_hash, bool(AUDIT_ACTIVE_PROBES),
                      _audit_config_fingerprint(), (ct or "")[:64], _hdrs_sig)
        # 什么时候**不能**用缓存：
        #   ① 主动探针 + 跨请求污染信号：这一路的结论还取决于**活体** canary 注册表
        #      （`prior = 注册表 − 本条 canary`），而注册表不在键里 —— 命中缓存等于
        #      把"当时没扫出污染"回放成"现在也没有"，正是最该报的漏检被静默。
        #   ② 被预算截断 / 解析被跳过：残缺结果不是"干净"，缓存它等于把一次过载
        #      放大成整段 TTL 的系统性漏检（既有实现只挡了 truncated，漏了 parse_skipped）。
        _cacheable = not (AUDIT_ACTIVE_PROBES
                          and (AUDIT_SIGNALS or {}).get("cross_request_pollution"))
        if not _cacheable:
            with _AUDIT_STATS_LOCK:
                _AUDIT_RUNTIME["cache_disabled"] += 1
        findings = _audit_cache_get(_cache_key) if (resp_hash and _cacheable) else None
        if findings is None:
            # 响应头文本已在上面取好（它是缓存键的一部分，不能等到这里才算）。
            findings = _audit_scan_signals(flow, status_code, ct, scan_text, scan_req_text,
                                           body_text, _hdrs_text, deadline, _stats,
                                           body_oversize=_body_oversize)
            # 只缓存**完整扫完**的结果：被预算截断的列表是残缺的，缓存它就是
            # 把一次过载放大成 30s 的系统性漏检。
            if resp_hash and _cacheable and not _stats["truncated"] and not _stats["parse_skipped"]:
                _audit_cache_put(_cache_key, findings)
                with _AUDIT_STATS_LOCK:
                    _AUDIT_RUNTIME["cache_store"] += 1
        else:
            _stats["cache_hit"] = True
        _audit_record_timing(t_start, _stats)

        # ⚠️ 槽位级合并（会话作用域）**必须在缓存之外**：`cmd_hits` 属于本次会话，
        # 若把它并进 A-2 的缓存结果，B 会话就会拿到 A 会话的命令证据（跨会话串味）。
        # W2-1 / G1 契约：把**槽位级**命中（带通道来源）与全量 S9 扫描的结果合并。
        #   · 改写模式下命令已被就地替换，全量扫描看不见它们 → 槽位级是唯一来源；
        #   · 非改写模式下两者可能命中同一条命令，此处**以槽位级为准**（它带通道信息），
        #     并从全量结果里摘掉同片段的那条，避免一条命令写两条事件；
        #   · 思考通道的命中**不产生条目**（设计决定：模型在思考里权衡「要不要 rm -rf /」
        #     不是下发命令），但它能压掉全量扫描的对应误报——S9 扫的是混了思考块的
        #     全量拼接文本，这正是 §6.4 记录的既有污染。
        s_cmd = _session_get(sid) or {}
        slot_hits = s_cmd.get("cmd_hits") or []
        reason_snips = s_cmd.get("cmd_reason_snippets") or ()
        if slot_hits or reason_snips:
            slot_snips = [h.get("snippet") for h in slot_hits if h.get("snippet")]
            kept = []
            for f in findings:
                if f.get("signal") != "dangerous_action":
                    kept.append(f)
                    continue
                ev = str(f.get("evidence", ""))
                if any(sn in ev for sn in slot_snips) or any(sn in ev for sn in reason_snips):
                    continue
                kept.append(f)
            findings = kept
        for h in slot_hits:
            findings.append({
                "signal": "dangerous_action",
                # 与 S9 同档：只记不报（恒 LOW，不改档位）。真正“拦住”的是命令拦截本身，
                # 审计只是留痕。
                "severity": _audit.LOW,
                "evidence": (f"{h.get('snippet', '')} [通道={h.get('channel', '')}]"
                             f" [kind={h.get('kind', '')}]"
                             + (" [已阻断]" if h.get("blocked") else "")),
                "kind": str(h.get("kind") or "dangerous_action"),
            })

        # S3 tool_call_rewrite：仅主动探针模式，由 audit_engine 直接判定（需 expected 对照）
        # 此处被动模式跳过（无法区分正常 tool_call 与被改写的）

        # 写库（按 severity_floor 过滤）
        # 先跨信号去重：identity_swap 是逐 chunk 扫的，SSE 一条回复几百个 delta，
        # 同一句「我是 XX」会在多个 chunk 里各命中一次，不去重就是几百条相同告警。
        findings = _audit.dedupe_findings(findings)
        floor = AUDIT_SEVERITY_FLOOR or "MEDIUM"
        probe_id = flow.metadata.get("probe_id")
        for f in findings:
            sev = f.get("severity", _audit.LOW)
            # W2-1 G1：按信号的落库门槛例外。危险动作恒落库（档位仍 LOW），
            # 否则「默认只记录」在默认 floor=MEDIUM 下是空话。
            # 不打扰由三层各自保证：① 告警计数只数 HIGH/CRITICAL；
            # ② 默认事件列表按用户档位 floor 查询（前端传 floor）；
            # ③ 只在视图级 floor=LOW 的时间线（W2-5）里可见。
            if not (_audit.severity_ge(sev, floor) or f.get("signal") in AUDIT_ALWAYS_RECORD):
                continue
            enqueue_audit_event({
                **common,
                "signal_type": f.get("signal", ""),
                "severity": f.get("severity", "LOW"),
                "evidence": f.get("evidence", ""),
                "probe_id": probe_id,
                # A-1/C-1：本次审计的耗时与截断留痕随条目落库，
                # 排障时不必再猜「这条告警是不是扫描被削过的产物」。
                "audit_ms": round(float(_stats.get("ms") or 0.0), 2),
                "audit_scan_bytes": int(_stats.get("scan_bytes") or 0),
                "audit_scan_truncated": bool(_stats.get("truncated")),
            })
            # 审计信号 fail-closed（默认关）：CRITICAL 信号触发时把**本次响应**换成 503。
            # 产品定位是脱敏代理，检测到上游确凿在窃取数据却继续把污染内容交给客户端
            # 逻辑上不自洽（审计规则专项 P2）。
            # ⚠️ 边界（D1 纠偏）：仅替换本次响应，不写配置、不停用 upstream；且
            # 阻断发生在响应阶段——请求早已出网，这层**不防数据外泄**，只防客户端被污染。
            if AUDIT_FAIL_CLOSED and _audit.severity_ge(f.get("severity", _audit.LOW), _audit.CRITICAL):
                # 阻断必须留痕：BLOCK 主事件计入首页 alerts（BLOCK 口径），
                # 此前该路径只有一行 _log，用户盯着 Dashboard 的告警数完全看不到。
                # evidence 已过 _redact_evidence 掩码/摘要（sha256），截断后落 BLOCK，
                # 不含响应正文原文；upstream 只记配置名（flow.metadata 里的 name），不记 URL。
                _emit("BLOCK",
                      reason="audit_critical_signal", block_source="engine",
                      signal=str(f.get("signal", "")),
                      severity=str(f.get("severity", "")),
                      evidence=str(f.get("evidence", ""))[:200],
                      sid=sid, host=host, method=method, path=path.split("?")[0],
                      upstream=flow.metadata.get("shield_upstream") or "",
                      **source)
                block_resp = http.Response.make(
                    503, b'{"error":{"code":"shield_audit_blocked"}}',
                    {"Content-Type": "application/json"}
                )
                if apply_block:
                    flow.response = block_resp
                # _log 只收一个参数；这里原来写的是 _emit_log(msg, "warn")——
                # 该函数在本模块根本不存在，NameError 被外层 except 吞掉，
                # 结果 fail-closed 这条最该留痕的路径反而一行日志都没有。
                _log(f"[audit] fail-closed 阻断：{f.get('signal')} ({str(f.get('evidence', ''))[:80]})")
                break
    except Exception as e:
        # 审计失败永不影响流量 —— 但**不能连自己坏了都不说**。
        # 抽函数时踩过：helper 里引用了调用方的局部变量（NameError），
        # 被这里静默吞掉，审计整条链路无声失效而单测只挂了一条断言。
        # 同类只警告一次，避免刷屏。
        _audit_warn_once("audit_error",
                         f"审计异常已忽略（不影响流量）：{type(e).__name__}: {e}")
        return None
    return block_resp


def _parse_response_payload(body_text, ct):
    """单次解析 JSON/SSE body，产出 (text_chunks, model_field, events)。

    替代原 _extract_response_text + _extract_model_field + _parse_sse_events 三函数，
    避免对同一 body 三重 split + json.loads。
    """
    chunks = []
    model_field = None
    events = []
    is_sse = "event-stream" in ct
    is_json = "json" in ct
    if not body_text or not (is_sse or is_json):
        return chunks, model_field, events
    try:
        if is_sse:
            for line in body_text.split("\n"):
                if not line.startswith("data:"):
                    continue
                # SSE 规范里 `data:` 后的空格是**可选**的（`data:foo` 与 `data: foo` 等价）。
                # 旧实现要求 `data: ` 带空格，且用硬编码偏移 `line[6:]` 取载荷，于是
                # 不带空格的上游（部分网关的 SSE 实现）在 S2/S4 审计里被整段静默跳过
                # （审计 L1）。改成按规范剥掉至多一个前导空格。
                # ⚠️ 只影响审计侧：流式还原走的是另一套解析，本来就不带空格。
                payload = line[5:].lstrip(" ")
                payload = payload.rstrip("\r")
                if payload.strip() == "[DONE]":
                    continue
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                etype = data.get("type")
                events.append({"type": etype, "data": data})
                # model_field from message_start（取首个，恢复旧 _extract_model_field 语义）
                if etype == "message_start" and model_field is None:
                    msg = data.get("message") or {}
                    model_field = msg.get("model") or data.get("model")
                # OpenAI 兼容流式：**每个 chunk 顶层都带 model**，而且没有 `type` 键
                # （OpenAI 格式靠 choices 判别，不写事件名）。只看 message_start 会让
                # model_field 恒为 None → S2 换芯检测在所有 OpenAI 兼容中转上完全失效
                # （gpt-* / deepseek / 各类聚合网关，恰恰是换芯最高发的路径）。
                if model_field is None and isinstance(data, dict):
                    mf = data.get("model")
                    if isinstance(mf, str) and mf.strip():
                        model_field = mf
                # text chunks: Claude content_block_delta
                if etype == "content_block_delta":
                    txt = data.get("delta", {}).get("text", "")
                    if txt:
                        chunks.append(txt)
                # text chunks: OpenAI delta
                for c in data.get("choices", []):
                    d = c.get("delta", {})
                    if isinstance(d.get("content"), str):
                        chunks.append(d["content"])
        else:  # json
            data = json.loads(body_text)
            model_field = data.get("model")
            # OpenAI chat
            for c in data.get("choices", []):
                msg = c.get("message", {})
                if isinstance(msg.get("content"), str):
                    chunks.append(msg["content"])
                elif isinstance(msg.get("content"), list):
                    for p in msg["content"]:
                        if isinstance(p, dict) and isinstance(p.get("text"), str):
                            chunks.append(p["text"])
                for tc in msg.get("tool_calls", []):
                    args = tc.get("function", {}).get("arguments", "")
                    if args:
                        chunks.append(args)
            # Anthropic
            if isinstance(data.get("content"), list):
                for b in data["content"]:
                    if isinstance(b, dict) and isinstance(b.get("text"), str):
                        chunks.append(b["text"])
            if isinstance(data.get("output_text"), str):
                chunks.append(data["output_text"])
            # OpenAI Responses API 非流式
            if isinstance(data.get("output"), list):
                for item in data["output"]:
                    if isinstance(item, dict) and isinstance(item.get("content"), list):
                        for blk in item["content"]:
                            if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                                chunks.append(blk["text"])
    except Exception:
        # 解析失败退回整 body（仅 identity 扫描用）
        chunks = [body_text[:2000]]
    return chunks, model_field, events


def _sweep():
    now = time.time()
    # in-flight 会话（请求已发出、响应未到）默认跳过 TTL 回收：长生成可能远超
    # SESSION_TTL，提前删会让响应到达时查不到 rev → 占位符泄漏（P1-2）。
    #
    # 但豁免不能是无限期的：流式路径的 _finish()/_drop() 只在收到空块时触发，
    # 上游中途断连、连接被中间设备静默丢弃时空块永不到达，error 钩子也未必
    # 上报，该会话会带着 inflight=True 和脱敏原文映射永久驻留内存（实测复现）。
    # 因此再加一道硬上限：ts（每个流块由 _touch 刷新）静默超过 _INFLIGHT_MAX_IDLE
    # 即视为连接已死，强制回收。正常长生成只要还在收数据就会持续 _touch，不受影响。
    dead = []
    # 快照：本函数跑在事件循环线程，而 `sessions` 会被其他线程（panel 的 ext 桥接、
    # 以及 worker 里 `mask()` 的惰性 `_new_session`）插入，直接遍历活字典会抛
    # RuntimeError: dictionary changed size during iteration。
    for sid, s in list(sessions.items()):
        idle = now - s["ts"]
        if s.get("inflight"):
            if idle > _INFLIGHT_MAX_IDLE:
                dead.append(sid)
        elif idle > SESSION_TTL:
            dead.append(sid)
    for sid in dead:
        _drop(sid)
    # 清理过期 canary nonce（按 TTL + 上限）。整段持锁：迭代与 pop 必须原子，
    # 否则会与 request 线程的注册撞出 dict changed size during iteration。
    with _AUDIT_CANARY_LOCK:
        if _AUDIT_CANARY_REGISTRY:
            expired = [n for n, ts in _AUDIT_CANARY_REGISTRY.items() if now - ts > _AUDIT_REGISTRY_TTL]
            for n in expired:
                _AUDIT_CANARY_REGISTRY.pop(n, None)
            # 超上限清最早（按 ts 升序）
            if len(_AUDIT_CANARY_REGISTRY) > _AUDIT_REGISTRY_MAX:
                sorted_items = sorted(_AUDIT_CANARY_REGISTRY.items(), key=lambda kv: kv[1])
                for n, _ in sorted_items[:len(_AUDIT_CANARY_REGISTRY) - _AUDIT_REGISTRY_MAX]:
                    _AUDIT_CANARY_REGISTRY.pop(n, None)


def error(flow):
    """连接/上游异常兜底：清会话 + 按类型记录事件。

    按错误性质区分事件类型（曾全部记 ERR 计入 alerts，正常操作也被当异常）：
    - Client disconnected：客户端断开，可能是用户取消或 SDK 超时，记 CANCEL；
    - getaddrinfo failed：域名解析失败，记 DNS_ERROR；不据此认定故障责任方；
    - 其余连接/协议错误记 ERR。具体阶段以 transport 证据为准。
    """
    cancel_event = getattr(flow, "_shield_mask_cancel", None)
    if cancel_event is not None:
        cancel_event.set()
    _dispose_stream(flow)
    _transport_event("error", flow)
    flow.metadata["transport"] = _safe_transport_snapshot(flow)
    if getattr(flow, "_shield_cancel_reason", None) in (
            "client_cancelled", "client_disconnected", "client_protocol_error"):
        _record_client_cancel(flow, flow.metadata["transport"].get("phase", "unknown"))
    token = _aux_token(flow)
    owned_session = token.session_ref if token is not None else None
    _aux_abandon(flow)
    sid = flow.metadata.get("session_id")
    try:
        host = getattr(flow.request, "host", None) or getattr(flow.request, "pretty_host", "")
        path = flow.metadata.get("shield_orig_path") or getattr(flow.request, "path", "")
        s = _session_get(sid, {}) if sid else {}
        source = s.get("source", {})
        # 诊断串与 `_record_client_cancel` **同一份**（旧版本地各拼一份，导致先落地的
        # 薄记录把这条富记录挡掉，2026-10-02 实测事故）。
        detail, raw = _flow_error_detail(flow)
        if not (sid or raw):
            return
        ev_type = "ERR"
        if "Client disconnected" in raw:
            ev_type = "CANCEL"  # 客户端断开；不能据此推断用户主动操作
        elif "getaddrinfo" in raw or "Name or service not known" in raw:
            ev_type = "DNS_ERROR"  # 上游域名解析失败，属上游侧
        up_name = flow.metadata.get("shield_upstream") or (s.get("upstream_name") if s else "") or ""
        model = flow.metadata.get("shield_model") or (s.get("model") if s else "") or ""
        # 已完成交付的响应，其后的客户端关连接不算取消：连同「取消已记录过」一起去重，
        # 判据与 `_record_client_cancel` 同源（只影响 CANCEL，ERR/DNS_ERROR 口径不变）。
        concluded_cancel = ev_type == "CANCEL" and _response_concluded(flow)
        if not getattr(flow, "_shield_cancel_recorded", False) and not concluded_cancel:
            _emit(ev_type, transport=_transport_snapshot(flow), host=host or "", method=getattr(flow.request, "method", "") or "",
                  path=path.split("?")[0] if isinstance(path, str) else "",
                  sid=sid or "", msg="flow_error:" + detail,
                  failure_owner=_flow_failure_owner(flow, raw),
                  error_type=_flow_error_type(flow),
                  upstream=up_name, model=model, **source)
    except Exception:
        pass
    if sid and not flow.metadata.get("shield_mask_pending"):
        token = _aux_token(flow)
        if token is None:
            _drop(sid)
        elif not token.submitted and owned_session is not None:
            _drop(sid, expect=owned_session)


# ========== mitmproxy hooks ==========


def _clean_tool_enums(body):
    """清洗 tools schema：删除 enum 数组中的非字符串值。

    OpenAI 规范允许 enum 为任意 JSON 值，但 Gemini function_declarations
    要求 enum 是字符串数组；部分中转站/上游转换 tools 时对非字符串 enum
    直接 400 或流式中断（实测 pi 的 subagent 工具 enum 含 False/1）。
    enum 仅作取值提示，删除后不影响 schema 合法性，模型照常生成参数。

    过滤后为空必须**整个删掉 enum 键**，不能留 `enum: []`：空数组的语义是
    「该参数没有任何合法取值」，比不带 enum 更糟——模型会认为无法构造合法
    参数而干脆不调用该工具。boolean/integer 类型的 enum 天然全是非字符串
    （如 `{"type":"boolean","enum":[true,false]}`），是最常见的命中场景。

    返回值：body 是否真的被改动过。调用方据此决定要不要回写请求体 ——
    没改就一个字都不动，保住上游前缀缓存（见 `_mask_hit`）。
    """
    changed = False
    try:
        tools = body.get("tools") if isinstance(body, dict) else None
        if not isinstance(tools, list):
            return False

        def clean(obj):
            nonlocal changed
            if isinstance(obj, dict):
                if isinstance(obj.get("enum"), list):
                    kept = [x for x in obj["enum"] if isinstance(x, str)]
                    if kept:
                        if len(kept) != len(obj["enum"]):
                            changed = True
                        obj["enum"] = kept
                    else:
                        obj.pop("enum", None)  # 全非字符串：删键，不留空数组
                        changed = True
                for v in obj.values():
                    clean(v)
            elif isinstance(obj, list):
                for v in obj:
                    clean(v)

        for t in tools:
            clean(t)
    except Exception:
        pass
    return changed

def _clean_reasoning_effort(body, up_name):
    """标记 reasoning_effort 可疑值，不做删除——透明代理不改下游请求。

    实测根因：pi 在 thinking=off 时发 `reasoning_effort: "none"`（识图等扩展
    调用 mimo-v2.5 时必然携带），部分中转上游只认
    low/medium/high，其余值 400 Bad Request——表现为「同样的请求手动 200、
    插件 400」的假象。这本质是**下游模型配置问题**（pi 的 thinkingLevelMap
    把 off 映射成 "none"），不应由代理删字段掩盖：删字段会改变用户显式
    配置的思考强度语义，且不同模型/上游对取值支持不同，误伤面不可控。
    正确做法：请求原样透传（上游 400 就如实返回），同时标记可疑值，
    事件/面板提示「reasoning_effort=xxx 可能不被上游支持」，引导下游
    排查模型配置（pi 侧改 thinkingLevelMap off→None 即可，实测已生效）。
    返回可疑值字符串（供错误提示用），无则返回 None。
    """
    try:
        if not isinstance(body, dict):
            return None
        re_ = body.get("reasoning_effort")
        if re_ is None:
            return None
        if isinstance(re_, str) and re_ in ("low", "medium", "high"):
            return None
        # 非 low/medium/high（none/minimal/max/非字符串等）：标记，不改请求
        return str(re_) if not isinstance(re_, str) else re_
    except Exception:
        return None


def _reasoning_effort_hint(reasoning_value):
    """生成 reasoning_effort 可疑值的排查提示文案（供事件 msg 用）。"""
    if not reasoning_value:
        return ""
    return (f"reasoning_effort={reasoning_value} 可能不被上游支持"
            f"（部分中转上游仅支持 low/medium/high）；"
            f"请检查客户端模型配置的思考强度映射（pi 侧 thinkingLevelMap off→None）")


# 只给「上游明确拒绝请求体」的状态码附 reasoning_effort 提示：
#   400 参数错误、422 语义不可处理。这两类才可能是「取值不被接受」。
# **不得扩大到 5xx**：2026-10-02 实测，当天 27 条带该提示的事件里 25 条是 524
# （Cloudflare 源站超时：首字节 0、上游耗时 127s）、2 条是 502，全部与思考强度取值
# 无关；提示文案却指向「改客户端模型配置」，把排查方向带歪。
# 也不包含 401/403（鉴权）、413（体积）、429（限流）：它们各有自己的归因。
_REASONING_HINT_STATUSES = frozenset({400, 422})


def _reasoning_effort_hint_for_status(status, reasoning_value):
    """按上游状态码决定要不要给 reasoning_effort 提示（不给则返回空串）。

    抽成独立函数是为了让"哪些状态码配给提示"可被测试钉住：这段判断过去内联在
    事件组装里，只判 `>= 400`，于是超时也被判成参数问题。
    """
    if status not in _REASONING_HINT_STATUSES or not reasoning_value:
        return ""
    return _reasoning_effort_hint(reasoning_value)


# 单请求的语义识别（NER）总预算。值按 **body 体积** 伸缩，而不是一个固定秒数。
#
# 与 `ner_engine.CALL_BUDGET_S` 的区别是层级：那个是「每次调用」的上限，而代理链路
# 一条长会话有几百个字符串叶子，逐叶子各拿一份等于总量无上限。
#
# ⚠️ 曾用固定 2.0s（2026-09-24）：那时它同时承担「防止冻住事件循环」与「限流」两个
# 职责。冻机问题已由脱敏 offload 到专职线程解决（见 `_MASK_POOL`），而 NER 成本与
# 正文长度近似线性（实测约 11µs/字节中文）——2.0s 在 200 条/43KB 的长会话上会让
# **96/200 个「只有 NER 能识别」的中文人名明文出网**（实测，审计 2026-09-24）。
# 产品承诺是「不泄漏」优先于「快」，所以预算现在只做一件事：病态输入别把脱敏线程池
# 占掉几分钟（32MB 请求体全量 NER 约 6 分钟）。
#
# 取值依据（`tests/measure_ner_coverage.py` 可复现，均为冷缓存实测）：
# 单位成本 ≈ **93µs/字节**中文（≈0.28ms/字）—— 43KB ≈ 3.4s、60KB ≈ 5.6s、1MB ≈ 90s；
# 缓存命中后稳态 ≈ 1ms。因此 10s 打底 + 120s/MB，**封顶默认 10s（可配置）**：
# 常见会话（≤100KB）能跑完；超过封顶的请求会降级，但**看得见**。
# ⚠️ 别再凭印象写小这个系数：早期注释把单位成本写成 11µs/字节（差 8 倍），若按那个
# 算，每 MB 只给 20s，等于对大 body 静默停手 —— 又一次「以为脱了、其实没脱」。
# 超预算只停用语义识别，确定性规则（正则/词表）照常生效，**且跳过会被如实写进
# MASK 事件**（ner_truncated / ner_skip_reasons），不再静默降级。
_NER_REQ_BUDGET_BASE_S = 10.0
_NER_REQ_BUDGET_PER_MB_S = 120.0
# 单请求 NER 预算的**封顶值**（秒，可配置）。
#
# 为什么把默认值从 60s 压到 10s（P0-a，2026-09-28 实测事故）：
# 60s 封顶 = 「允许单条请求的脱敏吃满 60 秒」，而客户端（Pi/编程代理）的解包超时
# 是 180s，还要给上游首包留位。实测同一条 1.76MB 请求：脱敏冷缓存 58.5s +
# 上游首包 91.7s ≈ 150s；而热缓存的那条（脱敏 0.4s）仍然在 180s 超时 —— 说明
# 上游首包不可控（同批 328 条成功请求 p50 6.4s、max 99.8s），脱敏必须节约着用，
# 而不是占掉三分之一的超时窗口。
# 默认 10s 与 `BASE` 相同 ⇒ **任何单条请求的语义识别至多 10 秒**；
# 代价是大 body 会更多降级（提前出现 budget_exhausted），这是「用可接受的漏码换
# 响应时间」的明确产品取舍（已与所有者确认），且降级**写进事件**不会静默。
# 想换回宽裕口径：面板设置页 `ner_req_budget_s`，或环境变量硬覆盖（容器/CI 用）。
_NER_REQ_BUDGET_MAX_DEFAULT_S = 10.0
# 硬上限：上限本身也得有上限，否则一个手改的 config.json 就能把引擎拉回 0.6.0
# 的形态（32MB 请求体全量 NER 约 6 分钟）。
_NER_REQ_BUDGET_MAX_HARD_S = 120.0
# 环境变量硬覆盖（存在时配置改不动）——与 `MASKIT_ENGINE_DEADLINE_S` 同类：
# 容器/CI 需要把参数固定住，而配置里的值可能被 UI 操作改掉。
_NER_REQ_BUDGET_MAX_ENV = None
try:
    _raw_budget_env = (os.environ.get("MASKIT_NER_REQ_BUDGET_S") or "").strip()
    _NER_REQ_BUDGET_MAX_ENV = float(_raw_budget_env) if _raw_budget_env else None
except ValueError:
    _NER_REQ_BUDGET_MAX_ENV = None
_NER_REQ_BUDGET_MAX_S = _clamp_float(
    _NER_REQ_BUDGET_MAX_ENV, _NER_REQ_BUDGET_MAX_DEFAULT_S, 1.0, _NER_REQ_BUDGET_MAX_HARD_S)


def _norm_ner_req_budget(raw):
    """单请求 NER 预算上限的取值口径（配置热重载与 `set_ner_req_budget` 共用）。

    非数字 / NaN / 非正数 → 回落默认；正数超范围 → 钳到硬上限。
    与面板 `panel._normalize_ner_budget` 同口径（跨进程无法共享函数，靠测试钉住两边一致）。
    """
    try:
        n = float(raw)
    except (TypeError, ValueError):
        return _NER_REQ_BUDGET_MAX_DEFAULT_S
    if n != n or n <= 0:                 # NaN / 0 / 负数
        return _NER_REQ_BUDGET_MAX_DEFAULT_S
    return max(1.0, min(_NER_REQ_BUDGET_MAX_HARD_S, n))


def set_ner_req_budget(seconds):
    """更新单请求 NER 预算上限（秒），返回实际生效值。

    优先级：环境变量 `MASKIT_NER_REQ_BUDGET_S` > 配置 `ner_req_budget_s` > 默认 10s。
    环境变量存在时本函数不改任何东西（硬覆盖），否则容器里会“时而生效时而不生效”。
    """
    global _NER_REQ_BUDGET_MAX_S
    if _NER_REQ_BUDGET_MAX_ENV is not None:
        return _NER_REQ_BUDGET_MAX_S
    _NER_REQ_BUDGET_MAX_S = _norm_ner_req_budget(seconds)
    return _NER_REQ_BUDGET_MAX_S


def _ner_req_budget(body_bytes):
    """按请求体体积给单请求的 NER 总预算（秒）。纯函数（只读模块级上限），便于直接断言。

    上限是**运行时可变**的（见 `set_ner_req_budget`），所以这里不能把上限写成默认参数
    或提前绑定的局部量。
    """
    mb = max(0.0, float(body_bytes or 0)) / (1024.0 * 1024.0)
    return min(_NER_REQ_BUDGET_MAX_S,
               _NER_REQ_BUDGET_BASE_S + mb * _NER_REQ_BUDGET_PER_MB_S)

# 脱敏重活专用线程池（池宽按核数自适应 1~4，见 _default_mask_workers）。
#
# 为什么必须离开事件循环：`request` 若同步执行，mitmproxy 12 的
# `addonmanager.invoke_addon` 就是直接在**事件循环线程**里 `res = func(*event.args())`
# （全仓无 to_thread / run_in_executor）。一次 20 秒的脱敏会把全部 upstream 端口
# 一起冻住，在途请求的上游连接被上游/中间设备判死断开，客户端看到的是引擎自己
# 渲染的 502 Bad Gateway + `connection closed`（2026-09-24 实测事故，此前被误判成
# 上游故障）。offload 之后，排队只增加该请求自身的延迟，不再牵连其他连接。
#
# workers 宽度自 0.6.0 起可配（MASKIT_MASK_WORKERS，默认按核数自适应）。
# 之所以现在敢放开：会话态的并发契约已经在 0.6.0 里逐字段定下来
# （见文件上方「B-1a：sessions[sid] 的并发契约」），NER 也不再是"每个 worker
# 各自抢 ONNX 线程"——进程级信号量 + 令牌桶把推理收敛成受控的固定并发
# （ner_engine 的 _NER_CONCURRENCY / _NER_BUDGET_MS_PER_S）。
#
# 残留窗口（已知、已评估）：线程里跑的同时，事件循环上的下一个请求会执行
# `_maybe_reload()` / `_sweep()`。前者会重建词表（就地 clear/update），若刚好压在
# 本线程遍历词表的瞬间会抛异常 —— 走既有 fail-closed 分支阻断，**不会**放行原文；
# 后者只在会话空闲超过 TTL 时回收，本次会话刚建，不受影响。
def _available_cpu_count():
    """本进程**实际可用**的核数（cgroup 配额 ∩ 亲和性掩码），拿不到就回落宿主核数。

    池宽也必须用这个而不是 `os.cpu_count()`：16 核宿主上 `docker run --cpus=2` 时
    后者返回 16，于是脱敏池开 4 个 worker、aux 池再开 4 个 —— **2 个核上摞 8 个线程**，
    比 NER 线程数超配更严重（NER 那边已经改为同一判据，两处必须同源）。
    判据本体在 `ner_engine.effective_cpu_count()`：那里已经把 cgroup v1/v2 配额与
    亲和性两种情形都写了单测，不复刻一份（复刻的那份迟早会与它漂）。
    """
    try:
        import ner_engine
        return max(1, int(ner_engine.effective_cpu_count()))
    except Exception:
        return max(1, int(os.cpu_count() or 2))


def _default_mask_workers():
    """脱敏池默认宽度（§8.1 定稿）。

    弱机（≤2 核）恒为 1：多 worker 在那种机器上只会互相抢核，还放大内存与
    ONNX 线程数。其余机器取 min(4, max(2, 核数 // 2)) —— 这一段（JSON 解析 +
    规则扫描）是百毫秒级的 CPU 活，4 个 worker 也压不满现代 CPU，收益主要体现在
    "NER 期间不再让其他请求排队"。

    「弱机」按**实际可用**核数判（见 `_available_cpu_count`）：否则一个 `--cpus=2`
    的容器会在 16 核宿主上被判成“好机器”，拿到 4 个 worker。
    """
    if MASKIT_MASK_WORKERS_ENV:
        return max(1, min(16, MASKIT_MASK_WORKERS_ENV))
    cores = _available_cpu_count()
    if cores <= 2:
        return 1
    return max(2, min(4, cores // 2))


# 池宽与队列预算（环境变量在导入时读一次；set_mask_workers 供压测脚本动态调整）
MASKIT_MASK_WORKERS_ENV = _env_int("MASKIT_MASK_WORKERS", 0)
_MASK_WORKER_COUNT = _default_mask_workers()
_MASK_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=_MASK_WORKER_COUNT, thread_name_prefix="maskit-mask")
# A-6/B-4：**按字节**限制"已提交但还没开跑"的请求体总量。
# 为什么不是条数：单条上限 32MB，`4×workers` 条在最坏情况下就是 512MB 常驻
# （而 B-4 的字节预算当时排在更后面的提交里）。按字节可以给出一个能算出来的上界：
#   最坏常驻 ≈ 正在跑的 workers × 32MB + queue_bytes（默认 workers × 8MB）。
# ⚠️ 下限必须是**单条 body 上限**（`_MAX_REQUEST_BODY`），不能只是 1MB：
# 准入判据是 `queued_bytes + nbytes > 预算`，而 nbytes 就是这条请求自己的大小 ——
# 预算比单条上限还小时，那条请求**永远**被自己顶出去（workers=1 时预算 8MB < 单条 32MB，
# 于是 8~32MB 的 body 在 1~2 核机器上恒定 engine_busy，空闲机器也一样）。
# 预算的用途是限制**堆积**（多条同时排队），不是限制单条：单条已由体积闸门兜住。
def _mask_queue_bytes_for(limit_bytes):
    """排队字节预算 = max(单条上限, 环境变量/池宽默认)，见上方注释的下限理由。"""
    return max(int(limit_bytes), _env_int(
        "MASKIT_MASK_QUEUE_BYTES", _MASK_WORKER_COUNT * 8 * 1024 * 1024))


_MASK_QUEUE_BYTES = _mask_queue_bytes_for(_MAX_REQUEST_BODY)
# 同时在飞的请求条数上限：即使 body 都很小，条数也要有界（防线程池队列无界增长）
_MASK_MAX_INFLIGHT = max(4, _MASK_WORKER_COUNT * 4)
_MASK_ADMISSION_LOCK = threading.Lock()
_MASK_ADMISSION = {"queued_bytes": 0, "inflight": 0, "busy": 0, "peak_queue_bytes": 0}
# 端到端超时计数（B-5）：busy 是"没准入"，timeout 是"准入了但迟迟不回来"，两者要分开看。
_MASK_TIMEOUTS = {"count": 0, "peak_wait_ms": 0.0}
# 下限 5s：0 会让每个请求都 engine_timeout，负数会让 wait_for 抛 ValueError
# （被最外层 fail-closed 兜成 503 mask_pipeline_failed）—— 都是"整个网关不可用"的配置事故，
# 由环境变量误写触发，所以在这里夹住（其余旋钮如 NER 预算同样有下限）。
_ENGINE_DEADLINE_S = max(5.0, float(_env_float("MASKIT_ENGINE_DEADLINE_S", 120.0)))
# 上游建连 / TLS 握手的**预算**（秒）。mitmproxy 12.2.3 在 `proxy/server.py:212` 直接
# `await asyncio.open_connection(...)`，既没有 timeout 也没有 wait_for，所以一条被丢包的
# 握手会一路走到内核 SYN 重传梯（实测 ≈127 s），而客户端在 180 s 整放弃 —— 用户看到的是
# 一句无信息量的 `Request timed out.`。addon 侧也拦不住它：`flow.kill()` 与写
# `flow.response` 都不改变客户端等待（黑洞实测 45s/50s 均拿到 0 字节）。
# 有效的执行点是取消「正在建立这一跳的那个 task」：mitmproxy 自己的
# `open_connection` 捕获 CancelledError 后会落 `server_connect_error` → 给客户端一个
# 干净的 502（实测：8 次连续熔断后客户端连接仍可用、`max_conns` 信号量不泄漏）。
# 20 s 的取值来自实测分布：健康握手 0.5–1.8 s，家里最坏一次**成功**握手 13.1 s，
# 留 1.5x 余量；卡过 20 s 的那一跳剩下的是 4/8/16/32/64 s 的重传梯，掐掉让客户端
# 立刻重试，比让它赌 127 s 好。熔断只在「请求尚未写出」时发生（判据见
# `ConnectionGovernance.stalled_before_send`），推理模型首包几分钟的请求完全豁免。
_CONNECT_STALL_S = _connect_budget(_env_float("MASKIT_CONNECT_STALL_S", 20.0))
# 关掉它（`MASKIT_CONNECT_KILL=0`）= 退回纯观测：仍然统计、仍然归因，只是不落刀。
_CONNECT_KILL = _env_int("MASKIT_CONNECT_KILL", 1) != 0 and _CONNECT_STALL_S > 0


def set_mask_workers(n):
    """重建脱敏池（压测脚本 `--workers N` 与未来的运行时调参用）。

    不提供"减容"语义：线程池无法安全收缩，只能整体换新（在飞任务由旧池跑完）。
    """
    global _MASK_POOL, _MASK_WORKER_COUNT, _MASK_QUEUE_BYTES, _MASK_MAX_INFLIGHT
    n = max(1, min(16, int(n or 1)))
    if n == _MASK_WORKER_COUNT:
        return _MASK_WORKER_COUNT
    old = _MASK_POOL
    _MASK_WORKER_COUNT = n
    # 与模块级同口径（见 _MASK_QUEUE_BYTES 的注释）：下限必须是单条 body 上限，
    # 否则换池之后大 body 的请求又会被自己的体积顶出去（恒定 engine_busy）。
    _MASK_QUEUE_BYTES = _mask_queue_bytes_for(_MAX_REQUEST_BODY)
    _MASK_MAX_INFLIGHT = max(4, _MASK_WORKER_COUNT * 4)
    _MASK_POOL = concurrent.futures.ThreadPoolExecutor(
        max_workers=n, thread_name_prefix="maskit-mask")
    try:
        old.shutdown(wait=False)
    except Exception:
        pass
    return n


def set_max_request_body(mb=None):
    """设置单条请求体上限（MiB，§H4a）。默认 32，范围 1~256。返回生效字节数。

    与面板侧 `_clamp_max_request_body_mb` 同口径（两处各写一份，靠
    `ConstantParityTests` 钉住）。抬高上限会同时抬高两样东西：
      · 内存预算：最坏常驻 ≈ 池宽 × 单条上限；
      · 单条脱敏耗时：实测 ≈112 ms/MiB（GIL 串行化的纯 Python + re）。
    因此排队字节预算必须跟着抬（`_MASK_QUEUE_BYTES` 的下限就是单条上限，
    否则大 body 会被自己的体积顶出准入，空闲机器也恒定 engine_busy）。
    """
    global _MAX_REQUEST_BODY, _MASK_QUEUE_BYTES
    if mb is None:
        _MAX_REQUEST_BODY = _DEFAULT_MAX_REQUEST_BODY
    else:
        try:
            n = int(float(mb))
        except (TypeError, ValueError):
            n = 32
        n = max(1, min(256, n))
        _MAX_REQUEST_BODY = n * 1024 * 1024
    _MASK_QUEUE_BYTES = _mask_queue_bytes_for(_MAX_REQUEST_BODY)
    return _MAX_REQUEST_BODY


def _mask_admit(nbytes):
    """准入判定（A-6/B-4）：字节预算 + 条数上限，**必须在任何签发副作用之前**。

    返回 True 表示已占额，调用方必须在 worker 真正开跑时调用 `_mask_release`
    把"排队中"的名额换成"在跑"（字节数在开跑时就减掉，队列预算只约束排队）。
    """
    with _MASK_ADMISSION_LOCK:
        if (_MASK_ADMISSION["queued_bytes"] + nbytes > _MASK_QUEUE_BYTES
                or _MASK_ADMISSION["inflight"] >= _MASK_MAX_INFLIGHT):
            _MASK_ADMISSION["busy"] += 1
            return False
        _MASK_ADMISSION["queued_bytes"] += max(0, int(nbytes))
        _MASK_ADMISSION["inflight"] += 1
        if _MASK_ADMISSION["queued_bytes"] > _MASK_ADMISSION["peak_queue_bytes"]:
            _MASK_ADMISSION["peak_queue_bytes"] = _MASK_ADMISSION["queued_bytes"]
        return True


def _mask_release(nbytes):
    """请求彻底结束（成功/失败/超时）时归还 **in-flight 名额**。

    ⚠️ 这里**不再**扣 `queued_bytes`（0.6.0 修）：排队的字节在 worker 开跑时已由
    `_mask_dequeued` 扣过一次，再扣一次会抹掉**别的请求**的排队字节 —— 并发下
    `queued_bytes` 会系统性偏小，B-4 的内存天花板随之失效（实测：A 出队后 B 入队，
    A 结束时 B 的字节被抹成 0）。`nbytes` 参数保留是为了调用点签名一致与可读性，
    不再参与扣减。
    """
    with _MASK_ADMISSION_LOCK:
        _MASK_ADMISSION["inflight"] = max(0, _MASK_ADMISSION["inflight"] - 1)


def _mask_abandon(nbytes):
    """请求**从未开跑**就被放弃（提交进线程池失败）时归还全部名额。

    单独的入口是必须的：worker 没跑 → 它的 `finally` 不会执行 → `_mask_dequeued`
    与 `_mask_release` 都不会被调用。只还 inflight 会漏掉排队字节（内存预算被
    永久占用），只还不扣字节会漏掉名额（准入池被锁死）。两者都在这里还。
    """
    with _MASK_ADMISSION_LOCK:
        _MASK_ADMISSION["inflight"] = max(0, _MASK_ADMISSION["inflight"] - 1)
        _MASK_ADMISSION["queued_bytes"] = max(0, _MASK_ADMISSION["queued_bytes"] - max(0, int(nbytes)))


def _mask_dequeued(nbytes):
    """worker 真正开跑：从"排队字节"里扣掉（在跑的由 workers 数量天然有界）。"""
    with _MASK_ADMISSION_LOCK:
        _MASK_ADMISSION["queued_bytes"] = max(0, _MASK_ADMISSION["queued_bytes"] - max(0, int(nbytes)))


def mask_pool_stats():
    """脱敏池/队列指标（C-1 的 /api/engine/metrics + 一键自检都读这里）。"""
    depth = None
    try:
        depth = int(_MASK_POOL._work_queue.qsize())
    except Exception:
        depth = None
    with _MASK_ADMISSION_LOCK:
        adm = dict(_MASK_ADMISSION)
        # 快照必须与写入持**同一把锁**：`count` / `peak_wait_ms` 由工作线程与事件循环
        # 线程更新，锁外读会拿到半更新值（典型是“计数已加、峰值还是旧的”）。
        adm["engine_timeouts"] = _MASK_TIMEOUTS["count"]
        adm["peak_wait_ms"] = round(float(_MASK_TIMEOUTS["peak_wait_ms"]), 1)
    adm.update({
        "workers": _MASK_WORKER_COUNT,
        "queue_bytes_limit": _MASK_QUEUE_BYTES,
        "max_inflight": _MASK_MAX_INFLIGHT,
        "queue_depth": depth,
        "deadline_s": _ENGINE_DEADLINE_S,
        "busy_total": adm.get("busy", 0),
    })
    return adm


async def _await_with_deadline(fut, timeout_s, cancel_signal=None):
    """Wait without cancelling the actual worker; client abort still completes the hook."""
    if cancel_signal is None:
        return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout_s)
    shielded = asyncio.shield(fut)
    aborted = asyncio.create_task(cancel_signal.wait())
    try:
        finished, _ = await asyncio.wait((shielded, aborted), timeout=max(0.0, timeout_s),
                                         return_when=asyncio.FIRST_COMPLETED)
        # Surface waiter failures instead of misreporting them as timeouts.
        if aborted in finished:
            aborted.result()
        # Client termination wins a simultaneous worker completion: no late success.
        if cancel_signal.is_set():
            raise _ClientFlowCancelled()
        if shielded in finished:
            return shielded.result()
        raise asyncio.TimeoutError()
    finally:
        if shielded.done() and not shielded.cancelled():
            shielded.exception()
        else:
            shielded.cancel()  # only the shield wrapper, never the running worker
        aborted.cancel()
        await asyncio.gather(aborted, return_exceptions=True)


_RUNTIME_METRICS_FILE = "engine-runtime.json"
_RUNTIME_METRICS_MIN_INTERVAL_S = 30.0
_RUNTIME_METRICS_LAST = [0.0]
_RUNTIME_METRICS_LOCK = threading.Lock()


def write_runtime_metrics(force=False):
    if not _RUNTIME_METRICS_LOCK.acquire(blocking=False):
        return False
    try:
        return _write_runtime_metrics(force)
    finally:
        _RUNTIME_METRICS_LOCK.release()


def _write_runtime_metrics(force=False):
    """把本进程的运行指标写进数据目录（面板的 /api/engine/metrics 与自检读它）。

    请求路径节流到 30s，独立心跳在无请求时也刷新。文件 I/O 只在线程中执行；
    写失败不影响转发，也不会把旧快照伪装成新数据。
    """
    now = time.time()
    if not force and now - _RUNTIME_METRICS_LAST[0] < _RUNTIME_METRICS_MIN_INTERVAL_S:
        return False
    _RUNTIME_METRICS_LAST[0] = now
    try:
        payload = {
            "schema": 1,
            "generated_at": int(now),
            "pid": os.getpid(),
            "mask_pool": mask_pool_stats(),
            "aux_pool": aux_pool_stats(),
            "audit": audit_runtime_stats(),
            "engine_deadline_s": _ENGINE_DEADLINE_S,
            "connect": dict(_CONNECT_STALL, stall_after_s=_CONNECT_STALL_S,
                            actuating=_CONNECT_KILL, kills=dict(_CONNECT_KILL_TOTAL)),
            "transport": dict(_CONNECTION_STATS),
            "heartbeat": dict(_HEARTBEAT),
        }

        # 敏感词表：**引擎里真正生效的词数**与**问题清单**（词 -> 原因）。
        # 必须由引擎进程产生：panel 是另一个进程，它只能看到配置里"写了多少词"，
        # 看不到引擎里"真正生效了几个词"。2026-09-30 那次「整表静默失效」正是因为
        # 这个差异没有任何出口 —— 面板显示一切正常，用户却什么都脱敏不了。
        payload["word_table"] = {
            "count": len(CUSTOM_WORDS),
            "issues": word_table_issues(),
        }
        # 内存映射规模（§D3.3「清空内存映射」按钮旁边要显示“现在有多少东西可清”）。
        # 引擎是代理链路的真值源，面板只能看到它自己那份（扩展桥接）。
        payload["mappings"] = mapping_stats()
        try:
            import ner_engine
            payload["ner"] = {
                "enabled": bool(NER_ENABLED),
                # 当前生效的单请求预算上限（秒）：面板与自检不再需要猜它到底是 10s 还是
                # 环境变量硬覆盖成了别的值。
                "req_budget_s": float(_NER_REQ_BUDGET_MAX_S),
                "budget_env_override": _NER_REQ_BUDGET_MAX_ENV is not None,
                "available": bool(ner_engine.is_ner_available()),
                "initialized": bool(getattr(ner_engine, "_INITIALIZED", False)),
                "failed": bool(getattr(ner_engine, "_INIT_FAILED", False)),
                "last_error": str(getattr(ner_engine, "_LAST_ERROR", "") or "")[:300],
                "governor": ner_engine.governor_status(),
                # C-2：缓存命中/未命中（含超长文本分段次数）。冷热差实测 138 倍，
                # 没有这组计数就只能靠人肉翻事件库对比两条 mask_ms。
                "cache": ner_engine.cache_stats(),
            }
        except Exception as e:
            payload["ner_error"] = "%s: %s" % (type(e).__name__, e)
        tmp = _DATA_ROOT / (_RUNTIME_METRICS_FILE + ".tmp")
        dst = _DATA_ROOT / _RUNTIME_METRICS_FILE
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(str(tmp), str(dst))     # 原子替换：读者不会看到半截 JSON
        return True
    except Exception as e:
        _audit_warn_once("runtime_metrics_write",
                         f"运行指标写入失败（面板的引擎指标会显示为过期）：{type(e).__name__}: {e}")
        return False


def _retry_after_seconds():
    """busy 时的 Retry-After：**带抖动**，不能固定 1s。

    固定值会让所有被拒客户端在同一时刻一起重试（正是本次故障里"503 重试风暴"
    的形态）；抖动把重试摊开，指数上限避免无限等待。1~3s。
    """
    return round(1.0 + random.random() * 2.0, 2)

# A-3：响应侧重活在独立池执行，准入覆盖等待上游、排队和运行全生命周期。
# worker 数限制 CPU 并发，条数/字节预算限制保留的任务输入。
def _aux_pool_width():
    """保守的启动宽度；运行时不替换执行器。

    同样按**实际可用**核数判（见 `_available_cpu_count`）：aux 池与脱敏池会同时
    干活，两个池各自按宿主核数开 4，在 2 核容器上就是 8 个线程抢 2 个核。
    """
    cores = _available_cpu_count()
    default = 1 if cores <= 2 else max(2, min(4, cores // 2))
    try:
        override = int(os.environ.get("MASKIT_AUX_WORKERS", "0"))
        return max(1, min(4, override)) if override else default
    except (TypeError, ValueError):
        return default


_AUX_MAX_INFLIGHT = _aux_pool_width()
# Reservations cover upstream-inflight, queued AND running jobs. 1 MiB is the
# worst-case UTF-8 retained SSE window, not a speculative 32 MiB per response.
# Queued jobs charge actual wire bytes; the worker atomically charges decoded
# bytes before retaining them. A separate SINGLE decode workspace permits bounded
# expansion before that charge: <=2 * admitted request/response ceiling + 32 MiB
# codec window + 64 KiB Brotli chunk slack. Request ceiling is its already-charged
# masked size (which may exceed the 32 MiB incoming/response cap).
# Parse-tree expansion and session/reuse tables have separate limits.
_AUX_MAX_JOBS = 64
_AUX_MAX_BYTES = 128 * 1024 * 1024
_AUX_RESPONSE_MAX = 32 * 1024 * 1024
_AUX_BASE_BYTES = 4 * _SSE_KEEP_MAX
# Allocations inside admission may run cyclic finalizers that release an older
# token. Reentrancy is required even though ordinary callers are serialized.
_AUX_BUDGET_LOCK = threading.RLock()
_AUX_DECODE_LOCK = threading.Lock()
_AUX_JOBS = 0
_AUX_BYTES = 0
_AUX_SESSION = threading.local()


def _session_get(sid, default=None):
    owned = getattr(_AUX_SESSION, "owned", None)
    if owned is not None and owned[0] == sid:
        return owned[1] if owned[1] is not None else default
    return sessions.get(sid, default)


@contextlib.contextmanager
def _aux_session(sid, session_ref):
    old = getattr(_AUX_SESSION, "owned", None)
    _AUX_SESSION.owned = (sid, session_ref)
    try:
        yield
    finally:
        _AUX_SESSION.owned = old


class _AuxReservation:
    def __init__(self, size, owner_id=None):
        self.size = size
        self.owner_id = owner_id
        self.request_size = 0
        self.submitted = False
        # Uncharged construction is safe even if GC runs or allocation fails.
        self.released = True
        self.future = None
        self.abandoned = False
        self.session_ref = None

    def __deepcopy__(self, memo):
        # A generic Python copy may copy runtime attrs too. _aux_token's owner
        # check prevents that copy from consuming or releasing this owner's quota.
        return self

    def __del__(self):
        # Submitted jobs retain their owner until actual completion. Avoid even
        # acquiring the lock for the common already-released finalizer case.
        if not self.released and not self.submitted:
            self.release()

    def release(self):
        global _AUX_JOBS, _AUX_BYTES
        with _AUX_BUDGET_LOCK:
            if self.released:
                return
            self.released = True
            _AUX_JOBS -= 1
            _AUX_BYTES -= self.size
            self.future = None
            self.session_ref = None

    def retain_response(self, size):
        """Charge actual wire + decoded bytes before they leave decode workspace."""
        global _AUX_BYTES
        with _AUX_BUDGET_LOCK:
            desired = self.request_size + max(_AUX_BASE_BYTES, size)
            extra = max(0, desired - self.size)
            if self.released or _AUX_BYTES + extra > _AUX_MAX_BYTES:
                raise RuntimeError("aux decoded byte budget exceeded")
            _AUX_BYTES += extra
            self.size += extra


def _aux_token(flow):
    """Runtime-only ownership: never serialized by Flow.get_state/copy/FlowWriter."""
    token = getattr(flow, "_shield_aux_reservation", None)
    return token if token is not None and token.owner_id == id(flow) else None


def _message_bytes(message):
    if message is None:
        return b""
    raw = getattr(message, "raw_content", None)
    return raw if raw is not None else (getattr(message, "content", None) or b"")


class _AuxBody:
    """Immutable wire input; decode at most once, only after entering the worker."""
    def __init__(self, message, *, request=False, limit=None, token=None):
        self.raw_content = _message_bytes(message)
        headers = getattr(message, "headers", {})
        self.headers = ({"content-encoding": headers.get("content-encoding", "identity")}
                        if request else copy.deepcopy(headers))
        self.status_code = getattr(message, "status_code", 0)
        self._content = None
        self._decode_error = False
        self._limit = _AUX_RESPONSE_MAX if limit is None else limit
        self._token = token if not request else None

    @property
    def content(self):
        if self._content is None:
            if self._decode_error:
                raise ValueError("aux body decoding previously failed")
            # Only one bounded, not-yet-charged decoding workspace may exist.
            # No decompression or large body copying runs on the event loop.
            with _AUX_DECODE_LOCK:
                content = None
                try:
                    content = decode_body(self.raw_content,
                                          self.headers.get("content-encoding") or "identity",
                                          self._limit)
                    if self._token is not None:
                        retained = len(self.raw_content)
                        if content is not self.raw_content:
                            retained += len(content)
                        self._token.retain_response(retained)
                    self._content = content
                    self._token = None
                except Exception as exc:
                    # A failed Future retains exception tracebacks. Do not let
                    # them retain an uncharged decode workspace after this lock.
                    content = None
                    self._decode_error = True
                    self._token = None
                    exc.__traceback__ = exc.__cause__ = exc.__context__ = None
                    raise exc from None
        return self._content


def _aux_request_size(flow):
    request = getattr(flow, "request", None)
    wire = len(_message_bytes(request))
    decoded = flow.metadata.get("shield_request_decoded_bytes", wire)
    kind = ((getattr(request, "headers", {}).get("content-encoding") or "identity").lower())
    return (max(wire, decoded) if kind in ("identity", "none") else wire + decoded), decoded


def _aux_reserve(flow, response_bytes=None):
    global _AUX_JOBS, _AUX_BYTES
    token = _aux_token(flow)
    request_size, _ = _aux_request_size(flow)
    size = request_size + max(_AUX_BASE_BYTES, response_bytes or 0)
    with _AUX_BUDGET_LOCK:
        if token is not None and token.released:
            token = None  # A completed in-place replay obtains a fresh owner.
        if token is not None and token.submitted:
            return None  # Never steal capacity from a live job on replay/reset.
        extra = size - token.size if token else size
        rejected = ((not token and _AUX_JOBS >= _AUX_MAX_JOBS) or
                    _AUX_BYTES + extra > _AUX_MAX_BYTES or
                    (response_bytes or 0) > _AUX_RESPONSE_MAX)
        if not rejected:
            if token is None:
                token = _AuxReservation(size, id(flow))
                token.session_ref = _session_get(flow.metadata.get("session_id"))
                _AUX_JOBS += 1
                token.released = False
                flow._shield_aux_reservation = token
            else:
                token.size = size
            token.request_size = request_size
            _AUX_BYTES += extra
            return token
    # Never take the stats lock while holding the budget lock: a stats allocation
    # may run a cyclic finalizer that needs the budget lock on another thread.
    _aux_stat_add("rejected")
    return None


def _aux_abandon(flow):
    """Loop-owned abort: a running job retains its reservation until completion."""
    token = _aux_token(flow)
    if token is not None:
        if not token.submitted:
            token.release()
        else:
            # Future.cancel() leaves a WorkItem (and all args) in the executor
            # queue. Releasing here would allow an unbounded cancel/submit storm.
            # Skip queued work when dequeued; retain capacity until then.
            token.abandoned = True


def _aux_snapshot(flow):
    # No mutable live flow, response, headers or metadata reach a worker. Immutable
    # bytes are shared safely; metadata excludes the lifecycle token.
    resp = getattr(flow, "response", None)
    token = _aux_token(flow)
    _, request_limit = _aux_request_size(flow)
    return SimpleNamespace(
        request=_AuxBody(getattr(flow, "request", None), request=True,
                         limit=request_limit),
        response=_AuxBody(resp, token=token) if resp else None,
        metadata=copy.deepcopy({k: flow.metadata[k] for k in (
            "session_id", "shield_model", "shield_upstream", "probe_id",
            "audit_canaries", "shield_reasoning_effort", "shield_stream_degraded",
            "shield_stream_requested", "shield_streamed", "transport") if k in flow.metadata}))


def _aux_submit(token, sid, session_ref, fn, *args):
    """Exactly one bounded submission and one actual-completion resource owner."""
    if token is None or token.released or token.submitted:
        raise RuntimeError("aux reservation unavailable")
    token.submitted = True
    with _AUX_PENDING_LOCK:
        _AUX_PENDING[0] += 1

    def run():
        if token.abandoned:
            _aux_stat_add("cancelled_queued")
            return None
        with _aux_session(sid, session_ref):
            return fn(*args)

    def done(future):
        nonlocal session_ref, args, fn
        try:
            if not future.cancelled():
                future.exception()
        finally:
            try:
                if session_ref is not None:
                    _drop(sid, expect=session_ref)
            finally:
                # Futures retain done callbacks after execution. Clear closure
                # cells too, not merely token fields; GC/refcount timing is irrelevant.
                session_ref, args, fn = None, (), None
                token.release()
                with _AUX_PENDING_LOCK:
                    _AUX_PENDING[0] -= 1

    try:
        future = _AUX_POOL.submit(run)
        token.future = future
    except BaseException:
        token.release()
        with _AUX_PENDING_LOCK:
            _AUX_PENDING[0] -= 1
        raise
    future.add_done_callback(done)
    return future


# 预览/对话抽取的源文本上限：两个 helper 的输出上限是 800B / 4000 字，源文本给到
# 256KB 早已远超需要（含超长 SSE 首包）。见 _emit_restore_summary 的注释。
_PREVIEW_SRC_MAX = 64 * 1024
# 审计文本探测的字节数上限：要覆盖 `AUDIT_SCAN_MAX` 个**字符**的最坏情况（UTF-8 最长
# 4 字节/字），多留 4 字节让"被截断的那个字"落在窗口之外（否则窗口末尾会出现替换符）。
#
# ⚠️ 必须是**函数**而不是模块级常量：`audit.scan_max` 运行时可改（`_maybe_reload`
# 会更新 `AUDIT_SCAN_MAX`），常量在 import 时就冻结了 —— 于是"把窗口调到 512KB"
# 只对扫描生效、对 decode 窗口不生效，设置页承诺的可检范围被悄悄腰斩（改了没反应）。
def _audit_text_probe_bytes():
    return AUDIT_SCAN_MAX * 4 + 4
# "流式收尾已投递但可能还没跑完"的计数：流式回调是同步的，投递后不等待，
# 所以"流结束了"不再等于"审计已经落库"。测试/诊断/关卡用 aux_drain() 对齐。
_AUX_PENDING_LOCK = threading.Lock()
_AUX_PENDING = [0]
_AUX_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=_AUX_MAX_INFLIGHT,
                                                 thread_name_prefix="maskit-aux")
# ⚠️ `_AUX_STATS` 的写入发生在 aux 线程（池里）与事件循环线程两处，而读取
# （`aux_pool_stats` → /api/engine/metrics 与一键自检）在第三个线程。
# 此前“峰值 / 等待累计 / stream_finish”这些键是**首次插入**（会改 size），与读取侧的
# `dict(_AUX_STATS)` 快照并发就撞出 `RuntimeError: dictionary changed size during
# iteration`；异常被 write_runtime_metrics 的宽 except 吞掉 → engine-runtime.json
# 静默停更（面板与自检读到的都是旧值）。统一走这两个带锁的写入口。
_AUX_STATS_LOCK = threading.Lock()
_AUX_STATS = {"submitted": 0, "completed": 0, "failed": 0}


def _aux_stat_add(key, delta=1):
    """`_AUX_STATS` 的原子累加（含首次插入新键）。"""
    with _AUX_STATS_LOCK:
        _AUX_STATS[key] = _AUX_STATS.get(key, 0) + delta


def _aux_stat_max(key, value):
    """`_AUX_STATS` 的原子取大（峰值类指标）。"""
    with _AUX_STATS_LOCK:
        if value > _AUX_STATS.get(key, 0):
            _AUX_STATS[key] = value
# 响应侧等待 aux 池多久才值得留痕。为什么是"留痕"而不是"超时放弃"：
# 这条 await 之后就是"把还原结果写回 flow.response"，一旦超时放弃，客户端拿到的就是
# **带占位符（或未还原明文）的响应** —— 那是本产品的核心承诺（本地还原后再出网/交付），
# 比"慢"严重得多；改回 503 又会把一条已经成功的上游响应判死。
# 但"短超时后放弃"与"等到永远"都错：
#   · 短超时放弃 → 客户端拿到带占位符（或未还原明文）的响应，违反核心承诺；
#   · 等到永远   → 客户端自己的超时先到，真实结果是连接被挂到断开（用户侧即
#                  502 / connection closed），比明确回 503 更差，而且不可诊断。
# 因此分两层：超过 `_AUX_WAIT_TRACE_S` 留痕；超过 `_AUX_WAIT_HARD_S` 不再等，
# 回本地失败（上游可能已执行），绝不建议自动重发。
# 硬上限只对**尚未向客户端写出任何字节**的整包路径生效；流式已边下边发，只能留痕。
_AUX_WAIT_TRACE_S = 2.0
_AUX_WAIT_HARD_S = 120.0          # 响应侧等待脱敏线程池的硬上限（秒）：超时回 503
_AUX_WAIT_TRACE_MS = [0.0]        # 本进程见过的最长等待（写进运行指标供自检读）


def aux_pool_stats():
    """aux 池的运行指标（C-1 的 /api/engine/metrics 用）。"""
    depth = None
    try:
        depth = int(_AUX_POOL._work_queue.qsize())     # 私有 API，取不到就算了
    except Exception:
        depth = None
    with _AUX_STATS_LOCK:
        out = dict(_AUX_STATS)
    with _AUX_BUDGET_LOCK:
        out.update(reserved_jobs=_AUX_JOBS, reserved_bytes=_AUX_BYTES,
                   max_jobs=_AUX_MAX_JOBS, max_bytes=_AUX_MAX_BYTES,
                   workers=_AUX_MAX_INFLIGHT)
    out["queue_depth"] = depth
    # 最长等待（ms）：0 = 从未超过留痕阈值
    out["max_wait_ms"] = round(float(_AUX_WAIT_TRACE_MS[0]), 1)
    return out


class _MaskResult(NamedTuple):
    """脱敏管线在专职线程里的产出（只带纯数据回事件循环线程）。

    回写 `flow.request.content` 必须在事件循环线程做：那是 mitmproxy 的对象，
    在线程里碰它会让「钩子跑在循环上」这条隐含前提失效。
    """
    masked_bytes: bytes | None   # None = 零改写，客户端字节一个都不动
    first_diff_byte: int
    scan_scope: dict
    role_texts: dict
    ner_skips: dict              # 本轮语义识别降级原因计数（空 = 全程生效）
    ner_metrics: dict            # 本轮 NER 治理器指标（等待/限流），空 = 无异常
    queue_wait_ms: float = 0.0   # 脱敏池排队时长（提交 → 开跑），A-6/B-5


def _ner_skips_of_this_round():
    """本轮脱敏里语义识别的降级记账（空 dict = 全程生效）。

    `_note_skip` 写的是当前**线程**的记账，本函数在 worker 线程里调用，取完即清，
    所以拿到的一定是本次请求这一轮的结果。
    """
    try:
        import ner_engine
        return ner_engine.request_skips(reset=True)
    except Exception:
        return {}


def _ner_metrics_of_this_round():
    """本轮语义识别的运行指标（信号量等待 / 限流次数），取完即清。

    `ner_sem_wait_ms` 与 `ner_global_throttled` 必须进事件：用户看到"开了 NER 但
    这条没识别"时，第一个要回答的问题就是"是排队等不到，还是被限流了"。
    与 `_ner_skips_of_this_round` 同源：都在本轮结束时取一次、清一次。
    """
    try:
        import ner_engine
        return ner_engine.request_metrics(reset=True)
    except Exception:
        return {}


_NER_METRIC_MAP = {
    "init_ms": "ner_init_ms", "infer_ms": "ner_infer_ms",
    "budget_wait_ms": "ner_budget_wait_ms", "sem_wait_ms": "ner_sem_wait_ms",
    "calls": "ner_calls", "cache_hit": "ner_cache_hits", "cache_miss": "ner_cache_misses",
    "windows": "ner_windows", "global_throttled": "ner_global_throttled",
}
_NER_EVENT_METRICS = frozenset(_NER_METRIC_MAP.values())


def _ner_metric_fields():
    """Request-local numeric evidence; decode wall time is not CPU time."""
    metrics = _ner_metrics_of_this_round() or {}
    if not any(metrics.values()):
        return {}
    return {target: (round(float(metrics.get(key) or 0), 2) if key.endswith("_ms")
                     else int(metrics.get(key) or 0))
            for key, target in _NER_METRIC_MAP.items()}


def _check_mask_work(deadline, cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise _ClientFlowCancelled()
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("mask processing deadline exhausted")


# ── NER 预取：最新消息优先（批次 8 / P0-2）───────────────────────────────────
# 为什么需要：`_mask_tree` 按文档序走（system → 最老的消息 → … → 最新一条），而 NER
# 的单请求预算是先到先得。长会话里预算总是先被最老的历史吃光，**用户刚发的那条**
# （或刚拿到的 tool_result）反而整段不做语义识别 —— 恰恰是最该扫的部分。
# 更糟的是它会自我维持：被跳过的叶子因为「不完整」不会进叶子结果缓存，下一轮仍然
# 从头开始吃预算，最新那条永远轮不到。
#
# 做法：先把 body 里的字符串叶子按文档序收集起来，再**逆序**预热 `extract_entities`
# （只填 NER 结果缓存，不改任何映射、不产生任何副作用），随后 `_mask_tree` 按正常
# 顺序走到它们时直接命中缓存。
# 预算只花掉一部分（`_NER_PREFETCH_SHARE`）：留一些给正常遍历，否则老历史永远
# 拿不到识别，只是把「最新的漏」换成「最老的漏」。
# 可用 `MASKIT_NER_PREFETCH_SHARE=0` 整个关掉（回退到旧行为）。
_NER_PREFETCH_SHARE = min(0.9, max(0.0, _env_float("MASKIT_NER_PREFETCH_SHARE", 0.5)))
_NER_PREFETCH_LEAVES = max(0, _env_int("MASKIT_NER_PREFETCH_LEAVES", 512))
# 单条预取上限：预取只为了「让最新的那条排到前面」，不是把整包大附件搬去跑 NER。
# 太大的叶子即使排前面也会自己撞 `CALL_BUDGET_S`（单次调用 10s 上限）并触发降级，
# 白白把后续叶子的预算一起搭进去；超过这个量级的交给正常遍历按同一套降级路径处理。
_NER_PREFETCH_MAX_CHARS = max(256, _env_int("MASKIT_NER_PREFETCH_MAX_CHARS", 32768))
_NER_PREFETCH_WARNED = [False]


def _collect_leaf_texts(obj, out, limit, depth=0):
    """按文档序收集 body 里的字符串叶子（预取专用）。

    不做路径判定（豁免/扫描范围）—— 那是 `_mask_tree` 的职责，这里复刻一份迟早会漂。
    多抽到的叶子只浪费一点预算，不会漏扫也不会改变结果：预取只写 NER 结果缓存。
    无汉字/纯符号的叶子由 `extract_entities` 的早返回免费跳过，不用在这里判。

    深度与 `_mask_tree` **同上限**（`_MASK_MAX_DEPTH`）：超深的 body 随后会被
    `_mask_tree` 抛异常 fail-closed 阻断，预取没必要先在它上面把递归跑到 Python
    栈底再去撞同一个墙（那是纯浪费，还会在日志里多一条无关告警）。
    """
    if depth > _MASK_MAX_DEPTH:
        return
    if len(out) >= limit:
        return
    if isinstance(obj, str):
        if 3 < len(obj) <= _NER_PREFETCH_MAX_CHARS:
            out.append(obj)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_leaf_texts(v, out, limit, depth + 1)
        return
    if isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_leaf_texts(v, out, limit, depth + 1)


def _ner_prefetch_newest_first(body, budget_s):
    """逆序预热 NER 结果缓存，返回实际预取的叶子数。

    失败一律吞掉：预取是优化而不是正确性路径，它报错绝不能把请求打死。
    降级（预算耗尽/槽位超时/推理失败）一开始就停：再往下只是白烧时间，
    剩下的交给正常遍历按既有降级路径处理并如实记账。

    吞异常 ≠ 无声无息：真出了意外（如超深嵌套 body 把 `_collect_leaf_texts`
    递归到爆）会首次告警一行。

    降级记账必须包在 `prefetch_scope()` 里：预取的降级是**推测性**的（可能只是撞上
    瞬时额度不足），而正常遍历随后会对同一段文本重新裁定；写进请求级跳过记录会在
    严格模式下把「其实完整扫完」的请求判成未完成而 503。
    """
    if not (NER_ENABLED and _NER_PREFETCH_LEAVES and _NER_PREFETCH_SHARE > 0):
        return 0
    try:
        import ner_engine
        if not ner_engine.is_ner_available():
            return 0
        texts = []
        _collect_leaf_texts(body, texts, _NER_PREFETCH_LEAVES)
        if not texts:
            return 0
        deadline = time.monotonic() + max(0.0, float(budget_s)) * _NER_PREFETCH_SHARE
        epoch0 = ner_engine.skip_epoch()
        done = 0
        with ner_engine.prefetch_scope():
            for text in reversed(texts):
                if time.monotonic() >= deadline or ner_engine.skip_epoch() != epoch0:
                    break
                ner_engine.extract_entities(text)
                done += 1
        return done
    except Exception as e:
        if not _NER_PREFETCH_WARNED[0]:
            _NER_PREFETCH_WARNED[0] = True
            _log("[transparent] NER 最新消息优先预取失败，已跳过（不影响脱敏）: %s: %s"
                 % (type(e).__name__, e))
        return 0


def _mask_pipeline_worker(body, sid, raw_content, enum_changed, has_dup_keys,
                          root_is_object, t_submit=0.0, deadline=None, cancel_event=None):
    """在 `_MASK_POOL` 线程里跑脱敏重活（纯计算 + 本模块全局态，不碰 mitmproxy 对象）。

    `body` 由调用方解析好传入，就地改写（原实现即如此，调用方后续还要用）。
    异常一律向上抛：由调用方的 fail-closed 分支决定阻断还是记录，绝不在这里静默放行。
    """
    # C-1：顺手刷新运行指标（内部节流 30s，绝大多数请求是一次 time() 判断）。
    # 放在**worker 线程**里而不是事件循环上：它要 write_text + os.replace，属阻塞 syscall，
    # 而 A-3 的前提就是"循环上不做这类事"（节流只是让它变稀，不是让它变对）。
    write_runtime_metrics()
    # A-6：真正开跑 = 从"排队字节"里出列（在跑的数量由 workers 数量天然有界）。
    # B-5：排队时长在这里记账（提交 → 开跑），用户与自检都靠它区分
    # "是我算得慢"还是"是在排队等前面的请求"。
    _mask_dequeued(len(raw_content))
    queue_wait_ms = (time.perf_counter() - t_submit) * 1000 if t_submit else 0.0
    # 读-改-写必须持锁：≤4 个 worker 会并发走到这里，无锁时峰值会被彼此覆盖（少记）
    with _MASK_ADMISSION_LOCK:
        if queue_wait_ms > _MASK_TIMEOUTS["peak_wait_ms"]:
            _MASK_TIMEOUTS["peak_wait_ms"] = queue_wait_ms
    # A-6：名额必须在 worker 自己结束（含异常）时归还——超时返回给客户端后
    # 孤儿 worker 仍在跑，若由调用方归还，B-4 的并发上界就成了事后失真的数字。
    old_control = getattr(_MASK_WORK_CONTEXT, "control", None)
    _MASK_WORK_CONTEXT.control = (deadline, cancel_event)
    try:
        masked_bytes = None
        first_diff_byte = -1
        _check_mask_work(deadline, cancel_event)
        _ner_budget_s = _ner_req_budget(len(raw_content))
        with _ner_doc_budget(_ner_budget_s, deadline=deadline, cancel_event=cancel_event):
            # 脱敏前记录扫描范围 + 各角色文本（仅内存，归因用，不落原文）
            scan_scope = _request_scope(body)
            role_texts = _collect_role_texts(body)
            # P0-2：语义识别预算按「最新消息优先」花（详见 _ner_prefetch_newest_first）。
            # 必须在本上下文管理器之内，与正常遍历共用同一份单请求预算。
            _ner_prefetch_newest_first(body, _ner_budget_s)
            # 递归脱敏所有承载正文的顶层字段。逐格式硬编码会漏掉工具调用参数等嵌套位置，
            # 这里统一走 _mask_tree（内部路径感知：协议位置跳过、业务区强制扫描）。
            # 注意：必须遍历 body 全部顶层 key——曾只处理白名单 key，顶层自定义业务对象
            # （customer 等）整体绕过脱敏（审计验收点"任意 customer.id"实测漏检）。
            # 非字符串/列表/字典（数字/bool/null）_mask_tree 原样返回，无副作用。
            # body_changed 是单元素 list（可变），由 _mask_hit 在真的替换过时置 True。
            body_changed = [False]
            # 顶层**键名**也要过一遍（审计 B2 的「敏感值作键名」）。
            #
            # 为什么之前漏了：这里按顶层 key 逐个取值送进 `_mask_tree`，于是键名本身
            # 一次都没经过 `mask()`。而扩展链路的 `mask_body` 是把整个 body 交给
            # `_mask_tree`（其 dict 分支会脱敏键名）——**同一个 body 走两条链路结果不同**，
            # `{"手机号": "safe"}` 在扩展链路已打码、在代理链路仍原样上行。
            #
            # 判据与 `_mask_tree` 的 dict 分支**完全一致**（同一个白名单、同一个 `mask()`），
            # 不另立一套，否则两边迟早再漂一次。
            # ⚠️ `_ROOT_WRAP_KEY` 必须原样保留：非对象根（列表根）会被包成
            # `{__shield_root__: [...]}`，键名一旦被改写，下面 `body[_ROOT_WRAP_KEY]`
            # 直接 KeyError → 整个脱敏管线抛异常 → fail-closed 503，所有列表根请求全挂。
            renamed = {}
            for key in list(body.keys()):
                _check_mask_work(deadline, cancel_event)
                new_key = key
                if (isinstance(key, str) and key != _ROOT_WRAP_KEY
                        and key not in _MASK_PROTECTED_KEY_NAMES):
                    masked_key = mask(key, sid)
                    if masked_key != key:
                        new_key = masked_key
                        body_changed[0] = True
                # 传进去的仍是**原键**：`_leaf_exempt` 的协议位置判定必须看客户端真实的键名
                # （同 `_mask_tree` dict 分支的注释）。
                renamed[new_key] = _mask_tree(body[key], sid, key, flag=body_changed)
            # 就地替换内容而非给 body 重新绑定：body 是调用方持有的对象，
            # 下面 enum 清洗 / splice / `masked_root` 都还在用它，且要保持键的插入顺序。
            body.clear()
            body.update(renamed)

            # has_dup_keys 必须一起算进脏标记：树里丢了被覆盖的值，判定「没改过」是假的。
            if body_changed[0] or enum_changed or has_dup_keys:
                # 只有真的改过才回写请求体。回写方式分三级，目标都是别把「前缀」整体挪位 ——
                # 上游按前缀做 Prompt Cache，前缀字节一变就整段 miss：
                #   1) 首选**字节级文本替换**（`_splice_mask`）：直接在客户端原始 JSON 文本上
                #      做敏感值占位符替换，客户端 body 的排版（空格、缩进、数字写法、转义风格）
                #      全部原样保留。实测一条带空格 + `\u` 转义的请求：敏感值在 byte 74，
                #      整棵重序列化的差异位却在 byte 9 —— 中间 65 字节的前缀被白白改掉。
                #      由等价校验确保结构正确。见 `_splice_mask`。
                #   2) 替换结果必须通过 `json.loads(结果) == 脱敏后的树` 等价校验才采用；
                #      不过（含 enum 清洗这类结构性改动，splice 表达不了）就退回下一级。
                #   3) 退路是整棵重序列化，两个细节同样为了保前缀：
                #      · separators 用紧凑形态：json.dumps 默认 (", ", ": ") 会在每个
                #        逗号/冒号后插空格，把 SDK 普遍发的紧凑体整体改写（实测 113→123 字节）。
                #      · ensure_ascii 跟随客户端已表现出的策略：正文里出现过 `\u` 转义，
                #        说明客户端用 ensure_ascii=True，我们回写时也转义；否则这次重序列化
                #        会把 `\u5f20\u4e09` 展开成「张三」，凭空扩大与客户端前缀的字节差异。
                # 三级回写的都是**同一棵已经脱敏的树**，所以不存在放行原文的路径。
                masked_root = body if root_is_object else body[_ROOT_WRAP_KEY]
                masked_raw = None
                # has_dup_keys 时禁用 splice：丢掉的重复键不在替换表里，而等价校验
                # （json.loads(spliced) == masked_root）会因为「解析回来仍是那棵折叠后的树」
                # 而误判通过，于是原文里的敏感值被原样带出去。直接重序列化脱敏树。
                if BYTE_SPLICE and not enum_changed and not has_dup_keys:
                    try:
                        spliced = _splice_mask(
                            raw_content, masked_root,
                            {o: t for o, t in (_session_get(sid, {}).get("fwd") or {}).items() if t},
                        )
                    except Exception:
                        spliced = None
                    if spliced is not None:
                        try:
                            if json.loads(spliced) == masked_root:
                                masked_raw = spliced.decode("utf-8")
                        except Exception:
                            masked_raw = None
                if masked_raw is None:
                    masked_raw = json.dumps(
                        masked_root,
                        ensure_ascii=(b"\\u" in raw_content),
                        separators=(",", ":"),
                    )
                # 历史里带上来的、上一轮遗留的占位符：登记进本会话，响应侧仍能还原（自愈）
                _seed_known(masked_raw, sid)
                # 回写由事件循环侧完成（见 _MaskResult）；这里只算出最终字节与差异位。
                masked_bytes = masked_raw.encode("utf-8")
                first_diff_byte = _first_diff_byte(raw_content, masked_bytes)
            else:
                # 零改写透传：一个敏感词都没命中，就**一个字都不动** flow.request.content。
                # 除了省一次序列化，更重要的是保证上游收到的字节与客户端发出的完全一致
                # （含分隔符、键序、\u 转义、数字字面量写法），这是 Prompt Cache 命中的前提。
                # _seed_known 照常跑：客户端历史里带来的占位符本轮响应若被模型复述仍要能还原。
                _seed_known(raw_content.decode("utf-8", "replace"), sid)
        _check_mask_work(deadline, cancel_event)
        return _MaskResult(
            masked_bytes, first_diff_byte, scan_scope, role_texts,
            _ner_skips_of_this_round(), _ner_metric_fields(),
            round(queue_wait_ms, 1),
        )
    finally:
        _MASK_WORK_CONTEXT.control = old_control
        _mask_release(len(raw_content))


async def request(flow: http.HTTPFlow):
    # Native replay/copy must start a new attempt, not inherit terminal lifecycle flags.
    for key in tuple(flow.metadata):
        if key.startswith("shield_") or key in ("session_id", "transport", "_maskit_transport", "_maskit_cancel_observers"):
            flow.metadata.pop(key, None)
    if getattr(flow, "_shield_request_seen", False):
        for name in ("_shield_cancel_wakeup", "_shield_cancel_reason", "_shield_cancel_recorded"):
            if hasattr(flow, name):
                delattr(flow, name)
    flow._shield_request_seen = True
    completed = False
    cancel_event = threading.Event()
    client_id = str(getattr(getattr(flow, "client_conn", None), "id", ""))
    _MASK_CANCEL_BY_CLIENT.setdefault(client_id, set()).add(cancel_event)
    flow._shield_mask_cancel = cancel_event
    _transport_event("request_started", flow)
    try:
        if _cancel_signal(flow).is_set():
            raise _ClientFlowCancelled()
        await _request_impl(flow)
        if cancel_event.is_set() and getattr(flow, "response", None) is None:
            raise _ClientFlowCancelled()
        if (getattr(flow, "response", None) is None and _aux_token(flow) is not None
                and _aux_reserve(flow) is None):
            # Masking can expand the request body. Account for the actual retained
            # bytes before upstream send, without reserving 32 MiB for every job.
            flow.response = http.Response.make(
                503, b'{"error":{"code":"shield_aux_busy","upstream_sent":false}}',
                {"content-type": "application/json"})
            _emit("BLOCK", sid=flow.metadata.get("session_id"), reason="aux_busy",
                  block_source="engine")
        completed = True
    except _ClientFlowCancelled:
        # Returning from the hook is essential: mitmproxy must issue HookCompleted
        # and drain its already-queued protocol error for this stream.
        cancel_event.set()
        _aux_abandon(flow)
        _record_client_cancel(flow, "local_request")
        flow.response = http.Response.make(
            503, b'{"error":{"code":"shield_request_cancelled"}}',
            {"content-type": "application/json", "x-should-retry": "false"})
    finally:
        cancel_event.set()
        if hasattr(flow, "_shield_mask_cancel"):
            delattr(flow, "_shield_mask_cancel")
        pending = _MASK_CANCEL_BY_CLIENT.get(client_id)
        if pending is not None:
            pending.discard(cancel_event)
            if not pending:
                _MASK_CANCEL_BY_CLIENT.pop(client_id, None)
        if not completed or getattr(flow, "response", None) is not None:
            token = _aux_token(flow)
            owned_session = token.session_ref if token is not None else None
            if getattr(flow, "response", None) is not None:
                flow.metadata["shield_local_response"] = True
            _aux_abandon(flow)
            if (not flow.metadata.get("shield_mask_pending") and token is not None
                    and not token.submitted and owned_session is not None):
                _drop(flow.metadata.get("session_id"), expect=owned_session)
            _transport_event("error", flow)
        flow.metadata["transport"] = _safe_transport_snapshot(flow)
        if completed and getattr(flow, "response", None) is None and not _cancel_signal(flow).is_set():
            # Request waiters are gone; response owns a fresh wake signal. This also
            # keeps recorded/test flows usable when hooks are driven on separate loops.
            flow._shield_cancel_wakeup = asyncio.Event()


async def _request_impl(flow: http.HTTPFlow):
    _maybe_reload()  # 热重载：加词即时生效
    method = getattr(flow.request, "method", "") or ""
    source = _client_source(flow)
    orig_host = flow.request.pretty_host
    orig_path = flow.request.path

    # 反向代理模式：按 base_path 路由到真实上游，剥掉前缀，改写 host/scheme/port
    matched_up = None
    if CAPTURE_MODE == "reverse":
        flow.metadata["shield_orig_path"] = orig_path
        matched_up, final_path = apply_reverse_routing(flow)
        if not matched_up:
            _emit_skip(orig_host, method, orig_path, "no_reverse_route", source=source)
            flow.response = http.Response.make(404, b'{"error":"no_reverse_route"}', {"content-type": "application/json"})
            return
        # 路由后用最终路径和真实上游 host 判断是否为目标 LLM API
        host = getattr(flow.request, "host", None) or orig_host
        path = flow.request.path
        # 非白名单路径不再 404 拦下：/v1/models、/v1/embeddings、健康检查等是客户端
        # 初始化必打的接口，直接拒绝会让人以为代理坏了。这里只决定"是否脱敏"，转发照旧。
        up_name = matched_up.get("name") or ""
        flow.metadata["shield_upstream"] = up_name
        # 客户端级注入请求头（extra_headers）：只注入与凭据无关的协议头
        # （凭据头与占位符/空值都会被 _apply_extra_headers 跳过）。
        # 必须在转发前设置（客户端请求头在 request() 阶段可改）。
        _apply_extra_headers(flow, matched_up)
        # 出口代理必须在任何 return 之前挂上（含下面的 passthrough_unlisted_path 分支）
        _apply_egress_proxy(flow, matched_up)
        try:
            validate_connection_policy(matched_up.get("connection_policy"), http2=False)
        except ValueError:
            flow.response = http.Response.make(
                503, b'{"error":{"code":"unsupported_connection_policy"}}',
                {"content-type": "application/json"})
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
                  reason="unsupported_connection_policy", block_source="engine", **source)
            return
        if not _upstream_path_ok(matched_up, path):
            if method in _READONLY_METHODS:
                _emit_skip(host, method, path, "passthrough_unlisted_path", source=source, upstream=up_name)
                return
            # 无论是否在白名单，非只读请求只要像 LLM 请求就继续进入脱敏流程；
            # 但若未在白名单路径且并非标准 LLM 文本补全请求：
            # 若是声明非 JSON（如 multipart/form-data 音频上传、二进制流），在 FAIL_CLOSED 下绝不能静默透传，必须阻断；
            # 若是 JSON，FAIL_CLOSED 下**同样不能按 passthrough 放行** —— 见下面 fail_closed 分支的说明。
            if not _looks_like_llm_request(flow):
                ct_unlisted = (flow.request.headers.get("content-type", "") or "").lower()
                # FILTER_ENABLED=False（用户承诺「透明转发」）时不阻断：开关语义
                # 必须完整——关了脱敏还 503 拦 multipart/二进制，等于没关（审计 P2）。
                if "json" not in ct_unlisted and FAIL_CLOSED and FILTER_ENABLED:
                    _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
                          reason="unlisted_non_json_blocked", block_source="engine", upstream=up_name, **source)
                    flow.response = http.Response.make(
                        503,
                        json.dumps({"error": "shield_mask_failed", "reason": "unlisted_non_json_blocked"},
                                   ensure_ascii=False).encode("utf-8"),
                        {"content-type": "application/json"},
                    )
                    return
                # 请求已经落在用户配置的上游路由上（matched_up 为真），此时
                # 「形态不认识」在 FAIL_CLOSED 下必须交给主管线按 unknown_shape
                # 脱敏，不能凭「路径不在白名单」就把原文放出去。
                #
                # 原因（外部审计 SHIELD-UNLISTED-PASSTHROUGH-001）：放行判据是
                # _LLM_BODY_KEYS，而它是**白名单**，永远追不上新协议（实测 Cohere
                # v1 chat / Bedrock Titan / 讯飞星火 都曾整包透传原文）。主管线
                # L3080 对同样的形态是「配置路由 + fail_closed → 一律脱敏」；这里若
                # 放行，fail_closed 的承诺就取决于**路径在不在白名单**，而不取决于
                # fail_closed 本身。实测可达：未配 paths 时白名单只有 7 条默认路径，
                # POST /v1/vector_stores、/v1/fine_tuning/jobs、/v2/chat、以及任意
                # 厂商新端点 {"text":"张三 手机号 …"} 都会明文上行。
                #
                # 走主管线还顺带消掉一个倒挂：_looks_like_llm_request 对「声明 JSON
                # 但解析失败」返回 True（交 fail_closed 脱敏），对「解析成功但键不
                # 认识」返回 False（放行） —— 原本解析失败反而比解析成功更安全。
                if not FAIL_CLOSED:
                    _emit_skip(host, method, path, "passthrough_unlisted_path", source=source, upstream=up_name)
                    return
    else:
        host = orig_host
        path = orig_path
        if not is_target(host, path):
            _emit_skip(host, method, path, _target_miss_reason(host, path) or "not_target", source=source)
            return
        up_name = ""

    up_name = (matched_up or {}).get("name") or flow.metadata.get("shield_upstream") or ""

    # 只读方法没有请求体，无需脱敏，直接转发 —— 仍记 PASS（过网关必有日志）
    if method in _READONLY_METHODS:
        _emit_skip(host, method, path, "readonly_method", source=source, upstream=up_name)
        return

    # 过滤开关关闭：路由已生效（reverse 模式已改写 host），但不脱敏，透明转发到上游
    if not FILTER_ENABLED:
        flow.metadata["shield_filter_off"] = True
        # 声明 identity：否则上游对 SSE 压缩后，responseheaders 的流式接管只能
        # 退回整包路径，客户端失去打字机效果（与脱敏路径 3592 的处理一致；
        # 代价是过滤关闭期间非流式 JSON 响应也不压缩，PT 兜底层同样如此）。
        if STREAM_RESPONSE and "json" in (flow.request.headers.get("content-type", "") or "").lower():
            flow.request.headers["accept-encoding"] = "identity"
        _emit(
            "BYPASS",
            host=host, method=method,
            path=orig_path.split("?")[0] if CAPTURE_MODE == "reverse" else path.split("?")[0],
            reason="filter_disabled",
            upstream=up_name, **source,
        )
        return

    ct = (flow.request.headers.get("content-type", "") or "").lower()
    if "json" not in ct:
        # 声明非 JSON（multipart 上传、二进制等）：脱敏管线处理不了。
        # fail_closed 下阻断（无法确认里面没有原文）；仅排查问题时
        # 可关 fail_closed 放行，此时记 BYPASS 让用户在日志里看得见。
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
                  reason="non_json_body", block_source="engine", content_type=str(ct or "")[:80],
                  upstream=up_name, **source)
            flow.response = http.Response.make(
                503,
                json.dumps({"error": "shield_mask_failed", "reason": "non_json_body"},
                           ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit(
            "BYPASS", host=host, method=method, path=path.split("?")[0],
            reason="non_json_body", content_type=str(ct or "")[:80],
            upstream=up_name, **source,
        )
        return
    try:
        raw_content = flow.request.content or b""
    except Exception:
        raw_content = b""
    # 体积闸门放在 json.loads 之前：解析本身对超大 body 同样昂贵，且一样阻塞
    # event loop。超限一律拒绝（不看 fail_closed）——放行等于把原文原样上行，
    # 正是脱敏代理绝不能做的事。
    if len(raw_content) > _MAX_REQUEST_BODY:
        # §H4(b)：超限必须能归因。错误体只写 `shield_request_too_large` 时，用户
        # 不知道该删什么（实测：带大附件的合法请求被整条拒掉且无法自查）。
        # 注意：闸门是**内容盲**的（在 json.loads 之前），看不到"大在正文还是大在媒体"，
        # 所以措辞只能到"缩小附件或上下文"，不能声称"附件过大"。
        _too_large_hint = (
            "请求体 %d 字节，超过单条上限 %d 字节（≈%.1f MiB），已在本机阻断、未上行。"
            "请缩小附件或上下文后重试。"
            % (len(raw_content), _MAX_REQUEST_BODY, _MAX_REQUEST_BODY / 1048576.0)
        )
        _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
              reason="request_too_large", block_source="engine", bytes=len(raw_content),
              msg=_too_large_hint,
              upstream=up_name, **source)
        flow.response = http.Response.make(
            413,
            json.dumps({"error": "shield_request_too_large",
                        "reason": "request_too_large",
                        "blocking": True,
                        "limit_bytes": _MAX_REQUEST_BODY,
                        "hint": _too_large_hint,
                        **inspection.report_for_skip(reason="request_too_large", blocked=True)},
                       ensure_ascii=False).encode("utf-8"),
            {"content-type": "application/json"},
        )
        return
    # 重复键（{"a":"手机号","a":"safe"}）：json.loads 取后者覆盖前者，树里
    # 已经丢了被覆盖的值，扫不到 → 零改写分支会放行原始字节（审计 B2 实测）。
    # 检出后强制走重序列化，并禁用 splice（见下方回写分支）。
    body, has_dup_keys = _load_json_pairs(raw_content)
    if body is None:
        # 声明了 JSON 却解析不了：无法确认里面没有原文。fail_closed 下必须拦。
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0], reason="invalid_json", block_source="engine", upstream=up_name, **source)
            flow.response = http.Response.make(
                400,
                json.dumps({"error": "shield_invalid_json", "reason": "invalid_json"}, ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit_skip(host, method, path, "invalid_json", ct, source=source, upstream=up_name)
        return
    if has_dup_keys and not _DUP_KEY_WARNED[0]:
        _DUP_KEY_WARNED[0] = True
        try:
            _log("[mask] 请求体存在重复键：该请求已改为整棵重序列化，"
                 "被覆盖的字段值不会明文上行（首次告警，后续静默）")
        except Exception:
            pass
    # 顶层不是对象（JSON 数组/字符串/数字）。没有任何主流 LLM API 用这种形态，
    # 但它完全可能载有原文——["手机号 手机号"] 就是一次完整的泄漏。
    # 曾在这里直接 _emit_skip 放行，与相邻两个分支（non_json_body / invalid_json
    # 在 fail_closed 下都阻断）不一致，也与 fail_closed「绝不放行原文上行」的承诺
    # 冲突（SHIELD-NONOBJECT-BYPASS-001）。
    # 这里不阻断而是照常脱敏：_mask_tree 对 list/str/标量一样有效，脱敏比 400 更不
    # 容易误伤用户自建的非标准接口。做法是套一层合成根键让下游的 dict 逻辑照常跑，
    # 发往上游前再拆掉，上游看到的仍是原来的形态。
    root_is_object = isinstance(body, dict)
    if not root_is_object:
        body = {_ROOT_WRAP_KEY: body}
    unknown_shape = False
    stream_mode = "stream" if body.get("stream") is True else "non_stream"
    # 非 LLM 形态 JSON（无 messages/prompt 等特征键）。
    # 形态不认识 ≠ 没有原文：_LLM_BODY_KEYS 是白名单，而白名单永远追不上新协议
    # （实测 Cohere v1 chat / Bedrock Titan / 讯飞星火 都曾整包透传原文）。
    # 所以这里按「请求有没有落在用户显式配置的上游路由上」分流：
    #   - 在配置好的路由上 + fail_closed：一律脱敏，只把「形态不认识」记进事件供排查。
    #     用户把 /v1 路由到某个模型服务商，本来就意味着这条链路上的请求体要当正文对待。
    #   - 用户主动关了 fail_closed：保持原行为，记 PASS 不脱敏。
    #
    # 判据用 CAPTURE 模式各自的「已配置」证据，不用 up_name（2026-08-17 外部审计）：
    # up_name 只在 reverse 模式有值，explicit/local 恒为 ""，于是
    # `FAIL_CLOSED and up_name` 必然 falsy —— **那两个模式无论 fail_closed 开没开
    # 都直接放行原文上行**，与「fail-closed 绝不放行原文」的承诺直接冲突。
    # 顺带修掉第二个隐患：reverse 模式下 upstream 名字留空时 up_name 也是 ""，同样绕过。
    #
    # 走到这一行时两种模式都已经证明在配置好的路由上：
    #   reverse       —— matched_up 为真，否则前面已 404 返回
    #   explicit/local —— is_target(host, path) 为真（域名与路径都命中用户配置），
    #                     否则前面已 _emit_skip("not_target") 返回
    # 所以这里只需要看 fail_closed 本身。
    if root_is_object and not _looks_like_llm_request(flow, body) and not any(k in body for k in _LLM_BODY_KEYS):
        if not FAIL_CLOSED:
            _emit_skip(host, method, path, "non_llm_json", ct, source=source, upstream=up_name)
            return
        unknown_shape = True
    # 流式请求禁止上游压缩：压缩后的 SSE 在 responseheaders 阶段仍是压缩字节，
    # 无法按事件切分，只能退回整包路径 —— 客户端就此失去流式效果（首字延迟=整段
    # 生成时长）。这里主动声明 identity，把「能不能流式」从上游的压缩策略里解耦。
    # 非流式请求不动，保留压缩节省带宽。置于 LLM 形态判断之后：非 LLM 请求不白改。
    if stream_mode == "stream" and STREAM_RESPONSE and host not in STREAM_EXCLUDE_HOSTS:
        flow.request.headers["accept-encoding"] = "identity"
    if stream_mode == "stream":
        # 请求侧要了流式：响应侧据此判断"没走流式"到底算不算降级（C-2）。
        # 不设这个标记的话，普通非流式请求（绝大多数）也会被记成 non_sse 降级。
        flow.metadata["shield_stream_requested"] = True

    # 清洗 tools schema 的 enum 非字符串值（Gemini function_declarations 兼容）。
    # 仅限已知中转渠道（实测其 tools 转换器拒绝非字符串 enum）
    # 且模型为 gemini 系列（Google API 校验 enum 类型，其他模型原生 API 不校验）；
    # 其余渠道/模型不做改动，保持原生 schema。
    # enum 清洗对任何上游都是无损操作（enum 仅取值提示），官方三渠道原生 API
    # 校验宽松可不改；中转渠道的 tools 转换器拒绝非字符串 enum（实测），
    # 故对所有非官方渠道 + gemini 模型启用。
    enum_changed = False
    if up_name not in ("openai", "deepseek", "anthropic") and str(body.get("model", "")).startswith("gemini"):
        enum_changed = _clean_tool_enums(body)
    # 标记 reasoning_effort 可疑值（不修改请求）：上游 400 时在事件里提示
    # 下游排查模型配置（pi 的 thinkingLevelMap off→"none" 曾导致识图 400）
    flow.metadata["shield_reasoning_effort"] = _clean_reasoning_effort(body, up_name)
    _sweep()
    # 16 位十六进制 = 64 bit。原来取 8 位（32 bit），生日碰撞在实测里 1 万请求还是
    # 0 次、2 万就到约 4.6%、10 万约 69%——重度用户一天就能跑到那个量级，
    # 而 sid 碰撞意味着两个会话的占位符映射串到一起，会把别人的原文还原给你，
    # 属于最严重的一类故障。加宽到 64 bit 后同样 10 万请求碰撞概率约 2.7e-10。
    # sid 只在进程内内存表和事件库里做关联键，加长不影响任何对外协议。
    sid = uuid.uuid4().hex[:16]
    _new_session(sid, source=source)
    flow.metadata["session_id"] = sid
    # 命令拦截的回声抑制基线（W2-1）：请求体里已经出现的危险命令说明是用户自己
    # 问的（或上下文带进来的），上游没凭空多给东西 → 既不记录也不改写。
    # 必须在**脱敏之前**算（raw_content 还是客户端原文）：脱敏后路径/域名都变成
    # 占位符，判不准也没意义。注意 `raw_content` 在命令拦截未启用时不会扫。
    _remember_request_cmd_snippets(sid, raw_content)
    # 2.0 审计：从请求 header 读 probe_id + canaries（panel 主动探针注入），读完即 strip 不转发上游
    probe_id = flow.request.headers.get("x-shield-probe-id", "") or ""
    if probe_id:
        flow.metadata["probe_id"] = probe_id
        flow.request.headers.pop("x-shield-probe-id", None)
    canary_hdr = flow.request.headers.get("x-shield-canaries", "") or ""
    if canary_hdr:
        nonces = [n for n in canary_hdr.split(",") if n]
        flow.metadata["audit_canaries"] = set(nonces)
        # 注意：**只记在 flow 上，先不写全局表** —— 注册是"脱敏副作用"，
        # 必须排在准入之后（见下方 _mask_admit 处的不变式 7）：被 busy/timeout 拒掉的
        # 请求从未上行，注册进去只会留下永远不会被匹配的僵尸 nonce（占 TTL 表）。
        # 头照旧立刻剥掉：无论本条最终走不走脱敏，它都不该转发给上游。
        flow.request.headers.pop("x-shield-canaries", None)

    if DEBUG:
        _raw = flow.request.content or b""
        _debug(f"REQUEST {host}{path.split('?')[0]} -- 原始(未脱敏)", sid,
               _raw.decode("utf-8", errors="replace"))

    # fail-closed：整个脱敏管线包一层，异常时阻断请求（503），绝不放行原文上行。
    # 关闭 fail-closed 仅用于排查问题：异常时记录 ERR 后继续转发（可能泄露原文）。
    # body_rewritten / first_diff_byte 只用于 MASK 事件的诊断，不参与脱敏决策：
    # 用户报「上游缓存命中率归零」时，这两个值能直接区分「我们改了字节」与
    # 「上游自己 miss」，也是决定要不要做字节级替换的唯一实测依据。
    body_rewritten = False
    first_diff_byte = -1
    ner_skips = {}          # 管线异常时下面的 MASK 事件仍会走到（fail-open 分支），需先有默认值
    ner_metrics = {}        # 同上：治理器指标也要有默认值，异常路径才不至于 NameError
    _mask_t0 = time.perf_counter()
    # ---- A-6 / B-4：准入判定 ----
    # 必须在**任何签发副作用之前**（§4.2 不变式 7）：队列满就干净利落地拒掉，
    # 不能"先签了占位符再拒"——那会把复用表和 `_RECENT_*` 污染成"存在但从未上行"的条目。
    # 判据是字节预算 + 条数上限（按条数算的最坏值会失控：16 条 × 32MB = 512MB）。
    flow.metadata["shield_request_decoded_bytes"] = len(raw_content)
    _mask_deadline = time.monotonic() + _ENGINE_DEADLINE_S
    _mask_cancel = getattr(flow, "_shield_mask_cancel", None)
    if _aux_reserve(flow) is None:
        _emit("BLOCK", host=host, method=method, path=path.split("?")[0], sid=sid,
              reason="aux_busy", block_source="engine", upstream=up_name, **source)
        flow.response = http.Response.make(
            503, b'{"error":{"code":"shield_aux_busy","upstream_sent":false}}',
            {"content-type": "application/json"})
        _drop(sid)
        return
    if not _mask_admit(len(raw_content)):
        _st = mask_pool_stats()
        _emit("BLOCK", host=host, method=method, path=path.split("?")[0], sid=sid,
              reason="engine_busy", block_source="engine", engine_busy=True,
              engine_queue_depth=_st.get("queue_depth"),
              engine_queue_bytes=_st.get("queued_bytes"),
              bytes=len(raw_content),
              msg="脱敏队列已满，请求未脱敏且未上行（客户端应退避重试）",
              upstream=up_name, **source)
        flow.response = http.Response.make(
            503,
            json.dumps({"error": {"code": "shield_busy", "reason": "engine_busy"}},
                       ensure_ascii=False).encode("utf-8"),
            {"content-type": "application/json",
             # 抖动退避：固定 Retry-After 会让被拒客户端同一时刻一起回来，
             # 正是本次故障里"503 重试风暴"的形态。
             "Retry-After": str(_retry_after_seconds())},
        )
        _drop(sid)
        return
    # 准入通过才注册 canary（不变式 7：任何签发/登记副作用都排在准入之后）
    for _nonce in (flow.metadata.get("audit_canaries") or ()):
        with _AUDIT_CANARY_LOCK:
            _AUDIT_CANARY_REGISTRY[_nonce] = time.time()
    try:
        # 重活交给专职线程（见 _MASK_POOL）：本函数是 async 钩子，mitmproxy 会在
        # 事件循环里 await 它——等待期间其他连接的收发照常进行，一条慢会话不再冻住整机。
        _t_submit = time.perf_counter()
        try:
            _fut = asyncio.get_running_loop().run_in_executor(
                _MASK_POOL, _mask_pipeline_worker,
                body, sid, raw_content, enum_changed, has_dup_keys, root_is_object, _t_submit,
                _mask_deadline, _mask_cancel,
            )
        except Exception:
            # Submit failed: no worker will run its finally, so return admission here.
            _mask_abandon(len(raw_content))
            raise
        _mask_session = _session_get(sid)
        flow.metadata["shield_mask_pending"] = True

        def mask_finished(future):
            flow.metadata.pop("shield_mask_pending", None)
            if not future.cancelled():
                future.exception()
            if _mask_cancel is not None and _mask_cancel.is_set() and _mask_session is not None:
                _drop(sid, expect=_mask_session)

        _fut.add_done_callback(mask_finished)
        try:
            # ---- B-5：端到端 deadline ----
            _res = await _await_with_deadline(_fut, max(0.0, _mask_deadline - time.monotonic()),
                                               _cancel_signal(flow))
        except asyncio.TimeoutError:
            if _mask_cancel is not None:
                _mask_cancel.set()
            # 与 `peak_wait_ms` 同一把锁：`_MASK_TIMEOUTS` 是一个整体快照，
            # 两个字段分开加锁会让 `/api/engine/metrics` 读到“计数已增、峰值未更新”。
            with _MASK_ADMISSION_LOCK:
                _MASK_TIMEOUTS["count"] += 1
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0], sid=sid,
                  reason="engine_timeout", block_source="engine",
                  bytes=len(raw_content),
                  msg=f"脱敏超过 {int(_ENGINE_DEADLINE_S)}s 未完成，请求已中止（未上行）",
                  upstream=up_name, **source)
            flow.response = http.Response.make(
                503,
                json.dumps({"error": {"code": "shield_timeout", "reason": "engine_timeout"}},
                           ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json", "Retry-After": "5"},
            )
            # 不 `_drop(sid)`：worker 还在跑（shield 没取消它），主协程 pop 掉同一个
            # dict 就是"一边删一边写"的竞态。会话此刻 `inflight=False`（那是在脱敏
            # 成功、请求出网前才设的），`_sweep` 会按 TTL 正常回收它，不会泄漏。
            # 超时这件事本身已经由 BLOCK 事件（reason=engine_timeout）与
            # `engine_timeouts` 指标留痕，不需要再往会话里塞一个没人读的标记。
            # 孤儿 future 的异常必须被取走：否则 asyncio 会在 GC 时打
            # "Future exception was never retrieved"，污染日志（而这条日志正是
            # 用户排查时最需要干净的地方）。
            try:
                _fut.add_done_callback(lambda f: f.cancelled() or f.exception())
            except Exception:
                pass
            return
        # scan_scope / role_texts 在脱敏前算好带回：后面的 MASK 事件与会话都要用。
        if _res.masked_bytes is not None:
            flow.metadata["shield_request_decoded_bytes"] = len(_res.masked_bytes)
        scan_scope = _res.scan_scope
        role_texts = _res.role_texts
        # 本轮语义识别有没有降级（空 dict = 全程生效）：MASK 事件如实上报，
        # 静默降级等于「以为开了、其实没脱」。
        ner_skips = _res.ner_skips
        ner_metrics = _res.ner_metrics or {}
        if _res.masked_bytes is not None:
            # 回写必须在事件循环线程里做（flow 是 mitmproxy 的对象）。
            flow.request.content = _res.masked_bytes
            body_rewritten = True
            first_diff_byte = _res.first_diff_byte
    except Exception as e:
        _drop(sid)
        emit_path_err = orig_path if CAPTURE_MODE == "reverse" else path
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=emit_path_err.split("?")[0], reason="mask_pipeline_failed", block_source="engine", msg=str(e)[:200], upstream=matched_up["name"] if matched_up else "", **source)
            flow.response = http.Response.make(
                503,
                json.dumps({"error": "shield_mask_failed", "reason": "mask_pipeline_failed"}, ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit("ERR", host=host, method=method, path=emit_path_err.split("?")[0], sid=sid, msg="mask:" + str(e)[:200], **source)
        return

    if DEBUG:
        _raw2 = flow.request.content or b""
        _debug(f"REQUEST {host}{path.split('?')[0]} -- 脱敏后(发往上游)", sid,
               _raw2.decode("utf-8", errors="replace"))

    fwd = _session_get(sid, {}).get("fwd", {})
    labels = _session_get(sid, {}).get("labels", {})
    # 本次实际命中的唯一原文（mask 里累积，跨字符串叶子不覆盖）。
    # hit_count=本次命中数；new_count=其中本次新增的（_hit 在 _remember 前记录）
    last_hits = _session_get(sid, {}).get("last_hits") or set()
    new_orig = _session_get(sid, {}).get("new_orig") or set()
    hit_count = len(last_hits)
    new_count = len(last_hits & new_orig)
    items = []
    # 明细上限提到 30：OpenCode 长会话常 >10 命中，截断后无法定位误伤词
    # 优先展示本次命中的项，让 count 与明细对得上
    shown = set()
    hit_items = [o for o in last_hits if o in fwd]
    ordered = list(hit_items) + [o for o in fwd if o not in last_hits]
    for orig in ordered[:30]:
        tok = fwd.get(orig, "")
        if not tok:
            continue
        m = _PLACEHOLDER_PARTS_RX.match(tok)
        label = labels.get(orig, "")
        roles = _hit_roles_for(orig, role_texts)
        # 凭据类标签（CREDENTIAL_LABELS：API_KEY/TOKEN/SECRET/ACCESS_KEY/JWT/CONNSTR/PRIVATE_KEY）永不明文落库：
        # 只存类型 + 打码 preview + 长度 + sha256 摘要（审计要求，v1.5.19 起）。
        # 非凭据 PII 保留 original（项目约定：明文只进详情弹窗，导出/列表用 preview）。
        is_cred = label in CREDENTIAL_LABELS
        item = {
            "tok": tok,
            "label": label,
            "hash": m.group(2) if m else "",
            "length": len(orig),
            "preview": _preview(orig, label),
        }
        if is_cred:
            item["cred"] = True
            item["digest"] = _cred_digest(orig)
        else:
            item["original"] = orig
        if roles:
            item["roles"] = roles[:6]
        if len(orig) <= 2:
            item["short"] = True
        items.append(item)
        shown.add(orig)
    emit_path = orig_path if CAPTURE_MODE == "reverse" else path
    # 对话摘要：只保留 user/assistant 文本，便于日志阅读（不是整包 JSON）
    try:
        dialog = _extract_chat_dialog(flow.request.content, 4000)
    except Exception:
        dialog = ""
    try:
        raw_preview = _body_preview(flow.request.content, 800)
    except Exception:
        raw_preview = ""
    # 落库前凭据清洗：dialog/preview 即使残留凭据形态（SECRET 规则外的变体）也不留明文
    dialog = _redact_credentials(dialog)
    raw_preview = _redact_credentials(raw_preview)
    # 短词命中计数：便于界面提示「过短词误伤」
    short_hits = sum(1 for it in items if it.get("short"))
    model = _extract_model(body)
    try:
        flow.metadata["shield_model"] = model
    except Exception:
        pass
    # model 存入会话：RESTORE 事件（含流式接管路径）从会话读取，避免响应阶段再解析请求体
    try:
        s_sess = _session_get(sid)
        if s_sess is not None:
            s_sess["model"] = model
            # 标记 in-flight：请求已发出、响应未到，_sweep 不得按 TTL 删本会话
            s_sess["inflight"] = True
            # scan_scope 存入会话：RESTORE 事件要复用（前端归因展示），
            # 避免硬编码猜测「命中来自 system/历史」
            s_sess["scan_scope"] = scan_scope
            # role_texts 供 RESTORE items 归因（_hit_roles_for 需要）
            s_sess["role_texts"] = role_texts
            # 请求对话摘要存入会话：RESTORE 事件带 dialog_req（用户消息），
            # 回复日志弹窗才能显示用户发送的内容（曾 100% 缺失，SHIELD-DIALOG-002）
            s_sess["req_dialog"] = dialog
            s_sess["stream_mode"] = stream_mode
            # 客户端名存入会话：RESTORE 事件复用（曾缺 upstream 字段，
            # 日志列表「客户端」列 MASK 行有值、RESTORE 行空白，显示不统一）
            s_sess["upstream_name"] = matched_up["name"] if matched_up else "" 
            # 脱敏管线耗时（毫秒）：MASK 事件展示，用户可看到代理增加的开销
            s_sess["mask_ms"] = (time.perf_counter() - _mask_t0) * 1000
            if ner_skips:
                # 降级明细存会话：详情弹窗按 `_detailSeq` 回源的是 **RESTORE** 事件，
                # 只挂在 MASK 上的话列表合并行看得到、弹窗看不到（半可见）。
                s_sess["ner_skips"] = ner_skips
            if ner_metrics:
                # 同一条坑的第三次（前两次：degraded / block_source）：治理器指标
                # （等待时长、全局限流次数）原先只挂 MASK，配对的 RESTORE 行没有，
                # 于是"降级可见"在弹窗里等于没做。
                s_sess["ner_metrics"] = ner_metrics
    except Exception:
        pass
    # P0-b：脱敏耗时与完成时刻写进 flow.metadata，供 `error()` 在 resp=0 的 ERR
    # 事件里归因（「卡在脱敏」vs「卡在上游」）。放在 emit 之前、且不依赖会话是否
    # 存在 —— 会话被 `_sweep` 回收后 metadata 仍在，而归因靠的正是它。
    try:
        flow.metadata["shield_mask_ms"] = round((time.perf_counter() - _mask_t0) * 1000, 1)
        flow.metadata["shield_mask_done_at"] = time.time()
    except Exception:
        pass
    _s_signed = _take_signed_skips(sid)
    # 严格模式闸门（§B3）必须在**请求出网前**生效：此时脱敏已完成（命中/占位符已定），
    # 只差回写与放行。判据用 inspection 的类别表：exempt（签名块按契约不扫）与 info
    # （取消/直通）不阻断，只有「检测没跑完」类降级才阻断。
    # 代价（如实声明）：占位符已签发，会留在跨请求复用表里（同值复用，不新增泄漏面）；
    # 本条请求本身未上行、也未回写 flow。
    if NER_REQUIRE_COMPLETE and inspection.has_blocking_reason(ner_skips):
        _strict_codes = sorted(c for c in ner_skips if ner_skips.get(c))
        _strict_report = inspection.build_report(
            decision=inspection.DECISION_BLOCKED,
            reasons=dict(ner_skips, semantic_incomplete=1),
            failed=True,
        )
        _emit("BLOCK", host=host, method=method, path=path.split("?")[0], sid=sid,
              reason="semantic_incomplete", block_source="engine",
              bytes=len(raw_content),
              msg=("严格模式：本次语义检测未完整执行（%s），已阻断，未上行"
                   % ", ".join(_strict_codes)),
              upstream=up_name, **source, **_strict_report)
        flow.response = http.Response.make(
            503,
            json.dumps({"error": {"code": "shield_semantic_incomplete",
                                  "reason": "semantic_incomplete",
                                  "hint": "已开启「语义检测必须完整」，本条未上行。请稍后重试，或在面板关掉该开关。"},
                        **_strict_report},
                       ensure_ascii=False).encode("utf-8"),
            {"content-type": "application/json", "Retry-After": "5"},
        )
        _drop(sid)
        return
    _emit(
        "MASK",
        host=host,
        method=method,
        path=emit_path.split("?")[0],
        sid=sid,
        count=hit_count,          # 本次实际命中的唯一原文数（含历史复用）
        new_count=new_count,      # 其中本次新增的
        masked_total=len(fwd),    # 会话累计脱敏的唯一值总数（历史会增长）
        items=items,
        upstream=matched_up["name"] if matched_up else "",
        model=model,
        dialog=dialog,
        req_preview=raw_preview,
        scan_scope=scan_scope,
        short_hits=short_hits,
        stream_mode=stream_mode,
        mask_ms=round((time.perf_counter() - _mask_t0) * 1000, 1),
        # 语义识别降级审计：本轮是否有叶子没走 NER（预算耗尽 / 单条过长 / 单次超时 /
        # 模型不可用），以及各原因各几条。非空时事件行会标出来，用户不必再去翻日志。
        **({"ner_truncated": True, "ner_skip_reasons": ner_skips} if ner_skips else {}),
        # A-6/C-1：排队时长单列（它与 mask_ms 是两回事：一个在等前面的请求，
        # 一个是自己在算），排障时"慢"的归因靠它。
        **({"queue_wait_ms": _res.queue_wait_ms} if _res.queue_wait_ms >= 1.0 else {}),
        # B-2：治理器指标（信号量等待 / 全局限流次数）。缺省不加字段，避免噪声。
        **(ner_metrics or {}),
        # 请求体形态：标准 LLM 形态不带该字段；非对象根 / 白名单外形态各记一种，
        # 便于用户在日志里发现「这条是靠兜底脱敏的」并反馈新协议形态。
        **({"body_shape": "non_object_root"} if not root_is_object
           else {"body_shape": "unknown_shape"} if unknown_shape else {}),
        # 前缀诊断（均不含原文）：本次是否回写了请求体、回写后与客户端原始字节的
        # 首个差异位置、命中的占位符是否为复用。用户报「上游缓存命中率归零」时，
        # 这三项能直接区分「我们改了字节」与「上游自己 miss」。
        body_rewritten=body_rewritten,
        first_diff_byte=first_diff_byte,
        suffix_reused=bool(_session_get(sid, {}).get("suffix_reused")),
        # 签名思考块整块豁免计数（本轮）：静默豁免必须可见，否则用户会以为全扫过了。
        # 缺省不加字段，避免常态噪声（与 ner_truncated 同一做法）。
        **({"signed_blocks_skipped": _s_signed} if _s_signed else {}),
        # 统一检测口径（§B1）：处置结论 + 完整度 + 原因码，与扩展桥接同源。
        **inspection.report_for_mask(changed=bool(hit_count), ner_skips=ner_skips,
                                     signed_skipped=_s_signed),
        **source,
    )


class _ResponseResult(NamedTuple):
    content: bytes | None  # already encoded wire bytes; no loop-side compression
    ok: bool
    error: str | None
    block: http.Response | None
    debug_text: str | None
    summary: dict | None  # worker-prepared event, published only by the result owner


def _response_offload(flow, sid, host, method, emit_path, source, ct):
    """整包响应侧的重活（A-3），跑在 `_AUX_POOL` 线程里。

    只**读** flow，不改它的任何字段；需要正文的三处一律显式传 `streamed_text`
    （restore 后的文本），回写统一交给调用它的协程（§4.2 不变式 3）。

    返回 `_ResponseResult`，包含编码后的正文和已准备的 RESTORE 事件：
      new_content  None = 未还原（体积超限或非结构化 ct），事件循环保持原文；
      err          非空 = 还原阶段抛异常（调用方记 ERR）；**审计与响应扫描照常执行**
                   —— 它们是安全层，不能因为"还原没做"就整段跳过（见下方注释）；
      block        非空 = 要把响应换成这个 503（命令拦截或审计熔断）。
    """
    _aux_stat_add("submitted")
    return _response_offload_locked(flow, sid, host, method, emit_path, ct, source)


def _stream_finish_offload(flow, sid, host, method, emit_path, source, restored_text,
                          session_ref=None, enqueued_at=None):
    """流式收尾的审计 + 响应扫描（0.6.0：从事件循环搬到 `_AUX_POOL`）。

    为什么**可以**搬：整包路径的 `_response_offload` 早就在 aux 线程里调用同样的
    `_audit_response` / `_scan_response`（含只读访问 flow.metadata）—— "审计/扫描在
    非循环线程上跑"已是本仓库的既有事实，这里只是把同款模式用到流式路径上。

    与整包路径唯一的差别：流式回调是**同步**的（mitmproxy 的 stream 回调没有 await
    点），所以投递后不等待。由此带来一个必须一起处理的事：`_drop(sid)` 也放到这里，
    否则会话可能在扫描读会话态之前就被丢掉（会静默少一次响应扫描）。

    实测收尾成本（事件循环原被占住的时间）：64KB ≈ 15ms、1MB ≈ 127ms、4MB ≈ 216ms。
    """
    _waited0 = time.perf_counter()
    # 流式收尾是"投递即返回"，事件循环侧看不到任何等待 —— 这里是唯一能证明
    # "响应慢在池排队"的位置：排队时长 = 投递时刻 → 真正开跑的时刻。
    _queued_ms = 0.0
    if enqueued_at:
        _queued_ms = (_waited0 - enqueued_at) * 1000.0
        if _queued_ms >= _AUX_WAIT_TRACE_MS[0]:
            _AUX_WAIT_TRACE_MS[0] = _queued_ms
        if _queued_ms >= _AUX_WAIT_TRACE_S * 1000.0:
            _emit("ERR", host=host, method=method, path=emit_path.split("?")[0], sid=sid,
                  msg="流式收尾在脱敏线程池排队 %.0fms（池宽 %d，见 aux_pool_stats）" % (
                      _queued_ms, _AUX_POOL._max_workers),
                  reason="stream_finish_wait", aux_wait_ms=round(_queued_ms, 1), **source)
    try:
        _aux_stat_add("wait_ms_total", _queued_ms)
        _aux_stat_add("stream_finish")
        # `apply_block=False`：流式响应此刻已逐块下发到客户端，**再写 flow.response
        # 既拦不住也已经晚了**；而且这里是 aux 线程，`flow.response = ...` 是 mitmproxy
        # 状态，按本模块不变式 3 只能在事件循环线程碰（整包路径同样显式传 False）。
        # 熔断的**记录**不受影响：`_audit_response` 先 `_emit("BLOCK", ...)` 再判断是否回写，
        # 所以流式路径上的语义是"审计熔断：只记录、不回写"，且如实写在这里。
        _audit_response(flow, sid, host, method, emit_path, source,
                        streamed_text=restored_text, apply_block=False)
        _scan_response(flow, sid, host, method, emit_path, source,
                       streamed_text=restored_text)
    except Exception as e:
        # 与整包路径同口径：失败必须留痕（审计是安全层，不能因为搬了线程就静默丢）
        _aux_stat_add("failed")
        _log("[stream] 收尾审计/扫描失败：%s: %s" % (type(e).__name__, str(e)[:120]))


def aux_drain(timeout=10.0):
    """等"已投递但未完成"的 aux 任务收尾（测试 / 诊断 / 冒烟脚本用）。

    流式收尾是投递即返回的，所以断言审计结果前必须先过这个闸口。
    返回 True = 已排空；False = 超时（并留一行日志，不静默）。
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        with _AUX_PENDING_LOCK:
            if _AUX_PENDING[0] <= 0:
                return True
        time.sleep(0.005)
    with _AUX_PENDING_LOCK:
        left = _AUX_PENDING[0]
    _log("[aux] drain 超时：仍有 %d 项未完成" % left)
    return False


def _response_offload_locked(flow, sid, host, method, emit_path, ct, source):
    """Response computation under the submission's count/byte reservation."""
    raw = flow.response.content or b""
    new_content = None
    err = None
    try:
        if "text/event-stream" in ct:
            new_content = _restore_sse_body(raw, sid)
        elif _is_ndjson_ct(ct):
            new_content = _restore_ndjson_body(raw, sid)
        elif "json" in ct:
            new_content = _restore_json_body(
                raw, sid, host, method, emit_path,
                flow.response.headers.get("content-type", "") or "")
    except Exception as e:
        # ⚠️ 这里**不能 return**（0.6.0 修 A-3 重构引入的 fail-open 回归）：
        # 0.5.0 的等价分支只置 ok = False，紧接着的审计与响应扫描**无条件执行**；
        # 本函数一度在异常时直接 return，于是"body 形态能诱发还原异常"就等价于
        # "这条响应不做审计、不落响应扫描" —— 输入可控地关掉一层安全检测。
        # 还原失败时下游按**未还原原文**继续扫（审计口径照旧只扫前 128KB）。
        _aux_stat_add("failed")
        err = str(e)[:200]
    # 还原后的文本：审计与 S9 都必须扫**还原后**的文本（占位符状态下路径/主机名
    # 都是假的，判不准也没意义）；未还原时退回原文，与旧路径一致。
    text = new_content.decode("utf-8", errors="replace") if new_content is not None \
        else raw.decode("utf-8", errors="replace")

    block = None
    cmd_blocked = (_session_get(sid) or {}).get("cmd_blocked")
    if cmd_blocked:
        # W2-4：block 模式的**非流式**收敛——整包换成结构化错误。
        # 流式路径无法回收已下发的字节，那条路径靠槽位置空截断下发（见 _cmd_process）。
        block = http.Response.make(
            503,
            json.dumps({"error": {"code": "shield_command_blocked",
                                   "reason": "dangerous_command_in_response"}},
                       ensure_ascii=False).encode("utf-8"),
            {"content-type": "application/json"},
        )
    ok = not cmd_blocked and not err
    debug_text = text if DEBUG else None
    # 审计：apply_block=False —— 只构造熔断响应，回写由事件循环负责
    audit_block = _audit_response(flow, sid, host, method, emit_path, source,
                                  streamed_text=text, apply_block=False)
    if audit_block is not None:
        block = audit_block
    # 响应侧扫描：检测模型回复中不在本会话映射里的 PII（幻觉/训练数据泄漏）
    _scan_response(flow, sid, host, method, emit_path, source, streamed_text=text)
    summary = None
    if ok and block is None:
        summary = _emit_restore_summary(
            flow, sid, host, method, emit_path, source,
            ok=True, streamed_text=text, prepare_only=True)
    if new_content is not None:
        from mitmproxy.net import encoding
        new_content = encoding.encode(new_content, flow.response.headers.get("content-encoding") or "identity")
    _aux_stat_add("completed")
    return _ResponseResult(new_content, ok, err, block, debug_text, summary)


async def response(flow: http.HTTPFlow):
    """整包响应处理（A-3：重活下池，回写留在事件循环）。

    mitmproxy 12 的 `addonmanager.invoke_addon` 对协程钩子会 `await`
    （实测 `inspect.isawaitable(res) -> await res`），所以这里可以安全地
    `await run_in_executor`。**注意**：`invoke_addon_sync` 遇到协程钩子会直接
    抛 AddonManagerError，而它只用于 Load/Running/Configure 这类生命周期事件，
    不涉及 response。
    """
    if flow.metadata.get("shield_local_response"):
        return
    if _cancel_signal(flow).is_set():
        _aux_abandon(flow)
        _record_client_cancel(flow, "local_response")
        return
    _transport_complete(flow)
    sid = flow.metadata.get("session_id")
    if not sid:
        return
    # 流式响应已在 stream 回调里逐块还原并收尾，这里不再重复处理
    if flow.metadata.get("shield_streamed"):
        return
    host = getattr(flow.request, "host", None) or flow.request.pretty_host
    path = flow.request.path
    emit_path = flow.metadata.get("shield_orig_path") or path
    method = getattr(flow.request, "method", "") or ""
    # reverse 模式下 host/path 已在 request 阶段改写为真实上游；session_id 存在即为已拦截流量
    if CAPTURE_MODE != "reverse" and not is_target(host, path):
        _aux_abandon(flow)
        _drop(sid)
        return
    if not flow.response or not _message_bytes(flow.response):
        _aux_abandon(flow)
        _drop(sid)
        return

    ct = (flow.response.headers.get("content-type", "") or "").lower().strip()
    _touch(sid)
    _sweep()
    admission = _aux_token(flow)
    s_cur = admission.session_ref if admission is not None and not admission.released else _session_get(sid)
    source = (s_cur or {}).get("source", {})
    # 响应到达时间：整包路径在此刻记（首字节=响应完成）；流式在 _stream 首 chunk 记
    if s_cur is not None and s_cur.get("resp_ts") is None:
        s_cur["resp_ts"] = time.time()
    # A-3：解析/还原/序列化 + RESTORE 摘要 + 审计 + 响应扫描全部下池。
    # 事件循环在这里只是 `await`，不再被 O(body) 的 CPU 活占住。
    _aux_t0 = time.perf_counter()
    future = None
    try:
        raw_size = len(_message_bytes(flow.response))
        # Queue only immutable wire inputs. Output-limited decoding and the
        # atomic actual-retained-byte upgrade happen inside the worker.
        token = _aux_reserve(flow, raw_size)
        if token is None:
            raise RuntimeError("aux response byte budget exceeded")
        snapshot = _aux_snapshot(flow)
        future = _aux_submit(token, sid, s_cur, _response_offload,
                             snapshot, sid, host, method, emit_path.split("?")[0],
                             dict(source), ct)
        wrapped = asyncio.wrap_future(future)
        wrapped.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        result = await _await_with_deadline(wrapped, _AUX_WAIT_HARD_S, _cancel_signal(flow))
        if token.abandoned:
            # error() may terminate a flow while its response hook is awaiting.
            # The worker still audits, but only the existing terminal outcome wins.
            _aux_stat_add("late_completed")
            return
        new_content, ok, err, block, debug_text, summary = result
    except _ClientFlowCancelled:
        _aux_abandon(flow)
        _aux_stat_add("cancelled")
        _record_client_cancel(flow, "local_response")
        return
    except asyncio.CancelledError:
        _aux_abandon(flow)
        _aux_stat_add("cancelled")
        raise
    except Exception as exc:
        _aux_abandon(flow)
        reason = ("response_offload_timeout" if isinstance(exc, asyncio.TimeoutError)
                  else "response_offload_failed")
        _aux_stat_add("timeout" if isinstance(exc, asyncio.TimeoutError) else "failed")
        _emit("ERR", host=host, method=method, path=emit_path.split("?")[0], sid=sid,
              reason=reason, failure_phase="local_response", upstream_may_have_executed=True,
              msg="Local response processing failed; upstream may have executed.", **source)
        flow.response = http.Response.make(
            503, json.dumps({"error": {"code": "shield_offload_timeout" if
                isinstance(exc, asyncio.TimeoutError) else "shield_offload_failed",
                "upstream_may_have_executed": True}}).encode(),
            {"Content-Type": "application/json", "x-should-retry": "false"})
        if future is None and s_cur is not None:
            _drop(sid, expect=s_cur)
        return
    # 等待留痕（阈值与硬上限的分工见 _AUX_WAIT_TRACE_S 的注释）
    _aux_wait_ms = (time.perf_counter() - _aux_t0) * 1000.0
    if _aux_wait_ms >= _AUX_WAIT_TRACE_MS[0]:
        _AUX_WAIT_TRACE_MS[0] = _aux_wait_ms
    _aux_wait_kw = {}
    if _aux_wait_ms >= _AUX_WAIT_TRACE_S * 1000.0:
        _aux_wait_kw["aux_wait_ms"] = round(_aux_wait_ms, 1)
    if _aux_wait_kw:
        # 慢在哪要给得出证据：这条事件让"响应很慢"从主观感受变成可导出的时间戳
        _emit("ERR", host=host, method=method, path=emit_path.split("?")[0], sid=sid,
              msg="响应侧等待脱敏线程池 %.0fms（池宽 %d，见 aux_pool_stats）" % (
                  _aux_wait_ms, _AUX_POOL._max_workers),
              reason="response_offload_wait", **_aux_wait_kw, **source)
    if err:
        s_err = _session_get(sid, {}) if sid else {}
        _emit("ERR", host=host, method=method, path=emit_path.split("?")[0], sid=sid,
              msg=err,
              upstream=s_err.get("upstream_name") or flow.metadata.get("shield_upstream") or "",
              model=s_err.get("model") or flow.metadata.get("shield_model") or "",
              **source)
    # ---- 回写（只在事件循环线程碰 flow）----
    if new_content is not None:
        if isinstance(flow.response, http.Response):
            flow.response.raw_content = new_content
            if "transfer-encoding" not in flow.response.headers:
                flow.response.headers["content-length"] = str(len(new_content))
        else:
            flow.response.content = new_content
    if ok and block is None and summary is not None:
        _emit("RESTORE", **summary)
    if DEBUG and debug_text is not None:
        _debug(f"RESPONSE {host}{path.split('?')[0]} -- 还原后(返回客户端)", sid, debug_text)
    if block is not None:
        flow.response = block
    # 只丢“自己那条”会话：上面那次 await 期间，同一 sid 可能已经建了新会话
    # （同一会话的连续两轮请求），无条件 pop 会把新会话连同 rev 表一起抹掉 ——
    # 表现为“占位符还原不回来”。流式侧已按 expect 加固，整包路径原先漏了。
    if s_cur is not None:
        _drop(sid, expect=s_cur)



def _scan_response(flow, sid, host, method, path, source, streamed_text=None):
    """响应侧扫描：还原后的 body 里出现本会话未脱敏过的 PII = 模型自己生成的（幻觉/训练数据泄漏）。

    只读不改 body，异常静默，仅在 RESPONSE_SCAN 开启时执行。
    """
    if not RESPONSE_SCAN:
        return
    try:
        resp = flow.response
        if resp is None:
            return
        s = _session_get(sid) or {}
        fwd = s.get("fwd", {})
        restored_origs = s.get("restored_origs") or set()
        now = time.time()
        recent_ttl = _recent_ttl()

        def _is_known_orig(val):
            if val in fwd or val in restored_origs:
                return True
            rec = _tables().fwd.get(val)
            if rec and (now - rec[2] <= recent_ttl):
                return True
            return False
        # 流式接管时 flow.response.content 不可用，用回调累积文本
        if streamed_text is not None:
            body = streamed_text
        elif resp.content:
            body = resp.content.decode("utf-8", errors="replace")
        else:
            return
        # 响应 JSON 可能带 \uXXXX 转义（部分 SDK 默认 ensure_ascii）：直接扫原文时，
        # 转义序列的十六进制尾巴（如 \u8bdd 末位 d）会粘住数字边界导致漏检。
        # 先解析重排为非转义文本再扫（解析失败保持原文，SSE 场景走这里）。
        # ⚠️ 解析本身是 O(body)：A-1 给审计加了 `AUDIT_PARSE_MAX`，这里曾漏掉同形态的一处
        # —— 一个 30MB 的响应会在事件循环上白付一次全量 `json.loads`，而下面只扫前
        # `_SCAN_BODY_MAX`。超过解析预算就**跳过解析**（与审计 parse_skipped 同口径），
        # 直接扫原文：宁可少一层"转义归一"，也不在循环上做整份解析。
        # ⚠️ 单位说明：这里是**字符数**与字节预算比较。对中文（UTF-8 3 字节/字）
        # 等于放行约 3 倍字节量 —— 属刻意的近似（对 body 再 encode 一次反而更贵），
        # 但确实意味着 CJK 大响应的解析开销比英文高 3 倍，故记在这里而非留给读者猜。
        if len(body) <= AUDIT_PARSE_MAX:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, (dict, list)):
                    body = json.dumps(parsed, ensure_ascii=False)
            except Exception:
                pass
        # 超长 body 全量正则扫描会霸占事件循环（几 MB 文本 × N 条规则）：只扫前段。
        # 响应侧扫描是防御性功能，前段命中已覆盖大部分幻觉/泄漏场景，代价是可控的。
        if len(body) > _SCAN_BODY_MAX:
            body = body[:_SCAN_BODY_MAX]
        found = {}
        # 与 mask() 同款避让：被豁免的连接串区间不许 EMAIL 规则二次命中，
        # 否则模型复述的模板会被误报成「发现邮箱」（此处只影响告警，不改文本）。
        exempt_conn = []
        for rx, label, gidx in RULES:
            if not _rule_enabled(label):
                continue
            if not _rule_may_hit(body, label):
                continue  # 特征预检：不含必含特征，跳过整条规则扫描（与脱敏路径同款）
            for m in rx.finditer(body):
                orig = m.group(gidx)
                if label == "CARD" and not _card_ok(orig):
                    continue
                if label == "IDCARD" and not _idcard_ok(orig):
                    continue
                if label == "PHONE" and not _phone_ok(orig):
                    continue
                if label == "LANDLINE" and not _landline_ok(orig):
                    continue
                if label == "EMAIL" and not _email_ok(orig):
                    continue
                if label == "IBAN" and not _iban_ok(orig):
                    continue
                if label == "JWT" and not _jwt_ok(orig):
                    continue
                if label == "IP_PUBLIC" and not _ip_public_ok(orig):
                    continue
                if label == "IPV6_PRIVATE" and not _ipv6_private_ok(orig):
                    continue
                if label == "USCC" and not _uscc_ok(orig):
                    continue
                if label == "CONNSTR" and not _connstr_ok(orig, m, body):
                    if len(exempt_conn) < _CONNSTR_EXEMPT_MAX:
                        exempt_conn.append((m.start(), m.end()))
                    continue
                if label == "EMAIL" and _overlaps_exempt_conn(m.start(), m.end(), exempt_conn):
                    continue
                if _is_known_orig(orig):
                    continue  # 本会话/跨轮次脱敏或本次还原回来的值，跳过
                found.setdefault(label, {})[orig] = None
        # 用户配置的前缀规则（sk-/ah- 等）不在 RULES 里，响应侧同样要扫
        if _rule_enabled("API_KEY"):
            prefix_rx = _prefix_secret_regex()
            if prefix_rx:
                for m in prefix_rx.finditer(body):
                    orig = m.group()
                    if _is_known_orig(orig):
                        continue
                    found.setdefault("API_KEY", {})[orig] = None
        if found:
            items = []
            # found[label] 用 dict 当有序集合去重：曾用 list 直接 append 每次命中，
            # 同一个手机号在长回复里出现上万次就攒上万个重复项，SCAN_WARN 的
            # count 与明细全是同一个值刷屏（「发现 10 项」实为 1 个值重复 10 次），
            # 且白白占内存。去重后 count 才是「发现几个不同的 PII」。
            for label, vals in found.items():
                for v in list(vals)[:10]:
                    # 凭据类响应 PII 同样不明文落库（与 MASK 口径一致）
                    if label in CREDENTIAL_LABELS:
                        items.append({"label": label, "cred": True,
                                      "digest": _cred_digest(v),
                                      "preview": _preview(v, label),
                                      "length": len(v)})
                    else:
                        items.append({"label": label, "original": v, "preview": _preview(v, label)})
            s_scan = _session_get(sid, {}) if sid else {}
            up_name = s_scan.get("upstream_name") or (flow.metadata.get("shield_upstream") if hasattr(flow, "metadata") else "") or ""
            model_name = s_scan.get("model") or (flow.metadata.get("shield_model") if hasattr(flow, "metadata") else "") or ""
            _emit("SCAN_WARN", host=host, method=method, path=path, sid=sid, count=len(items), items=items[:10],
                  upstream=up_name, model=model_name, **source)
    except Exception as e:
        s_scan = _session_get(sid, {}) if sid else {}
        _emit("ERR", host=host, method=method, path=path, sid=sid, msg="scan:" + str(e)[:120],
              upstream=s_scan.get("upstream_name", ""), model=s_scan.get("model", ""), **source)


def _setter(obj, key):
    def _set(value):
        obj[key] = value
    return _set


def _sse_choice_index(choice, position):
    index = choice.get("index")
    return index if type(index) is int and index >= 0 else position


def _sse_response_channel(data, kind):
    """Responses API 的通道键：同一 output item 的多个 content part 必须分开。

    规范允许一个 message item 的 `content` 是数组（多个 output_text part），
    delta / .done 事件都带 `content_index`。只按 output_index 建通道会让同一 item
    下所有 part 共用一个跨 chunk 缓冲，实测两个后果：
      - part 0 的 `.done` 会 flush/pop 掉整个 item 的通道，part 1 的半截占位符
        被当成 part 0 的尾巴吐出、或被直接丢掉；
      - 两个 part 的增量交错时，半截占位符会串到另一个 part 的文本里。

    `content_index` 缺失或为 0 时**省略该段**，键形与改动前完全一致
    （`r0.text`）—— 官方目前每个 message 只发一个 part，存量单 part 流的行为
    零变化。这个改动只影响真的下发多 part 的自建/中转实现。

    刻意**不引入 item_id**：它在部分中转实现里会缺失，一旦 delta 与 .done 的
    item_id 不齐，就会让「.done 清理该通道」失配（缓冲残留被重复吐出），比只用
    output_index 更糟；而 output_index 已足以区分不同 item。
    """
    ci = data.get("content_index")
    if type(ci) is int and ci > 0:
        return "r%s.%d.%s" % (data.get("output_index", 0), ci, kind)
    return "r%s.%s" % (data.get("output_index", 0), kind)


def _sse_text_slots(data):
    """列出 SSE 事件里的增量文本槽位：[(channel, text, setter, escape)]。

    只有"增量"字段才需要跨 chunk 缓冲半截占位符，且每个字段必须用独立通道 ——
    正文 delta 与 tool 参数 delta 共用缓冲会把上一个字段的尾巴吐进下一个字段，
    表现为字段被清空、内容错位。
    """
    slots = []
    if not isinstance(data, dict):
        return slots
    # OpenAI Chat Completions / Completions 流
    for position, c in enumerate(data.get("choices", []) or []):
        if not isinstance(c, dict):
            continue
        # Sparse chunks may each contain only one of several completion choices.
        idx = _sse_choice_index(c, position)
        d = c.get("delta")
        if isinstance(d, dict):
            if isinstance(d.get("content"), str):
                slots.append((f"c{idx}.content", d["content"], _setter(d, "content"), False))
            if isinstance(d.get("reasoning_content"), str):
                slots.append((f"c{idx}.reason", d["reasoning_content"], _setter(d, "reasoning_content"), False))
            # 部分上游同时下发 reasoning_content 与 reasoning 两份同内容
            # 增量，各自独立切分——必须单独槽位独立缓冲，否则半截占位符原样透传
            # （探针实测：{{TESTNAME 残片直接出现在 SSE 里），且与 reason 通道共用
            # 会把两份文本互相串字。
            if isinstance(d.get("reasoning"), str):
                slots.append((f"c{idx}.reason2", d["reasoning"], _setter(d, "reasoning"), False))
            for tidx, tc in enumerate(d.get("tool_calls", []) or []):
                fn = tc.get("function") if isinstance(tc, dict) else None
                # 槽位键必须用 tool_calls[].index（协议里标明这段增量属于第几个工具），
                # 不能用数组下标：并行工具调用时每个 chunk 通常只带一个元素，
                # index=0 和 index=1 的增量都会拿到下标 0，两个工具的跨包缓冲直接串在
                # 一起——表现为参数互相污染、JSON 解析失败（SHIELD-TOOLIDX-001）。
                # index 缺失时才回落数组下标（少数上游不下发该字段）。
                slot_no = tc.get("index") if isinstance(tc, dict) and isinstance(tc.get("index"), int) else tidx
                # arguments 是 JSON 文本，还原值要按 JSON 转义，否则客户端解析工具参数直接报错
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    slots.append((f"c{idx}.tool{slot_no}", fn["arguments"], _setter(fn, "arguments"), True))
            # 旧式 function_call（OpenAI 2023 协议，部分中转与本地推理框架仍在用）：
            # 参数同样按增量下发，没有槽位就完全不还原，客户端拿占位符去执行工具。
            fc = d.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
                slots.append((f"c{idx}.fcall", fc["arguments"], _setter(fc, "arguments"), True))
        if isinstance(c.get("text"), str):
            slots.append((f"c{idx}.text", c["text"], _setter(c, "text"), False))
    etype = data.get("type") if isinstance(data.get("type"), str) else ""
    # Anthropic Messages 流
    if etype == "content_block_delta":
        d = data.get("delta")
        if isinstance(d, dict):
            blk = data.get("index", 0)
            if isinstance(d.get("text"), str):
                slots.append((f"a{blk}.text", d["text"], _setter(d, "text"), False))
            # Anthropic 思考增量**不建还原槽位**（2026-10-02 定案，D6-B）。
            # 思考块带 `signature`、上游校验「签名 = 被签正文」；还原会把正文改成明文，
            # 而签名覆盖的是占位符形态 → 下一轮历史回放必 400，而正文不可编辑，
            # 用户无法自救。不能改成「按块判断是否签名块」：签名在流末的
            # `signature_delta` 才到，delta 时点根本不知道——流式下只有"不还原"是安全的。
            # 未列入槽位的字段由 `_restore_sse_data` 原样透传（它只改槽位），故去掉槽位
            # 就是逐字节透传；但该事件会改走 `_restore_tree` 兜底，所以另一边必须同步
            # 挡 `thinking_delta`（见 `_RESTORE_SKIP_BLOCK_TYPES`）。
            # OpenAI `reasoning_content`/`reasoning`、Responses `reasoning_text`、
            # Gemini 无签名的思考文本都不受这条影响，继续还原（上下的其它槽位）。
            # tool_use 参数按 partial_json 增量下发，不还原客户端就拿占位符去执行工具
            if isinstance(d.get("partial_json"), str):
                slots.append((f"a{blk}.pj", d["partial_json"], _setter(d, "partial_json"), True))
    # OpenAI Responses API 流
    if etype == "response.output_text.delta" and isinstance(data.get("delta"), str):
        slots.append((_sse_response_channel(data, "text"), data["delta"], _setter(data, "delta"), False))
    elif etype == "response.reasoning_text.delta" and isinstance(data.get("delta"), str):
        # 思考文本独立通道（同 reasoning_content：跨 chunk 半截占位符必须缓冲还原，
        # 曾漏槽位导致 {{ 残片透传；与正文通道分开避免串字）
        slots.append((_sse_response_channel(data, "reason"), data["delta"], _setter(data, "delta"), False))
    elif etype == "response.function_call_arguments.delta" and isinstance(data.get("delta"), str):
        slots.append((_sse_response_channel(data, "args"), data["delta"], _setter(data, "delta"), True))
    # Ollama NDJSON 增量。用 "done" 做判别（Ollama 每条记录都带它），避免把
    # OpenAI 非流式响应里的 choices[].message 误当增量槽位。
    if "done" in data:
        msg = data.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            slots.append(("o.message.content", msg["content"], _setter(msg, "content"), False))
        # /api/generate 的正文直接放在顶层 response 字段
        if isinstance(data.get("response"), str):
            slots.append(("o.response", data["response"], _setter(data, "response"), False))
    return slots


def _sse_terminal_prefixes(data):
    """Channels ending in this event: None means all, () means none."""
    if not isinstance(data, dict):
        return ()
    if data.get("type") in ("message_stop", "message_delta", "response.completed",
                            "response.incomplete", "response.failed"):
        return None
    if data.get("type") == "content_block_stop":
        return (f"a{data.get('index', 0)}.",)
    # 收尾通道必须与 _sse_text_slots 的通道键同源（含 content_index），否则
    # part 0 的 .done 会把 part 1 的缓冲一起冲掉。
    if data.get("type") == "response.output_text.done":
        return (_sse_response_channel(data, "text"),)
    if data.get("type") == "response.reasoning_text.done":
        return (_sse_response_channel(data, "reason"),)
    if data.get("type") == "response.function_call_arguments.done":
        return (_sse_response_channel(data, "args"),)
    return tuple(f"c{_sse_choice_index(c, position)}."
                 for position, c in enumerate(data.get("choices", []) or [])
                 if isinstance(c, dict) and c.get("finish_reason"))


def _restore_sse_data(data, sid, final=False, final_prefixes=()):
    """就地还原单个 SSE 事件的 JSON 负载。非 dict 负载（null/[]/"x"/123）直接原样返回。"""
    if not isinstance(data, dict):
        return data
    slots = _sse_text_slots(data)
    if slots:
        s = _session_get(sid) or {}
        for channel, text, setter, escape in slots:
            channel_final = final or final_prefixes is None or channel.startswith(final_prefixes)
            restored = restore(text, sid, channel=channel, escape=escape, final=channel_final)
            # 命令拦截（W2-1/2/4）挂在**还原后**的文本上：占位符状态下路径/主机名
            # 都是假的，判不准也没意义。observe 模式下它逐字节原样返回。
            restored = _cmd_process(restored, channel, sid, escape=escape, final=channel_final)
            setter(restored)
        # 只有真的留下半截占位符或命令前瞻缓冲时才记模板（收尾补发用），正常路径零额外序列化。
        # 命令缓冲也必须记：否则收尾补发无模板可克隆，只能退到 `_wrap_bare_flush` 的
        # 裸文本外壳——SSE 里那是一条**非法 JSON** 的 data 行，严格客户端（以及本仓库的
        # 冒烟脚本）整条丢弃，表现为「改写后正文凭空消失」（2026-09-22 冒烟实测）。
        pend = s.get("pending") or {}
        cmdp = s.get("cmd_pend") or {}
        for channel, _t, _s, escape in slots:
            if pend.get(channel) or cmdp.get(channel):
                s.setdefault("flush_tmpl", {})[channel] = json.dumps(data, ensure_ascii=False)
        return
    # 非增量事件（message_start / content_block_start / response.completed …）是完整快照，整树还原
    for k, v in list(data.items()):
        data[k] = _restore_tree(v, sid, k)
    # Responses .done payloads replace the full value, rather than extending
    # its deltas. Discard that channel's stale tail after restoring the snapshot;
    # appending it would duplicate text or emit a delta after completion.
    snapshot = {
        "response.output_text.done": ("text", "text"),
        "response.reasoning_text.done": ("text", "reason"),
        "response.function_call_arguments.done": ("arguments", "args"),
    }.get(data.get("type"))
    if snapshot is not None and isinstance(data.get(snapshot[0]), str):
        channel = _sse_response_channel(data, snapshot[1])
        s = _session_get(sid) or {}
        s.get("pending", {}).pop(channel, None)
        s.get("flush_tmpl", {}).pop(channel, None)


def _build_flush_event(tmpl_json, channel, leftover):
    """用最后一个同通道事件做模板，补发一条只含残留文本的事件。

    直接把残留文本裸拼在流末尾会破坏 SSE 结构，克隆真实事件才能保证
    客户端 SDK 的字段校验（id/model/created 等）通过。
    """
    try:
        data = json.loads(tmpl_json)
    except Exception:
        return ""
    hit = False
    for ch, _text, setter, escape in _sse_text_slots(data):
        if ch == channel:
            setter(leftover)
            hit = True
        else:
            setter("")  # 其余槽位清空，避免重复下发同一段文本
    if not hit and channel.endswith(":db") and isinstance(data, dict):
        # 支持扩展豆包等私有信封模板回填，避免异常截断时收尾退化为裸文本
        cnt = data.get("content")
        if isinstance(cnt, str) and cnt.startswith("{") and "text" in cnt:
            try:
                inner = json.loads(cnt)
                if isinstance(inner, dict) and "text" in inner:
                    inner["text"] = leftover
                    data["content"] = json.dumps(inner, ensure_ascii=False)
                    hit = True
            except Exception:
                pass
        elif isinstance(cnt, dict) and "text" in cnt:
            cnt["text"] = leftover
            hit = True
    if not hit:
        return ""
    for c in data.get("choices", []) or []:
        if isinstance(c, dict):
            c["finish_reason"] = None  # 补发事件不能带结束标记
    prefix = ""
    if isinstance(data.get("type"), str):
        prefix = "event: %s\n" % data["type"]  # Anthropic / Responses 客户端依赖 event: 行
    return prefix + "data: " + json.dumps(data, ensure_ascii=False) + "\n\n"


def _wrap_bare_flush(text, framing):
    """无模板可克隆时的**最小合法外壳**（兜底，只为不丢字）。

    SSE：每行都要带 `data: ` 前缀，内部的换行必须拆成多条 data 行——直接拼裸文本
    会被符合规范的解析器丢掉。NDJSON：必须是一行合法 JSON，用 {"content": ...} 承接。
    两种外壳都不引入新语义，客户端读不到就忽略，但不会让补发的字连同整行一起消失。
    """
    if not text:
        return ""
    try:
        if framing == "ndjson":
            return json.dumps({"content": text}, ensure_ascii=False) + "\n"
        return "\n".join("data: " + ln for ln in str(text).split("\n")) + "\n\n"
    except Exception:
        return ""


def _cmd_flush_frames(sid, channel_prefixes, framing):
    """流末把命令拦截的前瞻缓冲补发出去（**不吞字**），返回已封装的帧列表。

    为什么必须补发：rewrite/block 模式会把每块末尾 hold 个字符暂留到下一块判命令，
    流结束时最后那一段从没被处理过——不补就是静默吞字。
    顺序：命令缓冲装的是本次流末尾**更靠前**的文本（占位符截留的尾巴在后），
    所以调用方必须先吐本函数的帧，再吐 `pending` 的帧。
    block 模式下已命中的会话不再补发（回复已阻断）。
    """
    s = _session_get(sid)
    if not isinstance(s, dict):
        return []
    pend = s.get("cmd_pend")
    if not isinstance(pend, dict) or not pend:
        return []
    if s.get("cmd_blocked"):
        pend.clear()
        return []
    tmpl_all = s.get("flush_tmpl") or {}
    builder = _build_flush_line if framing == "ndjson" else _build_flush_event
    out = []
    for channel in list(pend.keys()):
        if channel_prefixes is not None and not channel.startswith(channel_prefixes):
            continue
        leftover = pend.pop(channel, "") or ""
        if not leftover:
            continue
        # 走**统一入口**而不是直接 rewrite：缓冲里可能压着一条从没被扫过的命令，
        # 补发时必须一并做探测与留痕——rewrite 模式下槽位级命中是这条信号落库的
        # 唯一来源，漏在这里就是「改了但没记」。
        restored = _cmd_process(leftover, channel, sid, final=True)
        if not restored:
            continue
        tmpl_json = tmpl_all.get(channel, "")
        evt = builder(tmpl_json, channel, restored) if tmpl_json else ""
        # 无模板时不能裸拼文本（SSE 里裸文本没有 data: 前缀，严格解析器整行忽略），
        # 与 _flush_pending 同一口径：退到最小合法外壳。
        out.append(evt if evt else _wrap_bare_flush(restored, framing))
    return out


def _flush_pending(sid, channel_prefixes=None, framing="sse"):
    """把各通道滞留的半截占位符补发出去，返回待追加的流文本。

    补发前必须先把 leftover 还原成原文（final=True 清空通道缓冲），
    否则客户端收到的补发帧里是未还原的占位符。
    framing 决定补发帧的封装形态：SSE 要克隆完整事件（客户端 SDK 会校验字段），
    NDJSON 只要一行 JSON。

    先吐命令拦截的前瞻缓冲（本轮末尾更靠前的文本），再吐占位符截留的尾巴。
    """
    s = _session_get(sid)
    if not s:
        return ""
    out = _cmd_flush_frames(sid, channel_prefixes, framing)
    pend = s.get("pending")
    if not isinstance(pend, dict) or not pend:
        return "".join(out)
    if s.get("cmd_blocked"):
        # block 模式已命中的会话：回复已阻断，**连占位符半截缓冲也不再补发**。
        # 不拦这里就会出现「已停止下发」之后又补一帧残片 —— `_cmd_flush_frames`
        # 有同样的守卫，两条补发路径的口径必须一致。
        pend.clear()
        (s.get("flush_tmpl") or {}).clear()
        return ""
    tmpl = s.get("flush_tmpl") or {}
    for channel, leftover in list(pend.items()):
        if channel_prefixes is not None and not channel.startswith(channel_prefixes):
            continue
        pend.pop(channel, None)  # 先取出，避免 restore 内部把自身 pending 再拼一遍
        tmpl_json = tmpl.pop(channel, "")
        if not leftover:
            continue
        try:
            slots = _sse_text_slots(json.loads(tmpl_json)) if tmpl_json else []
            escape = next((slot[3] for slot in slots if slot[0] == channel), False)
            restored = restore(leftover, sid, channel=channel, escape=escape, final=True)
        except Exception:
            restored = leftover
        builder = _build_flush_line if framing == "ndjson" else _build_flush_event
        evt = builder(tmpl_json, channel, restored)
        if evt:
            out.append(evt)
        elif restored:
            # 没有可用模板时**不能裸拼文本**：SSE 里裸文本没有 `data:` 前缀，严格解析器
            # 整行忽略；NDJSON 里裸文本不是合法 JSON，整行同样被丢弃。两条路径都会把
            # 补发内容吃掉（channel="raw" 的非 JSON 载荷走的正是这条无模板路径）。
            out.append(_wrap_bare_flush(restored, framing))
    return "".join(out)


def _build_flush_line(tmpl_json, channel, leftover):
    """NDJSON 版的收尾补发：克隆最后一条同通道记录，只留残留文本。"""
    try:
        data = json.loads(tmpl_json)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    hit = False
    for ch, _text, setter, _escape in _sse_text_slots(data):
        if ch == channel:
            setter(leftover)
            hit = True
        else:
            setter("")  # 其余槽位清空，避免重复下发同一段文本
    if not hit:
        return ""
    if "done" in data:
        data["done"] = False  # 补发帧不能带结束标记
    return json.dumps(data, ensure_ascii=False) + "\n"


def _restore_ndjson_line(line, sid, final=False):
    """还原 NDJSON 流中的单行 JSON（Ollama /api/chat 等）。

    整包 `json.loads` 对 NDJSON 必然失败，此前这条路径整个退化成「未还原透传」——
    用户在自己的客户端里看到 `{{PHONE_ab12cd}}` 原样留在回复中，而面板显示一切正常。

    与 SSE 同构：增量文本槽位走通道缓冲（半截占位符不原样透传），其余字段整树还原。
    解析失败的行原样返回：一行坏不能把整段输出吃掉。
    """
    stripped = line.strip()
    if not stripped:
        return line
    try:
        obj = json.loads(stripped)
    except Exception:
        # 调用方已保证只在「整行到齐」时进来（流式路径按 \n 切帧），
        # 走到这里说明上游本来就发了非 JSON 的行，吞掉它只会让客户端缺数据。
        return line
    if not isinstance(obj, dict):
        return line
    try:
        slots = _sse_text_slots(obj)
        if slots:
            s = _session_get(sid) or {}
            for channel, text, setter, escape in slots:
                restored = restore(text, sid, channel=channel, escape=escape, final=final)
                # 命令拦截：同 SSE 槽位路径（NDJSON 的增量文本也会被切成多块）
                restored = _cmd_process(restored, channel, sid, escape=escape, final=final)
                setter(restored)
            # 只有真的留下半截占位符或命令前瞻缓冲时才记模板（收尾补发用），正常路径零额外序列化
            pend = s.get("pending") or {}
            cmdp = s.get("cmd_pend") or {}
            for channel, _t, _s2, _e in slots:
                if pend.get(channel) or cmdp.get(channel):
                    s.setdefault("flush_tmpl", {})[channel] = json.dumps(obj, ensure_ascii=False)
            return json.dumps(obj, ensure_ascii=False)
        return json.dumps(_restore_tree(obj, sid), ensure_ascii=False)
    except Exception:
        return line


# NDJSON（换行分隔 JSON）内容类型。Ollama 用 application/x-ndjson，
# 部分网关用 application/jsonl / application/x-jsonlines。
_NDJSON_CONTENT_TYPES = ("application/x-ndjson", "application/ndjson",
                         "application/jsonl", "application/x-jsonlines")


def _is_ndjson_ct(content_type):
    ct = (content_type or "").lower()
    return any(t in ct for t in _NDJSON_CONTENT_TYPES)


def _handle_ndjson(flow, sid):
    """薄包装（保留给单测）：纯函数 + 回写。"""
    flow.response.content = _restore_ndjson_body(flow.response.content or b"", sid)


def _restore_ndjson_body(raw_bytes, sid):
    """整包 NDJSON 还原（纯函数，A-3：由 aux 线程调用）。"""
    raw = raw_bytes.decode("utf-8", errors="replace")
    lines = raw.split("\n")
    last = len(lines) - 1
    out = []
    for i, line in enumerate(lines):
        out.append(_restore_ndjson_line(line, sid, final=(i == last)))
    # 与 _handle_sse 对齐补收尾：最后一行以半截占位符结尾（模型被 max_tokens 截断在
    # 占位符中间）时，通道缓冲里的碎片不补发就被静默丢弃——回复少几个字，
    # 而 RESTORE 事件显示一切正常。
    tail = _flush_pending(sid, framing="ndjson")
    if tail:
        out.append(tail.rstrip("\n"))
    return "\n".join(out).encode("utf-8")


def _restore_sse_event(block, sid, final=False):
    """还原一个 SSE 事件块（可能含多行）。返回还原后的文本块。

    按事件粒度处理是流式透传的前提：一个事件到手立刻还原、立刻下发，
    首字延迟才不会等于整段生成时长。
    """
    out_lines = []
    for line in block.split("\n"):
        stripped = line.rstrip("\r")
        # 兼容 `data:`（无空格）与 `data: ` 两种 SSE 写法
        if stripped.startswith("data:"):
            payload = stripped[5:].lstrip(" ")
            if payload.strip() == "[DONE]":
                tail = _flush_pending(sid)  # [DONE] 之前必须把缓冲吐净，客户端见到 DONE 就不再收了
                if tail:
                    # tail 是完整 SSE 事件块（自带 \n\n），作为独立段插入，
                    # 前后必须有空行分隔，否则与相邻 data 行粘连成一个事件
                    out_lines.append("")
                    out_lines.extend(tail.rstrip("\n").split("\n"))
                    out_lines.append("")
                out_lines.append(line)
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                out_lines.append("data: " + restore(payload, sid, channel="raw", final=final))
                continue
            # 合法 JSON 但**不是对象**（null / [] / "x" / 123）：下面一律按 dict 用
            # （.get() / .items()），以前会抛 AttributeError，被 _handle_response 的
            # 外层 except 吞成一条 ERR 事件 —— 整条响应就此退化成「未还原透传」，
            # 用户看到的是占位符原样留在回复里。这类负载没有可还原的槽位，原样透传即可。
            if not isinstance(data, dict):
                out_lines.append(line)
                continue
            ending = _sse_terminal_prefixes(data)
            # A terminal chunk can contain the final text fragment. Restore it
            # before flushing, and leave other choices' partial tokens buffered.
            _restore_sse_data(data, sid, final=final, final_prefixes=ending)
            if ending is None or ending:
                tail = _flush_pending(sid, channel_prefixes=ending)
                if tail:
                    out_lines.append("")
                    out_lines.extend(tail.rstrip("\n").split("\n"))
                    out_lines.append("")
            out_lines.append("data: " + json.dumps(data, ensure_ascii=False))
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _restore_ext_sse_event(block, sid, stream_id, final=False):
    """扩展链路专属 SSE 事件还原。优先解耦处理豆包等私有信封，其余走标准 SSE 管线。

    块内**逐行独立判定**：SSE 规范允许一个事件块里有多条 data: 行，而豆包信封与
    标准 OpenAI 行完全可能同块并存。旧实现一见豆包行就整块 early return，同块其余
    的 data: 行既不还原、也不再交给 `_restore_sse_event` —— 占位符原样漏到页面上，
    这是浏览器链路唯一的泄漏形态且极难复现（要上游正好把两种行合进同一个事件块）。
    未命中豆包信封的行按**连续段**交回标准管线，保住多行事件的原有语义。
    """
    out_lines = []
    rest = []          # 连续的非豆包行，攒成一段后整体走标准管线

    def flush_rest():
        if not rest:
            return
        out_lines.extend(_restore_sse_event("\n".join(rest), sid, final=final).split("\n"))
        rest.clear()

    for line in block.split("\n"):
        stripped = line.rstrip("\r")
        if stripped.startswith("data:"):
            payload = stripped[5:].lstrip(" ")
            if payload.strip() and payload.strip() != "[DONE]":
                try:
                    data = json.loads(payload)
                except Exception:
                    data = None
                if isinstance(data, dict) and "choices" not in data and "response" not in data:
                    cnt = data.get("content")
                    channel = f"ext:{stream_id}:db"
                    replaced = None
                    if isinstance(cnt, str) and cnt.startswith("{") and "text" in cnt:
                        try:
                            inner = json.loads(cnt)
                        except Exception:
                            inner = None
                        if isinstance(inner, dict) and isinstance(inner.get("text"), str):
                            inner["text"] = restore(inner["text"], sid, channel=channel,
                                                    escape=False, final=final)
                            data["content"] = json.dumps(inner, ensure_ascii=False)
                            replaced = data
                    elif isinstance(cnt, dict) and isinstance(cnt.get("text"), str):
                        cnt["text"] = restore(cnt["text"], sid, channel=channel,
                                              escape=False, final=final)
                        replaced = data
                    if replaced is not None:
                        flush_rest()
                        out_lines.append("data: " + json.dumps(replaced, ensure_ascii=False))
                        s_ = _session_get(sid) or {}
                        pend = s_.get("pending") or {}
                        if pend.get(channel):
                            s_.setdefault("flush_tmpl", {})[channel] = json.dumps(replaced, ensure_ascii=False)
                        continue
        rest.append(line)
    flush_rest()
    return "\n".join(out_lines)


def restore_stream_chunk(text, sid, stream_id, content_type="", escape=False, final=False):
    """扩展链路的**分帧**还原入口：按帧边界切开流文本，逐帧走与代理链路相同的管线。

    ── 为什么必须有这一层（2026-09-16 真机往返实测定位）──

    代理链路是**引擎自己解析 SSE**：`_sse_stream_factory` 按空行切事件 →
    `json.loads` 取出负载 → `_sse_text_slots` 抽出**增量文本槽位** → 把**槽位文本**
    交给 `restore()`。于是半截占位符天然落在缓冲区结尾，`_PARTIAL_RX` 的
    「半截正好在结尾」判据成立，跨事件拼接正常。

    扩展链路此前把**整段 SSE 原文**（含 `data: {...}` 外壳）直接喂给 `restore()`。
    模型逐 token 输出时占位符会被切成两个事件：

        event A  content = "{{EMAIL"
        event B  content = "_dsszcd}}"

    `restore()` 看到的缓冲区结尾是 `"}}]}\\n\\n` 而不是半截占位符，判据永不成立 →
    两半各自原样下发，页面上留下裸 `{{EMAIL_dsszcd}}`。实测 Qwen 真实往返即此现象，
    且引擎侧 RESTORE 事件是 `restored=0 unresolved=0`——因为 `{{{` 从没进过替换阶段。

    修法**不是**放宽 `restore()` 的半截判据：那是代理链路共用的核心，改它等于让
    两条链路的缓冲行为互相牵扯。正确做法是把扩展链路提升到与代理链路**同一粒度**，
    由引擎做分帧 + 槽位抽取。副作用是扩展链路顺带继承了代理链路的全部能力：

    - 每个槽位独立通道，正文 / reasoning / tool_calls.arguments 互不串字；
    - 按槽位判定 escape（工具参数需 JSON 转义、正文不需要），不再靠"整条流猜一个值"；
    - 终止事件与 `[DONE]` 前后的缓冲补发（`_flush_pending`），不吞最后几个字。

    `stream_id` 用于在当前会话中隔离半帧切片缓冲 `ext_frames[stream_id]`。
    当前扩展链路每次 mask 均签发唯一的独立 sid，单 sid 对应单条流；通道状态由 sid 隔离。
    """
    s = _session_get(sid)
    if not isinstance(text, str):
        return text
    if not s:
        # 同 restore()：会话不存在 → 原样返回（安全门，绝不借全局复用表还原），
        # 但要如实计数，否则整条流在统计里是 0、页面上却满是 `{{...}}`。
        _count_orphans_without_session(sid, text)
        return text
    frames = s.get("ext_frames")
    if not isinstance(frames, dict):
        frames = s["ext_frames"] = {}
    elif stream_id not in frames and len(frames) >= _EXT_FRAMES_MAX:
        # stream_id 由页面可控（审计 M2）：不设上限就能在会话 TTL 内把引擎内存撑大。
        # dict 保持插入序，淘汰最老的一条即可。
        frames.pop(next(iter(frames)), None)

    ct = (content_type or "").lower()
    if _is_ndjson_ct(ct):
        kind, sep = "ndjson", "\n"
    elif "text/event-stream" in ct:
        kind, sep = "sse", "\n\n"
    else:
        # 非流式整体：JSON 响应体里的占位符都落在字符串内部，必须按 JSON 转义。
        # 其它类型（text/plain 等）沿用调用方判定。
        # 透传 final 参数：扩展对大响应的每个 TCP chunk 都会调用本函数（final=False），
        # 只有在 flush 阶段才会发 final=True。若写死 final=True，跨分片的占位符
        # 会在第一片就被提前清空缓冲，导致第二片拼不回。
        if final:
            frames.pop(stream_id, None)
        return restore(text, sid, channel=f"ext:{stream_id}",
                       escape=("json" in ct) or escape, final=final)

    # SSE 允许 CRLF；统一成 LF 后再按空行切事件（与 _sse_stream_factory 同源）
    buf = (frames.get(stream_id, "") + text).replace("\r\n", "\n")
    out = []
    # 只处理**已完整到达**的帧，半帧留在缓冲里等下一次调用——
    # 这正是「占位符被切在两个事件之间」能拼回来的原因。
    while True:
        idx = buf.find(sep)
        if idx < 0:
            break
        block, buf = buf[:idx], buf[idx + len(sep):]
        if kind == "sse":
            out.append(_restore_ext_sse_event(block, sid, stream_id, final=False) + sep)
        else:
            out.append(_restore_ndjson_line(block, sid, final=False) + sep)
    # 异常上游防御：持续推送不含帧边界的数据会让缓冲无限增长（内存 + 首字延迟失控）。
    # 与代理链路同样优先在最后一个换行处切分，避免把合法 JSON 拦腰截断。
    if len(buf) > _SSE_BUF_MAX:
        if kind == "sse":
            idx = buf.rfind("\n")
            if idx >= 0:
                out.append(_restore_ext_sse_event(buf[:idx], sid, stream_id, final=True) + sep)
                buf = buf[idx + 1:]
            else:
                out.append(_restore_ext_sse_event(buf, sid, stream_id, final=True) + sep)
                buf = ""
        else:
            out.append(_restore_ndjson_line(buf, sid, final=True) + sep)
            buf = ""
    if final:
        if buf:
            out.append(_restore_ext_sse_event(buf, sid, stream_id, final=True) if kind == "sse"
                       else _restore_ndjson_line(buf, sid, final=True))
        tail = _flush_pending(sid, framing="ndjson") if kind == "ndjson" else _flush_pending(sid)
        if tail:
            out.append(tail)
        frames.pop(stream_id, None)
    else:
        frames[stream_id] = buf
    return "".join(out)


def _sse_stream_factory(flow, sid, host, method, emit_path, source, framing="sse"):
    """构造 mitmproxy 响应流回调：按帧边界增量还原并立即下发。

    mitmproxy 默认把响应整包收完才交给 response 钩子，流式因此完全失去效果
    （首字延迟 = 整段生成时长，长回答表现为卡死）。这里在 responseheaders 阶段
    接管流，逐块处理。

    framing 决定切帧方式：`sse`（空行分隔的事件块，OpenAI/Anthropic/Gemini alt=sse/
    Cohere v2）与 `ndjson`（换行分隔的 JSON 行，Ollama）。两种格式的占位符跨 TCP 块
    分裂问题靠同一套「只在帧完整时处理」解决。
    """
    admission = _aux_token(flow)
    session_ref = admission.session_ref if admission is not None and not admission.released else _session_get(sid)
    state = {
        "decoder": codecs.getincrementaldecoder("utf-8")(errors="replace"),
        "buf": "",
        "text": [],       # 还原后文本留存（供审计/扫描），有上限
        "text_len": 0,
        "truncated": False,  # 文本留存已达上限，后续块不再累积
        "usage": {},      # 累计 token 用量，保留未再次上报的字段（与文本留存解耦）
        "done": False,
        "calls": 0,       # 诊断：stream 回调被调用次数
        "bytes_in": 0,    # 诊断：累计输入字节
    }

    def _keep(chunk):
        # usage 在流末最后几个 chunk 才出现，但文本留存有 256KB 上限：长回答
        # （实测单次 completion 达 1 万+ token）会把带 usage 的尾部整个丢掉，
        # 「今日 Token 用量」永久少计。因此 usage 每块单独扫，不受留存上限影响。
        try:
            u = _extract_usage(chunk, previous=state["usage"])
            if u:
                state["usage"] = u
        except Exception:
            pass
        if state["text_len"] < _SSE_KEEP_MAX:
            kept = chunk[:_SSE_KEEP_MAX - state["text_len"]]
            state["text"].append(kept)
            state["text_len"] += len(kept)
        elif not state["truncated"]:
            state["truncated"] = True

    def _finish():
        if state["done"]:
            return
        state["done"] = True
        # 收尾：还原摘要留在循环上（微秒级），审计与响应扫描投递 `_AUX_POOL`
        # （实测原占住循环 64KB≈15ms / 1MB≈127ms / 4MB≈216ms）。
        # 注意本回调是**同步**的（mitmproxy 的 stream 回调无 await 点），投递后不等待，
        # 所以"流结束"≠"审计已落库" —— 需要对齐时用 `aux_drain()`。
        # 另一条硬约束仍在：流式接管下绝不能设置 flow.response.content（会被 mitmproxy
        # 标记成已改写 → 客户端收到连接重置），所以下池的活里也不许碰它。
        # 关键：流式接管下绝不能设置 flow.response.content —— mitmproxy 12 会把响应
        # 标记为已改写，导致客户端收到连接重置(0 字节)。还原后的完整文本已在
        # state["text"] 里，直接传给事件/审计/扫描，不再碰 flow.response.content。
        restored_text = "".join(state["text"])
        state["text"] = []          # 文本已转入局部变量，提前释放列表引用
        # 标记「整条流已交付」：客户端随后的关连接不再算取消（见 `_record_client_cancel`）。
        # 判据只此一处落点——本回调是唯一能证明「整条流转交给 mitmproxy」的时刻。
        flow.metadata["shield_response_concluded"] = _RESPONSE_CONCLUDED_STREAM_DONE
        # 还原摘要留在循环上发（它只是读几个计数 + 800B 预览，已成微秒级）：
        # 这样 RESTORE → AUDIT/SCAN 的事件顺序与搬走之前**完全一致**。
        _transport_complete(flow)
        _emit_restore_summary(flow, sid, host, method, emit_path, source, ok=True, streamed_text=restored_text, stream_actual="stream", stream_usage=state["usage"])
        # 审计与响应扫描是 O(body)（512KB 正则 + 摘要抽取），投递到 aux 池执行。
        # `_drop(sid)` 也交给它（见 _stream_finish_offload 的注释）。
        _session_ref = _session_get(sid)
        try:
            token = _aux_token(flow) or _aux_reserve(flow)
            snapshot = _aux_snapshot(flow)
            _aux_submit(token, sid, _session_ref, _stream_finish_offload,
                        snapshot, sid, host, method, emit_path, dict(source),
                        restored_text, _session_ref, time.perf_counter())
        except Exception:
            # Explicit failed audit, never unbudgeted synchronous work on the loop.
            _aux_abandon(flow)
            _aux_stat_add("stream_finish_failed")
            _emit("ERR", host=host, method=method, path=emit_path, sid=sid,
                  reason="stream_finish_failed", failure_phase="local_response", **source)
            if _session_ref is not None:
                _drop(sid, expect=_session_ref)

    def _dispose():
        nonlocal session_ref
        state["done"] = True
        state["aborted"] = True
        state["buf"] = ""
        state["text"] = []
        state["text_len"] = 0
        state["decoder"] = None
        session_ref = None

    def _stream(data: bytes):
        nonlocal session_ref
        if state.get("aborted"):
            return []
        try:
            with _aux_session(sid, session_ref):
                return _stream_owned(data)
        finally:
            if state["done"]:
                # mitmproxy may retain the stream callback on a completed flow.
                # The submitted job now owns its session, or failure retired it.
                session_ref = None
                state["text"] = []
                state["buf"] = ""

    def _stream_owned(data: bytes):
        if state["done"]:
            return data
        try:
            state["calls"] += 1
            state["bytes_in"] += len(data)
            # 计数同步到 flow.metadata：流被中途切断时 _finish() 不会执行，
            # 只有 error() 钩子能看到现场，靠这两个数区分「上游没吐完」与
            # 「我们处理到一半崩了」。
            flow.metadata["shield_stream_calls"] = state["calls"]
            flow.metadata["shield_stream_bytes"] = state["bytes_in"]
            _touch(sid)  # 长生成期间刷新会话 TTL，防止 _sweep 误删活动中的流式会话
            # 首字节计时：第一次收到非空数据块即记（含流式接管路径）
            if data:
                s_cur = _session_get(sid)
                if s_cur is not None:
                    if s_cur.get("resp_ts") is None:
                        s_cur["resp_ts"] = time.time()
                    if s_cur.get("first_byte_ms") is None:
                        s_cur["first_byte_ms"] = (time.perf_counter() - s_cur.get("req_t0", time.perf_counter())) * 1000
            last = not data
            state["buf"] += state["decoder"].decode(data, final=last)
            # SSE 允许 CRLF；统一成 LF 后按空行切事件。此前只找 \n\n，
            # CRLF 上游会把整段响应攒到流结束，客户端可能 chunk timeout 并截断。
            state["buf"] = state["buf"].replace("\r\n", "\n")
            out = []
            if framing == "ndjson":
                # NDJSON：一行一个 JSON。只处理已带换行的完整行，半行留在缓冲里
                # （占位符被 TCP 边界切开时靠这条保证不会被当成坏 JSON 丢掉）。
                while True:
                    idx = state["buf"].find("\n")
                    if idx < 0:
                        break
                    line, state["buf"] = state["buf"][:idx], state["buf"][idx + 1:]
                    out.append(_restore_ndjson_line(line, sid, final=False) + "\n")
                # 异常上游防御：单个超长行无换行符，累积超过 _SSE_BUF_MAX 强制还原清空
                if len(state["buf"]) > _SSE_BUF_MAX:
                    out.append(_restore_ndjson_line(state["buf"], sid, final=True) + "\n")
                    state["buf"] = ""
                if last:
                    if state["buf"]:
                        out.append(_restore_ndjson_line(state["buf"], sid, final=True))
                        state["buf"] = ""
                    tail = _flush_pending(sid, framing="ndjson")
                    if tail:
                        out.append(tail)
                    _touch(sid)
            else:
                # SSE 事件以空行分隔；只处理已完整到达的事件，半个事件留在缓冲里
                while True:
                    idx = state["buf"].find("\n\n")
                    if idx < 0:
                        break
                    block, state["buf"] = state["buf"][:idx], state["buf"][idx + 2:]
                    out.append(_restore_sse_event(block, sid, final=False) + "\n\n")
                # 异常上游防御：上游持续推送只有单换行（无 \n\n 双空行）或无换行的巨型数据，
                # 导致 buf 无限累积超过 _SSE_BUF_MAX。优先在最后一个换行符切分以保留完整
                # data: 行（避免破坏合法 JSON），无换行时整段强制还原清空。
                if len(state["buf"]) > _SSE_BUF_MAX:
                    idx = state["buf"].rfind("\n")
                    if idx >= 0:
                        block, state["buf"] = state["buf"][:idx], state["buf"][idx + 1:]
                        out.append(_restore_sse_event(block, sid, final=True) + "\n\n")
                    else:
                        out.append(_restore_sse_event(state["buf"], sid, final=True) + "\n\n")
                        state["buf"] = ""
                if last:
                    if state["buf"]:
                        out.append(_restore_sse_event(state["buf"], sid, final=True))
                        state["buf"] = ""
                    # 收尾：把各通道缓冲里的残留补发出去，避免吞掉最后几个字
                    tail = _flush_pending(sid)
                    if tail:
                        out.append(tail)
                    _touch(sid)
            text = "".join(out)
            _keep(text)
            if _STREAM_DEBUG:
                # 断流归因用：能区分「上游没吐完」（回调停了但无 last）与
                # 「我们卡在半个事件里」（buf 一直非空、out 恒为空）。
                _log(f"[stream:dbg] {host} cb#{state['calls']} in={len(data)}B "
                     f"out={len(text)}B buf={len(state['buf'])} last={last}")
            if last:
                _finish()
                # 末块走 mitmproxy 的 ResponseEndOfMessage 分支，那里对 b"" 有
                # 专门过滤（chunks == b"" -> []），返回 bytes 安全。
                return text.encode("utf-8")
            # 关键：中途块绝不能返回 b""。mitmproxy 的 ResponseData 分支不过滤空块，
            # 会按 chunked 语法写出 b"0\r\n\r\n"——那正是**终止块**，客户端据此判定
            # 响应结束、停止读取并关连接（引擎侧表现为 CANCEL Client disconnected）。
            # SSE 事件被上游按 TCP 边界切成两段时（半个事件留在 buf 里，本次无完整
            # 事件可发）必然触发，能否复现只取决于分片运气，与上游是否支持流式无关。
            # 返回空列表则 mitmproxy 的 for 循环零次迭代，一个字节都不写，流保持打开。
            if not text:
                return []
            return text.encode("utf-8")
        except Exception as e:
            # 流式处理失败：放弃改写，原样透传剩余数据，绝不把连接搞断。
            # 缓冲里已解码但未输出的部分必须拼回去，否则客户端收到缺块的半截流。
            state["done"] = True
            s_sse = _session_get(sid, {}) if sid else {}
            _emit("ERR", host=host, method=method, path=emit_path, sid=sid, msg=f"{framing}_stream:" + str(e)[:160],
                  upstream=s_sse.get("upstream_name", ""), model=s_sse.get("model", ""), **source)
            try:
                buf = state.get("buf") or ""
                state["buf"] = ""
                # 异常时 buf 是已解码但未还原的 SSE 残片（含占位符/半截占位符）：
                # 先做最后一次还原再下发，把残片泄漏面压到最小。正常路径的还原
                # 在 _restore_sse_event 流末 final=True 已完成，这里仅兜底异常分支。
                try:
                    restored_buf = restore(buf, sid, final=True)
                except Exception:
                    # 还原与流式处理同一异常源（会话结构损坏等）：回退原始 buf，
                    # 宁可透传占位符也绝不丢数据（占位符不含明文，fail-safe 方向）。
                    restored_buf = buf
                # 通道级残留也必须吐出去。restore(..., final=True) 的 channel 默认是
                # ""，只清得掉那一个槽；正文/思考/工具参数通道（c0.content / a0.think /
                # r0.args …）里被扣住的半截占位符会被静默丢弃 —— 与上面「已解码但未
                # 输出的部分必须拼回去」的意图相悖，客户端会看到文本凭空少一截。
                # 顺序与正常流末（_stream 的 last 分支）一致：先 buf（事件级残片）
                # 再 pending（更早的通道滞留，此时已被上面那次 restore 顺带清掉同通道）。
                try:
                    flush_txt = _flush_pending(sid)
                except Exception:
                    flush_txt = ""
                # 补发的是完整 SSE 事件块（自带 \n\n），前面必须另起一行：否则会与
                # 残片粘成同一行 `data: {…}data: {…}`，严格按行解析的 SDK 直接
                # JSON.parse 失败并丢掉整条补发事件（等于白补）。
                sep = "\n\n" if restored_buf and not restored_buf.endswith("\n\n") else ""
                passthrough = (restored_buf + sep + flush_txt).encode("utf-8", errors="replace") + data
            except Exception:
                passthrough = data
            # 必须补发 RESTORE：只发 ERR 会让该请求在日志里只有 MASK 没有还原记录，
            # 「已还原回复」统计永久少一条，用户无从判断这次到底还原没有。
            # ok=False + 已还原文本一并带上，success/unresolved 如实反映失败态。
            try:
                _emit_restore_summary(
                    flow, sid, host, method, emit_path, source,
                    ok=False, streamed_text="".join(state["text"]), stream_actual="stream_error",
                    stream_usage=state["usage"],
                )
            except Exception:
                pass
            try:
                _aux_abandon(flow)
                if session_ref is not None:
                    _drop(sid, expect=session_ref)
            except Exception:
                pass
            # 这里无需防空返回：passthrough = 残留 + data，data 非空则必非空；
            # data 为空即末块，走 mitmproxy 的 EndOfMessage 分支（对 b"" 有过滤）。
            return passthrough

    _stream._maskit_dispose = _dispose
    return _stream


def _emit_restore_summary(flow, sid, host, method, path, source, ok=True, streamed_text=None, stream_actual="whole", stream_usage=None, prepare_only=False):
    """记录 RESTORE 事件（流式与非流式共用）。

    stream_actual 表示引擎实际处理方式（区别于客户端请求类型 stream_mode）：
    - "stream"：responseheaders 流式接管，逐事件下发
    - "whole"：整包还原后一次性下发（黑名单上游 / stream_response 关闭 / 非 SSE）
    """
    s = _session_get(sid, {})
    masked_count = len(s.get("fwd", {}))
    restored_count = int(s.get("restored", 0) or 0)
    restored_unique = len(s.get("restored_tokens", set()) or set())
    unresolved = int(s.get("unresolved", 0) or 0)
    degraded = int(s.get("degraded", 0) or 0)
    if masked_count == 0:
        restore_status = "no_sensitive_data"
    elif unresolved > 0:
        # 有占位符查不到原文（复用表淘汰/会话被扫/孤儿占位符）：告警态，前端要能看到
        restore_status = "unresolved"
    elif restored_count > 0:
        restore_status = "restored"
    else:
        restore_status = "no_placeholder_in_response"
    resp_preview = ""
    resp_dialog = ""
    try:
        # 流式接管时用回调累积的文本；非流式读 flow.response.content
        if streamed_text is not None:
            # ⚠️ 这里曾写 `streamed_text.encode("utf-8")`：为了取 800 字节预览与
            # 4000 字对话，把**整份**还原文本编码成 bytes（再被 helper decode 回来）
            # —— 纯白的 O(body)，实测 4MB 响应 109ms，而这一步跑在事件循环上
            # （流式收尾）。两个 helper 的输出上限就 800B/4000 字，只给前缀足够；
            # 传 str 也免掉 helper 内部那次全量 decode。
            _src = streamed_text[:_PREVIEW_SRC_MAX]
            resp_preview = _body_preview(_src, 800, total_len=len(streamed_text))
            resp_dialog = _extract_chat_dialog(_src, 4000)
        elif flow.response and flow.response.content:
            resp_preview = _body_preview(flow.response.content, 800)
            resp_dialog = _extract_chat_dialog(flow.response.content, 4000)
    except Exception:
        resp_preview = ""
        resp_dialog = ""
    # 还原后的文本可能复述模型见到的凭据原文：落库前必须清洗。
    # 两步互补：形态正则（防用户自贴的凭据）+ 本会话原文精确串（防模型裸复述值本身）。
    resp_dialog = _redact_credentials(_redact_session_credentials(resp_dialog, s))
    resp_preview = _redact_credentials(_redact_session_credentials(resp_preview, s))
    # token 用量（尽力而为）：非流式顶层 usage；流式最后带 usage 的 chunk
    usage = {}
    try:
        if stream_usage:
            # 流式路径：usage 已由 `_keep()` 逐块采集（每块只解析自己那几行），
            # **绝不再回退**到"整段文本重解析"——那是 O(留存文本 × 行数) 的重复劳动
            # （实测 256KB ≈ 10ms、4MB ≈ 158ms），而结论不会更好：采集器逐块看过
            # 每一个 chunk，它没找到就是流里确实没有。此处回退只会在收尾处
            # （事件循环上）白烧，且"文本留存上限"一改就悄悄放大。
            usage = dict(stream_usage)
        elif str(stream_actual or "").startswith("stream"):
            # 流式（含中途失败）但采集器没找到 → 流里确实没有，不回退重解析。
            # 判据必须是“引擎实际处理方式”（stream_actual），**不能**用
            # `streamed_text is not None`：整包路径也传 streamed_text（那是还原后的
            # 正文），用后者会让整包永远走本分支，`_extract_usage(body)` 成了死代码
            # —— 非流式响应的 token 用量恒为空，日 token/费用统计整体塔掉
            # （0.6.0 回归，已用真实非流式响应用例钉住）。
            usage = {}
        elif flow.response and flow.response.content:
            usage = _extract_usage(flow.response.content.decode("utf-8", errors="replace"))
    except Exception:
        usage = {}
    # RESTORE 明细：本会话脱敏过的占位符清单，标注每个是否真的被还原
    # （曾完全不带 items，前端详情弹窗永远显示「无敏感项明细」）
    items = []
    try:
        restored_tokens = s.get("restored_tokens") or set()
        seen_toks = set()
        for orig, tok in list(s.get("fwd", {}).items())[:30]:
            seen_toks.add(tok)
            m = _PLACEHOLDER_PARTS_RX.match(tok)
            lbl = s.get("labels", {}).get(orig, "")
            is_cred = lbl in CREDENTIAL_LABELS
            item = {
                "tok": tok,
                "label": lbl,
                "hash": m.group(2) if m else "",
                "length": len(orig),
                "preview": _preview(orig, lbl),
                "restored": tok in restored_tokens,
            }
            # 凭据类不明文落库（与 MASK 口径一致），详情弹窗只显示打码预览
            if is_cred:
                item["cred"] = True
                item["digest"] = _cred_digest(orig)
            else:
                item["original"] = orig
            # 归因（roles）：复用会话里存的角色文本，前端据此展示真实命中位置
            try:
                role_texts = s.get("role_texts") or {}
                roles = _hit_roles_for(orig, role_texts)
                if roles:
                    item["roles"] = roles[:6]
            except Exception:
                pass
            items.append(item)
        # 补充：跨请求复用表（_RECENT_REV / _CUSTOM_WORD_REV）中还原出来的历史敏感项
        for tok in restored_tokens:
            if tok in seen_toks or len(items) >= 30:
                continue
            seen_toks.add(tok)
            rec = _RECENT_REV.get(tok) or _CUSTOM_WORD_REV.get(tok)
            if rec and len(rec) >= 2:
                orig, lbl = rec[0], rec[1]
                m = _PLACEHOLDER_PARTS_RX.match(tok)
                is_cred = lbl in CREDENTIAL_LABELS
                item = {
                    "tok": tok,
                    "label": lbl,
                    "hash": m.group(2) if m else "",
                    "length": len(orig),
                    "preview": _preview(orig, lbl),
                    "restored": True,
                    "from_history": True,
                }
                if is_cred:
                    item["cred"] = True
                    item["digest"] = _cred_digest(orig)
                else:
                    item["original"] = orig
                items.append(item)
    except Exception:
        items = []
    # 上游参数类错误（400/422）+ 请求带可疑 reasoning_effort：附加排查提示。透明代理
    # 不改请求（下游配置问题由下游修），但事件里把原因说清楚，面板一眼可见。
    # 5xx/超时不附：那是上游侧超时或故障，与思考强度取值无关（见 `_REASONING_HINT_STATUSES`）。
    hint = ""
    # A-7：RESTORE 事件的 503 一律来自上游（引擎只是把上游的状态码如实记下来）。
    # 四种 503 来源（上游 / 请求侧 fail-closed / 响应侧阻断 / 兜底占位）此前
    # 混在一个 http_status 里，用户和我们都只能靠猜——这个字段是"归因"的唯一依据。
    block_source = "upstream"
    try:
        hint = _reasoning_effort_hint_for_status(
            getattr(flow.response, "status_code", None),
            flow.metadata.get("shield_reasoning_effort"))
    except Exception:
        pass
    summary = dict(
        block_source=block_source,
        # C-2：为什么整包（content_encoding:gzip / excluded_host / non_sse）。
        # 没有降级时**不带这个键**：前端按"有键才显示"处理，不给正常请求加噪声。
        **({"stream_degraded_reason": _stream_degraded_reason(flow)}
           if _stream_degraded_reason(flow) else {}),
        host=host,
        method=method,
        path=path,
        sid=sid,
        count=masked_count,
        restored=restored_count,
        restored_unique=restored_unique,
        unresolved=unresolved,
        # 未还原占位符样本（最多 5 条；样本本身是占位符，不含任何原文）。
        # 此前**只有扩展链路**（panel 的 /api/ext/restore）外发它，代理链路只在
        # 会话里收集 —— 面板只显示一个数字，用户无从区分「模型改写/自造占位符」
        # 与「映射过期或引擎重启导致查不到原文」，而这两种情况的处置完全不同。
        **({"unresolved_samples": [str(x)[:120] for x in (s.get("unresolved_samples") or [])][:5]}
           if s.get("unresolved_samples") else {}),
        # 靠宽松兜底（模型剥了花括号）修回来的个数。
        # 这个计数一直存在于会话里，但**从没被发进事件**——注释写着「计数进
        # RESTORE 事件，让用户看得见」，实际 _emit 参数里没有它，于是
        # 「靠兜底修回来的」这件事永远查不到。0.1.14 补上。
        degraded=degraded,
        success=bool(ok) and unresolved == 0,
        msg=hint,
        # status 兼容 SQLite 已有列/历史数据；restore_status 是前端统一读取的键
        # （曾只发 status，前端读 restore_status 全部不匹配，状态文案全是死代码）
        status=restore_status,
        restore_status=restore_status,
        items=items,
        scan_scope=s.get("scan_scope") or {},  # RESTORE 归因：复用 MASK 的扫描范围
        http_status=getattr(flow.response, "status_code", None),
        transport=_transport_snapshot(flow),
        model=s.get("model") or "",
        upstream=s.get("upstream_name") or "",
        dialog=resp_dialog,
        # 用户消息（MASK 阶段存入会话）：回复日志弹窗同时展示用户发送的内容。
        # MASK 阶段已过形态清洗，这里再过一遍本会话原文精确串（纵深防御，代价一次替换）
        dialog_req=_redact_session_credentials(s.get("req_dialog") or "", s),
        resp_preview=resp_preview,
        usage=usage or None,
        stream_mode=s.get("stream_mode") or "non_stream",
        stream_actual=stream_actual,
        # 耗时（毫秒）：mask_ms=脱敏管线；upstream_ms=请求到响应总耗时
        # （首字节/整包完成）；first_byte_ms=流式首字节（整包=upstream_ms）
        # 用 perf_counter 基准（req_t0）算，μs 精度
        mask_ms=round(float(s.get("mask_ms") or 0), 1),
        upstream_ms=round((time.perf_counter() - float(s.get("req_t0") or time.perf_counter())) * 1000, 1),
        first_byte_ms=round(float(s.get("first_byte_ms") or 0), 1),
        # 语义识别降级（本轮有空叶子没走 NER）：与 MASK 事件同源，从会话带过来。
        # 两边都得有 —— 详情弹窗回源的是 RESTORE，只挂 MASK 等于弹窗里看不到降级。
        **({"ner_truncated": True, "ner_skip_reasons": s.get("ner_skips")}
           if s.get("ner_skips") else {}),
        # 治理器派生字段（与 MASK 同源，从会话带过来）：详情弹窗回源的正是本条 RESTORE，
        # 不带就永远渲染不出来（前端 EventDetailDialog 读 event.ner_global_throttled）。
        **{k: v for k, v in (s.get("ner_metrics") or {}).items() if k in _NER_EVENT_METRICS},
        **source,
    )
    if prepare_only:
        return summary
    _emit("RESTORE", **summary)


def _raw_stream_passthrough(data: bytes):
    """过滤关闭（FILTER_ENABLED=False）时的流式接管：chunk 原样透传。

    无会话可查、无占位符可还原（请求本来就没脱敏），接管只为把「整包缓冲」
    变成「逐块下发」，保住客户端的打字机效果（此前过滤关闭时 SSE 首字节
    延迟 = 整段生成时长，与脱敏路径/PT 兜底行为不一致，审计 P2）。
    末块 b"" 走 mitmproxy 的 ResponseEndOfMessage 分支（那里会过滤成 []）。
    """
    return data


def responseheaders(flow: http.HTTPFlow):
    """对 SSE 启用逐块还原转发；非 SSE 保持原有整包路径。

    mitmproxy 12 会在响应头阶段安装 stream 回调，随后按 bytes 块调用，
    消息结束时再传入 b""。_sse_stream_factory 在流末完成 RESTORE、审计、
    响应扫描和会话清理；关闭 stream_response 时自然回退到 response()。
    """
    if flow.metadata.get("shield_local_response"):
        return
    _transport_event("responseheaders", flow)
    flow.metadata["transport"] = _safe_transport_snapshot(flow)
    if not STREAM_RESPONSE:
        return
    sid = flow.metadata.get("session_id")
    if not sid:
        # 过滤关闭的流量没有 session_id，但流式接管同样应该生效（纯透传）。
        # 前提是请求侧已声明 identity（见 request() 的 filter_off 分支），
        # 压缩响应在这里退回整包路径并留痕，与脱敏路径同款降级。
        if flow.metadata.get("shield_filter_off") and flow.response:
            headers0 = flow.response.headers
            ct0 = (headers0.get("content-type", "") or "").lower()
            framing0 = ("ndjson" if _is_ndjson_ct(ct0)
                        else ("sse" if "text/event-stream" in ct0 else None))
            if framing0:
                enc0 = (headers0.get("content-encoding", "") or "").lower().strip()
                if enc0 and enc0 != "identity":
                    _log(f"[stream] 过滤关闭但上游返回 content-encoding={enc0}，退回整包路径（失去流式）")
                    _note_stream_degraded(flow, "content_encoding:" + enc0)
                    return
                headers0.pop("content-length", None)
                flow.response.stream = _raw_stream_passthrough
        return
    if flow.metadata.get("shield_streamed") or not flow.response:
        return
    headers = flow.response.headers
    content_type = (headers.get("content-type", "") or "").lower()
    if _is_ndjson_ct(content_type):
        framing = "ndjson"
    elif "text/event-stream" in content_type:
        framing = "sse"
    else:
        # 响应不是 SSE/NDJSON。**只有请求侧明确要了流式**才算降级：普通非流式请求
        # 走整包路径是设计如此，给每个 JSON 响应挂一条"降级"只会把真降级淹掉。
        if flow.metadata.get("shield_stream_requested"):
            _note_stream_degraded(flow, "non_sse")
        return
    host = getattr(flow.request, "host", None) or flow.request.pretty_host
    path = flow.request.path
    emit_path = flow.metadata.get("shield_orig_path") or path
    method = getattr(flow.request, "method", "") or ""
    source = _session_get(sid, {}).get("source", {})
    # 压缩体在 responseheaders 阶段仍是压缩字节，无法按事件解析；
    # 交回 response() 的整包路径，让 mitmproxy 先完成解压。
    content_encoding = (headers.get("content-encoding", "") or "").lower().strip()
    if content_encoding and content_encoding != "identity":
        # request() 已对流式请求声明 identity，走到这里说明上游无视了该头。
        # 静默退化会让「面板显示流式、客户端实际卡整段」无法归因，必须留痕。
        _log(f"[stream] {host} 返回 content-encoding={content_encoding}，退回整包路径（失去流式）")
        _note_stream_degraded(flow, "content_encoding:" + content_encoding)
        return
    if host in STREAM_EXCLUDE_HOSTS:
        # 用户显式排除的上游：保持整包路径。这条**必须记**——用户在设置页加了黑名单
        # 之后"流式不见了"，唯一的解释来源就是这里（否则只能靠翻配置回忆起自己加过）。
        _note_stream_degraded(flow, "excluded_host")
        return
    _log(f"[LLM Shield] {framing.upper()} stream hook: {method} {host}{path.split('?')[0]} ct={content_type[:60]}")
    # 转换后长度不再等于上游 Content-Length；移除后由 mitmproxy 使用分块传输。
    headers.pop("content-length", None)
    flow.metadata["shield_streamed"] = True
    flow.response.stream = _sse_stream_factory(
        flow, sid, host, method, emit_path.split("?")[0], source, framing=framing
    )


def _stream_degraded_reason(flow):
    """读取「本该流式、实际整包」的原因；没有/读不到都返回 ""。

    防御式读取是必须的：`_emit_restore_summary` 会被无 `metadata` 的对象调用
    （测试里的 mock flow、以及历史上直接构造的 SimpleNamespace），直接
    `flow.metadata.get(...)` 会把"没有降级"变成 AttributeError —— 即
    **新增一个只在特定 flow 形态下炸的崩溃点**，而它恰好在响应收尾路径上。
    """
    try:
        return str(flow.metadata.get("shield_stream_degraded") or "")
    except Exception:
        return ""


def _note_stream_degraded(flow, reason):
    """记一次「本该流式、实际整包」的降级原因（C-2）。

    只写 metadata、不在这里发事件：真正的事件在 RESTORE 时统一发（那时才有 sid/
    会话计数），避免同一个请求因为降级多发一条半成品事件。
    """
    try:
        flow.metadata["shield_stream_degraded"] = str(reason)[:60]
    except Exception:
        pass


def _restore_json_body(raw, sid, host, method, path, content_type=""):
    """整包 JSON 还原（纯函数，A-3：由 aux 线程调用，返回新字节）。

    返回 None 表示"不还原"（体积超限等），调用方保持原文并已留痕。
    """
    # 体积闸（与请求侧 _MAX_REQUEST_BODY 对齐）：见该常量的注释。超限时**不还原**
    # 但必须留痕——否则用户看到裸占位符会以为是引擎坏了，而事件页毫无线索。
    if len(raw) > _MAX_RESPONSE_RESTORE_BODY:
        _emit_skip(
            host=host, method=method, path=path,
            reason="response_too_large",
            content_type=content_type or "",
            force=True,
        )
        return None
    body = json.loads(raw)
    body = _restore_tree(body, sid)
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _restore_sse_body(raw, sid):
    """整包 SSE 还原（纯函数）：流式接管失败时的回退路径，以及单测用。"""
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    blocks = text.split("\n\n")
    out = [_restore_sse_event(b, sid) for b in blocks]
    body = "\n\n".join(out)
    tail = _flush_pending(sid)  # 流末仍有半截占位符：补一条事件，不能吞字
    if tail:
        body = body.rstrip("\n") + "\n\n" + tail
    return body.encode("utf-8")


def _handle_json(flow, sid):
    """薄包装（保留给单测与其他调用点）：纯函数 + 回写。"""
    raw = flow.response.content or b""
    out = _restore_json_body(raw, sid,
                             getattr(flow.request, "host", None) or flow.request.pretty_host,
                             getattr(flow.request, "method", "") or "",
                             flow.metadata.get("shield_orig_path") or flow.request.path,
                             flow.response.headers.get("content-type", "") or "")
    if out is not None:
        flow.response.content = out


def _handle_sse(flow, sid):
    flow.response.content = _restore_sse_body(flow.response.content or b"", sid)




def _read_settings():
    """从 config.json 解析设置，返回 dict 或 None（文件缺失/解析失败）。"""
    cfg_path = _DATA_ROOT / "config.json"
    if not cfg_path.exists():
        return None
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as e:
        _log(f"[LLM Shield] config parse failed: {e}")
        return None
    cw = {}
    disabled_labels = set()
    word_disabled = {}
    sens = cfg.get("sensitive")
    if isinstance(sens, dict):
        for label, words in sens.items():
            label = str(label or "").strip()
            if not label:
                continue
            # 兼容两种结构：
            # 1) {"地域": ["重庆", ...]}
            # 2) {"地域": {"enabled": false, "words": ["重庆"], "disabled_words": []}}
            if isinstance(words, dict):
                enabled = bool(words.get("enabled", True))
                if not enabled:
                    disabled_labels.add(label)
                word_list = words.get("words") or []
                dis_words = set()
                for w in words.get("disabled_words") or []:
                    w = str(w or "").strip()
                    if w:
                        dis_words.add(w)
                if dis_words:
                    word_disabled[label] = dis_words
            else:
                word_list = words or []
            for w in word_list:
                w = str(w or "").strip()
                if w:
                    cw[w] = label
    # 额外：sensitive_disabled 列表（仅组名）
    for lab in cfg.get("sensitive_disabled") or []:
        lab = str(lab or "").strip()
        if lab:
            disabled_labels.add(lab)
    # 顶层词级禁用 sensitive_word_disabled（panel.normalize_config 的标准结构：
    # {label: [word]}，UI「禁用词」写入这里；曾只解析 sensitive 内嵌 dict 的
    # disabled_words，顶层字段被忽略导致禁用词持续命中——SHIELD-WORD-DISABLE-001）
    raw_word_disabled = cfg.get("sensitive_word_disabled")
    if isinstance(raw_word_disabled, dict):
        for lab, ws in raw_word_disabled.items():
            lab = str(lab or "").strip()
            if not lab:
                continue
            wset = word_disabled.setdefault(lab, set())
            for w in ws or []:
                w = str(w or "").strip()
                if w:
                    wset.add(w)
    flat = cfg.get("custom_words")
    if isinstance(flat, dict):
        for w, l in flat.items():
            cw.setdefault(str(w), str(l))
    prefixes = []
    raw_sp = cfg.get("secret_prefixes")
    raw_sp = DEFAULT_SECRET_PREFIXES if raw_sp is None else raw_sp
    for p in raw_sp:
        p = str(p or "").strip()
        if p:
            prefixes.append(p)
    # 内置规则开关
    builtin = dict(DEFAULT_BUILTIN_RULES)
    raw_builtin = cfg.get("builtin_rules")
    if isinstance(raw_builtin, dict):
        for k, v in raw_builtin.items():
            k = str(k or "").strip().upper()
            if k in builtin:
                builtin[k] = bool(v)
    # 反向代理 upstream 路由表
    ups = []
    raw_ups = cfg.get("upstreams")
    if isinstance(raw_ups, list):
        seen_names = set()
        seen_base = set()
        seen_port = set()
        for u in raw_ups:
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or "").strip()
            base = str(u.get("base_path") or "").strip()
            target = str(u.get("target") or "").strip()
            if not name or not target:
                continue
            name_key = name.lower()
            if name_key in seen_names:
                continue
            seen_names.add(name_key)

            slug = re.sub(r"[^A-Za-z0-9_\-]", "", name).lower()[:40]
            if not base or not re.fullmatch(r"/[A-Za-z0-9_\-/]{1,60}", base):
                base = "/" + (slug or f"up_{len(ups) + 1}")
            if not base.startswith("/"):
                base = "/" + base
            candidate_base = base
            idx = 2
            while candidate_base in seen_base:
                candidate_base = f"{base}_{idx}"
                idx += 1
            base = candidate_base
            seen_base.add(base)

            port = int(u.get("port") or 0)
            if port == 0:
                port = 18701 + len(ups)
            if port < 1024 or port > 65535 or port in seen_port:
                port = 18701 + len(ups)
                while port in seen_port:
                    port += 1
            seen_port.add(port)

            paths = u.get("paths") or DEFAULT_PATHS
            if not isinstance(paths, list):
                paths = DEFAULT_PATHS

            extra_headers = {}
            raw_extra = u.get("extra_headers")
            if isinstance(raw_extra, dict):
                for k, v in raw_extra.items():
                    kk = str(k or "").strip()
                    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", kk):
                        continue
                    vv = str(v or "")
                    if len(vv) > 2048:
                        continue
                    extra_headers[kk] = vv

            ups.append({"name": name, "base_path": base, "port": port, "target": target,
                        "paths": list(paths), "use_proxy": bool(u.get("use_proxy")),
                        "extra_headers": extra_headers,
                        **({"connection_policy": u["connection_policy"]} if "connection_policy" in u else {})})
    if not ups:
        ups = list(DEFAULT_UPSTREAMS)
    # 出口代理：enabled 关闭时直接置 None，省得 request() 每次都判两个字段。
    # 地址非法同样返回 None（panel 侧 normalize_config 已给过 warning）。
    egress_cfg = cfg.get("egress_proxy")
    egress = None
    if isinstance(egress_cfg, dict) and egress_cfg.get("enabled"):
        egress = parse_egress_proxy(egress_cfg.get("url"))
    capture_mode = str(cfg.get("capture_mode") or "reverse").strip().lower()
    if capture_mode not in {"reverse", "explicit", "local"}:
        capture_mode = "reverse"
    # 2.0 审计配置
    audit_cfg = cfg.get("audit") or {}
    if not isinstance(audit_cfg, dict):
        audit_cfg = {}
    audit_signals_cfg = audit_cfg.get("signals") or {}
    if not isinstance(audit_signals_cfg, dict):
        audit_signals_cfg = {}
    return {
        "domains": cfg.get("target_domains") or DEFAULT_DOMAINS,
        "disabled": set(cfg.get("domains_disabled") or []),
        "paths": cfg.get("api_paths") or DEFAULT_PATHS,
        "words": cw,
        "sensitive_disabled": disabled_labels,
        "sensitive_word_disabled": word_disabled,
        "builtin_rules": builtin,
        "prefixes": prefixes,
        "ttl": int(cfg.get("session_ttl") or DEFAULT_TTL),
        "debug": bool(cfg.get("debug")),
        "diagnostic_unmatched": bool(cfg.get("diagnostic_unmatched")),
        "upstreams": ups,
        "egress_proxy": egress,
        "capture_mode": capture_mode,
        "filter_enabled": cfg.get("filter_enabled", True),
        # ⚠️ 两层「fail_closed」不要混读（缺陷 D2）：
        #   · 本条：**脱敏主线**的请求级熔断（默认 true）——脱敏管线自身异常时宁可 503
        #     也不放明文出网，是「绝不满放」那条安全红线。
        #   · "audit_fail_closed"（本函数下方几行）：**审计**的响应级熔断（默认 false）——
        #     仅把已污染的响应换成 503，不改写任何配置。
        # 同名不同层，前端文案已分别标注「脱敏失败熔断（请求级）」与「审计阻断（响应级）」。
        "fail_closed": bool(cfg.get("fail_closed", True)),
        # 敏感词统计是否记录明文（默认开——打码 preview 排出来的榜没有信息量）
        "record_plaintext_words": bool(cfg.get("record_plaintext_words", True)),
        "response_scan": bool(cfg.get("response_scan", True)),
        "stream_response": bool(cfg.get("stream_response", True)),
        # 缺该键 = 老配置（该特性之前的版本）→ 上层回落默认黑名单；
        # 键存在但为空 = 用户在面板里显式清空 → 必须原样生效（返回空集，不是 None）。
        "stream_exclude_hosts": (
            {h.strip().lower() for h in (cfg.get("stream_exclude_hosts") or [])
             if isinstance(h, str) and h.strip()}
            if "stream_exclude_hosts" in cfg else None
        ),
        "audit_enabled": bool(audit_cfg.get("enabled", True)),
        "audit_passive": bool(audit_cfg.get("passive", True)),
        "audit_active_probes": bool(audit_cfg.get("active_probes", False)),
        "audit_severity_floor": str(audit_cfg.get("severity_floor") or "MEDIUM").upper(),
        "audit_fail_closed": bool(audit_cfg.get("fail_closed", False)),
        "audit_signals": {
            k: bool(audit_signals_cfg.get(k, dflt))
            for k, dflt in DEFAULT_AUDIT_SIGNALS.items()
        },
        # A-1：审计扫描窗口 / 体积闸 / 时间预算。上限锁在旧的 `_SCAN_BODY_MAX`
        # 上——用户可以把窗口调回 512KB（回到 0.5.0 的覆盖范围），但不许超过，
        # 因为再往上就是本次故障里被线性放大的那段成本。
        "audit_scan_max": _clamp_int(
            audit_cfg.get("scan_max", _ENV_AUDIT_SCAN_MAX), AUDIT_SCAN_MAX,
            16 * 1024, _SCAN_BODY_MAX),
        "audit_parse_max": _clamp_int(
            audit_cfg.get("parse_max", _ENV_AUDIT_PARSE_MAX), AUDIT_PARSE_MAX,
            64 * 1024, _MAX_RESPONSE_RESTORE_BODY),
        "audit_time_budget": _clamp_float(
            audit_cfg.get("time_budget_ms", _ENV_AUDIT_TIME_BUDGET * 1000.0) / 1000.0
            if audit_cfg.get("time_budget_ms") is not None else _ENV_AUDIT_TIME_BUDGET,
            AUDIT_TIME_BUDGET_S, 0.01, 5.0),
        "ner_enabled": bool(cfg.get("ner_enabled", False)),
        # 单请求语义识别预算上限（秒）。默认 10s（见 `_NER_REQ_BUDGET_MAX_DEFAULT_S`
        # 的注释）；环境变量 MASKIT_NER_REQ_BUDGET_S 存在时硬覆盖，配置不生效。
        # 必须在这里读取、在 `_maybe_reload` 里发布：只写成模块常量的话，面板改了
        # 要等进程重启才生效，而“改完没反应”在用户侧就是一个 bug。
        "ner_req_budget_s": _norm_ner_req_budget(cfg.get("ner_req_budget_s")),
        # 命令拦截（W2-3）：解析 + 编译在 _read_settings 里做（热重载时一次），
        # 而不是每个 chunk 都编译。非法条目在此丢弃并记日志。
        "command_block": _parse_command_block(cfg.get("command_block")),
        # 整词匹配词表：UI「整词匹配」开关写入 config.sensitive_word_whole。
        # 曾漏返回该键，_maybe_reload 读到 None 后回落空集，开关全程无效。
        "sensitive_word_whole": {
            str(w).strip() for w in (cfg.get("sensitive_word_whole") or []) if str(w).strip()
        },
    }


_cfg_mtime = [0.0]


def _maybe_reload(force=False):
    """热重载：config.json mtime 变了就刷新内存设置。每个请求调用，开销=一次 stat。"""
    global TARGET_DOMAINS, API_PATHS, CUSTOM_WORDS, SESSION_TTL, DEBUG, DIAGNOSTIC_UNMATCHED, DOMAINS_DISABLED, SECRET_PREFIXES, UPSTREAMS, CAPTURE_MODE, FILTER_ENABLED
    global AUDIT_ENABLED, AUDIT_PASSIVE, AUDIT_ACTIVE_PROBES, AUDIT_SEVERITY_FLOOR, AUDIT_SIGNALS
    global AUDIT_SCAN_MAX, AUDIT_PARSE_MAX, AUDIT_TIME_BUDGET_S, _ENV_AUDIT_SCAN_MAX, _ENV_AUDIT_PARSE_MAX, _ENV_AUDIT_TIME_BUDGET
    global FAIL_CLOSED, RESPONSE_SCAN, STREAM_RESPONSE, STREAM_EXCLUDE_HOSTS
    global SENSITIVE_DISABLED, SENSITIVE_WORD_DISABLED, SENSITIVE_WORD_WHOLE, BUILTIN_RULES, EGRESS_PROXY
    global COMMAND_BLOCK, _EXTRA_HEADER_SKIP_WARNED, _CUSTOM_WORD_RX_CACHE
    # 跨进程信号（清空内存映射）必须在 config mtime 的**提前返回之前**检查：
    # 它不依赖配置文件是否变过。读盘已由 event_store 做 5s 节流，热路径只是一次
    # 缓存查找，不新增 syscall。
    _maybe_apply_mapping_reset()
    try:
        mt = _DATA_ROOT.joinpath("config.json").stat().st_mtime
    except Exception:
        return
    if not force and mt == _cfg_mtime[0]:
        return
    _cfg_mtime[0] = mt
    s = _read_settings()
    if not s:
        return
    TARGET_DOMAINS = s["domains"]
    DOMAINS_DISABLED = s["disabled"]
    API_PATHS = s["paths"]
    SECRET_PREFIXES = s["prefixes"]
    SESSION_TTL = s["ttl"]
    DEBUG = s["debug"]
    DIAGNOSTIC_UNMATCHED = s["diagnostic_unmatched"]
    # 整表换对象，不做就地 clear/update：就地重建的中间态里词表是**空的或半填充**
    # 的，而 `_custom_words_sorted()` 一见内容变化就会把当时的 `CUSTOM_WORDS` 发布
    # 成当前词表 —— 于是并发那一轮少脱敏用户自定义词，明文直接上行。
    # 换成整体赋值后，读者只会看到上一代或新一代。
    CUSTOM_WORDS = dict(s["words"])
    # 配置变更后允许对注入请求头的占位符/空值重新告警一次（用户改了配置就该重新提醒）
    _EXTRA_HEADER_SKIP_WARNED = set()
    SENSITIVE_DISABLED = set(s.get("sensitive_disabled") or set())
    SENSITIVE_WORD_DISABLED = {
        k: set(v) for k, v in (s.get("sensitive_word_disabled") or {}).items()
    }
    SENSITIVE_WORD_WHOLE = set(s.get("sensitive_word_whole") or set())
    # 永久映射的重建必须排在禁用集赋值**之后**：_sync_custom_word_mappings 用
    # SENSITIVE_DISABLED / SENSITIVE_WORD_DISABLED 判断哪些词仍启用，放在前面会
    # 永远按上一代配置计算（禁用词要等第二次改配置才被清掉）。
    _refresh_custom_words_sorted()
    _CUSTOM_WORD_RX_CACHE = {}
    # 词表换代：上一代的问题登记作废（新词表会在下次构建计划时重新评估）；
    # 计划缓存的键已含词表内容，本来就会自行失效，显式置空只为可读性。
    _CUSTOM_COMBINED_CACHE["plan"] = None
    _clear_word_table_issues()

    br = dict(DEFAULT_BUILTIN_RULES)
    raw_br = s.get("builtin_rules") or {}
    # 旧配置 IP 键迁移（与 panel.normalize_config 一致）：IP 拆 IP_PRIVATE/IP_INTERNAL
    if "IP" in raw_br and "IP_PRIVATE" not in raw_br:
        raw_br = dict(raw_br)
        raw_br["IP_PRIVATE"] = bool(raw_br.get("IP"))
        raw_br["IP_INTERNAL"] = False
    br.update(raw_br)
    # 构建完成后一次性发布：原地 update 会让读者看到「默认值已覆盖、用户开关未生效」
    # 的中间态（用户刚禁用的规则会短暂重新生效）。
    BUILTIN_RULES = br
    AUDIT_ENABLED = s["audit_enabled"]
    AUDIT_PASSIVE = s["audit_passive"]
    AUDIT_ACTIVE_PROBES = s["audit_active_probes"]
    AUDIT_SEVERITY_FLOOR = s["audit_severity_floor"]
    global AUDIT_FAIL_CLOSED
    AUDIT_FAIL_CLOSED = bool(s.get("audit_fail_closed", False))
    AUDIT_SIGNALS = s["audit_signals"]
    # A-1 预算：配置换代必须让缓存指纹同步换代（指纹含这两个值），
    # 否则改了窗口大小还会拿到按旧窗口算出来的结论。
    AUDIT_SCAN_MAX = int(s.get("audit_scan_max") or AUDIT_SCAN_MAX)
    AUDIT_PARSE_MAX = int(s.get("audit_parse_max") or AUDIT_PARSE_MAX)
    AUDIT_TIME_BUDGET_S = float(s.get("audit_time_budget") or AUDIT_TIME_BUDGET_S)
    # 命令拦截：整段替换（含编译好的正则）——不能就地改，否则已停用的条目
    # 会在下一轮热重载里「复活」（_parse_command_block 每次返回全新结构）
    COMMAND_BLOCK = s.get("command_block") or _parse_command_block(None)
    global NER_ENABLED
    NER_ENABLED = bool(s.get("ner_enabled", False))
    global NER_REQUIRE_COMPLETE
    NER_REQUIRE_COMPLETE = bool(s.get("ner_require_complete", False))
    # P0-a：预算上限随配置热重载（内部已处理优先级与环境变量硬覆盖）
    set_ner_req_budget(s.get("ner_req_budget_s"))
    UPSTREAMS = s["upstreams"]
    EGRESS_PROXY = s.get("egress_proxy")
    CAPTURE_MODE = s["capture_mode"]
    FILTER_ENABLED = bool(s.get("filter_enabled", True))
    FAIL_CLOSED = bool(s.get("fail_closed", True))
    # 敏感词统计明文开关：事件由本进程 enqueue_event 写库，必须在这里同步
    try:
        import event_store as _es
        _es.set_record_plaintext_words(s.get("record_plaintext_words", True))
        # 日志写入模式基值（§D1）：引擎是主要写入方，必须与面板同口径热重载。
        # trace 是限时运行时状态，不在这里（由 engine-signals.json 单独控制）。
        _es.set_log_mode(s.get("log_mode"))
    except Exception:
        pass
    # 单条请求体上限（§H4a）：与面板 _EXT_MAX_BODY 同源，可配置热重载。
    set_max_request_body(s.get("max_request_body_mb"))
    RESPONSE_SCAN = bool(s.get("response_scan", True))
    STREAM_RESPONSE = bool(s.get("stream_response", True))
    # 空集合是用户在面板里显式清空黑名单的意思，必须原样生效。
    # 曾写 `or {"opencode.ai"}`：空列表 falsy 直接回落默认黑名单，用户清空后
    # opencode.ai 仍被永久排除，实测 2798 次流式请求 100% 退化成整包路径。
    excl = s.get("stream_exclude_hosts")
    STREAM_EXCLUDE_HOSTS = set(excl) if excl is not None else set(_DEFAULT_STREAM_EXCLUDE_HOSTS)
    disabled_rules = [k for k, v in BUILTIN_RULES.items() if not v]
    _log(
        "[LLM Shield] config loaded: "
        f"mode={CAPTURE_MODE} upstreams={len(UPSTREAMS)} "
        f"egress={'%s://%s:%d' % (EGRESS_PROXY[0], EGRESS_PROXY[1][0], EGRESS_PROXY[1][1]) if EGRESS_PROXY else 'off'}"
        f"({sum(1 for u in UPSTREAMS if u.get('use_proxy'))} 个客户端走代理) "
        f"domains={len(TARGET_DOMAINS)} disabled={len(DOMAINS_DISABLED)} "
        f"paths={len(API_PATHS)} words={len(CUSTOM_WORDS)} "
        f"label_off={len(SENSITIVE_DISABLED)} rule_off={len(disabled_rules)} "
        f"prefixes={len(SECRET_PREFIXES)} debug={'on' if DEBUG else 'off'} diagnostic={'on' if DIAGNOSTIC_UNMATCHED else 'off'}"
    )


def _prune_debug_logs(max_days=7):
    """清理超过 max_days 天的 debug-YYYYMMDD.log。"""
    try:
        import glob
        cutoff = time.time() - max_days * 86400
        for f in glob.glob(str(_DATA_ROOT / "debug-*.log")):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
            except Exception:
                pass
    except Exception:
        pass


def load(l):
    _maybe_reload(force=True)
    _warmup_recent_from_db()
    _prune_debug_logs()
    # 重启即关闭限时排障（§D1：trace 不跨重启）。面板启动时也会清一次，
    # 两处都清是为了覆盖「只重启引擎」与「只重启面板」两种启法。
    try:
        _stop_log_trace()
    except Exception:
        pass
    _log("=" * 50)
    _log("[LLM Shield] proxy started; config hot reload enabled")
    _log("=" * 50)


# 注意：预热**只在 mitmproxy 的 load() 钩子里做**，不在模块 import 期做。
# 0.1.12 曾在文件尾部无条件跑一次 _warmup_recent_from_db()，后果是任何
# import transparent 的进程都会去读事件库——包括 `python -m unittest discover`。
# 实测隔离数据目录下裸 import 就载入了生产库 420 条真实映射
# （EMAIL 99 / IP_PRIVATE 81 / PHONE 36 / CARD 13 / IDCARD 11）。
# 单测不该读生产数据，import 也不该有 I/O 副作用。
