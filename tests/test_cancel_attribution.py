"""客户端断开（CANCEL）的归因契约：区分「响应已收尾后的关连接」与「真中断」。

背景（2026-10-02 本机实测）：客户端改成每请求新建 TCP 连接后，每次读完流式响应关闭
连接都会触发 mitmproxy 的 `CLIENT_DISCONNECTED`，于是 CANCEL 与 MASK 变成 1:1
（10-02：1334 / 1450），而其中带诊断的每一条都伴随已下发的流式内容（bytes 最小 951、
中位 7.1 KB、p90 211 KB，`bytes<200` 为 0 条）。它们既不是上游故障，也不是脱敏失败
——是收尾信号被记成了取消，而且最新版本把这类记录的信息量降到了最低。

三条契约（本文件逐条锁住）：

1. **证据**：流已定论（`complete` / 失败）后再收到客户端 FIN 时，**不得**把 phase
   写回完成前的 `response_stream`——那会把「已完成」这一事实从证据里抹掉，正是那批
   记录无法归因的根因；须改标 `cancelled_after_complete`。
2. **信号与事件分离**：整条响应已交付完毕（流式收尾回调执行过）后的关连接
   **不再落 CANCEL 事件**，但治理层的取消信号必须照旧发出——AUX 任务与脱敏池的
   等待者仍要被唤醒，否则是拿日志噪声换资源泄漏。
3. **真中断仍可归因**：未完成的取消照旧记 CANCEL，且必须带齐
   `[stream calls/bytes]`、`resp=`、`ms=`、上游与模型，不得只留一条无法归因的薄记录。

范围声明（保守方向）：事件抑制的判据是「流式收尾回调执行过」，因此**整包（非流式）
响应在写出途中被客户端掐断**仍照旧记 CANCEL——那种情况我们拿不到「body 已写完」的
证据，宁可留着噪声也不隐藏可能真实的中断。
测试样例不含真实凭据或占位符字面量（`AGENTS.md` §3.9）。
"""
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import connection_policy as cp  # noqa: E402
import panel  # noqa: E402
import transparent as tr  # noqa: E402
from tests.test_stream_cancellation import HTTPDriver  # noqa: E402

REQUIRES_STREAM_CANCELLATION = unittest.skipUnless(
    cp.transport_capabilities()["stream_cancellation"],
    "requires mitmproxy 12.2.3 HttpStream cancellation interfaces",
)


class SettledEvidenceTests(unittest.TestCase):
    """契约 1：证据不得被收尾 FIN 抹回「进行中」。"""

    def setUp(self):
        self.signals = []
        self.g = cp.ConnectionGovernance(
            on_cancel=lambda flow, reason: self.signals.append((flow, reason)))
        self.assertTrue(self.g.running())
        self.addCleanup(self.g.done)

    def _settled_flow(self):
        driver = HTTPDriver()
        request = driver.request()
        self.g.request_started(request.flow)
        response = driver.response_hook(request)
        self.g.responseheaders(response.flow)
        self.g.response_complete(response.flow)
        return driver, response.flow

    @REQUIRES_STREAM_CANCELLATION
    def test_disconnect_after_complete_keeps_complete_phase(self):
        driver, flow = self._settled_flow()
        self.assertEqual(self.g.snapshot(flow)["phase"], "complete")

        driver.disconnect()

        # 取消信号仍然发出：AUX 任务与脱敏池的等待者需要被唤醒。
        self.assertEqual(self.signals, [(flow, "client_disconnected")])
        evidence = self.g.snapshot(flow)
        self.assertEqual(evidence["phase"], "complete",
                         "响应已完成后收到 FIN，phase 不得被写回 response_stream")
        self.assertTrue(evidence.get("cancelled_after_complete"),
                        "证据里必须留下「这次断开发生在收尾之后」")
        self.assertEqual(evidence["reason"], "client_disconnected")

    @REQUIRES_STREAM_CANCELLATION
    def test_disconnect_before_complete_is_still_inflight(self):
        driver = HTTPDriver()
        request = driver.request()
        self.g.request_started(request.flow)
        response = driver.response_hook(request)
        self.g.responseheaders(response.flow)

        driver.disconnect()

        evidence = self.g.snapshot(response.flow)
        self.assertEqual(evidence["phase"], "response_stream",
                         "真·未完成的中断仍要如实报出流进行中")
        self.assertFalse(evidence.get("cancelled_after_complete"),
                         "未完成的取消不得标成「收尾之后」")
        self.assertEqual(evidence["reason"], "client_disconnected")

    @REQUIRES_STREAM_CANCELLATION
    def test_stats_separate_settled_from_live_cancellations(self):
        driver, _flow = self._settled_flow()
        driver.disconnect()

        stats = self.g.stats()
        self.assertEqual(stats.get("cancelled_after_complete"), 1,
                         "收尾后的断开要单独计数，否则「不再落事件」就成了静默丢弃")


def _fake_flow(*, transport=None, stream_done=False, streamed=True):
    """构造足以走完 `_record_client_cancel` 的假 flow（不注册进治理器）。"""
    metadata = {
        "session_id": "sid-cancel-test",
        "shield_upstream": "ciyuan",
        "shield_model": "deepseek-v4-flash",
        "shield_mask_ms": 1310.8,
        "shield_mask_done_at": time.time() - 21.4,
        "shield_streamed": streamed,
        "shield_stream_calls": 261,
        "shield_stream_bytes": 96122,
    }
    if stream_done:
        metadata["shield_response_concluded"] = "stream_done"
    if transport is not None:
        metadata["_maskit_transport"] = dict(transport)
    return SimpleNamespace(
        metadata=metadata,
        request=SimpleNamespace(host="token.ciyuanroute.com", method="POST",
                                path="/v1/chat/completions",
                                raw_content=b"r" * 1024,
                                timestamp_start=time.time() - 21.5),
        # 被取消的流式请求一定有 response（响应头已到，流才开始），诊断里的 resp=1
        # 正是据此判断「上游已经把响应发出来了」，夹具不能省掉它。
        response=SimpleNamespace(status_code=200,
                                 headers={"content-type": "text/event-stream"},
                                 content=b""),
        error=RuntimeError("Client disconnected."),
    )


class CancelEventTests(unittest.TestCase):
    """契约 2/3：事件层面的取舍与归因字段（直接驱动 `_record_client_cancel`）。"""

    def setUp(self):
        self.events = []
        patcher = mock.patch.object(
            tr, "_emit", side_effect=lambda typ, **kw: self.events.append((typ, kw)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def cancels(self):
        return [kw for typ, kw in self.events if typ == "CANCEL"]

    def test_live_cancel_is_recorded_with_diagnostics(self):
        """未完成的取消：照旧记录，且带齐归因字段（旧版薄记录的问题）。"""
        flow = _fake_flow(transport={"phase": "response_stream", "reason": "client_disconnected"})

        tr._record_client_cancel(flow, "response_stream")

        events = self.cancels()
        self.assertEqual(len(events), 1, "真·未完成的中断必须留下一条 CANCEL")
        event = events[0]
        self.assertEqual(event.get("reason"), "client_disconnected")
        self.assertEqual(event.get("failure_phase"), "response_stream")
        self.assertEqual(event.get("upstream"), "ciyuan")
        self.assertEqual(event.get("model"), "deepseek-v4-flash")
        message = str(event.get("msg") or "")
        self.assertTrue(message.startswith("flow_error:"), "msg 口径要与 error() 一致：%r" % message)
        for token in ("[stream calls=261 bytes=96122]", "resp=1", "req=1024B", "ms="):
            self.assertIn(token, message, "归因字段缺失：%s -> %r" % (token, message))

    def test_concluded_stream_disconnect_is_not_recorded(self):
        """响应已交付完毕后的关连接：不落事件，但仍标记已记录以免 error() 再补一条。"""
        flow = _fake_flow(stream_done=True,
                          transport={"phase": "response_stream", "reason": "client_disconnected"})

        tr._record_client_cancel(flow, "response_stream")

        self.assertEqual(self.cancels(), [], "收尾后的关连接不该再产出 CANCEL 事件")
        self.assertTrue(getattr(flow, "_shield_cancel_recorded", False),
                        "必须置位去重标记：否则 error() 会紧接着补发一条同样的记录")

    def test_both_sides_agree_on_the_concluded_predicate(self):
        """抑制判据只能有一个来源，避免两条路径各判一次而漂移。"""
        concluded = _fake_flow(stream_done=True,
                               transport={"phase": "response_stream", "reason": "client_disconnected"})
        live = _fake_flow(transport={"phase": "response_stream", "reason": "client_disconnected"})
        self.assertTrue(tr._response_concluded(concluded))
        self.assertFalse(tr._response_concluded(live))


class StreamConcludedMarkerTests(unittest.TestCase):
    """契约 2 的上游事实：流式收尾回调必须留下「响应已交付完毕」的标记。

    标记的落点是 `_sse_stream_factory` 的收尾回调（`last` 块到达时执行），
    这是**唯一**能证明「整条流已交给 mitmproxy」的时刻——没有它，事件层只能靠
    「治理器说已完成」猜，而整包路径在响应钩子一开始就标了 complete。
    """

    def setUp(self):
        self.events = []
        for name, side in (("_emit", lambda typ, **kw: self.events.append((typ, kw))),
                           ("_audit_response", lambda *a, **k: None),
                           ("_scan_response", lambda *a, **k: None)):
            patcher = mock.patch.object(tr, name, side_effect=side)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(tr.sessions.clear)

    def _flow(self, sid):
        return SimpleNamespace(
            request=SimpleNamespace(host="api.openai.com", pretty_host="api.openai.com",
                                    method="POST", path="/v1/chat/completions",
                                    headers={"content-type": "application/json"}, content=b"{}"),
            response=SimpleNamespace(status_code=200, headers={"content-type": "text/event-stream"},
                                     content=b""),
            metadata={"session_id": sid},
        )

    def _open_stream(self, sid):
        tr._new_session(sid)
        flow = self._flow(sid)
        stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST",
                                        "/v1/chat/completions", {})
        stream(b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')
        return flow, stream

    def test_finish_marks_the_response_concluded(self):
        sid = "cancel-concluded"
        flow, stream = self._open_stream(sid)
        self.assertNotEqual(flow.metadata.get("shield_response_concluded"), "stream_done",
                            "收尾之前不得标记为已交付完毕")

        stream(b"")  # 末块：触发 _finish

        self.assertEqual(flow.metadata.get("shield_response_concluded"), "stream_done",
                         "流式收尾回调必须留下可判定的「已交付完毕」标记")
        tr.aux_drain(5.0)

    def test_unfinished_stream_has_no_marker(self):
        """对照组：没走到收尾的流不得带标记（否则真中断会被静默吞掉）。"""
        sid = "cancel-live"
        flow, _stream = self._open_stream(sid)
        self.assertNotEqual(flow.metadata.get("shield_response_concluded"), "stream_done")
        tr.sessions.pop(sid, None)


class ErrorHookTests(unittest.TestCase):
    """走**真实** `error()` 钩子（生产入口）验证两条路径的最终取舍。

    `CancelEventTests` 直接调 `_record_client_cancel`，但生产里先跑的是 `error()`：它自己
    也有一条兜底 CANCEL 分支，与 `_record_client_cancel` 共用 `_shield_cancel_recorded`
    去重。这条接缝必须单独锁——2026-10-02 的具实事故就是两处口径不一致（先发的薄记录
    把后到的富记录挡掉）。
    """

    def setUp(self):
        self.events = []
        patcher = mock.patch.object(
            tr, "_emit", side_effect=lambda typ, **kw: self.events.append((typ, kw)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _hook_flow(self, **metadata):
        flow = _fake_flow(transport=None, **metadata)
        flow._shield_cancel_reason = "client_disconnected"
        return flow

    def cancels(self):
        return [kw for typ, kw in self.events if typ == "CANCEL"]

    def test_live_abort_through_error_hook_logs_one_cancel_with_diagnostics(self):
        flow = self._hook_flow()

        tr.error(flow)

        events = self.cancels()
        self.assertEqual(len(events), 1, "真中断必须恰好记一条（不能重复也不能没有）")
        message = str(events[0].get("msg") or "")
        self.assertIn("[stream calls=261 bytes=96122]", message)
        self.assertIn("resp=1", message)
        self.assertEqual(events[0].get("upstream"), "ciyuan")

    def test_concluded_stream_through_error_hook_logs_nothing(self):
        flow = self._hook_flow(stream_done=True)

        tr.error(flow)

        self.assertEqual(self.events, [],
                         "流已交付完毕后的关连接，两条路径都不得留下 CANCEL")


class PanelProjectionTests(unittest.TestCase):
    """证据字段要能穿过面板投影到达前端，否则「已收尾」在 UI 上仍不可见。"""

    def test_projection_keeps_the_settled_flag(self):
        projected = panel._project_transport(
            {"phase": "complete", "reason": "client_disconnected", "cancelled_after_complete": True})
        self.assertTrue(projected.get("cancelled_after_complete"))
        self.assertEqual(projected.get("phase"), "complete")


if __name__ == "__main__":
    unittest.main()