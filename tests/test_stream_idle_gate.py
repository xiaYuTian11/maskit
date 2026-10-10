"""上游响应流空闲闸：判据是「相邻两块的间隔」，刀必须落在 mitmproxy 那 600 s 之前。

背景（2026-10-10 本机事件库）：上游「首包到了、然后彻底没声」时，响应侧**一个 idle
判据都没有**——`_ENGINE_DEADLINE_S=120 s` 只管脱敏阶段（超时文案就是「未上行」），
`_CONNECT_STALL_S` 只管「请求还没写出去」。那种流唯一的兜底是 mitmproxy 每连接的
空闲看门狗 `tcp_timeout`（默认 600 s），于是 Maskit 替客户端握着一条已经死了的连接
整整十分钟，客户端那边早就超时放弃了。当天这类形态 6 例（1~9 块 / 最少 569 字节后
静默），基数是 1833 个 MASK 请求 / 985 个 CANCEL。

N 只能由**间隔**定：同一天库里同时存在 876 chunks / 412 KB / 跑满 646 s 的合法长生成，
按总时长一刀切就是在砍真请求。所以本闸的记账里根本不该出现「开始时刻」——那条结构
约束由 `RecordShapeTests` 钉住；而 `max_gap_s` 每次收到块都刷新、随 runtime metrics
上报，下次调 N 向这个数要，不要再拍。

六条契约（本文件逐条锁住）：

1. **判据**：只有「距最后一个上游字节的间隔」过预算才算静默；预算两侧各差 0.5 s 必须
   翻转，登记之前（首包未到）一律不可见，且**仍在吐块的长流绝对不动**。
2. **执行点**：与建连闸同一把刀——取消 mitmproxy 自己的 `client connection handler`
   （`proxy/server.py` 的 `on_timeout` 就是这么结束静默连接的），只是预算提前、条件
   收窄到「首包之后」。匹配不唯一或认不出这条连接时**不落刀**（错杀一条健康连接的
   代价比漏杀大），但必须计数，不能变成静默丢弃。
3. **一次一刀**：掐过的流不得重复 cancel（会打乱 mitmproxy 的收尾）。
4. **可关**：`MASKIT_SSE_IDLE_KILL=0` 退回纯观测——仍然统计静默流，只是不断连接。
5. **证据与出口**：动手的是我们自己，必须在 flow 上留下 `shield_idle_killed`，让
   `_upstream_idle_killed` 直接认定（120 s 的预算**落不进** 600 s 那个反推窗口，
   不记这一笔就永远归因成客户端断开）；预算/是否落刀/累计计数/实测最大间隔必须
   出现在 runtime metrics 里，否则这套判据在面板上不可见。
6. **不拖累转发**：观测链路自己坏了（flow 不可弱引用、`client_conn` 取值抛异常）
   绝不能冒泡进流式还原——2026-10-10 实测回归：只捕 TypeError 时 SimpleNamespace
   flow 的 AttributeError 让 12+ 个流式用例一起变红。
测试样例不含真实凭据或占位符字面量（`AGENTS.md` §3.9）。
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import weakref
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr  # noqa: E402
from tests.test_cancel_attribution import _fake_flow  # noqa: E402

PEER = ("127.0.0.1", 4321)
HANDLER = "client connection handler"
BUDGET = 5.0  # 测试用的预算；默认 120 s 的形状由 `BudgetShapeTests` 单独钉


class WatchableFlow:
    """可弱引用的假 flow：空闲闸只认 `metadata` 与 `client_conn.peername`。

    真 mitmproxy flow 也能用，但这里要验的是「登记/命中/落刀」这条链路本身，
    拖进 mitmproxy 的连接对象只会让失败原因变得难读。
    """

    def __init__(self, peer=PEER, sid="sid-idle-flow"):
        self.metadata = {"session_id": sid}
        self.client_conn = SimpleNamespace(peername=peer)


class ConnRaises(WatchableFlow):
    """`client_conn` 本身抛异常的 flow：观测链路坏了不能拖累转发。"""

    def __init__(self, sid="sid-idle-raises"):
        self.metadata = {"session_id": sid}

    @property
    def client_conn(self):
        raise RuntimeError("conn gone")


class FakeTask:
    """只实现匹配器与执行器真正碰到的四个属性。"""

    def __init__(self, name=HANDLER, client=None, is_done=False):
        self._name, self._done, self.cancelled = name, is_done, False
        self.cancel_msg = None
        if client is not None:
            self.client = client

    def get_name(self):
        return self._name

    def done(self):
        return self._done

    def cancel(self, msg=None):
        self.cancelled = True
        self.cancel_msg = msg


class GateTestCase(unittest.TestCase):
    """把闸的登记表与预算换成每条用例自己的那份：漏一条清理就是跨用例串味。"""

    def setUp(self):
        self.watch = weakref.WeakKeyDictionary()
        # 登记表是**弱引用键**：夹具 flow 若只被局部变量之外的地方引用，会被当场回收，
        # 于是闸「什么都没看到」而用例以 0 != 1 失败——看着像实现坏了，其实是夹具的
        # 生命周期。所以每条 flow 都由 self 强持到用例结束。
        self.flows = []
        for name, value in (("_STREAM_WATCH", self.watch),
                            ("_SSE_IDLE_S", BUDGET),
                            ("_SSE_IDLE_KILL", True)):
            patcher = mock.patch.object(tr, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def flow(self, **kw):
        made = WatchableFlow(**kw)
        self.flows.append(made)
        return made

    def register(self, flow, idle_for=6.0, chunks=1, peer=PEER):
        entry = tr._stream_watch(flow)
        entry["peer"] = peer
        entry["last_byte"] = time.time() - idle_for
        entry["chunks"] = chunks
        return entry

    def scan(self, *tasks):
        with mock.patch.object(tr.asyncio, "all_tasks", lambda *a: list(tasks)):
            return tr._act_stream_idle()


class MatcherTests(GateTestCase):
    """契约 2：执行点是 mitmproxy 自己那条客户端 handler，匹配必须唯一。"""

    def test_only_the_live_handler_of_this_peer_matches(self):
        good = FakeTask(HANDLER, PEER)
        noise = [
            FakeTask(HANDLER, ("127.0.0.1", 9999)),       # 别的客户端连接
            FakeTask("server connection handler", PEER),   # 名字对不上就不动
            FakeTask(HANDLER, PEER, is_done=True),         # 已经收尾的那条
        ]
        self.assertEqual(tr._client_handler_tasks([good] + noise, PEER), [good])


class ScopeTests(GateTestCase):
    """契约 1 的范围：只看登记过的流，登记发生在首包。"""

    def test_unregistered_stream_is_invisible(self):
        """推理模型几分钟不出首包是合法的——首包之前这把刀不许落。"""
        task = FakeTask(HANDLER, PEER)

        self.assertEqual(self.scan(task), dict.fromkeys(tr._STREAM_IDLE_TOTAL, 0))
        self.assertFalse(task.cancelled)


class RecordShapeTests(GateTestCase):
    """契约 1 的结构面：记账里只要存在「开始时刻」，按总时长一刀切就是迟早的事。"""

    def test_record_has_no_start_anchor(self):
        entry = self.register(self.flow(), chunks=876)

        self.assertEqual(
            set(entry), {"peer", "last_byte", "max_gap_s", "chunks", "killed"},
            "空闲闸的记账形状变了：新增的必须是「间隔」类字段，不能是开始时刻——"
            "库里 876 chunks / 跑满 646 s 的合法长生成就是反例")


class BudgetBoundaryTests(GateTestCase):
    """契约 1：预算两侧各差 0.5 s 必须翻转。"""

    def test_just_under_budget_leaves_the_stream_alone(self):
        flow = self.flow()
        self.register(flow, idle_for=BUDGET - 0.5)
        task = FakeTask(HANDLER, PEER)

        counters = self.scan(task)

        self.assertEqual(counters["silent"], 0)
        self.assertFalse(task.cancelled)
        self.assertNotIn("shield_idle_killed", flow.metadata)

    def test_just_over_budget_kills(self):
        flow = self.flow()
        self.register(flow, idle_for=BUDGET + 0.5)
        task = FakeTask(HANDLER, PEER)

        counters = self.scan(task)

        self.assertEqual(counters["silent"], 1)
        self.assertEqual(counters["killed"], 1)
        self.assertTrue(task.cancelled)

    def test_still_producing_long_stream_survives(self):
        """跑满 646 s、876 块的合法长生成：静默只有 2 s，不能「见长就砍」。"""
        self.register(self.flow(), idle_for=2.0, chunks=876)
        task = FakeTask(HANDLER, PEER)

        self.assertEqual(self.scan(task)["silent"], 0)
        self.assertFalse(task.cancelled, "砍掉一条正在吐块的流 = 用户看到的回答凭空截断")

    def test_zero_budget_kills_nothing_only_if_the_switch_follows(self):
        """预算 0 时每条流都「过预算」，所以关闸必须由 `_SSE_IDLE_KILL` 跟着失效。

        `_act_stream_idle` 只做「间隔 vs 预算」的比较，不认识 0 的语义；耦合写在
        模块级的 `and _SSE_IDLE_S > 0` 里，退路由此保证（真实 env 形态见
        `BudgetShapeTests.test_env_knobs_reach_the_gate`）。这里锁的是合起来的效果：
        kill 失效时，即便预算为 0 也一条都不掐。
        """
        with mock.patch.object(tr, "_SSE_IDLE_S", 0.0), \
                mock.patch.object(tr, "_SSE_IDLE_KILL", False):
            self.register(self.flow(), idle_for=0.0)
            self.register(self.flow(sid="sid-old"), idle_for=99.0)
            tasks = [FakeTask(HANDLER, PEER), FakeTask(HANDLER, ("127.0.0.1", 2002))]

            counters = self.scan(*tasks)

        self.assertEqual(counters["silent"], 2, "预算 0 仍然要能观测到静默，否则关闸=失明")
        self.assertEqual(counters["killed"], 0)
        self.assertFalse(any(t.cancelled for t in tasks))


class NoGuessingTests(GateTestCase):
    """契约 2：判不准就不动，但要留下计数。"""

    def test_unidentified_peer_is_not_killed(self):
        flow = self.flow()
        self.register(flow, peer=None)
        task = FakeTask(HANDLER, PEER)

        counters = self.scan(task)

        self.assertEqual(counters["silent"], 1)
        self.assertEqual(counters["no_peer"], 1)
        self.assertEqual(counters["killed"], 0)
        self.assertFalse(task.cancelled)
        self.assertNotIn("shield_idle_killed", flow.metadata)

    def test_ambiguous_handler_is_not_guessed_and_stays_retryable(self):
        """两条同名 handler 时不猜：而且不得标成已处理，下一轮还得再试。"""
        entry = self.register(self.flow())
        a, b = FakeTask(HANDLER, PEER), FakeTask(HANDLER, PEER)

        counters = self.scan(a, b)

        self.assertEqual(counters["ambiguous"], 1)
        self.assertEqual(counters["killed"], 0)
        self.assertFalse(a.cancelled or b.cancelled)
        self.assertFalse(entry["killed"],
                         "没落刀却标了 killed = 这条流永久脱管，静默十分钟照旧")

    def test_missing_handler_is_reported_not_hidden(self):
        self.register(self.flow())

        counters = self.scan()

        self.assertEqual(counters["no_task"], 1)
        self.assertEqual(counters["killed"], 0)

    def test_empty_watch_does_not_enumerate_tasks(self):
        """心跳每 2 s 跑一次：没有流可看时不许去遍历 asyncio.all_tasks()。"""
        def boom(*_a):
            raise AssertionError("登记表为空时不该枚举全部 task")

        with mock.patch.object(tr.asyncio, "all_tasks", boom):
            self.assertEqual(tr._act_stream_idle(),
                             dict.fromkeys(tr._STREAM_IDLE_TOTAL, 0))


class KillOnceTests(GateTestCase):
    """契约 3：一次一刀，且各掐各的。"""

    def test_second_scan_does_not_re_cancel(self):
        self.register(self.flow())
        first = FakeTask(HANDLER, PEER)

        self.assertEqual(self.scan(first)["killed"], 1)
        second = FakeTask(HANDLER, PEER)
        counters = self.scan(second)

        self.assertEqual(counters["killed"], 0, "重复 cancel 会打乱 mitmproxy 的收尾")
        self.assertFalse(second.cancelled)
        self.assertTrue(first.cancelled)

    def test_kill_targets_only_this_flows_connection(self):
        """两条流同时静默：各掐自己那条，不能一把掐。"""
        self.register(self.flow(sid="sid-a"))
        self.register(self.flow(sid="sid-b"), peer=("127.0.0.1", 7777))
        task_a = FakeTask(HANDLER, PEER)
        task_b = FakeTask(HANDLER, ("127.0.0.1", 7777))
        unrelated = FakeTask(HANDLER, ("127.0.0.1", 5555))

        counters = self.scan(task_a, task_b, unrelated)

        self.assertEqual(counters["killed"], 2)
        self.assertEqual(counters["silent"], 2)
        self.assertTrue(task_a.cancelled and task_b.cancelled)
        self.assertFalse(unrelated.cancelled, "掐掉一条健康连接比漏杀更糟")
        self.assertEqual(task_a.cancel_msg, "upstream idle",
                         "cancel 的理由要传进去：mitmproxy 的日志靠它")

    def test_counters_add_up_per_scan(self):
        """一轮扫描里几种结局各归各位：计数是这套闸唯一的可观测出口。"""
        quiet, ambiguous, faceless = (self.flow(sid="sid-%d" % i) for i in range(3))
        fresh = self.flow(sid="sid-fresh")
        self.register(quiet, peer=("127.0.0.1", 1001))            # -> killed
        self.register(ambiguous, peer=("127.0.0.1", 1002))        # -> ambiguous
        self.register(faceless, peer=None)                         # -> no_peer
        self.register(fresh, idle_for=BUDGET - 3.0,
                      peer=("127.0.0.1", 1003))                   # 未过预算，不算静默
        tasks = [FakeTask(HANDLER, ("127.0.0.1", 1001)),
                 FakeTask(HANDLER, ("127.0.0.1", 1002)),
                 FakeTask(HANDLER, ("127.0.0.1", 1002))]

        counters = self.scan(*tasks)

        self.assertEqual(counters["silent"], 3, "未过预算的那条不能算静默")
        self.assertEqual(counters["killed"], 1)
        self.assertEqual(counters["ambiguous"], 1)
        self.assertEqual(counters["no_peer"], 1)
        self.assertEqual(counters["no_task"], 0)
        self.assertTrue(tasks[0].cancelled)
        self.assertFalse(tasks[1].cancelled or tasks[2].cancelled)


class KillSwitchTests(GateTestCase):
    """契约 4：关掉落刀 = 退回纯观测，不是关掉统计。"""

    def test_disabled_kill_still_counts_silence_every_round(self):
        flow = self.flow()
        self.register(flow)
        task = FakeTask(HANDLER, PEER)

        with mock.patch.object(tr, "_SSE_IDLE_KILL", False):
            counters = self.scan(task)
            again = self.scan(task)

        self.assertEqual(counters["silent"], 1)
        self.assertEqual(counters["killed"], 0)
        self.assertEqual(again["silent"], 1,
                         "纯观测模式下反复扫描要反复计数，否则「观测到了静默」会消失")
        self.assertFalse(task.cancelled)
        self.assertNotIn("shield_idle_killed", flow.metadata)


class RegistrationTests(GateTestCase):
    """契约 6：登记与释放。收尾路径有好几条，漏一条就是永久扣住一个 flow 对象。"""

    def test_watch_is_idempotent_and_returns_the_same_record(self):
        flow = self.flow()
        first = tr._stream_watch(flow)
        first["last_byte"] = 12.0

        self.assertIs(tr._stream_watch(flow), first,
                      "每块都新建记录的话，间隔永远算不出来，静默也永远判不出来")
        self.assertEqual(tr._stream_watch(flow)["last_byte"], 12.0)
        self.assertEqual(len(self.watch), 1)

    def test_peer_is_taken_from_the_client_connection(self):
        flow = self.flow(peer=("10.0.0.5", 44100))

        self.assertEqual(tr._stream_watch(flow)["peer"], ("10.0.0.5", 44100))

    def test_forget_releases_the_flow(self):
        flow = self.flow()
        tr._stream_watch(flow)
        self.assertEqual(len(self.watch), 1)

        tr._stream_watch_forget(flow)

        self.assertEqual(len(self.watch), 0)
        tr._stream_watch_forget(flow)  # 收尾路径可能重入，第二次不得抛

    def test_detached_record_when_the_flow_is_not_weakrefable(self):
        """不可弱引用的 flow 拿一条**不落表**的临时记录，闸自然看不到它。

        生产里的测试夹具与某些包装 flow 就是 SimpleNamespace；登记失败必须安静降级，
        不能把异常冒泡进 `_stream_owned` 的 except 而把整条流式还原打成原样直通。
        """
        flow = SimpleNamespace(metadata={}, client_conn=None)

        entry = tr._stream_watch(flow)

        self.assertEqual(entry["chunks"], 0)
        self.assertIsNotNone(entry["last_byte"])
        self.assertEqual(len(self.watch), 0, "不可弱引用的 flow 不该留在登记表里")
        tr._stream_watch_forget(flow)

    def test_broken_client_conn_attribute_degrades_quietly(self):
        """`client_conn` 取值抛异常：这条安静地不盯（登记在取 peer 之后），绝不冒泡。

        形状是刻意的取舍：观测链路自己坏了就少观测一条流，而不是让异常冒泡进
        `_stream_owned` 的 except，把**整条流式还原**降级成原样直通。
        """
        healthy = self.flow()
        self.register(healthy)

        entry = tr._stream_watch(ConnRaises())
        self.assertIsNone(entry["peer"])
        self.assertEqual(len(self.watch), 1, "坏 flow 不该进登记表，也不该顶掉好的那条")

        task = FakeTask(HANDLER, PEER)
        self.assertEqual(self.scan(task)["killed"], 1,
                         "一条 flow 登记失败不能整轮扫描报废：其余静默流照旧要有兜底")
        self.assertTrue(task.cancelled)


class ProductionPathTests(GateTestCase):
    """闸必须真的接在流式回调上：否则它是一段永远绿的死代码。"""

    def setUp(self):
        super().setUp()
        for name in ("_emit", "_audit_response", "_scan_response",
                     "_transport_complete", "_transport_event",
                     "_emit_restore_summary", "_aux_submit"):
            patcher = mock.patch.object(tr, name, lambda *a, **k: None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(tr.sessions.clear)
        self._gap = tr._STREAM_GAP_MAX["s"]
        self.addCleanup(lambda: tr._STREAM_GAP_MAX.__setitem__("s", self._gap))

    def _open(self, sid):
        tr._new_session(sid)
        flow = self.flow(sid=sid)
        stream = tr._sse_stream_factory(flow, sid, "api.openai.com", "POST",
                                       "/v1/chat/completions", {})
        return flow, stream

    def test_first_byte_registers_and_last_byte_releases(self):
        sid = "idle-gate-live"
        flow, stream = self._open(sid)
        self.assertEqual(len(self.watch), 0, "首包之前不该被盯着")

        stream(b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')

        self.assertEqual(len(self.watch), 1, "首包到了却没登记 = 空闲闸形同虚设")
        entry = tr._stream_watch(flow)
        self.assertEqual(entry["peer"], PEER)
        self.assertGreaterEqual(entry["chunks"], 1)

        stream(b"")  # 末块：整条流已交付

        self.assertEqual(len(self.watch), 0,
                         "流已收尾还盯着它，下一次心跳就把已结束的流掐一遍")
        tr.aux_drain(5.0)
        tr.sessions.pop(sid, None)

    def test_gap_between_chunks_is_measured(self):
        """`max_gap_s` 是下次调 N 唯一该向它要的数——没有它，N 只能一直靠猜。"""
        sid = "idle-gate-gap"
        flow, stream = self._open(sid)
        stream(b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n')
        time.sleep(0.02)
        stream(b'data: {"choices":[{"delta":{"content":"b"}}]}\n\n')

        entry = tr._stream_watch(flow)
        self.assertGreaterEqual(entry["max_gap_s"], 0.01,
                                "两块之间的间隔没被算出来（%r）" % (entry,))
        self.assertGreaterEqual(tr._STREAM_GAP_MAX["s"], entry["max_gap_s"],
                                "全局最大间隔没被这条流顶上去，面板会永远显示 0")
        stream(b"")
        tr.aux_drain(5.0)
        tr.sessions.pop(sid, None)

    def test_empty_final_chunk_is_not_upstream_activity(self):
        """收尾用的空块不算活动：否则静默时长会被低估，闸形同虚设。"""
        sid = "idle-gate-tail"
        flow, stream = self._open(sid)
        stream(b'data: {"x":1}\n\n')
        entry = tr._stream_watch(flow)
        stamped = entry["last_byte"]
        time.sleep(0.02)

        stream(b"")

        self.assertEqual(entry["last_byte"], stamped)
        tr.aux_drain(5.0)
        tr.sessions.pop(sid, None)


class EvidenceTests(GateTestCase):
    """契约 5：自己落的刀要留下证据，归因不再靠 600 s 反推。"""

    def test_stamp_records_the_idle_that_triggered(self):
        flow = self.flow()
        self.register(flow, idle_for=121.4)

        self.assertEqual(self.scan(FakeTask(HANDLER, PEER))["killed"], 1)
        self.assertEqual(flow.metadata["shield_idle_killed"], 121.4,
                         "证据里要留下「静了多久」，否则事后无法判断是不是 N 定低了")

    def test_predicate_accepts_the_stamp_below_the_watchdog_window(self):
        """120 s 量级的预算**落不进** 600 s 那个反推窗口——靠标记才认得出。"""
        bound = tr._UPSTREAM_INACTIVITY_BOUND_S
        flow = _fake_flow(last_byte_at=time.time() - (bound / 2.0))
        self.assertFalse(tr._upstream_idle_killed(flow, "response_stream"),
                         "对照组：没有标记时，半窗口的静默仍判不出上游问题")

        flow.metadata["shield_idle_killed"] = bound / 2.0

        self.assertTrue(tr._upstream_idle_killed(flow, "response_stream"))

    def test_stamp_wins_even_when_the_stream_looks_fresh(self):
        """标记优先于任何反推：刀是我们落的，不必猜。"""
        flow = _fake_flow(last_byte_at=time.time())
        flow.metadata["shield_idle_killed"] = 0.2

        self.assertTrue(tr._upstream_idle_killed(flow, "response_stream"))

    def test_cancel_is_attributed_to_upstream_with_the_new_reason(self):
        events = []
        with mock.patch.object(tr, "_emit",
                               side_effect=lambda typ, **kw: events.append((typ, kw))):
            flow = _fake_flow(last_byte_at=time.time() - 121.0,
                              transport={"phase": "response_stream",
                                         "reason": "client_disconnected"})
            flow.metadata["shield_idle_killed"] = 121.0
            tr._record_client_cancel(flow, "response_stream")

        cancels = [kw for typ, kw in events if typ == "CANCEL"]
        self.assertEqual(len(cancels), 1)
        self.assertEqual(cancels[0]["reason"], "upstream_idle")
        self.assertEqual(cancels[0]["failure_owner"], "upstream")
        self.assertAlmostEqual(cancels[0]["upstream_idle_s"], 121.0, delta=1.0)

    def test_owner_uses_the_same_predicate(self):
        flow = _fake_flow(last_byte_at=time.time())
        flow.metadata["shield_idle_killed"] = 130.5

        self.assertEqual(tr._flow_failure_owner(flow, "Client disconnected."), "upstream",
                         "两处判据必须同源：各写一遍必然漂移")


class BudgetShapeTests(unittest.TestCase):
    """默认预算的形状：比看门狗早得多，又远高于本机任何一条真流式的块间隔。"""

    def test_default_budget_sits_between_the_two_bounds(self):
        self.assertGreater(tr._SSE_IDLE_S, 60.0,
                           "低于 1 分钟会砍到正常的首包后思考间隔")
        self.assertLess(tr._SSE_IDLE_S, tr._UPSTREAM_INACTIVITY_BOUND_S / 2.0,
                        "贴着 600 s 看门狗等于没加这个闸")
        self.assertTrue(tr._SSE_IDLE_KILL,
                        "默认必须真的落刀，否则这次改动只是多了一组数字")

    def test_env_knobs_reach_the_gate(self):
        """预算与开关是模块级常量：只能在新进程里验，reload 会留下半套线程池状态。"""
        script = ("import json, transparent as tr;"
                  "print(json.dumps([tr._SSE_IDLE_S, tr._SSE_IDLE_KILL]))")
        env_base = dict(os.environ)
        # 本机若已设了这两个旋钮，"非法值回落默认"那条就会读到一个非 120 的期望值：
        # 先清掉，用例只对自己传进去的那份 env 负责。
        for key in ("MASKIT_SSE_IDLE_S", "MASKIT_SSE_IDLE_KILL"):
            env_base.pop(key, None)
        env_base["PYTHONPATH"] = str(ROOT / "engine") + os.pathsep + env_base.get("PYTHONPATH", "")
        cases = (
            ({"MASKIT_SSE_IDLE_S": "45"}, [45.0, True]),
            ({"MASKIT_SSE_IDLE_S": "45", "MASKIT_SSE_IDLE_KILL": "0"}, [45.0, False]),
            ({"MASKIT_SSE_IDLE_S": "-1"}, [0.0, False]),      # 夹到 0 = 闸整体失效
            ({"MASKIT_SSE_IDLE_S": "0"}, [0.0, False]),        # 0 也必须连着关落刀
            ({"MASKIT_SSE_IDLE_S": "nonsense"}, [120.0, True]),  # 非法值回落默认
        )
        for extra, expected in cases:
            env = dict(env_base)
            env.update(extra)
            with self.subTest(**extra):
                result = subprocess.run([sys.executable, "-c", script], env=env,
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]),
                                 expected, "环境变量旋钮没到达闸（预算, 是否落刀）")


class MetricsOutletTests(GateTestCase):
    """出口：这套判据必须在面板读到的 runtime metrics 里可见，否则等于没做。"""

    def test_stream_idle_block_is_published(self):
        flow = self.flow()
        self.register(flow, idle_for=BUDGET + 1)
        old_gap = tr._STREAM_GAP_MAX["s"]
        self.addCleanup(lambda: tr._STREAM_GAP_MAX.__setitem__("s", old_gap))
        tr._STREAM_GAP_MAX["s"] = 7.5
        self.scan(FakeTask(HANDLER, PEER))

        old_root, old_last = tr._DATA_ROOT, tr._RUNTIME_METRICS_LAST[0]
        tmp = Path(tempfile.mkdtemp())
        try:
            tr._DATA_ROOT = tmp
            tr._RUNTIME_METRICS_LAST[0] = 0.0
            self.assertTrue(tr.write_runtime_metrics(force=True))
            payload = json.loads((tmp / tr._RUNTIME_METRICS_FILE).read_text(encoding="utf-8"))
        finally:
            tr._DATA_ROOT = old_root
            tr._RUNTIME_METRICS_LAST[0] = old_last

        block = payload.get("stream_idle") or {}
        self.assertEqual(block.get("budget_s"), BUDGET)
        self.assertIs(block.get("actuating"), True)
        self.assertEqual(block.get("watching"), 1,
                         "在盯的流数必须是 len(登记表)：少了它看不出闸有没有在吃流")
        self.assertEqual(block.get("max_gap_s"), 7.5)
        self.assertEqual(set(block.get("kills") or {}), set(tr._STREAM_IDLE_TOTAL),
                         "计数字典形状变了：面板与自检读的是同一组键")


class HeartbeatWiringTests(GateTestCase):
    """上线接缝：心跳是唯一驱动这个闸的地方，没接进去就等于没上线。

    单测里直接调 `_act_stream_idle()` 能全绿，但生产里它是
    `_heartbeat_loop` 每 2 s 跑一遍、再把计数累进 `_STREAM_IDLE_TOTAL` 的。
    少接一行（或只算不累加）的表现是「闸永远不掐、面板永远 0」，而上面所有用例
    都不会红——所以这里跑真实的那一圈。
    """

    class _Break(RuntimeError):
        """在写指标处打断：累加已经跑完，不必真的等 2 s 的 sleep。"""

    def _one_pass(self):
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(tr._heartbeat_loop())
        except self._Break:
            return True
        finally:
            loop.close()
        return False

    def test_heartbeat_actuates_and_accumulates_the_idle_gate(self):
        self.register(self.flow(), idle_for=BUDGET + 1)
        task = FakeTask(HANDLER, PEER)
        totals = dict.fromkeys(tr._STREAM_IDLE_TOTAL, 0)

        class Gov:
            def stats(self):
                return {}

            def stalled_before_send(self, _s):
                return []

        with mock.patch.object(tr, "_STREAM_IDLE_TOTAL", totals), \
                mock.patch.object(tr, "_CONNECTIONS", Gov()), \
                mock.patch.object(tr, "_act_handshake_kills", lambda *a: {}), \
                mock.patch.object(tr.asyncio, "all_tasks", lambda *a: [task]), \
                mock.patch.object(tr, "write_runtime_metrics",
                                  side_effect=self._Break):
            self.assertTrue(self._one_pass(), "心跳没跑到写指标这一步")

        self.assertEqual(totals["silent"], 1, "心跳扫到的静默没累加：面板永远 0")
        self.assertEqual(totals["killed"], 1, "心跳没有落刀：这套判据只是纸上的")
        self.assertTrue(task.cancelled)


if __name__ == "__main__":
    unittest.main()
