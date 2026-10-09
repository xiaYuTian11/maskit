"""握手熔断的执行侧：匹配必须唯一，落刀必须一次，判不准就不动。

判据（`stalled_before_send`）与「一次一跳」记账在 `test_connection_policy.py`；
这里只钉执行器：它拿 mitmproxy 的 task 名与 `.client` 调试属性定位**这一跳**，
所以名字对不上、客户端对不上、命中多于一个，都只能是不落刀。
实测过的端到端形态（6 s 熔断拿到干净 502、客户端连接仍可用、慢流 0 次被 cancel）
不在单测里重复，见 tests/smoke_transport.py。
"""
import unittest
from types import SimpleNamespace
from unittest import mock

from mitmproxy import connection, http

import engine.transparent as transparent
from engine.connection_policy import ConnectionGovernance

PEER = ("127.0.0.1", 4321)
ADDRESS = ("203.0.113.7", 443)


def flow_for(server, peername=PEER):
    client = connection.Client(peername=peername, sockname=("127.0.0.1", 18709))
    flow = http.HTTPFlow(client, server)
    flow.request = http.Request.make("POST", "https://private.example", b"masked-body")
    return flow


class FakeTask:
    """Only the three attributes the matcher and the actuator touch."""

    def __init__(self, name, client=None, is_done=False):
        self._name, self._done, self.cancelled = name, is_done, False
        if client is not None:
            self.client = client

    def get_name(self):
        return self._name

    def done(self):
        return self._done

    def cancel(self):
        self.cancelled = True


class MatcherTests(unittest.TestCase):
    def test_only_the_exact_hop_matches(self):
        want = f"server connection handler {ADDRESS}"
        good = FakeTask(want, PEER)
        others = [
            FakeTask(want, ("127.0.0.1", 9999)),        # 别的客户端连接
            FakeTask(f"server connection handler {('203.0.113.8', 443)}", PEER),
            FakeTask("client connection handler", PEER),
            FakeTask(want, PEER, is_done=True),          # 已经收尾的那一跳
        ]
        self.assertEqual(transparent._hop_task_candidates([good] + others, ADDRESS, PEER),
                         [good])


class ActuatorTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.g = ConnectionGovernance(clock=lambda: self.now)
        self.conn = connection.Server(address=ADDRESS)
        self.data = SimpleNamespace(
            server=self.conn, conn=self.conn,
            client=connection.Client(peername=PEER, sockname=("127.0.0.1", 18709)))
        self.flow = flow_for(self.conn)
        self.g.request_started(self.flow)
        self.g.connection_pending(self.flow, self.conn)
        self.g.server_connect(self.data)
        self.g.tls_start_server(self.data)
        self.now += 30.0
        self.stalled = self.g.stalled_before_send(20.0)
        self.name = f"server connection handler {ADDRESS}"
        self.addCleanup(self.g.done)

    def _run(self, tasks, actuating=True, stalled=None):
        with mock.patch.object(transparent, "_CONNECTIONS", self.g), \
                mock.patch.object(transparent, "_CONNECT_KILL", actuating), \
                mock.patch.object(transparent.asyncio, "all_tasks",
                                           lambda *a: list(tasks)):
            return transparent._act_handshake_kills(
                self.stalled if stalled is None else stalled)

    def test_single_match_cancels_that_hop_only(self):
        hit, noise = FakeTask(self.name, PEER), FakeTask("client handler", PEER)
        self.assertEqual(self._run([hit, noise]), {"killed": 1, "ambiguous": 0, "no_conn": 0, "no_task": 0})
        self.assertTrue(hit.cancelled)
        self.assertFalse(noise.cancelled)
        self.assertEqual(self.g.stats()["handshake_kills"], 1)
        state = self.g._connections[str(self.conn.id)]
        self.assertEqual(state["reason"], "handshake_timeout")

    def test_one_hop_is_killed_at_most_once(self):
        first = FakeTask(self.name, PEER)
        self._run([first])
        second = FakeTask(self.name, PEER)
        self.assertEqual(self._run([second]),
                         {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0})
        self.assertFalse(second.cancelled)          # 重复 cancel 会打乱 mitmproxy 的收尾
        self.assertEqual(self.g.stalled_before_send(20.0), [])

    def test_ambiguous_match_does_not_guess(self):
        a, b = FakeTask(self.name, PEER), FakeTask(self.name, PEER)
        self.assertEqual(self._run([a, b]), {"killed": 0, "ambiguous": 1, "no_conn": 0, "no_task": 0})
        self.assertFalse(a.cancelled or b.cancelled)

    def test_no_task_is_reported_not_hidden(self):
        # mitmproxy 改名或这一跳已经收尾：必须记成 no_task，而不是静默成功。
        self.assertEqual(self._run([]), {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 1})

    def test_tries_are_bounded(self):
        for _ in range(ConnectionGovernance.MAX_KILL_TRIES):
            self.assertEqual(self._run([])["no_task"], 1)
        self.assertEqual(self._run([FakeTask(self.name, PEER)]),
                         {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0})

    def test_hop_without_identity_is_left_alone(self):
        # 钩子数据缺 address/peer（旧版或异常路径）时不许猜：宁可不掐。
        stale = [(str(self.conn.id), "tls_handshake", None, None)]
        self.assertEqual(self._run([FakeTask(self.name, PEER)], stalled=stale)["no_conn"], 1)

    def test_flows_sharing_a_pending_hop_are_killed_once(self):
        # 两条流等同一条在建连接 = 一个 task。重复取消会把 mitmproxy 的收尾踩乱。
        second = flow_for(self.conn)
        self.g.request_started(second)
        self.g.connection_pending(second, self.conn)
        hop_level = self.g.stalled_before_send(20.0)
        self.assertEqual(len(hop_level), 1)
        self.assertEqual(self._run([FakeTask(self.name, PEER)], stalled=hop_level)["killed"], 1)

    def test_observation_only_mode_never_acts(self):
        hit = FakeTask(self.name, PEER)
        self.assertEqual(self._run([hit], actuating=False),
                         {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0})
        self.assertFalse(hit.cancelled)

    def test_empty_candidate_set_is_free(self):
        self.assertEqual(self._run([FakeTask(self.name, PEER)], stalled=[]),
                         {"killed": 0, "ambiguous": 0, "no_conn": 0, "no_task": 0})


class BudgetTests(unittest.TestCase):
    """阈值语义与既有旋钮同口径：非法/NaN 回落默认，`0` 关闸，正数夹到硬下限。"""

    def test_default_and_floor(self):
        self.assertEqual(transparent._connect_budget(20.0), 20.0)
        self.assertEqual(transparent._connect_budget(1.0), 5.0)
        self.assertEqual(transparent._connect_budget("12"), 12.0)

    def test_gate_closed_on_zero_and_negative(self):
        for raw in (0, -5, "-1"):
            with self.subTest(raw=raw):
                self.assertEqual(transparent._connect_budget(raw), 0.0)

    def test_garbage_falls_back(self):
        for raw in ("", "abc", None, float("nan")):
            with self.subTest(raw=raw):
                self.assertEqual(transparent._connect_budget(raw), 20.0)

    def test_loaded_constants_are_in_range(self):
        # 跨进程一致性：进程里真正生效的那两个值必须落在同一口径内。
        self.assertTrue(transparent._CONNECT_STALL_S == 0.0
                        or transparent._CONNECT_STALL_S >= 5.0)
        if transparent._CONNECT_STALL_S == 0.0:
            self.assertFalse(transparent._CONNECT_KILL)


if __name__ == "__main__":
    unittest.main()
