import gc
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import connection, http
from engine.connection_policy import (
    ConnectionGovernance, normalize_connection_policy, validate_connection_policy,
    transport_capabilities,
)


PEER = ("127.0.0.1", 4321)
ADDRESS = ("secret.internal", 443)


def hook_data(conn, peer=PEER):
    """`server_connect` 的钩子数据：mitmproxy 真会给 client，熔断要靠它认出这一跳。"""
    return SimpleNamespace(server=conn, conn=conn,
                           client=connection.Client(peername=peer, sockname=("127.0.0.1", 18709)))


def flow_for(conn=None):
    client = connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2))
    flow = http.HTTPFlow(client, conn or connection.Server(address=("private.example", 443)))
    flow.request = http.Request.make("POST", "https://private.example", b"masked-body")
    return flow


class PolicyTests(unittest.TestCase):
    def test_defaults_do_not_imply_enforcement(self):
        self.assertEqual(normalize_connection_policy(None), {
            "reuse": "default", "idle_ttl_s": None,
            "connect_timeout_s": 15, "tls_handshake_timeout_s": 20,
        })
        self.assertEqual(validate_connection_policy(None), normalize_connection_policy(None))
        for raw in ({}, {"reuse": "default"}, {"connect_timeout_s": 15}):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "unavailable"):
                validate_connection_policy(raw)
        self.assertFalse(transport_capabilities()["deadlines"])

    def test_reject_malformed(self):
        for raw in ([], "default", False, {"bogus": 1}, {"reuse": "sometimes"},
                    {"reuse": []}, {"idle_ttl_s": True}, {"connect_timeout_s": None},
                    {"connect_timeout_s": 0}, {"connect_timeout_s": 121},
                    {"tls_handshake_timeout_s": float("nan")}, {"idle_ttl_s": float("inf")}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_connection_policy(raw)

    def test_h2_rejected_before_capability(self):
        for raw in ({"reuse": "never"}, {"idle_ttl_s": 30}):
            with self.assertRaisesRegex(ValueError, "HTTP/2 disabled"):
                validate_connection_policy(raw, http2=True)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                validate_connection_policy(raw, http2=False)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.g = ConnectionGovernance(clock=lambda: self.now, max_connections=4, max_flows=4)
        self.conn = connection.Server(address=ADDRESS)
        self.data = hook_data(self.conn)

    def tearDown(self):
        self.g.done()

    def test_unknown_not_age_inferred(self):
        flow = flow_for(self.conn)
        self.conn.timestamp_start = 1
        self.g.request_started(flow)
        self.assertIsNone(self.g.snapshot(flow)["server_conn_id"])
        self.g.connection_selected(flow, self.conn)
        result = self.g.snapshot(flow)
        self.assertIsNone(result["reused"])
        self.assertIsNone(result["idle_s"])
        self.assertFalse(result["evidence_complete"])

    def test_phases_timings_selection_idle_and_terminal_once(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_pending(flow, self.conn)
        self.g.server_connect(self.data)
        self.now += .25
        self.g.server_connected(self.data)
        self.assertEqual(self.g.snapshot(flow)["phase"], "tcp_connected")
        self.g.tls_start_server(self.data)
        self.now += .5
        self.g.tls_established_server(self.data)
        self.g.connection_selected(flow, self.conn)
        self.g.connection_selected(flow, self.conn)
        result = self.g.snapshot(flow)
        self.assertFalse(result["reused"])
        self.assertEqual(result["connect_ms"], 250)
        self.assertEqual(result["tls_ms"], 500)
        self.assertEqual(result["phase"], "awaiting_response")
        flow.response = http.Response.make(200)
        self.g.responseheaders(flow)
        self.now += 500  # Long legitimate response: there are no stream deadlines.
        self.assertEqual(self.g.snapshot(flow)["phase"], "response_stream")
        self.g.response_complete(flow)
        self.g.error(flow)
        self.assertEqual(self.g.snapshot(flow)["phase"], "complete")
        self.assertEqual(self.g.stats()["finished"], 1)
        self.now += 4
        second = flow_for(self.conn)
        self.g.request_started(second)
        self.g.connection_selected(second, self.conn)
        self.assertTrue(self.g.snapshot(second)["reused"])
        self.assertEqual(self.g.snapshot(second)["idle_s"], 4)

    def test_multiplexing_not_idle(self):
        first, second, third = (flow_for(self.conn) for _ in range(3))
        for flow in (first, second):
            self.g.request_started(flow)
            self.g.connection_selected(flow, self.conn)
        self.g.response_complete(first)
        self.now += 100
        self.g.request_started(third)
        self.g.connection_selected(third, self.conn)
        self.assertIsNone(self.g.snapshot(third)["idle_s"])

    def test_tls_failure_and_redaction(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_pending(flow, self.conn)
        self.g.tls_start_server(self.data)
        self.conn.error = "secret.internal credential=sk-test-000000"
        self.g.tls_failed_server(self.data)
        self.g.server_disconnected(self.data)
        self.g.connection_selection_failed(flow)
        self.g.error(flow)
        result = self.g.snapshot(flow)
        self.assertEqual(result["phase"], "tls_handshake")
        self.assertEqual(result["reason"], "tls_failed")
        self.assertIsNone(result["request_written"])
        serialized = json.dumps(result)
        for secret in ("secret.internal", "private.example", "sk-test", "masked-body"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(flow.request.raw_content, b"masked-body")

    def test_tables_bounded_and_flows_weak(self):
        flows = []
        for _ in range(20):
            conn = connection.Server(address=("private.example", 443))
            flow = flow_for(conn)
            flows.append(flow)
            self.g.request_started(flow)
            self.g.connection_selected(flow, conn)
        self.assertLessEqual(self.g.stats()["connections"], 4)
        self.assertLessEqual(self.g.stats()["inflight"], 4)
        flows.clear()
        del flow
        gc.collect()
        self.assertEqual(self.g.stats()["inflight"], 0)
        self.g.done()
        self.assertEqual(self.g.stats()["connections"], 0)
        self.assertEqual(self.g.stats()["timers"], 0)

    def test_dropped_flows_release_activity_without_inventing_idle(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_selected(flow, self.conn)
        state = self.g._connections[str(self.conn.id)]
        self.assertEqual(len(state["active"]), 1)
        del flow
        gc.collect()
        self.assertEqual(len(state["active"]), 0)
        self.assertTrue(state["activity_incomplete"])
        later = flow_for(self.conn)
        self.g.request_started(later)
        self.g.connection_selected(later, self.conn)
        self.assertTrue(self.g.snapshot(later)["reused"])
        self.assertIsNone(self.g.snapshot(later)["idle_s"])

    def test_untracked_selection_still_counts_for_reuse(self):
        self.g.server_connect(self.data)
        untracked = flow_for(self.conn)
        self.g.connection_selected(untracked, self.conn)
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_selected(flow, self.conn)
        self.assertTrue(self.g.snapshot(flow)["reused"])
        self.assertIsNone(self.g.snapshot(flow)["idle_s"])

    def test_cancel_signal_once_after_evidence_completion_and_bounded_reason(self):
        seen = []
        self.g.on_cancel = lambda flow, reason: seen.append((flow, reason))
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_selected(flow, self.conn)
        flow.response = http.Response.make(200)
        self.g.responseheaders(flow)
        self.g.response_complete(flow)
        self.g.flow_cancelled(flow, "sensitive.example sk-test-000000")
        self.g.flow_cancelled(flow, "client_cancelled")
        self.g.error(flow)
        self.g.response_complete(flow)
        self.assertEqual(seen, [(flow, "client_protocol_error")])
        snapshot = self.g.snapshot(flow)
        # 2026-10-02 归因修正：证据已定论（complete）后的取消**不覆写 phase**，
        # 只追加 cancelled_after_complete（见 tests/test_cancel_attribution.py）。
        self.assertEqual(snapshot["phase"], "complete")
        self.assertTrue(snapshot["cancelled_after_complete"])
        self.assertEqual(snapshot["reason"], "client_protocol_error")
        self.assertEqual(self.g.stats()["finished"], 1)
        self.assertNotIn("sensitive", json.dumps(flow.metadata))

    def test_cancel_active_flow_keeps_stage_and_does_not_invent_idle(self):
        first, second = flow_for(self.conn), flow_for(self.conn)
        self.g.request_started(first)
        self.g.connection_pending(first, self.conn)
        self.g.tls_start_server(self.data)
        self.g.flow_cancelled(first, "client_cancelled")
        self.assertEqual(self.g.snapshot(first)["phase"], "tls_handshake")
        self.assertEqual(self.g.snapshot(first)["reason"], "client_cancelled")
        self.g.request_started(second)
        self.g.connection_selected(second, self.conn)
        self.g.flow_cancelled(second, "client_cancelled")
        state = self.g._connections[str(self.conn.id)]
        self.assertFalse(state["active"])
        self.assertIsNone(state["idle_since"])
        self.assertTrue(state["activity_incomplete"])

    def test_signal_scoped_to_observer_survives_evidence_eviction(self):
        seen = []
        self.g.on_cancel = lambda flow, reason: seen.append(flow)
        flow = flow_for(self.conn)
        self.g.flow_cancelled(flow, "client_cancelled")
        self.assertEqual(seen, [])
        self.g.request_started(flow)
        others = [flow_for(self.conn) for _ in range(5)]
        for other in others:
            self.g.request_started(other)
        self.assertNotIn(flow, self.g._flows)
        self.g.flow_cancelled(flow, "client_cancelled")
        self.assertEqual(seen, [flow])
        self.g.done()
        self.g.flow_cancelled(others[-1], "client_cancelled")
        self.assertEqual(seen, [flow])

    def test_multiple_observers_each_receive_same_flow_once(self):
        seen = []
        other = ConnectionGovernance(on_cancel=lambda flow, reason: seen.append("other"))
        self.g.on_cancel = lambda flow, reason: seen.append("first")
        flow = flow_for(self.conn)
        try:
            for g in (self.g, other):
                g.request_started(flow)
            for g in (self.g, other, self.g, other):
                g.flow_cancelled(flow, "client_cancelled")
            self.assertEqual(seen, ["first", "other"])
        finally:
            other.done()

    def test_capability_snapshot_cached_but_counters_and_installation_live(self):
        with patch("engine.connection_policy.transport_capabilities", wraps=transport_capabilities) as detect:
            first = self.g.stats()
            first["capabilities"]["version"] = "caller mutation"
            self.g.stats()
            self.assertEqual(detect.call_count, 1)
            self.g.running()
            self.assertEqual(detect.call_count, 2)
            self.g.server_connect(self.data)
            self.g.observation_errors += 1
            current = self.g.stats()
            self.assertEqual(detect.call_count, 2)
            self.assertNotEqual(current["capabilities"]["version"], "caller mutation")
            self.assertEqual(current["connections"], 1)
            self.assertEqual(current["observation_errors"], 1)
            self.assertEqual(current["observation_installed"], current["capabilities"]["observation"])
            self.g.done()
            self.assertFalse(self.g.stats()["observation_installed"])
            self.assertEqual(self.g.stats()["connections"], 0)
            self.assertEqual(detect.call_count, 2)
        with patch("engine.mitm_transport_adapter.version", return_value="999.0"):
            self.assertFalse(self.g.running())
        cached = self.g.stats()["capabilities"]
        self.assertEqual(cached["version"], "999.0")
        self.assertFalse(cached["stream_cancellation"])
        self.assertIn("incomplete", cached["stream_cancellation_reason"])

    def test_connection_eviction_does_not_invent_freshness(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.server_connect(self.data)
        self.g.connection_selected(flow, self.conn)
        self.g.response_complete(flow)
        for _ in range(5):
            self.g.server_connect(SimpleNamespace(server=connection.Server(address=("other", 1))))
        second = flow_for(self.conn)
        self.g.request_started(second)
        self.g.connection_selected(second, self.conn)
        self.assertIsNone(self.g.snapshot(second)["reused"])


class StalledBeforeSendTests(unittest.TestCase):
    """`stalled_before_send` 是握手看门狗的唯一判据，必须只认「请求尚未写出」。"""

    def setUp(self):
        self.now = 100.0
        self.g = ConnectionGovernance(clock=lambda: self.now)
        self.conn = connection.Server(address=ADDRESS)
        self.data = hook_data(self.conn)

    def tearDown(self):
        self.g.done()

    def _stuck_in_tls(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_pending(flow, self.conn)
        self.g.server_connect(self.data)
        self.now += 20.0
        self.g.tls_start_server(self.data)
        self.now += 20.0
        return flow

    def _expected(self):
        """熔断的输入是「一跳」而不是「一条流」：地址与客户端连接就是它的身份。"""
        return [(str(self.conn.id), "tls_handshake", ADDRESS, PEER)]

    def test_tls_handshake_past_budget_is_stalled(self):
        self.flow = self._stuck_in_tls()
        self.assertEqual(self.g.stalled_before_send(15.0), self._expected())

    def test_within_budget_is_not_stalled(self):
        # 预算从 server_connect 起算，不是从 request_started，脱敏耗时不吃这份预算。
        self.flow = flow_for(self.conn)
        self.g.request_started(self.flow)
        self.g.connection_pending(self.flow, self.conn)
        self.g.server_connect(self.data)
        self.now += 10.0
        self.g.tls_start_server(self.data)
        self.assertEqual(self.g.stalled_before_send(15.0), [])

    def test_selected_flow_never_qualifies_however_slow(self):
        # 首包可以合法地慢到几分钟（推理模型），这类请求必须完全豁免。
        self.flow = self._stuck_in_tls()
        self.g.connection_selected(self.flow, self.conn)
        self.now += 600.0
        self.assertEqual(self.g.stalled_before_send(15.0), [])

    def test_established_phase_exits_scope(self):
        self.flow = self._stuck_in_tls()
        self.g.tls_established_server(self.data)
        self.assertEqual(self.g.stalled_before_send(15.0), [])

    def test_no_connect_attempt_is_not_killed(self):
        # 排队等脱敏 / 等连接槽位都是本机耗时，不是卡住的握手。
        # 误杀这类请求等于惩罚一台很忙的网关，所以必须完全豁免。
        self.flow = flow_for(self.conn)
        self.g.request_started(self.flow)
        self.now += 600.0
        self.assertEqual(self.g.stalled_before_send(15.0), [])
        pending = flow_for(self.conn)
        self.g.request_started(pending)
        self.g.connection_pending(pending, self.conn)   # 尚无 server_connect
        self.assertEqual(self.g.stalled_before_send(15.0), [])

    def test_budget_disabled_returns_nothing(self):
        self.flow = self._stuck_in_tls()
        for deadline in (0, None, -1):
            with self.subTest(deadline=deadline):
                self.assertEqual(self.g.stalled_before_send(deadline), [])


class HandshakeKillClaimTests(unittest.TestCase):
    """熔断的「一次一跳」记账：落刀权只能被领取一次，且领取失败不产生任何副作用。"""

    def setUp(self):
        self.now = 100.0
        self.g = ConnectionGovernance(clock=lambda: self.now)
        self.conn = connection.Server(address=ADDRESS)
        self.data = hook_data(self.conn)
        self.cid = str(self.conn.id)

    def tearDown(self):
        self.g.done()

    def _stuck(self):
        flow = flow_for(self.conn)
        self.g.request_started(flow)
        self.g.connection_pending(flow, self.conn)
        self.g.server_connect(self.data)
        self.g.tls_start_server(self.data)
        self.now += 30.0
        return flow

    def test_claims_are_bounded_per_hop(self):
        self._stuck()
        tries = ConnectionGovernance.MAX_KILL_TRIES
        self.assertEqual([self.g.claim_handshake_kill(self.cid) for _ in range(tries + 2)],
                         [True] * tries + [False] * 2)

    def test_unknown_hop_is_never_claimed(self):
        self.assertFalse(self.g.claim_handshake_kill("no-such-connection"))

    def test_confirm_drops_the_hop_out_of_the_candidate_set(self):
        # 没有这一条，每个心跳都会对同一跳重复落刀（重复 cancel 会打乱 mitmproxy 的收尾）。
        self._stuck()
        self.assertTrue(self.g.claim_handshake_kill(self.cid))
        self.g.confirm_handshake_kill(self.cid)
        self.assertEqual(self.g.stalled_before_send(15.0), [])
        self.assertFalse(self.g.claim_handshake_kill(self.cid))
        self.assertEqual(self.g.stats()["handshake_kills"], 1)

    def test_killed_reason_survives_the_aftermath_hooks(self):
        # 取消之后 mitmproxy 一定补报 connect/TLS 失败与 FIN；归因不能被打掉，
        # 否则「闸起过作用」这件事恰好只在它生效时看不见。
        self._stuck()
        self.g.confirm_handshake_kill(self.cid)
        for hook in ("server_connect_error", "tls_failed_server", "server_disconnected"):
            with self.subTest(hook=hook):
                getattr(self.g, hook)(self.data)
                self.assertEqual(self.g._connections[self.cid]["reason"], "handshake_timeout")

    def test_a_hop_we_did_not_kill_still_blames_the_upstream(self):
        # 反向用例：这道豁免不能把真的上游 TLS 失败也吞掉。
        self._stuck()
        self.g.tls_failed_server(self.data)
        self.assertEqual(self.g._connections[self.cid]["reason"], "tls_failed")
        self.g.server_connect_error(self.data)
        self.assertEqual(self.g._connections[self.cid]["reason"], "connect_failed")

    def test_stats_price_the_handshake_tax(self):
        # sends/handshakes 就是「每个握手服务几个请求」，它是这套拓扑的故障预算。
        first = self._stuck()
        self.g.connection_selected(first, self.conn)
        second = flow_for(self.conn)
        self.g.request_started(second)
        self.g.connection_selected(second, self.conn)
        stats = self.g.stats()
        self.assertEqual((stats["handshakes"], stats["sends"]), (1, 2))


if __name__ == "__main__":
    unittest.main()
