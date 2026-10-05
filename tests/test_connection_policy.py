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
        self.conn = connection.Server(address=("secret.internal", 443))
        self.data = SimpleNamespace(server=self.conn, conn=self.conn)

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


if __name__ == "__main__":
    unittest.main()
