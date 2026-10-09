"""Bounded, local connection evidence and shared policy validation.

An absent policy retains legacy transport behavior. Normalization describes the
requested defaults; it does NOT claim enforcement. Until P1 passes its transport
compatibility gate, any explicit policy is rejected by validation. Call validation
on the original value, before persisting configuration or stopping a live proxy.
"""
from __future__ import annotations

from collections import OrderedDict
from types import MappingProxyType
import math
import time
import uuid
import weakref

try:
    from . import mitm_transport_adapter as adapter
except ImportError:  # Source-side mitmdump loads engine modules as top-level files.
    import mitm_transport_adapter as adapter

DEFAULT_CONNECTION_POLICY = {
    "reuse": "default", "idle_ttl_s": None,
    "connect_timeout_s": 15, "tls_handshake_timeout_s": 20,
}
transport_capabilities = adapter.transport_capabilities


def normalize_connection_policy(raw) -> dict:
    if raw is None:
        return dict(DEFAULT_CONNECTION_POLICY)
    if not isinstance(raw, dict):
        raise ValueError("connection_policy must be an object")
    if set(raw) - set(DEFAULT_CONNECTION_POLICY):
        raise ValueError("Unknown connection_policy fields")
    policy = dict(DEFAULT_CONNECTION_POLICY, **raw)
    if policy["reuse"] not in ("default", "never"):
        raise ValueError("connection_policy.reuse must be default or never")
    for key in ("idle_ttl_s", "connect_timeout_s", "tls_handshake_timeout_s"):
        value = policy[key]
        if key == "idle_ttl_s" and value is None:
            continue
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not 1 <= value <= 120 or not math.isfinite(value)):
            raise ValueError(f"connection_policy.{key} must be a finite number from 1 to 120")
    return policy


def validate_connection_policy(raw, http2: bool = True) -> dict:
    policy = normalize_connection_policy(raw)
    if http2 and (policy["reuse"] == "never" or policy["idle_ttl_s"] is not None):
        raise ValueError("Strict reuse/idle TTL policies require HTTP/2 disabled")
    if raw is not None:
        raise ValueError(transport_capabilities()["reason"])
    return policy


class ConnectionGovernance:
    """Event-loop-owned evidence; no timers, socket closure, retries or body access.

    Connection entries and weak flow records are capped. Evicted/missed evidence
    becomes unknown, never an inferred fresh/reused connection. Completed flow
    snapshots live on that flow, not in a global history. Public hooks alone cannot
    prove selection; the compatible adapter supplies pending and selected events.
    """
    def __init__(self, *, max_connections=2048, max_flows=4096, clock=time.monotonic,
                 on_cancel=None):
        self._clock = clock
        # Synchronous event-loop callback (public HTTPFlow, bounded reason).
        # It may signal worker/wakeup events, but must not cancel the hook task:
        # mitmproxy still needs its normal HookCompleted event to drain the queue.
        self.on_cancel = on_cancel
        self._max_connections = max(1, int(max_connections))
        self._max_flows = max(1, int(max_flows))
        self._connections = OrderedDict()
        self._flows = weakref.WeakKeyDictionary()
        self._generation = uuid.uuid4().hex[:12]
        self.observation_errors = 0
        self._evictions = 0
        self._finished = 0
        # 「证据已定论之后才到的客户端 FIN」计数。这类断开不再落 CANCEL 事件
        # （见 flow_cancelled），但必须仍可观测——静默丢弃与「没发生过」无法区分。
        self._cancelled_after_complete = 0
        self._installed = False
        self._capabilities = None

    def running(self):
        self._capabilities = MappingProxyType(transport_capabilities())
        self._installed = adapter.install(self)
        return self._installed

    def done(self):
        adapter.uninstall(self)
        self._installed = False
        self._connections.clear()
        self._flows.clear()
        # Invalidate flow-local callback markers from the previous installation.
        self._generation = uuid.uuid4().hex[:12]

    def _state(self, conn):
        key = str(conn.id)
        if key not in self._connections:
            if len(self._connections) >= self._max_connections:
                self._connections.popitem(last=False)
                self._evictions += 1
            self._connections[key] = {
                "phase": "unknown", "reason": None, "start": None,
                "connect_ms": None, "tls_start": None, "tls_ms": None,
                "selected": 0, "active": set(), "idle_since": None,
                "observed_connect": False, "activity_incomplete": False,
                "killed": False, "kill_tries": 0, "address": None, "peer": None,
            }
        self._connections.move_to_end(key)
        return self._connections[key]

    def request_started(self, flow, upstream=None):
        if flow in self._flows:
            return
        raw = upstream.get("connection_policy") if isinstance(upstream, dict) else None
        validate_connection_policy(raw)
        if len(self._flows) >= self._max_flows:
            # No retained flow object; dropped records degrade evidence only.
            old = next(iter(self._flows))
            self._release(self._flows.pop(old), idle=False)
            self._evictions += 1
        self._flows[flow] = {
            "token": uuid.uuid4().hex, "conn": None, "phase": "unknown",
            "reason": None, "reused": None, "idle_s": None,
            "selected": False, "started": self._clock(), "protocol": "unknown",
            "via_proxy": None,
        }
        flow.metadata.pop("_maskit_transport", None)
        # Lifetime follows the flow, not the bounded connection-evidence table.
        # A response hook may finish evidence while its AUX jobs still need the
        # cancellation signal. Separate observer generations coexist on a flow.
        flow.metadata.setdefault("_maskit_cancel_observers", {})[self._generation] = {
            "reason": None, "phase": None,
        }

    def connection_pending(self, flow, conn):
        record = self._flows.get(flow)
        if record is not None and not record["selected"]:
            record["conn"] = str(conn.id)
            record["phase"] = "connecting"
            record["via_proxy"] = bool(conn.via)
            self._state(conn)

    def connection_selected(self, flow, conn):
        record = self._flows.get(flow)
        state = self._state(conn)
        if record is None:
            # Other requests may share this pool even if the parent does not
            # govern them. Count their actual selection; their activity is unknown.
            state["selected"] += 1
            state["activity_incomplete"] = True
            return
        if record["selected"]:
            return
        record.update(conn=str(conn.id), phase="awaiting_response", selected=True,
                      reused=True if state["selected"] else (False if state["observed_connect"] else None),
                      via_proxy=bool(conn.via))
        if state["selected"] and not state["active"] and not state["activity_incomplete"] and state["idle_since"] is not None:
            record["idle_s"] = max(0, self._clock() - state["idle_since"])
        state["selected"] += 1
        state["active"].add(record["token"])
        owner = weakref.ref(self)
        conn_id, token = record["conn"], record["token"]

        def abandoned(_):
            governance = owner()
            if governance is not None:
                current = governance._connections.get(conn_id)
                if current is not None and token in current["active"]:
                    current["active"].discard(token)
                    current["activity_incomplete"] = True
                    current["idle_since"] = None

        record["flow_ref"] = weakref.ref(flow, abandoned)
        state["idle_since"] = None
        # Bound active identifiers even when a caller drops a flow without error().
        if len(state["active"]) > self._max_flows:
            state["active"].clear()
            state["idle_since"] = None
            state["observed_connect"] = False
            state["activity_incomplete"] = True
        record["protocol"] = {b"h2": "HTTP/2", b"http/1.1": "HTTP/1.1"}.get(conn.alpn, "unknown")

    def connection_selection_failed(self, flow):
        record = self._flows.get(flow)
        if record is not None:
            record["reason"] = "connection_selection_failed"

    def _hook(self, conn, phase, reason=None):
        state = self._state(conn)
        state.update(phase=phase, reason=reason)
        return state

    def server_connect(self, data):
        state = self._hook(data.server, "connecting")
        state.update(start=self._clock(), observed_connect=True)
        # mitmproxy names the task that owns this hop after exactly these two values
        # (`server connection handler <address>`, tagged with the client peername), and
        # `data.server` *is* that command's connection. Capturing them here is what lets
        # the handshake gate find its hop without reading `flow.server_conn` — in regular
        # mode that attribute does not name the connection being established (measured:
        # address/identity mismatch, so the gate fell through to "do not kill").
        server = getattr(data, "server", None)
        client = getattr(data, "client", None)
        address = getattr(server, "address", None)
        peer = getattr(client, "peername", None)
        state["address"] = tuple(address) if address else None
        state["peer"] = tuple(peer) if peer else None

    def server_connected(self, data):
        state = self._hook(data.server, "tcp_connected")
        if state["start"] is not None:
            state["connect_ms"] = max(0, self._clock() - state["start"]) * 1000

    def _failure(self, conn, phase, reason):
        """Record why a hop died — unless we are the reason.

        Cancelling a stalled handshake makes mitmproxy fire `server_connect_error` /
        `tls_failed_server` right afterwards. Those are the *aftereffect* of our cancel;
        keeping `handshake_timeout` is what makes the gate visible in the event log
        exactly when it worked, instead of reading as the upstream's own failure.

        The verdict has to be read before writing: `_hook()` clears `reason` as part of
        the phase transition, so a killed hop would otherwise arrive here as "no reason
        yet" and lose the attribution precisely in the case the gate exists to record.
        The stuck phase is frozen for the same reason — a hop cut during TLS must not
        be relabelled as "connecting".
        """
        state = self._state(conn)
        if state["killed"]:
            return state
        state.update(phase=phase, reason=reason)
        return state

    def server_connect_error(self, data):
        self._failure(data.server, "connecting", "connect_failed")

    def server_disconnected(self, data):
        state = self._state(data.server)
        # Preserve the last failure stage rather than replacing TLS with closed.
        if state["reason"] is None:
            state["reason"] = "server_disconnected"
        state["idle_since"] = None

    def tls_start_server(self, data):
        self._hook(data.conn, "tls_handshake")["tls_start"] = self._clock()

    def tls_established_server(self, data):
        state = self._hook(data.conn, "tls_established")
        if state["tls_start"] is not None:
            state["tls_ms"] = max(0, self._clock() - state["tls_start"]) * 1000

    def tls_failed_server(self, data):
        self._failure(data.conn, "tls_handshake", "tls_failed")

    def responseheaders(self, flow):
        record = self._flows.get(flow)
        if record is not None:
            record["phase"] = "response_stream"
            protocol = getattr(flow.response, "http_version", "unknown")
            if protocol in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"):
                record["protocol"] = protocol

    def _release(self, record, *, idle=True):
        state = self._connections.get(record["conn"])
        if state is not None:
            state["active"].discard(record["token"])
            if not idle:
                state["activity_incomplete"] = True
            if idle and record["selected"] and not state["active"] and not state["activity_incomplete"]:
                state["idle_since"] = self._clock()

    def _finish(self, flow, failed):
        record = self._flows.get(flow)
        if record is None:
            return
        evidence = self.snapshot(flow)
        marker = flow.metadata.get("_maskit_cancel_observers", {}).get(self._generation)
        if marker is not None:
            marker["phase"] = evidence["phase"]
            marker["conn"] = record["conn"]
            # 证据已定论（complete 或 request_failed）。之后客户端再关连接时，
            # `flow_cancelled` 不能把这个事实抹回完成前的 phase。
            marker["settled"] = True
        if failed:
            evidence["reason"] = evidence["reason"] or "request_failed"
        else:
            evidence["phase"] = "complete"
        flow.metadata["_maskit_transport"] = evidence
        self._release(record, idle=not (marker and marker["reason"]))
        del self._flows[flow]
        self._finished += 1

    def flow_cancelled(self, flow, reason):
        """Signal application abandonment once, even after ``response_complete``.

        Adapter calls this before a client protocol error enters Layer's paused
        queue. Public-hook fallbacks may call it too, but cannot provide that
        timing guarantee on unsupported versions. Only this governance's tracked
        flows are eligible; arbitrary messages are mapped to a bounded reason.
        No flow.kill(), task cancellation, connection closure or AUX quota release
        occurs here. The owner of AUX jobs must keep charging running workers until
        they actually exit, and wake/return normally from a cancelled request hook.
        """
        marker = flow.metadata.get("_maskit_cancel_observers", {}).get(self._generation)
        if marker is None or marker["reason"] is not None:
            return
        if not isinstance(reason, str) or reason not in adapter.CANCELLATION_REASONS:
            reason = "client_protocol_error"
        marker["reason"] = reason
        if flow in self._flows:
            self._flows[flow]["reason"] = reason
            self._finish(flow, True)
        else:
            evidence = self.snapshot(flow)
            if marker.get("settled"):
                # 证据已定论后的客户端 FIN：保留原 phase（通常是 complete），只追加
                # 「这次断开发生在收尾之后」。
                # 不再写 `phase=marker["phase"]`——marker 里存的是**完成前**的 phase，
                # 写回去会把「已完成」从证据里抹掉（2026-10-02 实测：同一批 CANCEL
                # 记录全部显示 response_stream，其实响应已交付完毕，无从归因）。
                evidence.update(reason=reason, cancelled_after_complete=True)
                self._cancelled_after_complete += 1
            else:
                evidence.update(reason=reason, phase=marker["phase"] or evidence["phase"])
            flow.metadata["_maskit_transport"] = evidence
            state = self._connections.get(marker.get("conn"))
            if state is not None:
                state["idle_since"] = None
                state["activity_incomplete"] = True
        if self.on_cancel is not None:
            try:
                self.on_cancel(flow, reason)
            except Exception:
                self.observation_errors += 1

    def response_complete(self, flow):
        self._finish(flow, False)

    def error(self, flow):
        self._finish(flow, True)

    # Phases that prove the request never reached the upstream. Once a connection
    # is selected the remaining wait belongs to the model, and a reasoning request
    # may legitimately stay unanswered for minutes, so it is never eligible here.
    PRE_SEND_PHASES = frozenset({"unknown", "connecting", "tcp_connected", "tls_handshake"})
    # A hop we already killed, or one whose matcher could not resolve, is not
    # re-claimed forever: bounded tries keep a persistently ambiguous registry from
    # spinning on the same flow every heartbeat while defaulting to "do not kill".
    MAX_KILL_TRIES = 3

    def stalled_before_send(self, deadline_s):
        """Return ``[(conn_id, phase, address, client_peername)]`` for overruns.

        One entry per **hop**, not per flow: mitmproxy shares a pending connection
        between every request waiting on it, so there is exactly one task to cancel and
        the flows on it all die together through mitmproxy's own error path.

        The clock starts at ``server_connect`` and only a connection that actually
        began establishing qualifies: time spent waiting for masking or for a
        connection slot is local work, not a stalled handshake, and killing it
        would punish a busy gateway instead of a dead path. ``selected`` is set
        only once the connection is usable, so a flow still unselected is by
        definition pre-request — that is what makes a short budget safe for
        reasoning models whose first byte may take minutes.
        """
        if not deadline_s or deadline_s <= 0:
            return []
        now = self._clock()
        stalled = {}
        for record in self._flows.values():
            if record["selected"]:
                continue
            state = self._connections.get(record["conn"])
            if not state or state["start"] is None or state["killed"]:
                continue
            if now - state["start"] < deadline_s:
                continue
            if state["phase"] in self.PRE_SEND_PHASES:
                stalled[record["conn"]] = (record["conn"], state["phase"],
                                           state["address"], state["peer"])
        return list(stalled.values())

    def claim_handshake_kill(self, conn_id):
        """Claim one actuation attempt for this hop; False if it is not ours to take."""
        state = self._connections.get(conn_id)
        if state is None or state["killed"] or state["kill_tries"] >= self.MAX_KILL_TRIES:
            return False
        state["kill_tries"] += 1
        return True

    def confirm_handshake_kill(self, conn_id):
        """Mark the hop as killed, so its reason survives the later FIN."""
        state = self._connections.get(conn_id)
        if state is None:
            return
        state["killed"] = True
        # `server_disconnected` only fills an empty reason (see that hook), so writing
        # ours first is what keeps a killed handshake from being logged as an idle close.
        state["reason"] = "handshake_timeout"

    def snapshot(self, flow) -> dict:
        record = self._flows.get(flow)
        if record is None:
            return dict(flow.metadata.get("_maskit_transport", self._empty()))
        state = self._connections.get(record["conn"])
        result = self._empty()
        result.update(phase=record["phase"], reason=record["reason"], reused=record["reused"],
                      idle_s=record["idle_s"], protocol=record["protocol"], via_proxy=record["via_proxy"])
        if record["conn"] is not None:
            # conn.id is generated locally by mitmproxy, not a remote address.
            result["server_conn_id"] = self._generation + ":" + record["conn"][:64]
        if state is not None:
            result.update(connect_ms=state["connect_ms"], tls_ms=state["tls_ms"])
            if not record["selected"]:
                result["phase"] = state["phase"]
            result["reason"] = (record["reason"] if record["reason"] in adapter.CANCELLATION_REASONS
                                else state["reason"] or result["reason"])
        result["evidence_complete"] = bool(record["selected"] and state is not None and record["reused"] is not None)
        return result

    @staticmethod
    def _empty():
        return {"phase": "unknown", "reason": None, "server_conn_id": None,
                "reused": None, "idle_s": None, "connect_ms": None, "tls_ms": None,
                "protocol": "unknown", "via_proxy": None, "evidence_complete": False,
                "request_written": None}

    def stats(self) -> dict:
        # Polling stats must not rescan package metadata/signatures every time.
        # Refresh on running(); callers get a copy, not the immutable cached map.
        if self._capabilities is None:
            self._capabilities = MappingProxyType(transport_capabilities())
        now = self._clock()
        oldest = max((now - r["started"] for r in self._flows.values()), default=0)
        # 窗口内口径（_connections 是 2048 上限的 LRU，evictions>0 时比率会被截断）：
        # sends/handshakes 就是「每个上游握手服务几个请求」，它就是握手故障预算——
        # 实测 1.03，即每次 API 调用都独立赌一次这条链路的丢包。
        states = self._connections.values()
        handshakes = sum(1 for s in states if s["observed_connect"])
        sends = sum(s["selected"] for s in states)
        kills = sum(1 for s in states if s["killed"])
        return {"connections": len(self._connections), "inflight": len(self._flows),
                "finished": self._finished, "evictions": self._evictions,
                "handshakes": handshakes, "sends": sends, "handshake_kills": kills,
                "cancelled_after_complete": self._cancelled_after_complete,
                "observation_errors": self.observation_errors, "timers": 0,
                "oldest_request_age_s": max(0, oldest),
                "observation_installed": self._installed, "capabilities": dict(self._capabilities)}
