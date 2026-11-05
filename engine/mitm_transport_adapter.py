"""Read-only mitmproxy transport observation, isolated behind a version contract.

P1 deliberately stops at the feasibility gate. ``reuse=False`` does not exclude
an already connected context server; pending establishment is shared, and tunneled
TLS connections do not necessarily own a ConnectionHandler transport. Neither
header injection, flow.kill(), nor changing connection.error is a safe substitute
for targeted transport control. No transport, header, body, or retry is modified.
"""
from __future__ import annotations

import inspect
from importlib.metadata import PackageNotFoundError, version
import weakref

# 已通过「接口签名探测 + 真驱动取消测试」双重验证的版本。新版本接入步骤：
# ① 跑 transport_capabilities 的签名探测（下方 observation/stream_cancellation）；
# ② 跑 tests/test_stream_cancellation.py 与 tests/test_native_work_cancellation.py
#   （真实 HttpLayer/HttpStream 驱动，无 dispatch mock）；
# ③ 全绿后才能加进集合。12.3.1 于 2026-11-05 按此流程验证：五个接口签名与
#   ErrorCode 枚举值（1/6/8/10/11）均与 12.2.3 逐项一致，两个测试文件全绿。
# @guard G602 版本门只放行双验证过的版本，不得改成无条件放行
SUPPORTED_VERSIONS = frozenset({"12.2.3", "12.3.1"})
_CONTROL_REASON = (
    "Transport control unavailable: context/pending connection isolation and "
    "targeted tunnel cancellation have not passed the compatibility gate."
)
_observers: weakref.WeakSet = weakref.WeakSet()
_originals = None
_wrappers = None
_INHERITED = object()
CANCELLATION_REASONS = frozenset({
    "client_cancelled", "client_disconnected", "client_protocol_error",
})


def transport_capabilities() -> dict:
    try:
        installed = version("mitmproxy")
    except PackageNotFoundError:
        installed = "unavailable"
    observation = stream_cancellation = False
    if installed in SUPPORTED_VERSIONS:
        try:
            from mitmproxy.proxy.layers.http import HttpLayer, HttpStream, RequestProtocolError, ErrorCode
            observation = (
                tuple(inspect.signature(HttpLayer.get_connection).parameters)
                == ("self", "event", "reuse")
                and tuple(inspect.signature(HttpLayer.event_to_child).parameters)
                == ("self", "child", "event")
            )
            stream_cancellation = observation and (
                tuple(inspect.signature(HttpStream.handle_event).parameters) == ("self", "event")
                and tuple(inspect.signature(RequestProtocolError).parameters)
                == ("stream_id", "message", "code")
                and tuple(getattr(ErrorCode, name).value for name in (
                    "GENERIC_CLIENT_ERROR", "PASSTHROUGH_CLOSE", "HTTP_1_1_REQUIRED",
                    "CLIENT_DISCONNECTED", "CANCEL",
                )) == (1, 6, 8, 10, 11)
            )
        except (ImportError, AttributeError, TypeError, ValueError):
            pass
    return {
        "supported": False,
        "version": installed,
        "reason": _CONTROL_REASON,
        "deadlines": False,
        "http1_reuse_policy": False,
        "observation": observation,
        "observation_reason": None if observation else "Requires mitmproxy 12.2.3/12.3.1 observation interfaces.",
        "stream_cancellation": stream_cancellation,
        "stream_cancellation_reason": None if stream_cancellation else (
            "Requires mitmproxy 12.2.3/12.3.1 HttpStream cancellation interfaces; public hooks "
            "alone are incomplete while hooks are paused or the response hook has run."
        ),
    }


def _notify(method, *args):
    for observer in tuple(_observers):
        try:
            callback = getattr(observer, method, None)
            if callback is not None:
                callback(*args)
        except Exception:
            # Diagnostics must never alter the transport command stream, including
            # observers which implement only part of the optional signal API.
            try:
                observer.observation_errors += 1
            except Exception:
                pass


class _ObservedCommands:
    """PEP 380 delegation with an observation before each outward command."""
    def __init__(self, generator, observe):
        self.generator, self.observe = generator, observe

    def __iter__(self):
        return self

    def _out(self, value):
        self.observe()
        return value

    def __next__(self):
        return self._out(next(self.generator))

    def send(self, value):
        return self._out(self.generator.send(value))

    def throw(self, *args):
        return self._out(self.generator.throw(*args))

    def close(self):
        return self.generator.close()


def install(observer) -> bool:
    """Install once process-wide; observers are weakly held. Event-loop thread only.

    ``flow_cancelled(flow, reason)`` is a synchronous notification before Layer
    buffers the protocol event. Only the public flow and a bounded reason escape;
    observers must not raise or mutate transport state. Hook wakeup/worker shutdown
    is the application's responsibility, not a transport cancellation primitive.
    """
    global _originals, _wrappers
    capabilities = transport_capabilities()
    if not capabilities["observation"]:
        return False
    from mitmproxy.proxy.layers.http import (
        HttpLayer, HttpStream, GetHttpConnectionCompleted, RequestProtocolError, ErrorCode,
    )
    _observers.add(observer)
    if _originals is not None:
        return True
    original_get = HttpLayer.get_connection
    original_child = HttpLayer.event_to_child
    original_stream = HttpStream.handle_event
    local_stream = HttpStream.__dict__.get("handle_event", _INHERITED)
    # In 12.2.3/12.3.1 H2 resets other than CANCEL/HTTP_1_1_REQUIRED, GOAWAY, and
    # connection loss use GENERIC_CLIENT_ERROR. Do not parse their remote message.
    # EOM/END_STREAM and PASSTHROUGH_CLOSE are normal half-close, not cancellation.
    cancellation_codes = {
        ErrorCode.CANCEL: "client_cancelled",
        ErrorCode.CLIENT_DISCONNECTED: "client_disconnected",
        ErrorCode.GENERIC_CLIENT_ERROR: "client_protocol_error",
        ErrorCode.HTTP_1_1_REQUIRED: "client_protocol_error",
    }

    def pending(self, event):
        if _wrappers is None or _wrappers[0] is not get_connection:
            return  # A foreign wrapper may still delegate to an uninstalled one.
        stream = self.command_sources.get(event)
        flow = getattr(stream, "flow", None)
        if flow is not None:
            for conn, waiters in self.waiting_for_establishment.items():
                if any(waiter is event for waiter in waiters):
                    _notify("connection_pending", flow, conn)
                    break

    def get_connection(self, event, *, reuse=True):
        result = yield from _ObservedCommands(
            original_get(self, event, reuse=reuse), lambda: pending(self, event)
        )
        # Joining an existing pending connection emits no command.
        pending(self, event)
        return result

    def event_to_child(self, child, event):
        if (_wrappers is not None and _wrappers[1] is event_to_child
                and isinstance(event, GetHttpConnectionCompleted)):
            flow = getattr(child, "flow", None)
            if flow is not None:
                conn, error = event.reply
                if conn is not None and not error:
                    _notify("connection_selected", flow, conn)
                else:
                    _notify("connection_selection_failed", flow)
        return (yield from original_child(self, child, event))

    def handle_event(self, event):
        if (_wrappers is not None and _wrappers[2] is handle_event
                and isinstance(event, RequestProtocolError)
                and event.stream_id == self.stream_id):
            flow = getattr(self, "flow", None)
            reason = cancellation_codes.get(event.code)
            if flow is not None and reason is not None:
                _notify("flow_cancelled", flow, reason)
        # Real PEP 380 delegation, including send/throw/close and return value.
        # Never consume/rewrite the event, queue, flow.error, socket or h2 state.
        return (yield from original_stream(self, event))

    _originals = (original_get, original_child, local_stream)
    _wrappers = (get_connection, event_to_child,
                 handle_event if capabilities["stream_cancellation"] else None)
    HttpLayer.get_connection = get_connection
    HttpLayer.event_to_child = event_to_child
    if capabilities["stream_cancellation"]:
        HttpStream.handle_event = handle_event
    return True


def uninstall(observer) -> None:
    """Idempotent; do not overwrite instrumentation installed by another addon."""
    global _originals, _wrappers
    _observers.discard(observer)
    if _observers or _originals is None:
        return
    from mitmproxy.proxy.layers.http import HttpLayer, HttpStream
    if HttpLayer.get_connection is _wrappers[0]:
        HttpLayer.get_connection = _originals[0]
    if HttpLayer.event_to_child is _wrappers[1]:
        HttpLayer.event_to_child = _originals[1]
    if _wrappers[2] is not None and HttpStream.handle_event is _wrappers[2]:
        if _originals[2] is _INHERITED:
            del HttpStream.handle_event
        else:
            HttpStream.handle_event = _originals[2]
    _originals = _wrappers = None
