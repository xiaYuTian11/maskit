"""Real mitmproxy selection and executable P1 cancellation stop-gate evidence.

No production socket/config/process is touched. Counterexamples use fake local
transport objects, not unreachable public endpoints or timing-sensitive networks.
"""
import asyncio
import re
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import connection, options
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import (
    HttpLayer, HttpStream, HTTPMode, GetHttpConnection, GetHttpConnectionCompleted,
)
from mitmproxy.proxy.server import ConnectionHandler, ConnectionIO
from mitmproxy.proxy import server_hooks
from engine import mitm_transport_adapter as adapter
from engine.connection_policy import ConnectionGovernance
from tests.test_connection_policy import flow_for


class Stream:
    def __init__(self, flow):
        self.flow = flow
        self.received = []

    def handle_event(self, event):
        self.received.append(event)
        yield from ()


@unittest.skipUnless(adapter.transport_capabilities()["observation"], "requires mitmproxy 12.2.3/12.3.1")
class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.g = ConnectionGovernance()
        self.original_get = HttpLayer.get_connection
        self.original_child = HttpLayer.event_to_child
        self.original_stream = HttpStream.handle_event
        self.original_stream_local = HttpStream.__dict__.get("handle_event")
        self.assertTrue(self.g.running())
        client = connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2))
        self.context = Context(client, options.Options())
        self.layer = HttpLayer(self.context, HTTPMode.regular)

    def tearDown(self):
        self.g.done()

    def request(self, conn):
        flow = flow_for(conn)
        self.g.request_started(flow)
        stream = Stream(flow)
        event = GetHttpConnection(conn.address, conn.tls, conn.via, conn.transport_protocol)
        self.layer.command_sources[event] = stream
        return flow, stream, event

    def test_pool_actual_selection_not_request_server(self):
        conn = connection.Server(address=("private", 80))
        conn.state = connection.ConnectionState.OPEN
        self.layer.connections[conn] = object()
        flow, stream, event = self.request(connection.Server(address=conn.address))
        before = flow.request.raw_content
        self.assertEqual(list(self.layer.get_connection(event)), [])
        self.assertIs(stream.received[0].reply[0], conn)
        self.assertTrue(self.g.snapshot(flow)["server_conn_id"].endswith(str(conn.id)))
        self.assertEqual(flow.request.raw_content, before)
        self.g.response_complete(flow)
        second, _, command = self.request(conn)
        list(self.layer.get_connection(command))
        self.assertTrue(self.g.snapshot(second)["reused"])

    def test_connected_context_even_reuse_false(self):
        conn = self.context.server
        conn.address = ("private", 80)
        conn.state = connection.ConnectionState.OPEN
        flow, stream, event = self.request(conn)
        list(self.layer.get_connection(event, reuse=False))
        self.assertIs(stream.received[0].reply[0], conn)
        self.assertIn(conn, self.layer.connections)
        self.assertTrue(self.g.snapshot(flow)["server_conn_id"].endswith(str(conn.id)))
        # This executable counterexample is why reuse=False is not advertised
        # as a strict isolation policy, even with HTTP/1.1.

    def test_pending_shared_waiter_observed_without_commands(self):
        conn = connection.Server(address=("private", 80))
        self.layer.connections[conn] = object()
        self.layer.waiting_for_establishment[conn] = []
        flows = []
        for _ in range(2):
            flow, _, event = self.request(conn)
            flows.append(flow)
            self.assertEqual(list(self.layer.get_connection(event)), [])
            self.assertIn(event, self.layer.waiting_for_establishment[conn])
            self.assertTrue(self.g.snapshot(flow)["server_conn_id"].endswith(str(conn.id)))
        self.assertEqual(len(self.layer.waiting_for_establishment[conn]), 2)
        self.g.server_connect(SimpleNamespace(server=conn))
        self.g.server_connect_error(SimpleNamespace(server=conn))
        for flow in flows:
            self.assertEqual(self.g.snapshot(flow)["reason"], "connect_failed")

    def test_equal_connection_specs_do_not_confuse_pending_identity(self):
        first, _, event1 = self.request(connection.Server(address=("private", 80)))
        first_commands = list(self.layer.get_connection(event1, reuse=False))
        second, _, event2 = self.request(connection.Server(address=("private", 80)))
        second_commands = list(self.layer.get_connection(event2, reuse=False))
        self.assertEqual(event1, event2)  # dataclass equality is NOT waiter identity.
        opens = [[c.connection for c in output if isinstance(c, commands.OpenConnection)][0]
                 for output in (first_commands, second_commands)]
        self.assertIsNot(opens[0], opens[1])
        for flow, conn in zip((first, second), opens):
            self.assertTrue(self.g.snapshot(flow)["server_conn_id"].endswith(str(conn.id)))

    def test_new_connection_pending_before_open_hook(self):
        flow, _, event = self.request(connection.Server(address=("private", 80)))
        output = list(self.layer.get_connection(event))
        opens = [command for command in output if isinstance(command, commands.OpenConnection)]
        self.assertEqual(len(opens), 1)
        selected = opens[0].connection
        self.assertTrue(self.g.snapshot(flow)["server_conn_id"].endswith(str(selected.id)))

    def test_multiobserver_idempotence_and_uninstall(self):
        wrapped = HttpLayer.get_connection
        stream_wrapper = HttpStream.handle_event
        self.g.running()
        other = ConnectionGovernance()
        other.running()
        self.assertIs(HttpLayer.get_connection, wrapped)
        self.g.done()
        self.assertIs(HttpLayer.get_connection, wrapped)
        self.assertIs(HttpStream.handle_event, stream_wrapper)
        other.done()
        other.done()
        self.assertIs(HttpLayer.get_connection, self.original_get)
        self.assertIs(HttpLayer.event_to_child, self.original_child)
        self.assertIs(HttpStream.handle_event, self.original_stream)
        self.assertIs(HttpStream.__dict__.get("handle_event"), self.original_stream_local)

    def test_foreign_instrumentation_survives_uninstall_and_reinstall(self):
        from tests.test_stream_cancellation import HTTPDriver
        old_get, old_child, old_stream = HttpLayer.get_connection, HttpLayer.event_to_child, HttpStream.handle_event

        def foreign_get(self, event, *, reuse=True):
            return (yield from old_get(self, event, reuse=reuse))

        def foreign_child(self, child, event):
            return (yield from old_child(self, child, event))

        def foreign_stream(self, event):
            return (yield from old_stream(self, event))

        with patch.object(HttpLayer, "get_connection", foreign_get), \
                patch.object(HttpLayer, "event_to_child", foreign_child), \
                patch.object(HttpStream, "handle_event", foreign_stream):
            self.g.done()
            self.assertIs(HttpLayer.get_connection, foreign_get)
            self.assertIs(HttpLayer.event_to_child, foreign_child)
            self.assertIs(HttpStream.handle_event, foreign_stream)
            self.g.running()
            driver = HTTPDriver()
            hook = driver.request()
            self.g.request_started(hook.flow)
            with patch.object(self.g, "flow_cancelled", wraps=self.g.flow_cancelled) as signal:
                driver.disconnect()
            self.assertEqual(signal.call_count, 1)  # dormant old wrapper cannot double-notify
            self.g.done()
            self.assertIs(HttpLayer.get_connection, foreign_get)
            self.assertIs(HttpLayer.event_to_child, foreign_child)
            self.assertIs(HttpStream.handle_event, foreign_stream)
        # patch restores the original adapter wrappers; restore the pre-test methods.
        HttpLayer.get_connection = self.original_get
        HttpLayer.event_to_child = self.original_child
        if self.original_stream_local is None:
            del HttpStream.handle_event
        else:
            HttpStream.handle_event = self.original_stream_local

    def test_stream_wrapper_send_throw_close_return(self):
        self.g.done()
        final = []

        def source(self, event):
            try:
                value = yield event
                try:
                    yield value
                except ValueError:
                    yield "caught"
                return 42
            finally:
                final.append(True)

        with patch.object(HttpStream, "handle_event", source):
            self.g.running()
            try:
                event = events.Start()
                generator = HttpStream.handle_event(object(), event)
                self.assertIs(next(generator), event)
                self.assertEqual(generator.send("sent"), "sent")
                self.assertEqual(generator.throw(ValueError("test")), "caught")
                with self.assertRaises(StopIteration) as stopped:
                    next(generator)
                self.assertEqual(stopped.exception.value, 42)
                second = HttpStream.handle_event(object(), event)
                next(second)
                second.close()
                self.assertEqual(final, [True, True])
            finally:
                self.g.done()

    def test_observer_failure_cannot_change_command_stream(self):
        conn = connection.Server(address=("private", 80))
        conn.state = connection.ConnectionState.OPEN
        self.layer.connections[conn] = object()
        _, stream, event = self.request(conn)
        with patch.object(self.g, "connection_selected", side_effect=RuntimeError("diagnostics")):
            self.assertEqual(list(self.layer.get_connection(event)), [])
        self.assertEqual(self.g.observation_errors, 1)
        self.assertIs(stream.received[0].reply[0], conn)

    def test_h2_native_selection_unchanged(self):
        conn = connection.Server(address=("private", 443))
        conn.state = connection.ConnectionState.OPEN
        conn.tls = True
        conn.alpn = b"h2"
        self.layer.connections[conn] = object()
        self.context.client.alpn = b"h2"
        flows = []
        for _ in range(2):
            flow, stream, event = self.request(conn)
            flows.append(flow)
            self.assertEqual(list(self.layer.get_connection(event)), [])
            self.assertIs(stream.received[0].reply[0], conn)
            self.assertEqual(self.g.snapshot(flow)["protocol"], "HTTP/2")
        self.assertTrue(self.g.snapshot(flows[1])["reused"])
        self.assertIsNone(self.g.snapshot(flows[1])["idle_s"])

    def test_via_spec_does_not_match_another_route(self):
        direct = connection.Server(address=("private", 80))
        direct.state = connection.ConnectionState.OPEN
        self.layer.connections[direct] = object()
        via = connection.Server(address=direct.address)
        via.via = ("http", ("127.0.0.1", 43210))
        flow, _, event = self.request(via)
        commands_out = list(self.layer.get_connection(event))
        self.assertTrue(commands_out)
        self.assertNotEqual(self.g.snapshot(flow)["server_conn_id"],
                            self.g._generation + ":" + str(direct.id))
        self.assertTrue(self.g.snapshot(flow)["via_proxy"])

    def test_unknown_stream_interface_disables_only_cancellation_bridge(self):
        self.g.done()

        def unknown_interface(self, event, extra=None):
            yield from ()

        with patch.object(HttpStream, "handle_event", unknown_interface):
            try:
                self.assertTrue(self.g.running())
                self.assertIs(HttpStream.handle_event, unknown_interface)
                self.assertFalse(self.g.stats()["capabilities"]["stream_cancellation"])
                self.assertIn("incomplete", self.g.stats()["capabilities"]["stream_cancellation_reason"])
            finally:
                self.g.done()
            self.assertIs(HttpStream.handle_event, unknown_interface)

    def test_unknown_version_no_global_patch(self):
        self.g.done()
        with patch.object(adapter, "version", return_value="999.0"):
            self.assertFalse(self.g.running())
            self.assertIs(HttpLayer.get_connection, self.original_get)
            self.assertIs(HttpStream.handle_event, self.original_stream)
            capabilities = self.g.stats()["capabilities"]
            self.assertFalse(capabilities["stream_cancellation"])
            self.assertIn("public hooks alone are incomplete", capabilities["stream_cancellation_reason"])
            conn = connection.Server(address=("private", 80))
            self.g.server_connect(SimpleNamespace(server=conn))
            self.assertEqual(self.g.stats()["connections"], 1)


class GeneratorDelegationTests(unittest.TestCase):
    def test_send_throw_close_and_return_preserved(self):
        observed, final = [], []

        def source():
            try:
                value = yield "first"
                try:
                    yield value
                except ValueError:
                    yield "caught"
                return 42
            finally:
                final.append(True)

        def wrapped():
            return (yield from adapter._ObservedCommands(source(), lambda: observed.append(True)))

        generator = wrapped()
        self.assertEqual(next(generator), "first")
        self.assertEqual(generator.send("sent"), "sent")
        self.assertEqual(generator.throw(ValueError("test")), "caught")
        with self.assertRaises(StopIteration) as stopped:
            next(generator)
        self.assertEqual(stopped.exception.value, 42)
        self.assertEqual(len(observed), 3)
        self.assertEqual(final, [True])
        second = wrapped()
        next(second)
        second.close()
        self.assertEqual(final, [True, True])


class FakeWriter:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, name):
        return ("127.0.0.1", 43210)

    def close(self):
        self.closed = True


class ProbeHandler(ConnectionHandler):
    """Exercise unmodified open_connection without starting a proxy or socket."""
    def __init__(self):
        self.client = connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2))
        self.transports = {}
        self.max_conns = defaultdict(lambda: asyncio.Semaphore(5))
        self.seen = []
        self.hooks = []
        self.connected_entered = asyncio.Event()
        self.hold_connected_hook = False

    def log(self, *args, **kwargs):
        pass

    async def handle_hook(self, hook):
        self.hooks.append(hook)
        if isinstance(hook, server_hooks.ServerConnectedHook):
            self.connected_entered.set()
            if self.hold_connected_hook:
                await asyncio.Event().wait()

    async def server_event(self, event):
        self.seen.append(event)


@unittest.skipUnless(adapter.transport_capabilities()["version"] in adapter.SUPPORTED_VERSIONS, "12.2.3/12.3.1 cancellation contract")
class CancellationFeasibilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_semaphore_wait_does_not_unblock_open_waiter(self):
        handler = ProbeHandler()
        conn = connection.Server(address=("127.0.0.1", 43210))
        handler.max_conns[conn.address] = asyncio.Semaphore(0)
        command = commands.OpenConnection(conn)
        task = asyncio.create_task(handler.open_connection(command))
        handler.transports[conn] = ConnectionIO(handler=task)
        await asyncio.sleep(0)
        handler.close_connection(conn)
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(any(isinstance(h, server_hooks.ServerConnectHook) for h in handler.hooks))
        self.assertFalse(any(isinstance(e, events.OpenConnectionCompleted) for e in handler.seen))
        # The OpenConnection command remains unresolved; a generic cancel timer
        # would hang the HTTP waiter and retain this transport entry.
        self.assertIn(conn, handler.transports)

    async def test_cancel_connected_hook_leaves_installed_writer_unclosed(self):
        handler = ProbeHandler()
        handler.hold_connected_hook = True
        conn = connection.Server(address=("127.0.0.1", 43210))
        command = commands.OpenConnection(conn)
        writer = FakeWriter()
        with patch("mitmproxy.proxy.server.asyncio.open_connection", return_value=(object(), writer)):
            task = asyncio.create_task(handler.open_connection(command))
            handler.transports[conn] = ConnectionIO(handler=task)
            await asyncio.wait_for(handler.connected_entered.wait(), 1)
            handler.close_connection(conn)
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(writer.closed)
        self.assertIn(conn, handler.transports)
        self.assertFalse(any(isinstance(e, events.OpenConnectionCompleted) for e in handler.seen))
        self.assertFalse(any(isinstance(h, server_hooks.ServerDisconnectedHook) for h in handler.hooks))
        writer.close()  # Explicit cleanup of our fake, not production code.


class RequirementsDriftTests(unittest.TestCase):
    """G602/G603：requirements 锁定的 mitmproxy 版本必须已过适配器版本门。

    2026-11-05 事故链：Brotli==1.2.1（CVE 修复）与 mitmproxy 12.2.3 的 <=1.2.0
    互斥，本地 venv 共存态掩盖冲突，推送后 CI 装依赖直接红。这条测试防的是
    另一半：requirements 升了 mitmproxy、适配器的 SUPPORTED_VERSIONS 没跟上
    —— 干净安装能过、单测也绿，但 transport_capabilities() 全 False，连接
    观测与流取消整体哑火（降级不崩，没人会立刻发现）。
    """

    def _requirements(self):
        return (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")

    # Case G602 requirements 锁定的 mitmproxy 版本必须已过适配器版本门（SUPPORTED_VERSIONS）
    def test_pinned_mitmproxy_is_gate_verified(self):
        m = re.search(r"^mitmproxy==(\S+)", self._requirements(), re.MULTILINE)
        self.assertIsNotNone(
            m, "MASK_5043：requirements.txt 必须精确锁定 mitmproxy（浮动范围配不上版本门）")
        self.assertIn(
            m.group(1), adapter.SUPPORTED_VERSIONS,
            "MASK_5042：requirements 锁定 %s 未过适配器版本门；先跑签名探测与真驱动"
            "取消测试再扩 SUPPORTED_VERSIONS" % m.group(1))

    # Case G603 直接 import 的第三方库必须在 requirements 里显式声明（干净安装可解析）
    def test_direct_imports_are_explicitly_declared(self):
        reqs = self._requirements()
        self.assertRegex(
            reqs, r"(?m)^backports\.zstd==",
            "MASK_5043：body_buffer 直接 import backports.zstd，必须显式声明")
        self.assertRegex(
            reqs, r"(?m)^Brotli==",
            "MASK_5043：Brotli 必须显式声明（不再由 mitmproxy 12.3.1 传递约束兼容）")


if __name__ == "__main__":
    unittest.main()
