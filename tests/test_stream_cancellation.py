"""12.2.3 real HttpLayer/HttpStream cancellation; no sockets or mocks of dispatch."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import h2.config
import h2.connection
import h2.errors
from mitmproxy import connection, http
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import (
    ErrorCode, HTTPMode, HttpLayer, HttpStream, HttpErrorHook,
    HttpRequestHeadersHook, HttpRequestHook, HttpResponseHeadersHook, HttpResponseHook,
    RequestProtocolError, ResponseProtocolError,
)
from engine import mitm_transport_adapter as adapter
from engine.connection_policy import ConnectionGovernance


class HTTPDriver:
    """Deliver actual wire bytes and HookCompleted through the real layer tree."""
    body = b"masked-body"

    def __init__(self, use_h2=False):
        self.client = connection.Client(peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2))
        self.client.state = connection.ConnectionState.OPEN
        self.client.alpn = b"h2" if use_h2 else b"http/1.1"
        opts = SimpleNamespace(
            proxy_debug=False, validate_inbound_headers=True, keep_host_header=False,
            stream_large_bodies=None, body_size_limit=None, store_streamed_bodies=False,
            websocket=False, rawtcp=False, connection_strategy="lazy", http2=True,
            normalize_outbound_headers=True,
        )
        self.layer = HttpLayer(Context(self.client, opts), HTTPMode.regular)
        self.commands = []
        self.dispatch(events.Start())
        self.peer = None
        if use_h2:
            self.peer = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
            self.peer.initiate_connection()
            self.dispatch(events.DataReceived(self.client, self.peer.data_to_send()))

    def dispatch(self, event):
        output = list(self.layer.handle_event(event))
        self.commands.extend(output)
        return output

    @staticmethod
    def hook(output, cls):
        return next(command for command in output if isinstance(command, cls))

    def request(self, stream_id=1):
        if self.peer is None:
            raw = b"POST http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 11\r\n\r\n" + self.body
        else:
            self.peer.send_headers(stream_id, [
                (":method", "POST"), (":scheme", "https"),
                (":authority", "example.invalid"), (":path", "/"),
                ("content-length", "11"),
            ])
            self.peer.send_data(stream_id, self.body, end_stream=True)
            raw = self.peer.data_to_send()
        received = events.DataReceived(self.client, raw)
        headers = self.hook(self.dispatch(received), HttpRequestHeadersHook)
        assert received.data == raw
        return self.hook(self.dispatch(events.HookCompleted(headers)), HttpRequestHook)

    def response_hook(self, request):
        request.flow.response = http.Response.make(200, b"restored-body")
        headers = self.hook(self.dispatch(events.HookCompleted(request)), HttpResponseHeadersHook)
        return self.hook(self.dispatch(events.HookCompleted(headers)), HttpResponseHook)

    def disconnect(self, stream_id=1, code=h2.errors.ErrorCodes.CANCEL):
        if self.peer is None:
            self.client.state = connection.ConnectionState.CLOSED
            return self.dispatch(events.ConnectionClosed(self.client))
        self.peer.reset_stream(stream_id, error_code=code)
        raw = self.peer.data_to_send()
        event = events.DataReceived(self.client, raw)
        output = self.dispatch(event)
        assert event.data == raw
        return output


@unittest.skipUnless(adapter.transport_capabilities()["stream_cancellation"], "requires mitmproxy 12.2.3")
class StreamCancellationTests(unittest.TestCase):
    def setUp(self):
        self.signals = []
        self.g = ConnectionGovernance(on_cancel=lambda flow, reason: self.signals.append((flow, reason)))
        self.assertTrue(self.g.running())

    def tearDown(self):
        self.g.done()

    def test_h1_request_signal_precedes_hook_completion_and_event_queue(self):
        driver = HTTPDriver()
        request = driver.request()
        flow = request.flow
        self.g.request_started(flow)
        stream = driver.layer.streams[1]
        self.assertIsInstance(stream, HttpStream)
        before = flow.request.get_state()
        seen = []
        self.g.on_cancel = lambda f, r: seen.append((f, r, stream._paused.command, tuple(stream._paused_event_queue)))
        output = driver.disconnect()
        self.assertEqual(seen, [(flow, "client_disconnected", request, ())])
        self.assertEqual(output, [])
        self.assertIsNone(flow.error)
        self.assertIs(stream._paused.command, request)
        self.assertIsInstance(stream._paused_event_queue[0], RequestProtocolError)
        self.assertEqual(flow.request.get_state(), before)
        resumed = driver.dispatch(events.HookCompleted(request))
        error = driver.hook(resumed, HttpErrorHook)
        driver.dispatch(events.HookCompleted(error))
        self.assertIsNone(stream._paused)
        self.assertFalse(stream._paused_event_queue)
        self.assertFalse(any(isinstance(c, commands.OpenConnection) for c in driver.commands))
        self.assertEqual(len(seen), 1)

    def test_h1_response_hook_disconnect_public_error_is_suppressed(self):
        driver = HTTPDriver()
        request = driver.request()
        self.g.request_started(request.flow)
        response = driver.response_hook(request)
        self.g.responseheaders(response.flow)
        # Evidence may finish while async response-hook AUX work still needs cancel.
        self.g.response_complete(response.flow)
        self.assertEqual(self.g.snapshot(response.flow)["phase"], "complete")
        before = (response.flow.request.get_state(), response.flow.response.get_state())
        driver.disconnect()
        self.assertEqual(self.signals, [(response.flow, "client_disconnected")])
        self.assertIs(driver.layer.streams[1]._paused.command, response)
        self.assertIsNone(response.flow.error)
        self.assertEqual((response.flow.request.get_state(), response.flow.response.get_state()), before)
        driver.dispatch(events.HookCompleted(response))
        self.assertFalse(any(isinstance(c, HttpErrorHook) for c in driver.commands))
        self.assertFalse(driver.layer.streams)
        # 2026-10-02 归因修正：证据已定论（phase=complete）之后才到的客户端 FIN，
        # **不得**把 phase 写回完成前的 response_stream —— 那会把「已完成」从证据里
        # 抹掉，生产日志上表现为一整屏无从归因的 CANCEL（详见 tests/test_cancel_attribution.py）。
        self.assertEqual(self.g.snapshot(response.flow)["phase"], "complete")
        self.assertTrue(self.g.snapshot(response.flow)["cancelled_after_complete"])
        self.assertEqual(self.g.snapshot(response.flow)["reason"], "client_disconnected")
        self.assertEqual(self.g.stats()["finished"], 1)
        self.assertEqual(self.g.stats()["cancelled_after_complete"], 1)

    def test_baseline_late_public_hook_and_suppressed_response_error(self):
        self.g.done()
        for response_phase in (False, True):
            with self.subTest(response_phase=response_phase):
                driver = HTTPDriver()
                hook = driver.request()
                if response_phase:
                    hook = driver.response_hook(hook)
                driver.disconnect()
                self.assertIsNone(hook.flow.error)
                self.assertIs(driver.layer.streams[1]._paused.command, hook)
                self.assertFalse(any(isinstance(c, HttpErrorHook) for c in driver.commands))
                output = driver.dispatch(events.HookCompleted(hook))
                self.assertEqual(any(isinstance(c, HttpErrorHook) for c in output), not response_phase)

    def test_h2_reset_cancels_only_its_stream_preserves_native_connection(self):
        driver = HTTPDriver(use_h2=True)
        first, second = driver.request(1), driver.request(3)
        for hook in (first, second):
            self.g.request_started(hook.flow)
        self.assertEqual(self.signals, [])  # normal END_STREAM is not cancellation
        before = (first.flow.request.get_state(), second.flow.request.get_state())
        driver.disconnect(1)
        self.assertEqual(self.signals, [(first.flow, "client_cancelled")])
        self.assertIs(driver.layer.streams[3]._paused.command, second)
        self.assertFalse(driver.layer.streams[3]._paused_event_queue)
        self.assertEqual((first.flow.request.get_state(), second.flow.request.get_state()), before)
        error = driver.hook(driver.dispatch(events.HookCompleted(first)), HttpErrorHook)
        driver.dispatch(events.HookCompleted(error))
        response = driver.response_hook(second)
        driver.dispatch(events.HookCompleted(response))
        self.assertFalse(any(isinstance(c, commands.CloseConnection) for c in driver.commands))
        self.assertEqual(driver.client.state, connection.ConnectionState.OPEN)
        self.assertFalse(driver.layer.streams)
        self.assertEqual(second.flow.response.raw_content, b"restored-body")

    def test_h2_non_cancel_reset_and_connection_eof_use_bounded_reason(self):
        for code in (h2.errors.ErrorCodes.NO_ERROR, h2.errors.ErrorCodes.HTTP_1_1_REQUIRED, None):
            with self.subTest(code=code):
                driver = HTTPDriver(use_h2=True)
                request = driver.request()
                self.g.request_started(request.flow)
                if code is None:
                    driver.client.state = connection.ConnectionState.CLOSED
                    driver.dispatch(events.ConnectionClosed(driver.client))
                else:
                    driver.disconnect(code=code)
                self.assertEqual(self.signals[-1], (request.flow, "client_protocol_error"))

    def test_non_cancellation_protocol_events_do_not_signal(self):
        driver = HTTPDriver()
        hook = driver.request()
        self.g.request_started(hook.flow)
        stream = driver.layer.streams[1]
        for event in (
            RequestProtocolError(1, "EOF", ErrorCode.PASSTHROUGH_CLOSE),
            ResponseProtocolError(1, "server cancelled", ErrorCode.CANCEL),
            RequestProtocolError(99, "other stream", ErrorCode.CANCEL),
        ):
            self.assertEqual(list(stream.handle_event(event)), [])
        self.assertEqual(self.signals, [])
        self.assertEqual(len(stream._paused_event_queue), 3)

    def test_real_event_notifies_multiple_observers_and_survives_one_uninstall(self):
        other_signals = []
        other = ConnectionGovernance(on_cancel=lambda f, r: other_signals.append((f, r)))
        other.running()
        try:
            driver = HTTPDriver(use_h2=True)
            first, second = driver.request(1), driver.request(3)
            for g in (self.g, other):
                for hook in (first, second):
                    g.request_started(hook.flow)
            driver.disconnect(1)
            self.assertEqual(self.signals, [(first.flow, "client_cancelled")])
            self.assertEqual(other_signals, self.signals)
            self.g.done()
            driver.disconnect(3)
            self.assertEqual(len(self.signals), 1)
            self.assertEqual(other_signals[-1], (second.flow, "client_cancelled"))
        finally:
            other.done()

    def test_callback_exception_does_not_block_native_queue(self):
        driver = HTTPDriver()
        hook = driver.request()
        self.g.request_started(hook.flow)
        with patch.object(self.g, "on_cancel", side_effect=RuntimeError("application observer failed")):
            driver.disconnect()
        self.assertEqual(self.g.observation_errors, 1)
        self.assertIsInstance(driver.layer.streams[1]._paused_event_queue[0], RequestProtocolError)


@unittest.skipUnless(adapter.transport_capabilities()["stream_cancellation"], "requires mitmproxy 12.2.3")
class AsyncHookCompletionTests(unittest.IsolatedAsyncioTestCase):
    async def test_woken_request_hook_returns_normally_then_framework_completes(self):
        wake = asyncio.Event()
        governance = ConnectionGovernance(on_cancel=lambda flow, reason: wake.set())
        governance.running()
        try:
            driver = HTTPDriver(use_h2=True)
            hook = driver.request()
            governance.request_started(hook.flow)
            completed = []

            async def application_request_hook():
                await wake.wait()
                completed.append("returned normally")

            async def framework_hook_runner():
                await application_request_hook()
                return driver.dispatch(events.HookCompleted(hook))

            task = asyncio.create_task(framework_hook_runner())
            await asyncio.sleep(0)
            driver.disconnect()
            self.assertTrue(wake.is_set())
            output = await asyncio.wait_for(task, 1)
            self.assertEqual(completed, ["returned normally"])
            self.assertFalse(task.cancelled())
            error = driver.hook(output, HttpErrorHook)
            driver.dispatch(events.HookCompleted(error))
            self.assertFalse(driver.layer.streams)
        finally:
            governance.done()


if __name__ == "__main__":
    unittest.main()
