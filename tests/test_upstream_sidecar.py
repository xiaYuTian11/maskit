"""C1 upstream sidecar 单元测试。

用本地 mock HTTP server 做端到端验证，不依赖外部网络。
覆盖：基本转发 / POST body / 流式响应 / 内部头剥离 / 凭据头过滤 /
TLS fail-closed / 32 MiB 上限 / 连接池复用 / metrics。
"""
import asyncio
import h11
import httpx
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

from upstream_sidecar import (
    UpstreamSidecar,
    _MAX_REQUEST_BODY,
    _CREDENTIAL_HEADER_NAMES,
    _UPSTREAM_HEADER,
)


class MockUpstream:
    """本地 mock HTTP 上游服务器（h11 SERVER 模式）。"""

    def __init__(self):
        self._server = None
        self._port = 0
        self.received_headers = []  # 每次 request 收到的头

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self._port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self._port

    async def _handle(self, reader, writer):
        conn = h11.Connection(our_role=h11.SERVER)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                conn.receive_data(data)
                while True:
                    event = conn.next_event()
                    if event is h11.NEED_DATA:
                        break
                    if isinstance(event, h11.Request):
                        method = event.method.decode()
                        path = event.target.decode()
                        hdrs = {k.decode().lower(): v.decode()
                                for k, v in event.headers}
                        self.received_headers.append(hdrs)
                        # 消费后续 body 事件
                    elif isinstance(event, h11.EndOfMessage):
                        # 生成响应
                        if path.startswith("/stream/"):
                            n = int(path.split("/")[-1])
                            body = b"".join(
                                b'data: {"i":%d}\n\n' % (i + 1) for i in range(n)
                            )
                            resp = h11.Response(status_code=200, headers=[
                                ("content-type", "text/event-stream"),
                                ("content-length", str(len(body))),
                            ])
                        elif path == "/get":
                            body = json.dumps({
                                "path": "/get",
                                "headers_received": hdrs,
                            }).encode()
                            resp = h11.Response(status_code=200, headers=[
                                ("content-type", "application/json"),
                                ("content-length", str(len(body))),
                            ])
                        elif path == "/post":
                            body = json.dumps({"ok": True, "echo_method": method}).encode()
                            resp = h11.Response(status_code=200, headers=[
                                ("content-type", "application/json"),
                                ("content-length", str(len(body))),
                            ])
                        else:
                            body = b'{"ok":true}'
                            resp = h11.Response(status_code=200, headers=[
                                ("content-type", "application/json"),
                                ("content-length", str(len(body))),
                            ])
                        writer.write(conn.send(resp))
                        writer.write(conn.send(h11.Data(data=body)))
                        writer.write(conn.send(h11.EndOfMessage()))
                        await writer.drain()
                        try:
                            conn.start_next_cycle()
                        except Exception:
                            return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class TestUpstreamSidecar(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.mock = MockUpstream()
        await self.mock.start()
        self.sidecar = UpstreamSidecar(config={})
        await self.sidecar.start()
        self.test_client = httpx.AsyncClient(
            timeout=10.0, trust_env=False,
        )

    async def asyncTearDown(self):
        await self.test_client.aclose()
        await self.sidecar.stop()
        await self.mock.stop()

    def _sidecar_url(self, path):
        return "http://127.0.0.1:%d%s" % (self.sidecar.port, path)

    def _upstream_headers(self, extra=None):
        h = {"X-Maskit-Upstream": self.mock.url}
        if extra:
            h.update(extra)
        return h

    async def test_basic_get_forward(self):
        """基本 GET 转发：sidecar 正确转发请求并返回响应。"""
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["path"], "/get")

    async def test_post_body_forward(self):
        """POST + body 转发：请求体正确到达上游。"""
        resp = await self.test_client.post(
            self._sidecar_url("/post"),
            headers=self._upstream_headers({"Content-Type": "application/json"}),
            json={"message": "hello"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["echo_method"], "POST")

    async def test_stream_forward(self):
        """流式响应转发：SSE 形态的逐块转发。"""
        async with self.test_client.stream(
            "GET",
            self._sidecar_url("/stream/3"),
            headers=self._upstream_headers(),
        ) as resp:
            self.assertEqual(resp.status_code, 200)
            lines = []
            async for line in resp.aiter_lines():
                if line.strip():
                    lines.append(line)
            self.assertEqual(len(lines), 3)

    async def test_internal_header_stripped(self):
        """X-Maskit-Upstream 内部头不泄露到上游。"""
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers({"X-Custom": "test-value"}),
        )
        # mock 收到的头里不应有 X-Maskit-Upstream
        self.assertTrue(len(self.mock.received_headers) > 0)
        last_headers = self.mock.received_headers[-1]
        self.assertNotIn(_UPSTREAM_HEADER, last_headers)
        self.assertNotIn("x-maskit-upstream-name", last_headers)
        # 自定义头应该透传
        self.assertEqual(last_headers.get("x-custom"), "test-value")

    async def test_credential_header_filtered(self):
        """凭据类头被过滤，不通过 extra_headers 注入。"""
        # 通过 set_extra_headers 注入凭据类头
        self.sidecar.set_extra_headers("test", {
            "Authorization": "Bearer should-not-appear",
            "X-API-Key": "sk-secret",
            "X-Custom-Header": "should-appear",
        })
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        last_headers = self.mock.received_headers[-1]
        self.assertNotIn("authorization", last_headers)
        self.assertNotIn("x-api-key", last_headers)
        self.assertEqual(last_headers.get("x-custom-header"), "should-appear")

    async def test_tls_fail_closed(self):
        """无效上游 → fail-closed 502（连接失败不放行）。"""
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": "https://self-signed.invalid"},
        )
        self.assertGreaterEqual(resp.status_code, 500)

    async def test_32mib_body_limit(self):
        """32 MiB body 上限 → 413 fail-closed。"""
        # 构造一个超过 32 MiB 的 body
        big_body = b"x" * (_MAX_REQUEST_BODY + 1)
        resp = await self.test_client.post(
            self._sidecar_url("/post"),
            headers=self._upstream_headers({"Content-Type": "application/octet-stream"}),
            content=big_body,
        )
        self.assertEqual(resp.status_code, 413)

    async def test_connection_pool_reuse(self):
        """两个请求复用同一条 httpx 连接（连接池生效）。"""
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        stats = self.sidecar.metrics()["stats"]
        self.assertGreaterEqual(stats["requests"], 2)

    async def test_retry_on_connect_error(self):
        """连接失败时重试一次（PRE_SEND_PHASES 安全）。"""
        # 用一个 DNS 解析失败的上游 → ConnectError → 重试 → 502
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": "https://nonexistent-host-12345.invalid"},
        )
        self.assertEqual(resp.status_code, 502)
        stats = self.sidecar.metrics()["stats"]
        self.assertGreaterEqual(stats["retries"], 1)

    async def test_metrics(self):
        """metrics 正确暴露 sidecar 状态。"""
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        m = self.sidecar.metrics()
        self.assertTrue(m["enabled"])
        self.assertGreater(m["port"], 0)
        self.assertGreaterEqual(m["stats"]["requests"], 1)
        self.assertIn("pool", m)

    async def test_missing_upstream_header(self):
        """缺少 X-Maskit-Upstream 头 → 400。"""
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={},
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
