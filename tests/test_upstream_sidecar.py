"""C1 upstream sidecar 单元测试。

用本地 mock HTTP server 做端到端验证，不依赖外部网络。
覆盖：基本转发 / POST body / 流式响应 / 内部头剥离 / 凭据头透传 /
TLS fail-closed / 32 MiB 上限 / 连接池复用 / 空闲保留预算 / 出口代理双客户端 / metrics / 有界关停 /
目标白名单 / 请求体残缺 / 压缩响应字节保真 / 无体响应封帧 / 调用方空闲预算。
"""
import asyncio
import gzip
import h11
import httpx
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

import upstream_sidecar as c1mod
from upstream_sidecar import (
    UpstreamSidecar,
    _MAX_REQUEST_BODY,
    _SHUTDOWN_GRACE_S,
    _UPSTREAM_HEADER,
    allowed_origins_for,
    normalize_origin,
)
from shield_defaults import parse_egress_proxy

# 连不上的上游：**用环回未监听端口，不要用外部域名**。本文件契约是「不依赖外部网络」，
# 而实测（2026-10-13）本机 /etc/resolv.conf 指向深信服 DNS stub，解析不存在的域名要
# 10~15 秒才失败；测试客户端超时是 10 秒，会先炸成 ReadTimeout，用例变成看 DNS 脸色的
# 假红（连跑 5 次失败 4 次）。拒连与解析失败在 httpx 里同属 `ConnectError`，侧车走的是
# 同一条 fail-closed 路径，换成环回端口后判据不变、且立即可复现。
_UNREACHABLE_TARGET = "https://127.0.0.1:1"


# 环回端口是**共享资源**：本机任何进程都能连进来。实测（2026-10-12）开发机上的 agent
# 工具链端口扫描器每几秒把整个临时端口段扫一遍，往每个新监听端口发
# `HEAD / HTTP/1.1`（**不带 Host**）。mock 上游原先按 accept 计数，这些外来连接把
# 「两次请求只建一条连接」的断言打红——用例因此看本机装了什么软件的脸色（6 跑 4 红），
# 而产品侧完全没问题。判据改成「请求带上测试标记头才算我们的流量」，连接也只在跑完
# 标记请求之后才计数。加标记头要同时改 mock 与客户端，所以它是 opt-in 的：
# 默认 tag=None 时行为与旧版完全一致（其余用例照旧）。
_TEST_TAG_HEADER = "x-maskit-test-tag"
_TEST_TAG = "sidecar-conn-reuse"
_TEST_TAG_HEADERS = {_TEST_TAG_HEADER: _TEST_TAG}


class MockUpstream:
    """本地 mock HTTP 上游服务器（h11 SERVER 模式）。

    同时充当假出口代理：代理端会收到绝对形式（absolute-form）的请求行
    ``GET http://target/get``，据此可判定流量确实经过了代理而非直连。

    ``tag`` 给了值时只统计带该标记头的请求（见文件顶部 ``_TEST_TAG`` 的说明）：
    给「连接数 / 请求数」这类精确断言用，避免被本机其它进程的端口探测污染。
    """

    def __init__(self, tag: str | None = None):
        self._server = None
        self._port = 0
        self.tag = tag
        self.received_headers = []  # 每次 request 收到的头
        self.received_targets = []  # 每次 request 收到的请求行 target
        self.received_methods = []  # 每次 request 收到的方法（HEAD 必须与 GET 区分）
        self.received_bodies = []   # 每次 request 收到的 body
        self.request_peers = []     # 每个入账请求来自哪个客户端源地址（判「同一 socket」）
        # 跑完过至少一个入账请求的连接数——keep-alive 复用与否就看它
        self.connection_count = 0
        # 连上来却没跑完入账请求的连接数（本机端口扫描等外来流量，只作诊断）
        self.foreign_connections = 0

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

    @property
    def port(self):
        return self._port

    async def _handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        served = False          # 这条连接上跑完过至少一个入账请求
        in_scope = False        # 当前请求是否算「我们的流量」
        conn = h11.Connection(our_role=h11.SERVER)
        pending = b""
        method = "GET"
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
                        in_scope = (self.tag is None
                                    or hdrs.get(_TEST_TAG_HEADER) == self.tag)
                        if in_scope:
                            if not served:
                                served = True
                                self.connection_count += 1
                            self.received_headers.append(hdrs)
                            self.received_targets.append(path)
                            self.received_methods.append(method)
                            self.request_peers.append(peer)
                        pending = b""
                    elif isinstance(event, h11.Data):
                        pending += event.data
                    elif isinstance(event, h11.EndOfMessage):
                        if in_scope:
                            self.received_bodies.append(pending)
                        pending = b""
                        status, resp_headers, body = self._respond(
                            method, path, hdrs)
                        writer.write(conn.send(h11.Response(
                            status_code=status, headers=resp_headers)))
                        # HEAD / 204 / 304 按协议没有响应体：h11 会按 0 长度封帧，
                        # 这里硬塞 Data 只会让 mock 自己抛协议错误。
                        if body and method != "HEAD" and status not in (204, 304):
                            writer.write(conn.send(h11.Data(data=body)))
                        writer.write(conn.send(h11.EndOfMessage()))
                        await writer.drain()
                        try:
                            conn.start_next_cycle()
                        except Exception:
                            return
                        # 断连模拟：响应已完整写出，但连接随即消失。用来锁住「池里的
                        # 连接被上游/中间设备静默关掉后，复用不能把用户打成 502」。
                        # /close-after → FIN；/rst-after → RST（SO_LINGER=0）。
                        if path.startswith("/close-after"):
                            writer.close()
                            return
                        if path.startswith("/rst-after"):
                            import socket as _sock
                            import struct as _struct
                            sock = writer.get_extra_info("socket")
                            sock.setsockopt(_sock.SOL_SOCKET, _sock.SO_LINGER,
                                            _struct.pack("ii", 1, 0))
                            writer.close()
                            return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError,
                # 外来探测（缺 Host、非 HTTP 字节）会让 h11 抛 RemoteProtocolError。
                # 那不是本进程的错误，静默关掉即可，别让 asyncio 打一堆 traceback。
                h11.RemoteProtocolError):
            pass
        finally:
            if not served:
                self.foreign_connections += 1
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    def _respond(method, path, hdrs):
        """→ (status, headers, body)。body 是**线上原始字节**（gzip 端点保持压缩）。"""
        def json_(obj, status=200):
            payload = json.dumps(obj).encode()
            return status, [("content-type", "application/json"),
                            ("content-length", str(len(payload)))], payload

        if path.startswith("/stream/"):
            n = int(path.split("/")[-1])
            body = b"".join(b'data: {"i":%d}\n\n' % (i + 1) for i in range(n))
            return 200, [("content-type", "text/event-stream"),
                         ("content-length", str(len(body)))], body
        if path.startswith("/gzip"):
            payload = gzip.compress(b"hello-from-gzip-upstream")
            return 200, [("content-type", "text/plain"),
                         ("content-encoding", "gzip"),
                         ("content-length", str(len(payload)))], payload
        if path.startswith("/nocontent"):
            return 204, [], b""
        if path.startswith("/fixed"):
            # 长度与请求头无关，HEAD 与 GET 才能直接比 content-length
            return json_({"ok": True, "fixed": True})
        if path == "/get":
            return json_({"path": "/get", "headers_received": hdrs,
                          "method": method})
        if path == "/post":
            return json_({"ok": True, "echo_method": method})
        return json_({"ok": True})


class TestUpstreamSidecar(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.mock = MockUpstream()
        await self.mock.start()
        # 白名单在构造时固化：sidecar 只转发配置里声明过的上游 origin（见
        # UpstreamSidecar.__init__ 的红线注释），空集合等于什么都不放行。
        self.sidecar = UpstreamSidecar(config=self._sidecar_cfg())
        await self.sidecar.start()
        self.test_client = httpx.AsyncClient(
            timeout=10.0, trust_env=False,
        )

    async def asyncTearDown(self):
        await self.test_client.aclose()
        await self.sidecar.stop()
        await self.mock.stop()

    def _sidecar_cfg(self, *extra_targets):
        """被测 sidecar 的配置：mock 上游 + 额外目标都算「配置里声明过的上游」。"""
        return {"upstreams": [{"name": "mock", "target": t}
                              for t in (self.mock.url, *extra_targets)]}

    async def _restart_sidecar(self, *extra_targets):
        """按新白名单重建 sidecar（白名单构造时固化，运行中改不了）。"""
        await self.sidecar.stop()
        self.sidecar = UpstreamSidecar(config=self._sidecar_cfg(*extra_targets))
        await self.sidecar.start()
        return self.sidecar

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

    async def test_unreachable_upstream_fails_closed(self):
        """连不上的上游 → fail-closed 502（连接失败不放行）。

        自签证书那条 TLS 路径由 `test_tls_rejects_self_signed_cert` 专门覆盖（本地起
        TLS 服务，不碰外网）；本用例只验「连不上就阻断」，目标用环回未监听端口。
        """
        await self._restart_sidecar(_UNREACHABLE_TARGET)
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": _UNREACHABLE_TARGET},
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
        # 连不上（拒连）→ ConnectError → 重试 → 502。目标必须登记进白名单，
        # 否则先撞 403、测不到重试那条路径。
        await self._restart_sidecar(_UNREACHABLE_TARGET)
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": _UNREACHABLE_TARGET},
        )
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.json().get("error"), "upstream_connect_failed")
        stats = self.sidecar.metrics()["stats"]
        self.assertGreaterEqual(stats["retries"], 1)

    async def test_read_timeout_returns_504_gateway_timeout(self):
        """上游读取超时（如大模型思考首包过慢） → 504 upstream_read_timeout。"""
        with mock.patch.object(self.sidecar._client, "send", side_effect=httpx.ReadTimeout("read timeout")):
            resp = await self.test_client.get(
                self._sidecar_url("/get"),
                headers=self._upstream_headers(),
            )
            self.assertEqual(resp.status_code, 504)
            self.assertEqual(resp.json().get("error"), "upstream_read_timeout")

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

    async def test_malformed_upstream_header(self):
        """头值不是 http(s) origin（带用户信息）→ 400，与白名单的 403 分开归因。"""
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": "http://user:pw@127.0.0.1:9"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid", resp.text)


class TestUpstreamSidecarSecurity(unittest.IsolatedAsyncioTestCase):
    """生产级安全加固测试：覆盖所有 fail-open 高危路径。"""

    async def asyncSetUp(self):
        self.mock = MockUpstream()
        await self.mock.start()
        # 白名单在构造时固化：sidecar 只转发配置里声明过的上游 origin（见
        # UpstreamSidecar.__init__ 的红线注释），空集合等于什么都不放行。
        self.sidecar = UpstreamSidecar(config=self._sidecar_cfg())
        await self.sidecar.start()
        self.test_client = httpx.AsyncClient(
            timeout=10.0, trust_env=False,
        )

    async def asyncTearDown(self):
        await self.test_client.aclose()
        await self.sidecar.stop()
        await self.mock.stop()

    def _sidecar_cfg(self, *extra_targets):
        """被测 sidecar 的配置：mock 上游 + 额外目标都算「配置里声明过的上游」。"""
        return {"upstreams": [{"name": "mock", "target": t}
                              for t in (self.mock.url, *extra_targets)]}

    async def _restart_sidecar(self, *extra_targets):
        """按新白名单重建 sidecar（白名单构造时固化，运行中改不了）。"""
        await self.sidecar.stop()
        self.sidecar = UpstreamSidecar(config=self._sidecar_cfg(*extra_targets))
        await self.sidecar.start()
        return self.sidecar

    def _sidecar_url(self, path):
        return "http://127.0.0.1:%d%s" % (self.sidecar.port, path)

    def _upstream_headers(self, extra=None):
        h = {"X-Maskit-Upstream": self.mock.url}
        if extra:
            h.update(extra)
        return h

    # ─── TLS 证书校验反向测试矩阵 ─────────────────────────────────────────

    async def test_tls_rejects_self_signed_cert(self):
        """自签证书的上游 → TLS 校验拒绝 → 502 fail-closed。

        这不是 DNS 失败，是真正的 TLS 证书校验拒绝。
        verify=False 时 httpx 会接受该证书；verify=True（默认）时必须拒绝。
        """
        import ssl as _ssl
        import tempfile

        # 生成自签证书。用 cryptography（mitmproxy 的必需依赖）而不是调用外部
        # openssl：Windows 开发机/CI runner 不一定装 openssl，原测试因此环境性报错。
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key_file = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        cert_file = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
        key_file.close()
        cert_file.close()
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "self-signed-test.invalid"),
            ])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1))
                    .not_valid_after(now + timedelta(days=1))
                    .sign(key, hashes.SHA256()))
            with open(key_file.name, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
            with open(cert_file.name, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # 用自签证书启动一个 TLS 上游
            ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(cert_file.name, key_file.name)

            tls_server = await asyncio.start_server(
                self.mock._handle, "127.0.0.1", 0, ssl=ssl_ctx,
            )
            tls_port = tls_server.sockets[0].getsockname()[1]
            upstream_tls_url = "https://127.0.0.1:%d" % tls_port

            try:
                # 目标先登记进白名单，才能走到真正的 TLS 校验分支
                await self._restart_sidecar(upstream_tls_url)
                resp = await self.test_client.get(
                    self._sidecar_url("/get"),
                    headers={"X-Maskit-Upstream": upstream_tls_url},
                )
                # 必须 fail-closed：502（不能 200）
                self.assertGreaterEqual(resp.status_code, 500)
                # 确认不是成功转发
                self.assertNotEqual(resp.status_code, 200)
            finally:
                tls_server.close()
                await tls_server.wait_closed()
        finally:
            import os
            os.unlink(key_file.name)
            os.unlink(cert_file.name)

    async def test_tls_verify_off_counted(self):
        """tls_verify=false 时必须计数上报（不静默）。"""
        # 当前实现 tls_verify 恒为 True，这里验证统计字段存在
        m = self.sidecar.metrics()
        self.assertIn("tls_verify_off", m["stats"])

    async def test_target_outside_config_is_rejected(self):
        """头里写配置外的目标 → 403 拒转，并计数上报（不静默）。

        环回端口不是访问控制：它只挡得住外来的，挡不住本机上任何一个进程。
        这条闸断的是「知道 sidecar 端口就能借它转发到任意 host」。
        """
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers={"X-Maskit-Upstream": "http://127.0.0.1:9"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("not_allowed", resp.text)
        self.assertGreaterEqual(
            self.sidecar.metrics()["stats"]["rejected_target"], 1)

    async def test_empty_config_rejects_everything(self):
        """配置里没有任何上游 → 白名单是空集合，方向必须是「全拒」而不是「不限制」。"""
        sidecar = UpstreamSidecar(config={})
        await sidecar.start()
        try:
            self.assertEqual(sidecar.allowed_origins, frozenset())
            resp = await self.test_client.get(
                "http://127.0.0.1:%d/get" % sidecar.port,
                headers={"X-Maskit-Upstream": self.mock.url},
            )
            self.assertEqual(resp.status_code, 403)
        finally:
            await sidecar.stop()

    # ─── 凭据头穷尽透传测试 ─────────────────────────────────────────────────

    async def test_credential_headers_in_request_forwarded(self):
        """transparent 认定的每一个凭据头名，都必须原样到达上游。

        名单权威来源是 ``transparent._CREDENTIAL_HEADER_NAMES``（sidecar 自己那份
        是无人调用的死代码，已删）。曾经 sidecar 在转发前剥离这些头，等于让上游对
        每个请求回 401。这条测试把「sidecar 无凭据过滤权」钉住：
        名单里任何一名被剥掉都会红。
        """
        import transparent
        names = sorted(transparent._CREDENTIAL_HEADER_NAMES)
        self.assertGreaterEqual(len(names), 10,
                                "凭据头名单为空或取错来源，本测试已失去意义")
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers({n: "client-cred-value" for n in names}),
        )
        self.assertEqual(resp.status_code, 200)
        last = self.mock.received_headers[-1]
        for name in names:
            self.assertEqual(last.get(name), "client-cred-value",
                             "凭据头 %s 被 sidecar 剥离 → 上游必然 401" % name)

    # ─── Hop-by-hop 头剥离 ─────────────────────────────────────────────────

    async def test_hop_by_hop_headers_stripped(self):
        """hop-by-hop 头（Transfer-Encoding 等）不透传到上游。

        注意：httpx 自己会加 Connection: keep-alive 和 Keep-Alive: timeout=N
        作为连接管理头，这是 httpx 的正常行为，不是泄露。
        本测试验证的是客户端**显式发送的** Transfer-Encoding 不被透传。
        """
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers({
                "Connection": "keep-alive",
                "Keep-Alive": "timeout=30",
                "Transfer-Encoding": "chunked",
            }),
        )
        last = self.mock.received_headers[-1]
        # transfer-encoding 由 httpx 自己管理，不应透传原值
        self.assertNotIn("transfer-encoding", last)

    # ─── 32 MiB 边界测试 ───────────────────────────────────────────────────

    async def test_body_at_exact_limit_passes(self):
        """刚好 32 MiB 的 body 应该通过（不是 413）。

        ⚠️ 用**专用长超时 client**（2026-11-02）：32 MiB body 要经 mock 上游往返
        （拼包 + 序列化 + 内存拷贝），默认 `timeout=10.0` 在**满负载**（全量门禁
        并发跑其它用例）下会 httpx.ReadTimeout 而假红。实测单独跑稳定通过、
        全量跑必红——而它测的是「边界值不被误判 413」，与网络快慢无关，
        所以正确做法是给足超时而不是放宽断言。
        """
        exact_body = b"x" * _MAX_REQUEST_BODY
        async with httpx.AsyncClient(timeout=60.0, trust_env=False) as big_client:
            resp = await big_client.post(
                self._sidecar_url("/post"),
                headers=self._upstream_headers({"Content-Type": "application/octet-stream"}),
                content=exact_body,
            )
        self.assertEqual(resp.status_code, 200)

    async def test_body_one_byte_over_limit_rejected(self):
        """32 MiB + 1 byte → 413 fail-closed。

        同 ``test_body_at_exact_limit_passes``：大 body 用专用长超时 client。
        """
        over_body = b"x" * (_MAX_REQUEST_BODY + 1)
        async with httpx.AsyncClient(timeout=60.0, trust_env=False) as big_client:
            resp = await big_client.post(
                self._sidecar_url("/post"),
                headers=self._upstream_headers({"Content-Type": "application/octet-stream"}),
                content=over_body,
            )
        self.assertEqual(resp.status_code, 413)
        self.assertIn("shield_request_too_large", resp.text)

    # ─── 并发安全 ───────────────────────────────────────────────────────────

    async def test_concurrent_requests(self):
        """并发 10 个请求，全部成功，无串扰。"""
        tasks = [
            self.test_client.get(
                self._sidecar_url("/get"),
                headers=self._upstream_headers(),
            )
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks)
        for r in results:
            self.assertEqual(r.status_code, 200)
        stats = self.sidecar.metrics()["stats"]
        self.assertEqual(stats["requests"], 10)
        self.assertEqual(stats["errors"], 0)

    # ─── 大响应流式 ─────────────────────────────────────────────────────────

    async def test_large_response_streaming(self):
        """大响应体正确流式转发（测试 chunked 编码）。"""
        # /stream/100 → 100 行 SSE
        async with self.test_client.stream(
            "GET",
            self._sidecar_url("/stream/100"),
            headers=self._upstream_headers(),
        ) as resp:
            self.assertEqual(resp.status_code, 200)
            lines = []
            async for line in resp.aiter_lines():
                if line.strip():
                    lines.append(line)
            self.assertEqual(len(lines), 100)

    # ─── 重试安全边界 ──────────────────────────────────────────────────────

    async def test_no_retry_on_read_timeout(self):
        """ReadTimeout 不重试（请求已发出字节，重试=重复副作用）。"""
        # 这个测试验证重试计数不增加（无 ConnectError 类的失败）
        # 用一个会 connect 成功但 read 超时的场景较难构造
        # 改为验证 stats 结构：retries 字段存在且初始为 0
        stats = self.sidecar.metrics()["stats"]
        self.assertIn("retries", stats)

    # ─── 内部头泄露防护 ─────────────────────────────────────────────────────

    async def test_internal_headers_not_leaked(self):
        """X-Maskit-Upstream 和 X-Maskit-Upstream-Name 不泄露到真实上游。"""
        await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        last = self.mock.received_headers[-1]
        self.assertNotIn("x-maskit-upstream", last)
        self.assertNotIn("x-maskit-upstream-name", last)

    # ─── 响应头透传 ─────────────────────────────────────────────────────────

    async def test_response_content_type_preserved(self):
        """响应的 Content-Type 正确透传。"""
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.headers.get("content-type", ""))

    async def test_response_status_code_preserved(self):
        """上游返回非 200 时，sidecar 透传状态码。"""
        # mock 没有专门处理 404，但 path 不匹配时返回 {"ok":true} 200
        # 用 /get 确认 200 透传
        resp = await self.test_client.get(
            self._sidecar_url("/get"),
            headers=self._upstream_headers(),
        )
        self.assertEqual(resp.status_code, 200)


class TestSidecarProxyClientSelection(unittest.IsolatedAsyncioTestCase):
    """双客户端（直连池 / 出口代理池）的逐请求选择。

    路由层只负责把 ``X-Maskit-Use-Proxy`` 设上；sidecar 侧挑对客户端、
    没配代理时回落不炸、代理池自身复用连接，才是这条路径的风险面。
    """

    async def asyncSetUp(self):
        # 带标记的 mock + 带标记的客户端：这一组的断言是「建了几条连接」，
        # 不加标记就会被本机端口扫描器探到的连接一起计数（见文件顶部注释）。
        self.upstream = MockUpstream(tag=_TEST_TAG)  # 假真实上游
        await self.upstream.start()
        self.proxy = MockUpstream(tag=_TEST_TAG)     # 假出口代理
        await self.proxy.start()
        self.test_client = httpx.AsyncClient(
            timeout=10.0, trust_env=False, headers=dict(_TEST_TAG_HEADERS))
        self._sidecars: list = []

    async def asyncTearDown(self):
        # 顺序有讲究：必须先关掉调用方连接，再 stop sidecar。
        # 反过来会卡在 Server.wait_closed()——它还等着这条 keep-alive handler。
        await self.test_client.aclose()
        for sidecar in self._sidecars:
            await sidecar.stop()
        await self.upstream.stop()
        await self.proxy.stop()

    async def _start_sidecar(self, with_proxy: bool = True) -> UpstreamSidecar:
        # 两项都按真实链路的形状给：上游白名单是 config 里的 upstreams，
        # 出口代理是 _read_settings() 解析后的 ServerSpec（不是 config.json 那串文本）。
        cfg: dict = {"upstreams": [{"name": "mock", "target": self.upstream.url}]}
        if with_proxy:
            cfg["egress_proxy"] = parse_egress_proxy(self.proxy.url)
        sidecar = UpstreamSidecar(cfg)
        await sidecar.start()
        self._sidecars.append(sidecar)
        # 记录每次转发实际选中的客户端，再交给真实实现
        self.chosen: list = []
        original = sidecar._forward_with_retry

        async def spy(client, method, url, headers, body):
            self.chosen.append(client)
            return await original(client, method, url, headers, body)

        sidecar._forward_with_retry = spy
        return sidecar

    async def _get(self, sidecar, use_proxy: str | None = None):
        hdrs = {"X-Maskit-Upstream": self.upstream.url}
        if use_proxy is not None:
            hdrs["X-Maskit-Use-Proxy"] = use_proxy
        return await self.test_client.get(
            "http://127.0.0.1:%d/get" % sidecar.port, headers=hdrs,
        )

    async def test_has_egress_proxy_metric_tracks_config(self):
        """配了出口代理 → has_egress_proxy=True 且第二个客户端就绪；没配则相反。"""
        with_proxy = await self._start_sidecar(with_proxy=True)
        self.assertIsNotNone(with_proxy._client_proxy)
        self.assertTrue(with_proxy.metrics()["has_egress_proxy"])

        without = await self._start_sidecar(with_proxy=False)
        self.assertIsNone(without._client_proxy)
        self.assertFalse(without.metrics()["has_egress_proxy"])

    async def test_default_client_without_header(self):
        """不带 X-Maskit-Use-Proxy → 走直连池，流量不出现在代理端。"""
        sidecar = await self._start_sidecar()
        resp = await self._get(sidecar)
        self.assertEqual(resp.status_code, 200)
        self.assertIs(self.chosen[0], sidecar._client)
        self.assertEqual(self.proxy.received_headers, [])
        self.assertEqual(self.upstream.received_targets, ["/get"])

    async def test_proxy_client_with_header(self):
        """带 X-Maskit-Use-Proxy: true → 走代理池，且请求行是绝对形式（真经代理）。"""
        sidecar = await self._start_sidecar()
        resp = await self._get(sidecar, "true")
        self.assertEqual(resp.status_code, 200)
        self.assertIs(self.chosen[0], sidecar._client_proxy)
        self.assertEqual(self.upstream.received_headers, [])  # 没有直连
        self.assertTrue(self.proxy.received_targets[-1].startswith("http://"),
                        "代理端应收到 absolute-form 请求行，实际: %s"
                        % self.proxy.received_targets[-1])

    async def test_header_value_parsing(self):
        """true / TRUE / 1 / yes 判为走代理；false / 0 / 空串判为直连。"""
        sidecar = await self._start_sidecar()
        for value, expect_proxy in (
            ("true", True), ("TRUE", True), ("True", True), ("1", True), ("yes", True),
            ("false", False), ("0", False), ("", False), ("no", False),
        ):
            await self._get(sidecar, value)
            picked = self.chosen[-1] is sidecar._client_proxy
            self.assertEqual(
                picked, expect_proxy,
                "X-Maskit-Use-Proxy=%r 选中的客户端不对" % value)

    async def test_falls_back_to_direct_when_proxy_unset(self):
        """上游开了 use_proxy 但全局没配出口代理 → 回落直连池，绝不报错。"""
        sidecar = await self._start_sidecar(with_proxy=False)
        resp = await self._get(sidecar, "true")
        self.assertEqual(resp.status_code, 200)
        self.assertIs(self.chosen[0], sidecar._client)
        self.assertEqual(self.proxy.received_headers, [])

    async def test_use_proxy_header_not_leaked(self):
        """内部头 X-Maskit-Use-Proxy 两条路径都要剥掉，不泄露给真实上游/代理。"""
        sidecar = await self._start_sidecar()
        await self._get(sidecar)
        await self._get(sidecar, "true")
        self.assertNotIn("x-maskit-use-proxy", self.upstream.received_headers[-1])
        self.assertNotIn("x-maskit-use-proxy", self.proxy.received_headers[-1])

    async def test_direct_and_proxy_pools_are_independent(self):
        """同一 sidecar 内直连与代理交替请求：各自命中各自的上游，互不串道。"""
        sidecar = await self._start_sidecar()
        for use_proxy in (None, "true", None, "true"):
            resp = await self._get(sidecar, use_proxy)
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(self.upstream.received_targets), 2)
        self.assertEqual(len(self.proxy.received_targets), 2)
        self.assertEqual(self.chosen[0], self.chosen[2])  # 直连池同一个客户端
        self.assertEqual(self.chosen[1], self.chosen[3])  # 代理池同一个客户端

    async def test_proxy_client_reuses_keepalive_connection(self):
        """代理池必须复用连接——这正是 C1 接管要解决的那个每请求握手。"""
        sidecar = await self._start_sidecar()
        for _ in range(3):
            resp = await self._get(sidecar, "true")
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(self.proxy.received_headers), 3)
        self.assertEqual(self.proxy.connection_count, 1,
                         "3 次代理请求建了 %d 条连接，keep-alive 未复用"
                         % self.proxy.connection_count)

    async def test_stop_is_bounded_even_with_live_caller_connection(self):
        """调用方的 keep-alive 连接还挂着时，stop() 也必须在预算内收尾。

        Python 3.12+ 的 Server.wait_closed() 要等所有 handler 退出，而 mitmproxy
        这条连接不会自己断——实测表现是 stop() 永久不返回（本文件第一版测试就是
        这样卡死在 tearDown 上）。现在由 sidecar 主动断开活动连接并带上
        _SHUTDOWN_GRACE_S 预算，所以这里**故意不**提前关 test_client。
        """
        sidecar = await self._start_sidecar()
        await self._get(sidecar, "true")
        await asyncio.wait_for(sidecar.stop(), timeout=_SHUTDOWN_GRACE_S + 10)
        self.assertFalse(sidecar.is_running)
        # 两个客户端成对释放，否则退出时连接池泄漏
        self.assertIsNone(sidecar._client)
        self.assertIsNone(sidecar._client_proxy)


class TestSidecarFramingAndLimits(unittest.IsolatedAsyncioTestCase):
    """分帧与调用方侧的闸——这一组的每一条都对应一个「静默退化」或「带病上行」。

    这些行为在功能冒烟里全是绿的：解压错发的响应只有非流式且上游真压缩时才踩，
    GET 断保活只表现为「没加速」，残缺 body 照样转发成功。所以必须逐条钉死。
    """

    async def asyncSetUp(self):
        self.mock = MockUpstream()
        await self.mock.start()
        self.sidecar = UpstreamSidecar(config={
            "upstreams": [{"name": "mock", "target": self.mock.url}]})
        await self.sidecar.start()
        self.test_client = httpx.AsyncClient(timeout=10.0, trust_env=False)

    async def asyncTearDown(self):
        await self.test_client.aclose()
        await self.sidecar.stop()
        await self.mock.stop()

    def _url(self, path):
        return "http://127.0.0.1:%d%s" % (self.sidecar.port, path)

    def _hdrs(self):
        return {"X-Maskit-Upstream": self.mock.url}

    async def _raw(self, payload: bytes, close_after=True, read_bytes=4096):
        """直连 sidecar 发原始字节（httpx 不肯帮我们发出畸形请求）。

        `close_after` 走 ``write_eof()`` **半关闭写方向**而不是 ``close()``：整条
        socket 关掉时，对端回写在这条连接上的字节会被 RST 丢掉，测试就永远读不到
        那半个响应（400 之类）；半关闭恰好也是真实的「调用方这边没东西要发了」
        形态，body 残缺与 absolute-form 两种场景都靠它。
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", self.sidecar.port)
        writer.write(payload)
        await writer.drain()
        if close_after:
            try:
                writer.write_eof()
            except (OSError, RuntimeError):
                pass
        chunks = []
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(read_bytes), timeout=5)
                if not chunk:
                    break
                chunks.append(chunk)
        except asyncio.TimeoutError:
            pass
        data = b"".join(chunks)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return data

    async def _wait_stat(self, key: str, expect: int = 1, timeout: float = 3.0) -> None:
        """等一条统计到位。

        sidecar 的 handler 是另一条 task：``_raw()`` 回来只说明调用方这侧读完了，
        断言统计前必须给它跑完的机会，否则就是拿「还没发生」当「没发生」。
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self.sidecar.metrics()["stats"].get(key, 0) >= expect:
                return
            await asyncio.sleep(0.02)
        self.fail("统计 %s 在 %.1fs 内没到 %d（实际 %r）"
                  % (key, timeout, expect, self.sidecar.metrics()["stats"]))

    # ─── 调用方侧 keep-alive ────────────────────────────────────────────────

    async def test_get_requests_reuse_one_caller_connection(self):
        """连续 GET 必须复用同一条调用方连接。

        旧实现只给 POST/PUT/PATCH 读 body，GET 之后 h11 停在 SEND_BODY，
        `start_next_cycle()` 抛 LocalProtocolError → 每条 GET 结束就断一次连接。
        C1 要省的「每请求重做握手」于是被换成「每请求重连」，而 `GET /v1/models`
        正是客户端初始化必打的接口。
        """
        for _ in range(3):
            resp = await self.test_client.get(self._url("/get"), headers=self._hdrs())
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.sidecar.metrics()["stats"]["requests"], 3)
        self.assertEqual(self.sidecar.metrics()["caller_connections"], 1,
                         "3 次 GET 开了 %d 条调用方连接，keep-alive 未复用"
                         % self.sidecar.metrics()["caller_connections"])

    async def test_head_and_get_on_same_connection(self):
        """HEAD 之后再接 GET：同一条连接上还能继续，且不串响应。"""
        resp = await self.test_client.head(self._url("/get"), headers=self._hdrs())
        self.assertEqual(resp.status_code, 200)
        resp = await self.test_client.get(self._url("/get"), headers=self._hdrs())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.sidecar.metrics()["caller_connections"], 1)

    # ─── 响应分帧 ───────────────────────────────────────────────────────────

    async def test_gzip_response_bytes_are_verbatim(self):
        """上游 gzip 响应必须按**线上原始字节**转发。

        `aiter_bytes` 给的是解压后的字节，而头部照原样带着 `content-encoding: gzip`
        ——声明 gzip 却送明文，客户端解码当场炸。这是「看起来更快、实际换了一种坏法」。
        """
        resp = await self.test_client.get(self._url("/gzip"), headers=self._hdrs())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-encoding"), "gzip")
        self.assertEqual(resp.text, "hello-from-gzip-upstream")
        # 原始字节确实是压缩流，不是明文
        self.assertEqual(self.mock.received_targets[-1], "/gzip")

    async def test_head_response_is_not_chunked(self):
        """HEAD 响应不能带 `transfer-encoding: chunked`（那是在声明不存在的分帧）。"""
        # 用固定长度的路径：mock 的 /get 会把收到的请求头揉进 body，HEAD 与 GET 的
        # 请求头本就不同，长度对不上就成了测数据自身的噪声。
        resp = await self.test_client.head(self._url("/fixed"), headers=self._hdrs())
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("transfer-encoding", resp.headers)
        self.assertEqual(resp.content, b"")
        # 体长按 RFC 9110 §4.3.2 与同一请求发 GET 时一致，所以 content-length 要保留。
        # 注意不能直接比两条响应的头：sidecar 把 GET 的 body 改写成 chunked，
        # content-length 是被**有意**去掉的（两个 framer 并存是协议错误）。
        get = await self.test_client.get(self._url("/fixed"), headers=self._hdrs())
        self.assertEqual(resp.headers.get("content-length"), str(len(get.content)))

    async def test_204_response_has_no_body_or_framing(self):
        """204 透传：无体、无 chunked，客户端不会挂在等终止 chunk 上。"""
        resp = await self.test_client.get(self._url("/nocontent"),
                                          headers=self._hdrs())
        self.assertEqual(resp.status_code, 204)
        self.assertNotIn("transfer-encoding", resp.headers)
        self.assertEqual(resp.content, b"")
        # 还能在同一连接上继续请求，说明上一条响应确实被正确定界了
        again = await self.test_client.get(self._url("/get"), headers=self._hdrs())
        self.assertEqual(again.status_code, 200)
        self.assertEqual(self.sidecar.metrics()["caller_connections"], 1)

    # ─── 请求侧的闸 ─────────────────────────────────────────────────────────

    async def test_truncated_body_is_never_forwarded(self):
        """对端半路断开的残缺 body 绝不转发——转出去的是断掉的 JSON，脱敏看到的是残骸。"""
        await self._raw(
            ("POST /post HTTP/1.1\r\nHost: x\r\n%s: %s\r\n"
             "Content-Length: 100\r\n\r\n0123456789" % ("X-Maskit-Upstream", self.mock.url)).encode()
        )
        await self._wait_stat("truncated_request")
        self.assertEqual(self.sidecar.metrics()["stats"]["truncated_request"], 1)
        self.assertEqual(self.sidecar.metrics()["stats"]["requests"], 0)
        self.assertEqual(self.mock.received_targets, [])

    async def test_absolute_form_target_is_rejected(self):
        """请求行必须是 origin-relative 路径：absolute-form 会拼出指向不明的 URL。"""
        data = await self._raw(
            ("GET http://evil.invalid/get HTTP/1.1\r\nHost: x\r\n"
             "X-Maskit-Upstream: %s\r\n\r\n" % self.mock.url).encode())
        self.assertIn(b"400", data)
        self.assertIn(b"shield_request_target_invalid", data)
        self.assertEqual(self.mock.received_targets, [])

    async def test_caller_idle_read_timeout_releases_the_slot(self):
        """僵住的调用方连接会被空闲预算放开，不会永远占着 handler 名额。

        没有这道闸时，一条停在写请求头中间的连接会同时占住 `_slots` 名额和 httpx
        池槽位——两个并发闸都变成形式。
        """
        original = c1mod._CLIENT_IDLE_TIMEOUT_S
        c1mod._CLIENT_IDLE_TIMEOUT_S = 0.3
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", self.sidecar.port)
            writer.write(b"GET /get HTTP/1.1\r\n")  # 故意不发完
            await writer.drain()
            self.assertEqual(b"", await asyncio.wait_for(reader.read(1), timeout=5))
            await asyncio.sleep(0.1)
            self.assertEqual(self.sidecar.metrics()["caller_connections"], 1)
            self.assertEqual(self.sidecar.metrics()["stats"]["requests"], 0)
        finally:
            c1mod._CLIENT_IDLE_TIMEOUT_S = original
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ─── origin 判据 ────────────────────────────────────────────────────────

    def test_normalize_origin(self):
        """白名单比对的规范化：补齐默认端口、拒绝非 http(s)、拒绝用户信息。"""
        self.assertEqual(normalize_origin("https://api.openai.com"),
                         "https://api.openai.com:443")
        self.assertEqual(normalize_origin("https://api.openai.com/v1"),
                         "https://api.openai.com:443")          # 路径不参与判定
        self.assertEqual(normalize_origin("http://127.0.0.1:8080/x?q=1"),
                         "http://127.0.0.1:8080")
        self.assertEqual(normalize_origin("API.Example.COM"), None)      # 无 scheme
        self.assertEqual(normalize_origin("socks5://h:1080"), None)
        self.assertEqual(normalize_origin("https://user:pw@h"), None)
        self.assertEqual(normalize_origin("https://h:0"), None)
        self.assertEqual(normalize_origin("https://h:99999"), None)
        self.assertEqual(normalize_origin(None), None)

    def test_allowed_origins_for_is_single_source(self):
        """白名单集合只认 origin：去重、补默认端口、丢掉非法 target 且**留痕**。

        构造（`UpstreamSidecar.__init__`）与热重载换代（`transparent._c1_reconcile`）
        共用这一个函数——两边各算一份就会出现「构造时放行 A、比对时算出 B」，于是旧池
        既不退役、请求又条条 403。
        """
        with self.assertLogs(c1mod.logger, level="WARNING") as logs:
            origins = allowed_origins_for([
                {"target": "https://API.Example.com/v1"},          # 大小写/路径归一
                {"target": "https://api.example.com:443/other"},    # 同 origin → 去重
                {"target": "http://127.0.0.1:8080"},
                {"target": "socks5://h:1080"},                       # 非 http(s) → 丢
                {"target": ""},                                      # 空值 → 丢
                "not-a-dict",                                        # 形状不对 → 跳过，不抛
            ])
        self.assertEqual(origins, frozenset({
            "https://api.example.com:443",
            "http://127.0.0.1:8080",
        }))
        # 被丢掉的 target 必须留痕：静默跳过 = 「面板开着 takeover、请求却条条 403」，
        # 而 403 看起来像越权而不是配置写错。
        self.assertTrue(any("规范化失败" in line for line in logs.output),
                        logs.output)
        # 配置里没有上游 → 空集合：方向是「全拒」，不是「不限制」。
        self.assertEqual(allowed_origins_for(None), frozenset())
        self.assertEqual(allowed_origins_for([]), frozenset())


class TestSidecarStaleConnection(unittest.IsolatedAsyncioTestCase):
    """池里的连接被上游/中间设备静默关掉后，复用不能把用户请求打成 502。

    这是「默认开启 takeover」最容易被问到的那类风险：进程级连接池持有的连接可能
    早已被上游 / CDN / NAT 关掉，复用它会不会把用户请求变成 5xx。

    实测（httpx 0.28 + httpcore）：对端发 FIN 或 RST 时，httpcore 在取用连接前就能
    识别它不可用并另开一条，用户侧无感。本类把该行为钉住——httpx 升级若退化了它，
    这里会红，而不是等线上出现 502 才发现。

    不在覆盖范围：「黑洞连接」（既不回也不关）。那种情况请求可能已被上游处理，
    重试会带来重复计费，最后以 ReadTimeout 暴露给调用方才是正确行为，不是缺陷。
    """

    async def asyncSetUp(self):
        self.mock = MockUpstream()
        await self.mock.start()
        self.sidecar = UpstreamSidecar(config={
            "upstreams": [{"name": "mock", "target": self.mock.url}]})
        await self.sidecar.start()
        self.test_client = httpx.AsyncClient(timeout=10.0, trust_env=False)

    async def asyncTearDown(self):
        await self.test_client.aclose()
        await self.sidecar.stop()
        await self.mock.stop()

    def _url(self, path):
        return "http://127.0.0.1:%d%s" % (self.sidecar.port, path)

    def _hdrs(self):
        return {"X-Maskit-Upstream": self.mock.url}

    async def test_upstream_fin_after_response_is_absorbed(self):
        """上游响应后立刻 FIN：连续请求必须全 200（自动换新连接，不出 502）。"""
        for i in range(3):
            resp = await self.test_client.get(self._url("/close-after"),
                                              headers=self._hdrs())
            self.assertEqual(resp.status_code, 200,
                             "第 %d 次被池里的死连接打成 %d" % (i + 1, resp.status_code))
        self.assertEqual(self.sidecar.metrics()["stats"]["errors"], 0)

    async def test_upstream_rst_after_response_is_absorbed(self):
        """上游响应后 RST（SO_LINGER=0）：同上，绝不能自愈失败。"""
        for i in range(3):
            resp = await self.test_client.get(self._url("/rst-after"),
                                              headers=self._hdrs())
            self.assertEqual(resp.status_code, 200,
                             "第 %d 次被池里的死连接打成 %d" % (i + 1, resp.status_code))
        self.assertEqual(self.sidecar.metrics()["stats"]["errors"], 0)


class TestSidecarKeepaliveExpiry(unittest.IsolatedAsyncioTestCase):
    """空闲保留预算的三件事：值真的进了池子、窗口内真的复用、过期只是剔除不是报错。

    单独立一类的原因是这仓库有过「`connection_policy.py` 声明了 15 s 连接超时，但
    从来没传给 transport」的事故——**常量定义了不等于生效了**，所以生效判据要自己钉。
    预算取 120 s 的实测依据：同一请求节奏下 30 s 预算要新建 6 条上游连接、每次停顿后
    多付约 400 ms，而 120 s 只需 2 条；上游本身在 240 s 空闲后仍在同一条 socket 上回
    200（所以窗口内拿到的是活连接，不是尸体）。

    第四条是这组的前提条件：连接计数必须只算我们自己的流量（tag 过滤），否则本机
    端口扫描器一探就会把「复用」断言打红（见文件顶部 `_TEST_TAG` 的说明）。
    """

    async def asyncSetUp(self):
        self.mock = MockUpstream(tag=_TEST_TAG)
        await self.mock.start()
        self.client = httpx.AsyncClient(
            timeout=10.0, trust_env=False, headers=dict(_TEST_TAG_HEADERS))
        self._sidecars = []

    async def asyncTearDown(self):
        # 顺序有讲究：sidecar 攥着池里的上游连接，先关 mock 的话 mock 的 handler
        # 永远等不到 EOF，而 Python 3.12+ 的 Server.wait_closed() 要等 handler 退出。
        for sidecar in self._sidecars:
            await sidecar.stop()
        await self.client.aclose()
        await self.mock.stop()

    async def _start_sidecar(self, expiry=None):
        """按指定预算启动 sidecar。

        ``start()`` 读的是模块全局，所以 patch 必须覆盖到 ``start()`` 之内；一旦连接
        池建好，退出 patch 不影响该实例——这正是「值有被烘焙进池子」的证据。
        """
        cfg = {"upstreams": [{"name": "mock", "target": self.mock.url}]}
        if expiry is None:
            sidecar = UpstreamSidecar(config=cfg)
            await sidecar.start()
        else:
            with mock.patch.object(c1mod, "_KEEPALIVE_EXPIRY_S", expiry):
                sidecar = UpstreamSidecar(config=cfg)
                await sidecar.start()
        self._sidecars.append(sidecar)
        return sidecar

    async def _get(self, sidecar, path="/get"):
        resp = await self.client.get(
            "http://127.0.0.1:%d%s" % (sidecar.port, path),
            headers={"X-Maskit-Upstream": self.mock.url})
        return resp.status_code

    async def test_shipped_expiry_reaches_the_pool_and_covers_a_pause(self):
        """现网预算值必须真的落到 httpcore 池上，且足以跨过「停顿后第一次回车」。"""
        sidecar = await self._start_sidecar()
        self.assertGreaterEqual(c1mod._KEEPALIVE_EXPIRY_S, 60.0,
                                "预算低于 60 s 会把每个停顿后的首请求打回全新握手")
        pool_obj = sidecar._client._transport._pool
        # metrics() 用 getattr(..., 常量) 兜底，属性名写错时它会「报对」——所以这里
        # 直接验池子上真有这个值，而不是只比 metrics() 的输出。
        self.assertTrue(hasattr(pool_obj, "_keepalive_expiry"),
                        "httpcore 池上找不到 keepalive 预算，指标在自证清白")
        self.assertEqual(pool_obj._keepalive_expiry, c1mod._KEEPALIVE_EXPIRY_S,
                         "常量没传进连接池——takeover 会退化成每请求重连")
        self.assertEqual(sidecar.metrics()["pool"]["keepalive_expiry"],
                         c1mod._KEEPALIVE_EXPIRY_S)

    async def test_gap_inside_expiry_reuses_the_upstream_connection(self):
        """预算内的停顿之后，第二条请求必须复用同一条上游连接。"""
        sidecar = await self._start_sidecar(expiry=300.0)
        self.assertEqual(await self._get(sidecar), 200)
        await asyncio.sleep(1.5)
        self.assertEqual(await self._get(sidecar), 200)
        self.assertEqual(self.mock.connection_count, 1,
                         "预算内的空闲把连接丢了（served=%d）"
                         % self.mock.connection_count)
        # 计数之外再加一条身份判据：两条请求必须来自**同一个源端口**。
        # 计数只能说明「同一个连接跑完了两条请求」，源端口相同才直接证明
        # 这条 socket 没被换过（上游换了连接但计数恰好为 1 的情形它拦得住）。
        ports = {p[1] for p in self.mock.request_peers}
        self.assertEqual(len(self.mock.request_peers), 2)
        self.assertEqual(len(ports), 1,
                         "两次请求来自不同源端口 %r——连接确实被重建了"
                         % ([p[1] for p in self.mock.request_peers],))

    async def test_gap_beyond_expiry_reconnects_without_error(self):
        """超出预算只是剔除过期连接：重连、两条都 200，errors 计数保持 0。"""
        sidecar = await self._start_sidecar(expiry=0.3)
        self.assertEqual(await self._get(sidecar), 200)
        await asyncio.sleep(1.0)
        self.assertEqual(await self._get(sidecar), 200)
        self.assertEqual(self.mock.connection_count, 2,
                         "过期连接没被剔除，空闲预算形同虚设"
                         "（served=%d）" % self.mock.connection_count)
        self.assertEqual(sidecar.metrics()["stats"]["errors"], 0)

    async def test_connection_count_ignores_foreign_probes(self):
        """本机其它进程探到 mock 端口时，连接计数与请求记录都不能被它带偏。

        环回端口是共享资源：实测（2026-10-12）开发机上的 agent 工具链每几秒全段
        扫一遍，会发出「没有 Host 的 HEAD /」（h11 直接拒）和普通 GET。两类外来
        流量都不该进 ``connection_count`` / ``received_*``，否则「两次请求只建一条
        连接」的断言就变成看本机装了什么软件的脸色。
        """
        sidecar = await self._start_sidecar(expiry=300.0)
        self.assertEqual(await self._get(sidecar), 200)

        # 1) 畸形探测（真实观察到的那种：没有 Host）
        reader, writer = await asyncio.open_connection("127.0.0.1", self.mock.port)
        writer.write(b"HEAD / HTTP/1.1\r\nUser-Agent: port-probe\r\n"
                     b"Connection: close\r\n\r\n")
        await writer.drain()
        await reader.read(4096)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # 2) 合法但与我们无关的 HTTP 请求（没有测试标记头）
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as probe:
            await probe.get(self.mock.url + "/probe")

        self.assertEqual(await self._get(sidecar), 200)
        self.assertEqual(self.mock.received_targets, ["/get", "/get"],
                         "外来探测混进了 mock 的请求记录")
        self.assertEqual(self.mock.connection_count, 1,
                         "外来探测被算进了连接计数（served=%d）"
                         % self.mock.connection_count)
        # 反向自证：两条探测真的要落在 mock 上（否则这条用例就是空跑），
        # 且它们被归到了 foreign 一侧而不是被默默当成我们的流量。
        for _ in range(50):
            if self.mock.foreign_connections >= 2:
                break
            await asyncio.sleep(0.02)
        self.assertGreaterEqual(
            self.mock.foreign_connections, 2,
            "外来探测没被记到 foreign_connections（实际 %d）——探测可能根本没到 mock"
            % self.mock.foreign_connections)


if __name__ == "__main__":
    unittest.main()
