"""C1 sidecar: 跨客户端共享的 httpx keep-alive 连接池 + HTTP/1.1 转发器。

架构::

    [mitmproxy addon] --HTTP localhost--> [C1 sidecar] --HTTPS--> [真实上游]
    脱敏+还原(不变)           ↓
                        httpx 跨客户端 keep-alive 池

路由：``apply_reverse_routing`` 在 ``takeover=true`` 时改写 ``flow.request`` 到
``127.0.0.1:SIDECAR_PORT``，通过 ``X-Maskit-Upstream`` 头传递真实上游 URL。
sidecar 剥离该头，用 httpx 池转发。

红线：
- TLS 证书校验默认 ``verify=True``，异常**必须**冒泡到 fail-closed 503/502。
- 32 MiB 请求体上限在 sidecar 路径仍守，超限 413。
- 凭据类头（``Authorization`` / ``X-API-Key`` 等）禁止通过 extra_headers 注入。
- ``X-Maskit-Upstream`` 内部头在转发前剥离，不泄露到真实上游。
"""
from __future__ import annotations

import asyncio
import h11
import httpx
import logging
import ssl
import sys
import time
from typing import Any

logger = logging.getLogger("maskit.c1")

# ─── 内部头 ────────────────────────────────────────────────────────────────
_UPSTREAM_HEADER = "x-maskit-upstream"
_UPSTREAM_NAME_HEADER = "x-maskit-upstream-name"
_INTERNAL_HEADERS = frozenset({_UPSTREAM_HEADER, _UPSTREAM_NAME_HEADER})

# ─── 凭据类头禁令（与 transparent._CREDENTIAL_HEADER_NAMES 同源）────────────
_CREDENTIAL_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "api-key", "apikey",
    "x-goog-api-key", "x-auth-token", "x-access-token",
    "x-token", "x-session-token", "private-token",
})

# ─── 超时 ──────────────────────────────────────────────────────────────────
_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 120.0
_WRITE_TIMEOUT_S = 30.0
_POOL_TIMEOUT_S = 5.0

# ─── 连接池 ─────────────────────────────────────────────────────────────────
_MAX_CONNECTIONS = 64
_MAX_KEEPALIVE_CONNECTIONS = 16
_KEEPALIVE_EXPIRY_S = 30.0

# ─── 32 MiB 上限（与 transparent._DEFAULT_MAX_REQUEST_BODY 一致）────────────
_MAX_REQUEST_BODY = 32 * 1024 * 1024

# ─── 重试 ───────────────────────────────────────────────────────────────────
_MAX_RETRIES = 1


class UpstreamSidecar:
    """C1 sidecar: 进程级 httpx 池 + asyncio HTTP/1.1 转发器。

    生命周期由 mitmproxy addon 的 ``load`` / ``done`` hook 管理。
    跑在 mitmproxy 的 asyncio 事件循环上。
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}
        self._client: httpx.AsyncClient | None = None
        self._server: asyncio.base_events.Server | None = None
        self._port: int = 0
        self._stats: dict[str, int] = {
            "requests": 0,
            "retries": 0,
            "errors": 0,
            "tls_verify_off": 0,
            "body_too_large": 0,
        }
        self._extra_headers: dict[str, str] = {}

    @property
    def port(self) -> int:
        return self._port

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._client is not None

    def metrics(self) -> dict[str, Any]:
        pool_info: dict[str, Any] = {}
        if self._client is not None:
            pool = getattr(self._client, "_transport", None)
            pool_obj = getattr(pool, "_pool", None) if pool else None
            if pool_obj:
                pool_info = {
                    "max_connections": getattr(pool_obj, "_max_connections", _MAX_CONNECTIONS),
                    "max_keepalive": getattr(pool_obj, "_max_keepalive_connections", _MAX_KEEPALIVE_CONNECTIONS),
                    "keepalive_expiry": getattr(pool_obj, "_keepalive_expiry", _KEEPALIVE_EXPIRY_S),
                }
        return {
            "enabled": self.is_running,
            "port": self._port,
            "stats": dict(self._stats),
            "pool": pool_info,
        }

    # ─── 生命周期 ──────────────────────────────────────────────────────────

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """启动 sidecar TCP 服务器 + httpx 池。返回实际监听端口。"""
        # SSL 上下文：严格校验
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True

        # 代理配置平移
        proxy: str | None = None
        egress = self._config.get("egress_proxy") or {}
        if egress.get("enabled") and egress.get("url"):
            proxy = str(egress["url"])

        # tls_verify=false（仅限受信任反代场景）
        tls_verify = True
        # per-upstream 的 tls_verify 暂不在此层处理（由路由层决定是否启用 takeover）

        self._client = httpx.AsyncClient(
            verify=ssl_ctx if tls_verify else False,
            timeout=httpx.Timeout(
                connect=_CONNECT_TIMEOUT_S,
                read=_READ_TIMEOUT_S,
                write=_WRITE_TIMEOUT_S,
                pool=_POOL_TIMEOUT_S,
            ),
            limits=httpx.Limits(
                max_connections=_MAX_CONNECTIONS,
                max_keepalive_connections=_MAX_KEEPALIVE_CONNECTIONS,
                keepalive_expiry=_KEEPALIVE_EXPIRY_S,
            ),
            http2=False,
            trust_env=False,
            proxy=proxy,
        )

        self._server = await asyncio.start_server(
            self._handle_client, host, port,
        )
        self._port = self._server.sockets[0].getsockname()[1]
        logger.info("C1 sidecar started on %s:%d (httpx pool: max=%d keepalive=%d)",
                     host, self._port, _MAX_CONNECTIONS, _MAX_KEEPALIVE_CONNECTIONS)
        return self._port

    async def stop(self) -> None:
        """关闭 sidecar + 释放 httpx 池连接。"""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._port = 0
        logger.info("C1 sidecar stopped")

    def set_extra_headers(self, upstream_name: str, headers: dict[str, str]) -> None:
        """注入 extra_headers（凭据类头会被过滤）。由路由层在每次请求前调用。"""
        filtered: dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() in _CREDENTIAL_HEADER_NAMES:
                logger.warning("extra_headers rejected credential header: %s", k)
                continue
            filtered[k] = v
        self._extra_headers = filtered

    # ─── 核心转发 ──────────────────────────────────────────────────────────

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """处理一个 mitmproxy → sidecar 的 HTTP/1.1 连接（支持 keep-alive 多请求）。"""
        conn = h11.Connection(our_role=h11.SERVER)
        peer = writer.get_extra_info("peername")
        client = self._client
        if client is None:
            return

        try:
            while True:
                # 1. 读请求行 + 头
                request = await self._read_request_headers(reader, conn)
                if request is None:
                    break  # 客户端关闭

                method = request.method.decode() if isinstance(request.method, bytes) else request.method
                path = request.target.decode() if isinstance(request.target, bytes) else request.target
                raw_headers = request.headers

                # 提取真实上游 URL
                upstream_url = None
                upstream_name = None
                fwd_headers: list[tuple[str, str]] = []
                for k, v in raw_headers:
                    kn = k.decode().lower() if isinstance(k, bytes) else k.lower()
                    vv = v.decode() if isinstance(v, bytes) else v
                    if kn == _UPSTREAM_HEADER:
                        upstream_url = vv
                    elif kn == _UPSTREAM_NAME_HEADER:
                        upstream_name = vv
                    elif kn in _INTERNAL_HEADERS or kn in _CREDENTIAL_HEADER_NAMES:
                        continue  # 剥离内部头 + 凭据类头
                    elif kn in ("content-length", "transfer-encoding", "connection", "host"):
                        continue  # httpx 自己管理
                    else:
                        fwd_headers.append((kn, vv))

                # 注入 extra_headers
                if self._extra_headers:
                    for k, v in self._extra_headers.items():
                        if k.lower() not in _CREDENTIAL_HEADER_NAMES:
                            fwd_headers.append((k.lower(), v))

                if not upstream_url:
                    await self._send_error(conn, writer, 400,
                        b'{"error":"missing X-Maskit-Upstream header"}')
                    if not self._cycle_done(conn): break
                    continue

                # 2. 读请求 body（如果有）
                body = b""
                if method in ("POST", "PUT", "PATCH"):
                    body = await self._read_request_body(reader, conn)
                    if len(body) > _MAX_REQUEST_BODY:
                        self._stats["body_too_large"] += 1
                        await self._send_error(conn, writer, 413,
                            b'{"error":"shield_request_too_large"}')
                        if not self._cycle_done(conn): break
                        continue

                # 3. 用 httpx 池转发（带重试）
                self._stats["requests"] += 1
                url = upstream_url.rstrip("/") + path
                t0 = time.monotonic()
                resp = await self._forward_with_retry(
                    client, method, url, fwd_headers, body,
                )

                if resp is None:
                    # 重试后仍失败 → fail-closed
                    self._stats["errors"] += 1
                    await self._send_error(conn, writer, 502,
                        b'{"error":"upstream_connect_failed"}')
                    if not self._cycle_done(conn): break
                    continue

                # 4. 流式读响应，h11 chunked 编码写回
                try:
                    chunk_count = await self._stream_response(
                        conn, writer, resp,
                    )
                    elapsed = time.monotonic() - t0
                    logger.debug("sidecar %s %s -> %d (%d chunks, %.3fs) [%s]",
                                 method, path.split("?")[0], resp.status_code,
                                 chunk_count, elapsed, peer)
                except Exception as e:
                    logger.error("sidecar stream error: %s", e)
                    self._stats["errors"] += 1
                    break  # 流式出错，连接状态不可靠
                finally:
                    await resp.aclose()
                if not self._cycle_done(conn):
                    break

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error("sidecar handler error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ─── h11 请求解析 ──────────────────────────────────────────────────────

    async def _read_request_headers(
        self, reader: asyncio.StreamReader, conn: h11.Connection,
    ) -> h11.Request | None:
        """从 reader 读数据，直到拿到完整的 h11.Request。"""
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(65536)
                if not data:
                    return None
                conn.receive_data(data)
            elif isinstance(event, h11.Request):
                return event
            elif isinstance(event, h11.ConnectionClosed):
                return None
            # Data / EndOfMessage 等：先跳过，body 在后面读

    async def _read_request_body(
        self, reader: asyncio.StreamReader, conn: h11.Connection,
    ) -> bytes:
        """读取请求 body（Content-Length 或 chunked）。检查 32 MiB 上限。"""
        body = b""
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(65536)
                if not data:
                    break
                conn.receive_data(data)
                continue
            if isinstance(event, h11.Data):
                body += event.data
                if len(body) > _MAX_REQUEST_BODY:
                    return body  # 超限，外层会处理
            elif isinstance(event, h11.EndOfMessage):
                break
        return body

    # ─── httpx 转发 + 重试 ──────────────────────────────────────────────────

    async def _forward_with_retry(
        self, client: httpx.AsyncClient, method: str, url: str,
        headers: list[tuple[str, str]], body: bytes,
    ) -> httpx.Response | None:
        """用 httpx 池转发，连接失败时重试一次（请求未发出字节时安全）。"""
        req_headers = dict(headers)
        content = body if body else None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.send(
                    client.build_request(method, url, headers=req_headers, content=content),
                    stream=True,
                )
                return resp
            except httpx.ConnectError as e:
                # 连接失败 = 请求未发出任何字节 → 安全重试
                if attempt < _MAX_RETRIES:
                    self._stats["retries"] += 1
                    logger.warning("sidecar connect error (attempt %d), retrying: %s",
                                   attempt + 1, e)
                    continue
                logger.error("sidecar connect failed after %d attempts: %s",
                             attempt + 1, e)
                return None
            except httpx.ConnectTimeout as e:
                if attempt < _MAX_RETRIES:
                    self._stats["retries"] += 1
                    logger.warning("sidecar connect timeout (attempt %d), retrying: %s",
                                   attempt + 1, e)
                    continue
                return None
            except (httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
                # 这些可能发生在请求已发出之后 → 不重试
                logger.error("sidecar non-retryable error: %s", e)
                return None
            except Exception as e:
                # TLS 验证异常 → fail-closed，不重试
                logger.error("sidecar TLS/error (fail-closed): %s", e)
                return None
        return None

    # ─── h11 响应编码 ──────────────────────────────────────────────────────

    async def _stream_response(
        self, conn: h11.Connection, writer: asyncio.StreamWriter,
        resp: httpx.Response,
    ) -> int:
        """流式读 httpx 响应，h11 chunked 编码写回客户端。返回 chunk 数。"""
        # 构造响应头：透传 + 移除 content-length（用 chunked）
        resp_headers: list[tuple[str, str]] = []
        for k, v in resp.headers.items():
            kl = k.lower()
            if kl in ("content-length", "transfer-encoding", "connection"):
                continue
            resp_headers.append((kl, v))
        resp_headers.append(("transfer-encoding", "chunked"))

        h11_resp = h11.Response(status_code=resp.status_code, headers=resp_headers)
        writer.write(conn.send(h11_resp))

        chunk_count = 0
        async for chunk in resp.aiter_bytes(4096):
            if chunk:
                writer.write(conn.send(h11.Data(data=chunk)))
                chunk_count += 1
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
        return chunk_count

    def _cycle_done(self, conn: h11.Connection) -> bool:
        """h11 SERVER 模式：响应发送后重置状态以处理下一个 keep-alive 请求。

        返回 True 表示可以继续处理下一个请求，False 表示连接结束。
        """
        try:
            conn.start_next_cycle()
            return True
        except Exception:
            return False

    async def _send_error(
        self, conn: h11.Connection, writer: asyncio.StreamWriter,
        status: int, body: bytes,
    ) -> None:
        """发送错误响应。"""
        try:
            resp = h11.Response(
                status_code=status,
                headers=[
                    ("content-type", "application/json"),
                    ("content-length", str(len(body))),
                ],
            )
            writer.write(conn.send(resp))
            writer.write(conn.send(h11.Data(data=body)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
        except Exception:
            pass
