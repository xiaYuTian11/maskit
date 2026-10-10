"""C1 sidecar: 跨客户端共享的 httpx keep-alive 连接池 + HTTP/1.1 转发器。

架构::

    [mitmproxy addon] --HTTP localhost--> [C1 sidecar] --HTTPS--> [真实上游]
    脱敏+还原(不变)           ↓
                        httpx 跨客户端 keep-alive 池

路由：``apply_reverse_routing`` 在 ``takeover=true`` 时改写 ``flow.request`` 到
``127.0.0.1:SIDECAR_PORT``，通过 ``X-Maskit-Upstream`` 头传递真实上游 **origin**
（``scheme://host:port``，路径与 query 已留在 ``flow.request.path`` 里，由路由层按
``_merge_path_and_query`` 拼好）。sidecar 剥离该头，用 httpx 池转发。

红线：
- TLS 证书校验默认 ``verify=True``，异常**必须**冒泡到 fail-closed 503/502。
- 32 MiB 请求体上限在 sidecar 路径仍守，超限 413 **并断开这条连接**（半截 body 还在
  套接字里，继续 keep-alive 会让下一个请求读到上一请求的残渣）。
- **只转发配置里声明过的上游 origin**（``config["upstreams"][*]["target"]``）。
  环回端口挡不住「本机上任何一个进程」，也不该让读得到这个端口的人以为
  「头里写谁就转给谁」是安全的——没有这道闸，SECURITY.md 里「转发的仍是同一个上游」
  这句话就不成立。
- 客户端凭据头（``Authorization`` / ``x-api-key`` / ``Cookie`` 等）**必须透传**到上游——它们是客户端身份凭据，剥离会导致 401。sidecar 没有凭据过滤权，唯一该剥的是下面的内部路由头。
- ``extra_headers`` 由 ``transparent._apply_extra_headers`` 在 flow 上注入（凭据类头在该函数已被拦下），到 sidecar 只是普通请求头，原样透传。
- ``X-Maskit-Upstream`` / ``X-Maskit-Upstream-Name`` / ``X-Maskit-Use-Proxy`` 内部头在转发前剥离，不泄露到真实上游。
- 响应体按**线上原始字节**转发（``aiter_raw``）：解了压却照发 ``content-encoding: gzip``
  等于给客户端一份「声明是 gzip、实际是明文」的响应，客户端解码当场失败。
"""
from __future__ import annotations

import asyncio
import h11
import httpx
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlparse

# 出口代理的形状判据与逆转换只有 shield_defaults 一份（见其 docstring）：
# 本模块第一版照 config.json 的形状（`{"enabled":…, "url":…}`）去读元组，
# `tuple.get(...)` 在 sidecar 构造当场抛 AttributeError——takeover 一开就退直连。
from shield_defaults import egress_proxy_url

try:
    from .shield_defaults import egress_proxy_url
except ImportError:  # 源码态 mitmdump 以顶层文件方式加载 engine 模块
    from shield_defaults import egress_proxy_url

logger = logging.getLogger("maskit.c1")

# ─── 内部头 ────────────────────────────────────────────────────────────────
_UPSTREAM_HEADER = "x-maskit-upstream"
_UPSTREAM_NAME_HEADER = "x-maskit-upstream-name"
_USE_PROXY_HEADER = "x-maskit-use-proxy"
_INTERNAL_HEADERS = frozenset({_UPSTREAM_HEADER, _UPSTREAM_NAME_HEADER, _USE_PROXY_HEADER})

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

# ─── 关停 ───────────────────────────────────────────────────────────────────
# Server.wait_closed() 在 Python 3.12+ 会等到所有 handler 退出。调用方
# （mitmproxy）的 keep-alive 连接不会自己断，所以关停必须有上界：先主动断开
# 活动连接，再有界等待。没有这个预算时 stop() 会永久挂住，连接池永不释放。
_SHUTDOWN_GRACE_S = 5.0

# ─── 调用方（mitmproxy）侧的闸 ──────────────────────────────────────────────
# 读请求头/请求体时的**空闲**预算：本地管道里正常写入是毫秒级，长时间一个字节都不来
# 只有「对端已经不算这条请求了」这一种解释。没有这道闸时，一条僵在 handler 里的连接
# 会永远占着一个 httpx 池槽位。
_CLIENT_IDLE_TIMEOUT_S = 30.0
# 同时在处理的**连接**数上限。池子的 `_MAX_CONNECTIONS` 只约束到上游的连接数，
# 不约束这里的 handler 数——而每条 handler 最坏攥着一整个 32 MiB body，
# 连接数无界等于内存上界无界（单条上限的保护本意就是把总预算钉住）。
_MAX_CONCURRENT_HANDLERS = _MAX_CONNECTIONS

# 按 RFC 9110 永远不带响应体的状态码。给它们加 `transfer-encoding: chunked` 是在
# 声明一个不存在的分帧，客户端会一直等那个永不到来的终止 chunk。
_BODYLESS_STATUS = (204, 304)


class _MalformedRequest(Exception):
    """请求行/请求头本身解析失败（h11 在这里抛异常而不是给事件）。

    与「对端没发完」区分开：那一种在 `_read_request_body` 里折成 `complete=False`，
    这一种连请求是什么都无从确定，只能整条拒掉。
    """


def normalize_origin(url):
    """把任意 URL 收成 `scheme://host:port`（默认端口补齐），非法返回 None。

    白名单比对与 ``X-Maskit-Upstream`` 校验都走这一个函数：两边判据不一致就等于
    「配置里写着 A、请求头里递 B 也能过」。只保留 origin——路径是客户端要的，
    不该参与「这是不是配置里那个上游」的判断。
    """
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    try:
        host = parsed.hostname
        explicit_port = parsed.port
    except ValueError:  # 端口段不是数字
        return None
    if not host:
        return None
    # `parsed.port or 默认端口` 会把显式写了的 `:0` 当成「没写」——那是非法端口，
    # 必须留在判据里被拒掉，而不是悄悄规范成 443（白名单与请求头两边都这样错，
    # 就会拼出一个谁也没配置过的 origin）。
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if not (0 < port <= 65535):
        return None
    # netloc 里出现用户信息就不是我们认识的 upstream target
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return None
    host = host.lower().strip("[]")
    return "%s://%s:%d" % (scheme, host, port)


class UpstreamSidecar:
    """C1 sidecar: 进程级 httpx 池 + asyncio HTTP/1.1 转发器。

    生命周期由 mitmproxy addon 的 ``load`` / ``done`` hook 管理。
    跑在 mitmproxy 的 asyncio 事件循环上。
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}
        self._client: httpx.AsyncClient | None = None        # 无代理客户端（默认）
        self._client_proxy: httpx.AsyncClient | None = None   # 有代理客户端
        self._server: asyncio.base_events.Server | None = None
        self._port: int = 0
        # 出口代理在**构造时**定形：形状是 shield_defaults 的 ServerSpec
        # `(scheme, (host, port))`（来自 `transparent._read_settings()`，不是 config.json
        # 里那串文本）。配置热重载后由 `transparent._c1_reconcile` 停用并重建，
        # 否则「改了出口代理」在这里永远不会生效且没有任何提示。
        self._egress_url = egress_proxy_url(self._config.get("egress_proxy"))
        # 只转发配置里声明过的上游 origin（见模块红线）。空集合 = 配置里没有任何上游，
        # 这时**什么都不放行**，而不是「当作不限制」。
        _targets = [up.get("target") for up in (self._config.get("upstreams") or [])
                    if isinstance(up, dict)]
        _origins = [normalize_origin(t) for t in _targets]
        _dropped = [t for t, o in zip(_targets, _origins) if not o]
        if _dropped:
            # 静默跳过会变成「面板上开了 takeover、请求却条条 403」，而 403 的原因
            # 看起来像越权而不是配置写错。当场说清楚是哪几个 target。
            logger.warning("C1 上游 target 规范化失败，这些上游即使开 takeover 也会被拒转：%s",
                           ", ".join(str(t)[:80] for t in _dropped[:5]))
        self._allowed_origins = frozenset(o for o in _origins if o)
        # 调用方侧的并发闸：见 `_MAX_CONCURRENT_HANDLERS`
        self._slots = asyncio.Semaphore(_MAX_CONCURRENT_HANDLERS)
        self._stats: dict[str, int] = {
            "requests": 0,
            "retries": 0,
            "errors": 0,
            "tls_verify_off": 0,
            "body_too_large": 0,
            "rejected_target": 0,
            "truncated_request": 0,
            "malformed_request": 0,
        }
        # 活动中的 mitmproxy→sidecar 连接，关停时由 sidecar 主动断开
        self._live_writers: set[asyncio.StreamWriter] = set()
        # 累计 accept 过的调用方连接数。C1 的整条理由就是「省掉每请求重做握手」，
        # 所以「调用方有没有复用连接」必须能被看见——否则 keep-alive 悄悄退化成
        # 每请求重连，只剩下一句「统计里没有异常」。
        self._caller_connections = 0

    @property
    def port(self) -> int:
        return self._port

    @property
    def egress_url(self) -> str | None:
        """本实例建池时定型的出口代理 URL（配置变更后靠重建换代，见 `_c1_reconcile`）。"""
        return self._egress_url

    @property
    def allowed_origins(self) -> frozenset[str]:
        return self._allowed_origins

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
            "has_egress_proxy": self._client_proxy is not None,
            "caller_connections": self._caller_connections,
            # 白名单规模必须在指标里露出来：空集合等于「什么都不放行」，如果没人
            # 配置上游，症状是每条接管请求都 403，而面板上看不出任何异常。
            "allowed_origins": sorted(self._allowed_origins),
        }

    # ─── 生命周期 ──────────────────────────────────────────────────────────

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """启动 sidecar TCP 服务器 + httpx 池。返回实际监听端口。"""
        # SSL 上下文：严格校验
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True

        # 代理配置：构造时已把 ServerSpec 收成文本（`self._egress_url`）
        proxy = self._egress_url

        # tls_verify=false（仅限受信任反代场景）
        tls_verify = True
        # per-upstream 的 tls_verify 暂不在此层处理（由路由层决定是否启用 takeover）

        # 无代理客户端（所有上游默认走这个）
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
        )

        # 有代理客户端（仅 use_proxy=true 的上游走这个）
        if proxy:
            self._client_proxy = httpx.AsyncClient(
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
        logger.info("C1 sidecar started on %s:%d (httpx pool: max=%d keepalive=%d, proxy=%s)",
                     host, self._port, _MAX_CONNECTIONS, _MAX_KEEPALIVE_CONNECTIONS,
                     "yes" if self._client_proxy else "no")
        return self._port

    async def stop(self) -> None:
        """关闭 sidecar + 释放 httpx 池连接。可重复调用（幂等）。"""
        if self._server is not None:
            self._server.close()
            # 先主动断开调用方连接，否则 wait_closed() 等的是永远不会自己走的
            # keep-alive handler（实测：mitmproxy 侧连接未关时 stop() 永久不返回）。
            pending = len(self._live_writers)
            for writer in list(self._live_writers):
                try:
                    writer.close()
                except Exception:
                    pass
            self._live_writers.clear()
            try:
                await asyncio.wait_for(self._server.wait_closed(),
                                       timeout=_SHUTDOWN_GRACE_S)
            except asyncio.TimeoutError:
                logger.warning("C1 sidecar wait_closed exceeded %.1fs "
                               "(%d live connection(s) force-closed)",
                               _SHUTDOWN_GRACE_S, pending)
            self._server = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._client_proxy is not None:
            await self._client_proxy.aclose()
            self._client_proxy = None
        self._port = 0
        logger.info("C1 sidecar stopped")

    # ─── 核心转发 ──────────────────────────────────────────────────────────

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """处理一个 mitmproxy → sidecar 的 HTTP/1.1 连接（支持 keep-alive 多请求）。"""
        # 并发闸：每条 handler 最坏攥着一整个 32 MiB body，「同时进来几条」必须有界
        # （抬高单条上限等于等比抬高整个内存预算，这条红线在 sidecar 路径同样成立）。
        # 超出的连接停在 accept 积压里等——那是 TCP 自己的背压，比全部放进来一起把
        # 内存顶穿好。等待本身不设预算：调用方（mitmproxy）自己有超时。
        await self._slots.acquire()
        self._caller_connections += 1
        conn = h11.Connection(our_role=h11.SERVER)
        peer = writer.get_extra_info("peername")
        default_client = self._client
        if default_client is None:
            self._slots.release()
            return
        self._live_writers.add(writer)

        try:
            while True:
                # 1. 读请求行 + 头
                request = await self._read_request_headers(reader, conn)
                if request is None:
                    break  # 客户端关闭

                method = request.method.decode() if isinstance(request.method, bytes) else request.method
                path = request.target.decode() if isinstance(request.target, bytes) else request.target
                raw_headers = request.headers

                # 提取真实上游 URL + 透传客户端请求头
                upstream_url = None
                upstream_name = None
                use_proxy = False
                fwd_headers: list[tuple[str, str]] = []
                for k, v in raw_headers:
                    kn = k.decode().lower() if isinstance(k, bytes) else k.lower()
                    vv = v.decode() if isinstance(v, bytes) else v
                    if kn == _UPSTREAM_HEADER:
                        upstream_url = vv
                    elif kn == _UPSTREAM_NAME_HEADER:
                        upstream_name = vv
                    elif kn == _USE_PROXY_HEADER:
                        use_proxy = vv.lower() in ("true", "1", "yes")
                    elif kn in _INTERNAL_HEADERS:
                        continue  # 只剥离内部头，不碰凭据头（客户端凭据必须透传）
                    elif kn in ("content-length", "transfer-encoding", "connection", "host"):
                        continue  # httpx 自己管理
                    else:
                        fwd_headers.append((kn, vv))

                # 缺头与非 origin 值都是客户端拼错了（400），只有「格式合法但不在
                # 配置里」才是越权（403）。三种回法的可归因性完全不同，不能合并成一
                # 个 403：排障时看不出是调用方 bug 还是有人拿这个端口当开放代理。
                if not upstream_url:
                    await self._send_error(conn, writer, 400,
                        b'{"error":"missing X-Maskit-Upstream header"}')
                    break
                origin = normalize_origin(upstream_url)
                if origin is None:
                    self._stats["rejected_target"] += 1
                    logger.warning("sidecar 拒转非法目标 %r [%s]",
                                   (upstream_url or "")[:200], peer)
                    await self._send_error(conn, writer, 400,
                        b'{"error":"shield_upstream_target_invalid"}')
                    break
                if origin not in self._allowed_origins:
                    # 「头里写谁就转给谁」必须在这里断掉。环回端口不是访问控制：它只
                    # 挡住外来的，挡不住本机上任何一个进程，也不该让后来读这段代码的
                    # 人以为放行任意目标是安全的（SECURITY.md 那句「转发的仍是同一个
                    # 上游」靠的就是这道闸）。判错了就断开，不留 keep-alive。
                    self._stats["rejected_target"] += 1
                    logger.warning("sidecar 拒转未在上游配置里的目标 %r [%s]",
                                   (upstream_url or "")[:200], peer)
                    await self._send_error(conn, writer, 403,
                        b'{"error":"shield_upstream_target_not_allowed"}')
                    break

                if (not path.startswith("/") or path.startswith("//")
                        or "\r" in path or "\n" in path):
                    # 只接受 origin-relative 路径：absolute-form(`GET http://x/y`) 与
                    # `//host/…` 都会让 `origin + path` 拼出谁也不知道指向哪的东西。
                    await self._send_error(conn, writer, 400,
                        b'{"error":"shield_request_target_invalid"}')
                    break

                # 2. 读请求 body —— **每条请求都要读到 EndOfMessage**，与方法无关。
                #    只给 POST/PUT/PATCH 读的那个版本，GET 之后 h11 还停在 SEND_BODY，
                #    `start_next_cycle()` 抛 LocalProtocolError，于是每条 GET/HEAD 结束
                #    就断一次连接：C1 想省的「每请求重做握手」被换成了「每请求重连」。
                #    而 GET /v1/models 这类客户端初始化必打的接口正是重灾区。
                body, complete = await self._read_request_body(reader, conn)
                if len(body) > _MAX_REQUEST_BODY:
                    self._stats["body_too_large"] += 1
                    await self._send_error(conn, writer, 413,
                        b'{"error":"shield_request_too_large"}')
                    # 断开而不是 continue：半截 body 还在套接字里，下一条请求会读到
                    # 上一条的残渣。413 已经写完并 drain 过，客户端拿得到这个状态码。
                    break
                if not complete:
                    # 对端半路就断了：转出去的会是**残缺** body，脱敏看到的是断掉的
                    # JSON——宁可这条不转，也不带病上行。
                    self._stats["truncated_request"] += 1
                    logger.warning("sidecar 请求体未读完（%s %s）[%s]", method,
                                   path.split("?")[0], peer)
                    # 尽力回一个 400：多数情况下对端已经不读了，但能读到的那部分
                    # 值得一个明确状态码，而不是「连接凭空断掉」。
                    await self._send_error(conn, writer, 400,
                        b'{"error":"shield_request_incomplete"}')
                    break

                # 3. 选择 httpx 客户端（有代理 / 无代理）
                active_client = default_client
                if use_proxy and self._client_proxy is not None:
                    active_client = self._client_proxy

                # 4. 用 httpx 池转发（带重试）。origin 用的是校验后规范化的那一份，
                #    所以既没有尾斜杠重复，也不会把 target 里的路径前缀拼两遍。
                self._stats["requests"] += 1
                url = origin + path
                t0 = time.monotonic()
                resp = await self._forward_with_retry(
                    active_client, method, url, fwd_headers, body,
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
                        conn, writer, resp, method=method,
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

        except _MalformedRequest as e:
            # 请求行/头本身不合法。出错的是对端那一侧的 h11 状态，我们这侧还能正常
            # 发响应（实测 `conn.send()` 在此之后仍返回合法字节），所以给个 400。
            self._stats["malformed_request"] += 1
            logger.warning("sidecar 拒绝畸形请求 [%s]: %s", peer, e)
            await self._send_error(conn, writer, 400,
                b'{"error":"shield_bad_request"}')
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ConnectionResetError, BrokenPipeError) as e:
            # 调用方空闲超预算 / 半路断开：静默收尾，但留下一条能查的痕
            logger.debug("sidecar 连接中断（%s: %s）[%s]", type(e).__name__, e, peer)
        except Exception as e:
            logger.error("sidecar handler error: %s", e)
        finally:
            self._slots.release()
            self._live_writers.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ─── h11 请求解析 ──────────────────────────────────────────────────────

    async def _recv(self, reader: asyncio.StreamReader, conn: h11.Connection) -> bool:
        """读一段入站字节喂给 h11。返回 False = 对端已断开或空闲超预算。

        必须有超时：`reader.read()` 无界等待时，一条僵住的调用方连接会永远占着一个
        `_slots` 名额和一个 httpx 池槽位——两个闸都变成形式。
        """
        data = await asyncio.wait_for(reader.read(65536), timeout=_CLIENT_IDLE_TIMEOUT_S)
        if not data:
            return False
        conn.receive_data(data)
        return True

    async def _read_request_headers(
        self, reader: asyncio.StreamReader, conn: h11.Connection,
    ) -> h11.Request | None:
        """从 reader 读数据，直到拿到完整的 h11.Request。"""
        while True:
            try:
                event = conn.next_event()
            except h11.RemoteProtocolError as e:
                # 畸形请求行/头/超长头：h11 抛异常而不是给事件，这条连接后续无从定界。
                raise _MalformedRequest(str(e)) from e
            if event is h11.NEED_DATA:
                if not await self._recv(reader, conn):
                    return None
            elif isinstance(event, h11.Request):
                return event
            elif isinstance(event, h11.ConnectionClosed):
                return None
            # Data / EndOfMessage 等：先跳过，body 在后面读

    async def _read_request_body(
        self, reader: asyncio.StreamReader, conn: h11.Connection,
    ) -> tuple[bytes, bool]:
        """读到 EndOfMessage，返回 (body, 是否完整)。检查 32 MiB 上限。"""
        body = b""
        while True:
            try:
                event = conn.next_event()
            except h11.RemoteProtocolError as e:
                # 「EOF 撞上未满足的 Content-Length」「坏 chunk 头」在 h11 里是异常而非
                # 事件。语义就是这条请求没发完——折回控制流，外层按残缺处理，
                # 绝不把半截（还可能被截断在敏感位置上的）body 转出去。
                logger.debug("sidecar 请求体解析中断: %s", e)
                return body, False
            if event is h11.NEED_DATA:
                if not await self._recv(reader, conn):
                    return body, False
                continue
            if isinstance(event, h11.Data):
                body += event.data
                if len(body) > _MAX_REQUEST_BODY:
                    return body, False  # 超限，外层按 413 处理
            elif isinstance(event, h11.EndOfMessage):
                return body, True
            elif isinstance(event, h11.ConnectionClosed):
                return body, False

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
        resp: httpx.Response, method: str = "GET",
    ) -> int:
        """把上游响应按**原始字节**转发回调用方，返回 chunk 数。

        必须走 ``aiter_raw``：``aiter_bytes`` 给的是**解压后**的字节，而头部照原样
        带着 ``content-encoding: gzip``——声明 gzip 却送明文，客户端解码当场失败。
        SSE 本来就是明文，只有非流式响应会踩到这个坑，所以它在测试里最容易漏。
        """
        bodyless = method.upper() == "HEAD" or resp.status_code in _BODYLESS_STATUS
        has_length = any(k.lower() == "content-length" for k, _ in resp.headers.items())
        # 三种情况的 framing 不能混：
        #  · HEAD：按 RFC 9110 §4.3.2 保留上游的 `content-length`（它声明的是
        #    「同一请求发 GET 时该有多长」），h11 自己按 0 长度封帧；
        #  · 204/304：无体，`content-length` 与 `chunked` 都不能带；
        #  · 其余：上游给了长度就保真转发（长度又不变，为什么改口说不知道），
        #    只有未知长度（SSE / 上游自己就是 chunked）才切 `chunked`。
        # 此前无条件把非 HEAD 的 `content-length` 换成 `chunked`：对上游声明了长度
        # 的响应没必要，还让 HEAD 与同请求 GET 对不上（同一个 /get，HEAD 报 211、
        # GET 报「不知道」——测试就是这么抓到的）。
        keep_length = has_length and not (bodyless and method.upper() != "HEAD")
        use_chunked = not bodyless and not keep_length
        resp_headers: list[tuple[str, str]] = []
        for k, v in resp.headers.items():
            kl = k.lower()
            if kl in ("transfer-encoding", "connection"):
                continue
            if kl == "content-length" and not keep_length:
                continue
            resp_headers.append((kl, v))
        if use_chunked:
            resp_headers.append(("transfer-encoding", "chunked"))

        h11_resp = h11.Response(status_code=resp.status_code, headers=resp_headers)
        writer.write(conn.send(h11_resp))

        chunk_count = 0
        if not bodyless:
            async for chunk in resp.aiter_raw(4096):
                if chunk:
                    writer.write(conn.send(h11.Data(data=chunk)))
                    chunk_count += 1
                    # 逐块回压：不 drain 的话，慢客户端会让这条连接的缓冲无界增长
                    # （上游是全速发的，只有我们能把它堆起来）。缓冲过高水位时
                    # drain 才会真的等，快客户端仍是零额外往返。
                    await writer.drain()
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
