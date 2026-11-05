"""Output-limited HTTP content decoding, without mitmproxy's global body cache.

Only supported HTTP content codings are accepted. No fallback invokes an unbounded
codec. Callers bound wire input separately and run this helper off the event loop.
Returned output is at most ``limit``; transient output is at most two such buffers
plus Brotli's <=64 KiB native output-chunk slack. The zstd codec decodes via
backports.zstd (mitmproxy 12.3.1's own zstd backend, so codec semantics stay
identical to the proxy's), with its native window capped at 32 MiB (Brotli's
standard maximum is 16 MiB).
"""
import io
import zlib

import brotli
from backports import zstd


MAX_WINDOW_BYTES = 32 * 1024 * 1024


class BodyDecodeLimit(ValueError):
    """Decoded output exceeds its explicitly admitted ceiling."""


def _check(data, limit):
    if len(data) > limit:
        raise BodyDecodeLimit("aux decoded body limit exceeded")
    return data


def _inflate(raw, limit, wbits, *, complete=False):
    decoder = zlib.decompressobj(wbits)
    data = _check(decoder.decompress(raw, limit + 1), limit)
    # Never flush(): its argument is an initial buffer size, NOT an output limit.
    # gzip in mitmproxy accepts truncated streams and ignores trailing members;
    # deflate uses zlib.decompress and therefore requires a complete first stream.
    if complete and not decoder.eof:
        raise zlib.error("incomplete deflate stream")
    return data


def decode_body(raw: bytes, content_encoding: str, limit: int) -> bytes:
    """Decode once within an output ceiling, matching mitmproxy HTTP codec rules."""
    if limit < 0:
        raise ValueError("negative decoded body limit")
    kind = (content_encoding or "identity").lower()
    if kind in ("identity", "none"):
        return _check(raw, limit)
    if kind not in ("gzip", "deflate", "deflateraw", "br", "zstd"):
        raise ValueError("unsupported HTTP content encoding")
    if not raw:
        return b""
    try:
        if kind == "gzip":
            # mitmproxy accepts both gzip and zlib wrappers for this header.
            return _inflate(raw, limit, 47)
        if kind in ("deflate", "deflateraw"):
            try:
                return _inflate(raw, limit, zlib.MAX_WBITS, complete=True)
            except zlib.error:
                return _inflate(raw, limit, -zlib.MAX_WBITS, complete=True)
        if kind == "zstd":
            # @guard G601 与 mitmproxy 12.3.1 同库（backports.zstd）同语义：截断流与
            # 尾随垃圾必须报错（zstandard 的 stream_reader 会宽容收下部分输出），
            # 拼接帧完整穿越。旧 zstandard 实现对这些边界与 mitmproxy 12.3.1 分叉，
            # 语义对齐测试（test_body_buffer）已抓过这个漂移。
            # read(limit+1) 是流式部分读：输出超限时只产出 limit+1 字节即停，
            # 不是先解压完再截断（无声明 content-size 的帧同样有界）；
            # window_log_max 由 MAX_WINDOW_BYTES 推导（bit_length-1 = log2），
            # 保留大窗口炸弹防线，与旧实现的 max_window_size 等价。
            _opts = {zstd.DecompressionParameter.window_log_max:
                     MAX_WINDOW_BYTES.bit_length() - 1}
            with zstd.open(io.BytesIO(raw), "rb", options=_opts) as _zreader:
                return _check(_zreader.read(limit + 1), limit)
        decoder = brotli.Decompressor()
        if not hasattr(decoder, "can_accept_more_data"):
            raise ValueError("Brotli 1.2 output-limited decoder required")
        parts, size, pending = [], 0, raw
        while True:
            # Brotli 1.2 rounds its output buffer to native chunks; check the
            # returned size too. Older bindings reject this keyword: fail closed.
            chunk = decoder.process(pending, output_buffer_limit=limit - size + 1)
            size += len(chunk)
            if size > limit:
                raise BodyDecodeLimit("aux decoded body limit exceeded")
            parts.append(chunk)
            if decoder.is_finished():
                return b"".join(parts)
            if not chunk and decoder.can_accept_more_data():
                raise ValueError("incomplete Brotli stream")
            # All wire bytes were supplied once; drain buffered output only.
            pending = b""
    except BodyDecodeLimit:
        raise
    except Exception as exc:
        # Do not put wire/plaintext bodies in diagnostics.
        raise ValueError("invalid or unsupported bounded %s body" % kind) from exc
