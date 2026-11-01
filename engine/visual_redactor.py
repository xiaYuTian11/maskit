"""多模态脱敏：图片 / Office 内嵌图 / PDF 页 / 代理链路的像素级打码。

## 形态与边界（2026-10-31 重构）

只有一件事：**把像素里的敏感文字涂掉，其余一切原样**。不做意图判断、不把图转文本、
不猜用户想干什么（这三点都是需求方明确定的，改动前先确认）。

## 坐标从哪来（这是整条链路的地基）

默认走**本地 det+rec OCR**（`engine/ocr_engine.py`，PP-OCR，进程内、零出网）：

- det 给**真框**（实测误差 3~8px），rec 给文字；
- 判定沿用项目已有的规则引擎（`transparent.mask()`），与文本链路同一套命中口径。

留一条 **HTTP 后端**做兼容（自建 OCR 服务 / 老部署）：它的坐标来自模型输出的
`<loc_*>` 标记，实测**标记合规率只有 50%**（`gemini-3.8-flash` 14 行只标 3 行、
还有丢 `loc_` 前缀的），因此 HTTP 路径必须带"标记覆盖率闸门 + 一次重试"，
不达标就阻断。两条后端的下游完全共用（都是 `Block` 列表 → `locator` → 涂色）。

## 打码粒度

**实体级**：只涂敏感子串那几个字符，不是整行。实测整行遮会把 `手机：` 标签也盖掉；
实体级只遮 3.59% 画面，表头/姓名/部门仍完整可读。定位精度靠三件事保证：

1. 东亚宽度加权把行框切开（CJK=2、ASCII=1）；
2. 左右 pad 0.35em（实测宽度加权会偏窄 3~18px，宁可多遮半字也不漏字）；
3. **裁图复认**：把框裁出来再识别一次，实体串必须完整落在框里；
   否则退整行框（计数 `vision_lines_masked`），再不行就阻断。

## 失败语义（只有一种方向：阻断）

扫不了 / 定位不了 → `503 + blocking`（扩展链路）或 `mask_pipeline_failed`（代理链路）。
**不再有"整图遮盖"这条默认退路**——需求方明确：宁可不给图，也不给一张看不懂的废图。
唯一例外是 PDF 单页（整份文档阻断代价更高），见 `pdf_redactor.py`。
"""

import base64
import io
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import locator as _locator

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

OCR_ENDPOINT_ENV = "MASKIT_OCR_ENDPOINT"
# OCR 服务的 Bearer 密钥。只走环境变量，不进 config.json、不进 /api/config、不进事件库。
OCR_API_KEY_ENV = "MASKIT_OCR_API_KEY"
OCR_MODEL_ENV = "MASKIT_OCR_MODEL"
# OCR 后端：auto（有本地引擎就用本地）/ local / http
OCR_ENGINE_ENV = "MASKIT_OCR_ENGINE"

_DEFAULT_OCR_ENDPOINT = "http://127.0.0.1:8082/v1/chat/completions"
_DEFAULT_OCR_MODEL = "xiaomi-ocr-0"
_OCR_TIMEOUT_S = 20.0
_OCR_TOTAL_BUDGET_S = 32.0
_OCR_MAX_TOKENS = 4096
_OCR_MAX_RESPONSE = 4 * 1024 * 1024

MODE_REDACTED = "REDACTED_IMAGE"
MODE_CLEAN = "CLEAN_IMAGE"
MODE_BLOCKED = "BLOCKED"

ST_CLEAN = "clean"
ST_MASKED = "masked"
ST_COVER_UNLOCALIZED = "full_cover_unlocalized"
ST_COVER_UNSUPPORTED = "full_cover_unsupported"
ST_NOT_APPLICABLE = "not_applicable"

BLOCK_PILLOW_MISSING = "pillow_missing"
BLOCK_NOT_LOOPBACK = "ocr_not_loopback"
BLOCK_UNAVAILABLE = "ocr_unavailable"
BLOCK_RUNTIME_MISSING = "ocr_runtime_missing"
BLOCK_TIMEOUT = "ocr_timeout"
BLOCK_BUSY = "ocr_busy"
BLOCK_BAD_RESPONSE = "ocr_bad_response"
BLOCK_TRUNCATED = "ocr_truncated"
BLOCK_GEOMETRY = "geometry_unavailable"
BLOCK_DECODE = "image_decode_failed"
BLOCK_UNSUPPORTED = "unsupported_image_format"
BLOCK_TOO_LARGE = "image_too_large"
BLOCK_BUDGET = "ocr_budget_exhausted"
BLOCK_ENGINE_ERROR = "ocr_engine_error"
BLOCK_ANIMATED = "animated_image_unsupported"
BLOCK_METADATA = "image_metadata_unwritable"

_OK_STATUSES = frozenset({ST_CLEAN, ST_MASKED, ST_COVER_UNLOCALIZED, ST_COVER_UNSUPPORTED})

# 运行时配置（由 panel / transparent 在配置热重载时注入，见 configure）
_CONFIGURED_ENDPOINT = ""
_ALLOW_REMOTE = False
_ENGINE_PREF = "auto"

# 打码填充色：中性灰。不透明是有意的（半透明会把文字透出来），纯黑太刺眼。
_FILL = (128, 128, 128)

_SAVE_FORMATS = frozenset({"PNG", "JPEG", "WEBP", "BMP", "TIFF"})
_EXT_TO_FORMAT = {
    "png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP",
    "bmp": "BMP", "tif": "TIFF", "tiff": "TIFF",
}
RASTER_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff")

# HTTP 后端专用：坐标标记解析（两种写法，见 parse_located_lines）
_LOC_RX = re.compile(r"<loc_(\d{1,6})><loc_(\d{1,6})><loc_(\d{1,6})><loc_(\d{1,6})>")
_LOC_RX_NAMED = re.compile(
    r"<loc_y1>\s*(\d{1,6})\s*<loc_x1>\s*(\d{1,6})\s*"
    r"<loc_y2>\s*(\d{1,6})\s*<loc_x2>\s*(\d{1,6})", re.I)
_LOC_TAG_LEFTOVER_RX = re.compile(r"</?loc_[a-z0-9]+>", re.I)

# HTTP 提示词：实测宽松版标记合规率只有 50%，严格版 3/3（两边模型都验过）。
_OCR_PROMPT = (
    "You are a strict OCR engine. Output every text block on its own line, in this exact form:\n"
    "<loc_y1><loc_x1><loc_y2><loc_x2>text\n"
    "Coordinates are integers 0-1000, normalized to image width/height, with the origin at "
    "the TOP-LEFT of the image; y grows downward and x grows rightward. "
    "The four numbers are y1,x1,y2,x2 (top, left, bottom, right).\n"
    "Never output a line without the four location tokens. If you cannot localize a block, "
    "use <loc_0><loc_0><loc_1000><loc_1000> for it instead of omitting it. "
    "Output only those lines, nothing else."
)

_DATA_URL_RX = re.compile(
    r"^data:([a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*)((?:;[^,]*)?),(.*)$",
    re.I | re.S,
)
_RASTER_MIMES = frozenset({
    "image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp",
    "image/tiff", "image/x-tiff",
})
MAX_DATA_URL_IMAGE_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

def configure(ocr_endpoint=None, allow_remote=None, engine=None):
    """注入运行时配置（面板 / 引擎在配置热重载时调用）。

    本模块不自己读 config.json：它被两个进程（面板 / mitmdump）各自加载，
    路径与锁都不一样；让调用方把已归一化的值推进来，就不会有两份读盘逻辑慢慢漂开。
    """
    global _CONFIGURED_ENDPOINT, _ALLOW_REMOTE, _ENGINE_PREF
    if ocr_endpoint is not None:
        _CONFIGURED_ENDPOINT = str(ocr_endpoint or "").strip()
    if allow_remote is not None:
        _ALLOW_REMOTE = bool(allow_remote)
    if engine is not None:
        choice = str(engine or "").strip().lower()
        _ENGINE_PREF = choice if choice in ("auto", "local", "http") else "auto"


def engine_pref():
    return (os.environ.get(OCR_ENGINE_ENV) or "").strip().lower() or _ENGINE_PREF


def ocr_endpoint():
    """(可用端点, 不可用原因)。环回永远允许；非环回需显式 `ocr_allow_remote`。"""
    url = ((os.environ.get(OCR_ENDPOINT_ENV) or "").strip()
           or _CONFIGURED_ENDPOINT
           or _DEFAULT_OCR_ENDPOINT)
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None, BLOCK_NOT_LOOPBACK
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, BLOCK_NOT_LOOPBACK
    host = parsed.hostname.strip().lower()
    if host in ("localhost", "::1"):
        return url, ""
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url, ""
    except ValueError:
        pass
    if _ALLOW_REMOTE:
        return url, ""
    return None, BLOCK_NOT_LOOPBACK


def _pil():
    try:
        from PIL import Image, ImageDraw  # noqa: F401
        return Image, ImageDraw
    except Exception:
        return None, None


def available():
    """(是否可用, 原因)。按后端偏好判定：local 看引擎、http 看端点。"""
    image, _draw = _pil()
    if image is None:
        return False, BLOCK_PILLOW_MISSING
    pref = engine_pref()
    if pref in ("auto", "local"):
        import ocr_engine
        ok, why = ocr_engine.available()
        if ok:
            return True, ""
        if pref == "local":
            return False, why or BLOCK_RUNTIME_MISSING
    if pref in ("auto", "http"):
        url, why = ocr_endpoint()
        if url:
            return True, ""
        return False, why or BLOCK_UNAVAILABLE
    return False, BLOCK_RUNTIME_MISSING


# ---------------------------------------------------------------------------
# 后端：本地 det+rec / HTTP（兼容）
# ---------------------------------------------------------------------------

def _blocks_local(image_bytes, deadline):
    import ocr_engine
    res = ocr_engine.detect(image_bytes, deadline=deadline)
    return res.blocks, {"backend": "local", "orientation": res.orientation,
                        "ms": res.ms, "downscaled": res.downscaled,
                        "low_conf": len(res.low_conf)}


def _ocr_model():
    return (os.environ.get(OCR_MODEL_ENV) or "").strip() or _DEFAULT_OCR_MODEL


def _ocr_headers():
    headers = {"Content-Type": "application/json"}
    key = (os.environ.get(OCR_API_KEY_ENV) or "").strip()
    if key:
        headers["Authorization"] = "Bearer " + key
    return headers


def _sniff_mime(raw):
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    if raw[:2] == b"BM":
        return "image/bmp"
    if raw[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    return "application/octet-stream"


def query_local_ocr(image_bytes, timeout=None, max_tokens=None):
    """HTTP 后端：`(text, info)`。失败时 text 为 None，info["reason"] 是阻断原因。"""
    url, why = ocr_endpoint()
    if not url:
        return None, {"reason": why, "truncated": False}
    limit = _OCR_TIMEOUT_S if timeout is None else max(0.5, min(_OCR_TIMEOUT_S, timeout))
    budget_tokens = int(max_tokens or _OCR_MAX_TOKENS)
    b64 = base64.b64encode(image_bytes).decode("ascii")
    payload = {
        "model": _ocr_model(),
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": _OCR_PROMPT},
                {"type": "image_url",
                 "image_url": {"url": "data:%s;base64,%s" % (_sniff_mime(image_bytes), b64)}},
            ],
        }],
        "temperature": 0.0,
        "max_tokens": budget_tokens,
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=_ocr_headers())
    try:
        with urllib.request.urlopen(req, timeout=limit) as resp:
            raw = resp.read(_OCR_MAX_RESPONSE)
    except urllib.error.HTTPError as e:
        return None, {"reason": BLOCK_UNAVAILABLE, "truncated": False, "detail": "http %d" % e.code}
    except Exception as e:
        timeout_types = (TimeoutError,)
        try:
            import socket as _socket
            timeout_types = (_socket.timeout, TimeoutError)
        except Exception:
            pass
        reason = BLOCK_TIMEOUT if isinstance(e, timeout_types) else BLOCK_UNAVAILABLE
        return None, {"reason": reason, "truncated": False, "detail": type(e).__name__}
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
        choice = (data.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content")
        if not isinstance(content, str):
            return None, {"reason": BLOCK_BAD_RESPONSE, "truncated": False}
        finish = str(choice.get("finish_reason") or "")
        used = (data.get("usage") or {}).get("completion_tokens")
        truncated = finish == "length" or (isinstance(used, int) and used >= budget_tokens)
        return content, {"reason": "", "truncated": truncated, "finish": finish}
    except Exception:
        return None, {"reason": BLOCK_BAD_RESPONSE, "truncated": False}


def _plain_text(ocr_text):
    """去掉坐标标记（两种写法都抹），行边界用换行保住。"""
    s = _LOC_RX.sub("\n", ocr_text or "")
    s = _LOC_RX_NAMED.sub("\n", s)
    return _LOC_TAG_LEFTOVER_RX.sub("", s).strip()


def _loc_matches(text):
    out = [(m.start(), m.end(), tuple(int(x) for x in m.groups()))
           for m in _LOC_RX.finditer(text)]
    if out:
        return out
    return [(m.start(), m.end(), tuple(int(x) for x in m.groups()))
            for m in _LOC_RX_NAMED.finditer(text)]


def parse_located_lines(ocr_text):
    """HTTP 后端：把 `<loc_*>` 标记解析成 `([(box, text)], localized)`。

    box 是 (y1, x1, y2, x2) 归一化 0~1000（实测顺序，见常量注释）。
    """
    text = ocr_text or ""
    marks = _loc_matches(text)
    if not marks:
        return [], False
    boxes = [(n[0], n[1], n[2], n[3]) for _s, _e, n in marks]
    head = text[:marks[0][0]].strip()
    tail = text[marks[-1][1]:].strip()
    suffix_style = bool(head) and not tail
    lines = []
    if suffix_style:
        prev_end = 0
        for (start, end, _n), box in zip(marks, boxes):
            chunk = text[prev_end:start].strip()
            if chunk:
                lines.append((box, chunk))
            prev_end = end
        if tail:
            if not lines:
                return [], False
            lines[-1] = (lines[-1][0], (lines[-1][1] + " " + tail).strip())
    else:
        for i, (start, end, _n) in enumerate(marks):
            stop = marks[i + 1][0] if i + 1 < len(marks) else len(text)
            chunk = text[end:stop].strip()
            if chunk:
                lines.append((boxes[i], chunk))
        if head:
            if not lines:
                return [], False
            lines[0] = (lines[0][0], (head + " " + lines[0][1]).strip())
    return lines, bool(lines)


def tag_coverage_ok(lines, ocr_text):
    """标记是否覆盖了**所有**文本行（HTTP 后端的必备闸门，见模块 docstring）。"""
    text_lines = [ln for ln in _plain_text(ocr_text).splitlines() if ln.strip()]
    if not text_lines:
        return True
    return len(lines) >= len(text_lines)


def _http_lines_to_blocks(text, img_w, img_h):
    lines, localized = parse_located_lines(text)
    if not localized or not tag_coverage_ok(lines, text):
        return []
    blocks = []
    for (y1, x1, y2, x2), chunk in lines:
        boxes = _locator_box_to_pixels(y1, x1, y2, x2, img_w, img_h)
        if boxes:
            blocks.append((boxes, chunk))
    return blocks


def _locator_box_to_pixels(y1, x1, y2, x2, width, height):
    x1, x2 = sorted((x1, x2))
    y1, y2 = sorted((y1, y2))
    biggest = max(x1, x2, y1, y2)
    scale = 1.0 if biggest <= 1000 else 0.0  # 0.0 = 已是像素
    if scale:
        px1, px2 = x1 * width / 1000.0, x2 * width / 1000.0
        py1, py2 = y1 * height / 1000.0, y2 * height / 1000.0
    else:
        px1, px2, py1, py2 = float(x1), float(x2), float(y1), float(y2)
    px1 = max(0.0, min(float(width), px1))
    px2 = max(0.0, min(float(width), px2))
    py1 = max(0.0, min(float(height), py1))
    py2 = max(0.0, min(float(height), py2))
    if px2 - px1 < 1 or py2 - py1 < 1:
        return None
    return (px1, py1, px2, py2)


def _blocks_http(image_bytes, deadline, max_tokens=None):
    text, info = query_local_ocr(image_bytes, timeout=None, max_tokens=max_tokens)
    if text is None:
        raise _Blocked(info.get("reason") or BLOCK_UNAVAILABLE)
    if info.get("truncated"):
        raise _Blocked(BLOCK_TRUNCATED)
    image, _draw = _pil()
    img = image.open(io.BytesIO(image_bytes))
    lines = _http_lines_to_blocks(text, *img.size)
    if not lines:
        # 标记不全 → 再试一次（HTTP 后端实测会偶发整篇不带标记）
        text2, info2 = query_local_ocr(image_bytes, timeout=None, max_tokens=max_tokens)
        if text2 and not info2.get("truncated"):
            lines = _http_lines_to_blocks(text2, *img.size)
        if not lines:
            raise _Blocked(BLOCK_GEOMETRY)
    import ocr_engine
    return tuple(ocr_engine.Block(quad=tuple(box), text=chunk, score=1.0)
                 for box, chunk in lines), {"backend": "http", "orientation": 0,
                                            "ms": 0.0, "downscaled": False, "low_conf": 0}


class _Blocked(Exception):
    def __init__(self, reason, detail=""):
        self.reason = str(reason or BLOCK_UNAVAILABLE)
        self.detail = str(detail or "")
        super().__init__(self.reason)


def detect_blocks(image_bytes, *, deadline=None, max_tokens=None):
    """按后端偏好产出 `(blocks, info)`。任何失败都抛 `_Blocked`。"""
    pref = engine_pref()
    import ocr_engine
    if pref in ("auto", "local"):
        ok, why = ocr_engine.available()
        if ok:
            try:
                return _blocks_local(image_bytes, deadline)
            except ocr_engine.OcrError as e:
                raise _Blocked(e.reason, e.detail)
        if pref == "local":
            raise _Blocked(why or BLOCK_RUNTIME_MISSING)
    url, why = ocr_endpoint()
    if not url:
        raise _Blocked(why or BLOCK_UNAVAILABLE)
    return _blocks_http(image_bytes, deadline, max_tokens=max_tokens)


# ---------------------------------------------------------------------------
# 解码 / 编码 / 涂色
# ---------------------------------------------------------------------------

def _load_image(image_bytes):
    """`(img, why)`：解码 + 像素闸 + EXIF 摆正。元数据/帧数见 `_load_image_ex`。"""
    img, why, _meta, _frames = _load_image_ex(image_bytes)
    return img, why


def _load_image_ex(image_bytes):
    """`(img, why, 元数据, 帧数)`。元数据是 `_ImageMeta`（解码失败时为 None）。"""
    image, _draw = _pil()
    if image is None:
        return None, BLOCK_PILLOW_MISSING, None, 1
    try:
        img = image.open(io.BytesIO(image_bytes))
        # 与 ocr_engine 同一道像素闸，且在 load() 之前：这里是第二次解码（用于涂色），
        # 不判的话 HTTP 后端路径会绕过 OCR 引擎的检查。
        import ocr_engine
        w, h = img.size
        if w * h > ocr_engine.MAX_PIXELS:
            return None, BLOCK_TOO_LARGE, None, 1
        img.load()
        # 元数据要在摆正之前取：exif_transpose 返回新对象，`.info` 会被改写或丢弃。
        meta = _ImageMeta.read(img)
        frames = int(getattr(img, "n_frames", 1) or 1)
        # 与 ocr_engine._decode 同口径按 EXIF 摆正：OCR 的框是「摆正后」的坐标，
        # 这里不摆正就是把框画在躺着的像素上（实测 Orientation=6 的手机照片
        # 复认全失败 → 503 geometry_unavailable，等于手机拍的图一律传不了）。
        # 输出里方向标签会写成 1（见 _ImageMeta.save_kwargs），所以摆正后的像素就是用户看到的方向。
        from PIL import ImageOps
        fmt = img.format
        img = ImageOps.exif_transpose(img) or img
        if fmt and not getattr(img, "format", None):
            try:
                img.format = fmt   # 保住输出格式判定（exif_transpose 返回新对象）
            except Exception:
                pass
        return img, "", meta, frames
    except image.DecompressionBombError:
        return None, BLOCK_TOO_LARGE, None, 1
    except Exception:
        return None, BLOCK_DECODE, None, 1


# ---------------------------------------------------------------------------
# 图片元数据：只替换命中的文字，其余原样保留
# ---------------------------------------------------------------------------
#
# 为什么不整份剥掉：元数据是用户文件的一部分（作者、标题、拍摄参数、色彩配置），
# 打码只该动敏感值。曾经「命中就整份不带」会连 ICC 色彩配置一起丢，图片偏色。
# 口径与文字链路一致：命中的值换成占位符（可被还原），没命中的字节不动。

# info 里的非文字键：不扫、原样传给编码器（它们不含用户文字）。
_INFO_BINARY_KEYS = frozenset({
    "icc_profile", "exif", "dpi", "transparency", "gamma", "duration", "loop",
    "background", "interlace", "progressive", "progression", "jfif", "jfif_version",
    "jfif_unit", "jfif_density", "aspect", "adobe", "adobe_transform", "srgb",
    "chromaticity", "compression", "version", "extension", "disposal", "optimize",
})
# EXIF 里的文字标签（主 IFD）：描述/制造商/型号/软件/作者/版权/文档名 + Windows XP* 系列。
_EXIF_ASCII_TAGS = (0x010D, 0x010E, 0x010F, 0x0110, 0x0131, 0x013B, 0x8298)
_EXIF_XP_TAGS = (0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F)       # UTF-16LE
_EXIF_SUBIFD = 0x8769
_EXIF_USER_COMMENT = 0x9286                                    # 8 字节编码前缀
_EXIF_SUB_ASCII_TAGS = (0xA430, 0xA431, 0xA433, 0xA434, 0xA435)  # 机主名/序列号/镜头
_EXIF_ORIENTATION = 0x0112
_META_MAX_TEXT = 64 * 1024


class _ImageMeta(object):
    """一张图的元数据快照：可扫的文字字段 + 编码时要原样带上的二进制字段。"""

    def __init__(self):
        self.text_info = {}       # info 里的文字键（PNG tEXt/iTXt、comment、XMP 等）
        self.exif = None          # PIL Exif 对象（含全部标签）
        self.binary_info = {}     # icc_profile / dpi 等
        self.oriented = False     # 是否已按 EXIF 摆正（输出时方向标签要置 1）
        self.hits = 0

    @classmethod
    def read(cls, img):
        meta = cls()
        try:
            for key, val in (img.info or {}).items():
                if key in _INFO_BINARY_KEYS:
                    if key != "exif":
                        meta.binary_info[key] = val
                    continue
                if isinstance(val, (str, bytes)):
                    meta.text_info[key] = val
        except Exception:
            pass
        try:
            exif = img.getexif()
            if len(exif):
                meta.exif = exif
                meta.oriented = exif.get(_EXIF_ORIENTATION, 1) not in (1, None)
        except Exception:
            meta.exif = None
        return meta

    # ---- 文字替换 ----

    @staticmethod
    def _sub(text, mask_fn):
        """`(新文字, 是否命中)`。判定异常上抛（由调用方阻断，绝不当没命中）。"""
        if not text or not text.strip() or len(text) > _META_MAX_TEXT:
            # 超长文字不是「不扫」而是「扫不完」：交给调用方按失败处理
            if text and len(text) > _META_MAX_TEXT:
                raise ValueError("metadata_text_too_long")
            return text, False
        out = mask_fn(text)
        return out, out != text

    def mask(self, mask_fn):
        """就地替换全部文字字段，返回命中数。"""
        hits = 0
        for key, val in list(self.text_info.items()):
            if isinstance(val, bytes):
                text = val.decode("utf-8", "replace")
                new, hit = self._sub(text, mask_fn)
                if hit:
                    self.text_info[key] = new.encode("utf-8")
            else:
                new, hit = self._sub(val, mask_fn)
                if hit:
                    self.text_info[key] = new
            hits += hit
        if self.exif is not None:
            hits += self._mask_exif(mask_fn)
        self.hits = hits
        return hits

    def _mask_exif(self, mask_fn):
        hits = 0
        exif = self.exif
        for tag in _EXIF_ASCII_TAGS:
            val = exif.get(tag)
            if isinstance(val, bytes):
                val = val.decode("utf-8", "replace")
            if isinstance(val, str):
                new, hit = self._sub(val.rstrip("\x00"), mask_fn)
                if hit:
                    exif[tag] = new
                    hits += 1
        for tag in _EXIF_XP_TAGS:
            val = exif.get(tag)
            if isinstance(val, (bytes, tuple)):
                raw = bytes(val)
                new, hit = self._sub(raw.decode("utf-16-le", "replace").rstrip("\x00"), mask_fn)
                if hit:
                    exif[tag] = new.encode("utf-16-le") + b"\x00\x00"
                    hits += 1
        try:
            sub = exif.get_ifd(_EXIF_SUBIFD)
        except Exception:
            sub = {}
        if sub:
            val = sub.get(_EXIF_USER_COMMENT)
            if isinstance(val, bytes) and len(val) > 8:
                prefix, body = val[:8], val[8:]
                enc = "utf-16-le" if prefix.startswith(b"UNICODE") else "utf-8"
                new, hit = self._sub(body.decode(enc, "replace").rstrip("\x00"), mask_fn)
                if hit:
                    sub[_EXIF_USER_COMMENT] = prefix + new.encode(enc)
                    hits += 1
            elif isinstance(val, str):
                new, hit = self._sub(val, mask_fn)
                if hit:
                    sub[_EXIF_USER_COMMENT] = new
                    hits += 1
            for tag in _EXIF_SUB_ASCII_TAGS:
                val = sub.get(tag)
                if isinstance(val, str):
                    new, hit = self._sub(val.rstrip("\x00"), mask_fn)
                    if hit:
                        sub[tag] = new
                        hits += 1
        return hits

    # ---- 编码 ----

    def save_kwargs(self, fmt):
        """给 `Image.save` 的元数据参数：原样带回（已替换的字段用新值）。"""
        kw = {}
        for key in ("icc_profile", "dpi"):
            if key in self.binary_info and fmt in ("PNG", "JPEG", "WEBP", "TIFF"):
                kw[key] = self.binary_info[key]
        if self.exif is not None and fmt in ("PNG", "JPEG", "WEBP", "TIFF"):
            if self.oriented:
                # 像素已摆正：标签还写 6 的话看图软件会再转一次（得到横躺的图）。
                self.exif[_EXIF_ORIENTATION] = 1
            # 序列化失败（厂商私有标签等）上抛：退回原 EXIF 可能带着没替换的敏感值，
            # 悄悄不带又等于删掉用户的元数据，两条都不对，交给调用方阻断。
            kw["exif"] = self.exif.tobytes()
        if fmt == "PNG" and self.text_info:
            from PIL import PngImagePlugin
            info = PngImagePlugin.PngInfo()
            for key, val in self.text_info.items():
                if key == "xmp" or key == "XML:com.adobe.xmp":
                    info.add_itxt("XML:com.adobe.xmp", val.decode("utf-8", "replace")
                                  if isinstance(val, bytes) else val)
                elif isinstance(val, bytes):
                    info.add_text(str(key), val.decode("utf-8", "replace"))
                else:
                    # 非 Latin-1 内容 PIL 会自动转 iTXt
                    info.add_text(str(key), val)
            kw["pnginfo"] = info
        elif fmt in ("JPEG", "WEBP"):
            for key in ("comment", "xmp"):
                if key in self.text_info:
                    val = self.text_info[key]
                    kw[key] = val.encode("utf-8") if isinstance(val, str) else val
        elif fmt == "GIF" and "comment" in self.text_info:
            kw["comment"] = self.text_info["comment"]
        return kw


def _encode(img, fmt, meta=None):
    """重新编码。`meta` 给了就把元数据（替换后）原样带回。"""
    buf = io.BytesIO()
    kw = meta.save_kwargs(fmt) if meta is not None else {}
    if fmt == "JPEG":
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img.save(buf, format="JPEG", quality=95, subsampling=0, **kw)
    else:
        img.save(buf, format=fmt, **kw)
    return buf.getvalue()


def _output_format(img, hint_name):
    fmt = str(getattr(img, "format", "") or "").upper()
    if fmt == "MPO":
        fmt = "JPEG"
    if fmt in _SAVE_FORMATS:
        return fmt
    ext = os.path.splitext(hint_name or "")[1].lower().lstrip(".")
    return _EXT_TO_FORMAT.get(ext, "PNG")


def _paint(img, rects):
    _image, ImageDraw = _pil()
    if ImageDraw is None:
        return False
    draw = ImageDraw.Draw(img)
    for rect in rects:
        draw.rectangle([rect[0], rect[1], max(rect[0], rect[2] - 1), max(rect[1], rect[3] - 1)],
                       fill=_FILL)
    return True


# ---------------------------------------------------------------------------
# 核心：一张图 → 打码后的图
# ---------------------------------------------------------------------------

def redact_image_bytes(image_bytes, sid, tr, *, deadline=None, hint_name="",
                       max_tokens=None, allow_cover=False):
    """核心入口。返回 dict：

    - `mode`: `MODE_REDACTED` / `MODE_CLEAN` / `MODE_BLOCKED`
    - `bytes`: 新图（CLEAN 时为原字节，零触碰）
    - `format`: 输出格式
    - `hit_count`: 打码的实体数
    - `stats`: `{entities, verified, line_fallback, failed, low_conf, backend, orientation, ms}`
    - `reason`: BLOCKED 时的原因码
    """
    ok, why = available()
    if not ok:
        return {"mode": MODE_BLOCKED, "reason": why, "stats": {}, "hit_count": 0, "bytes": b""}
    img, decode_why, meta, frames = _load_image_ex(image_bytes)
    if img is None:
        return {"mode": MODE_BLOCKED, "reason": decode_why, "stats": {},
                "hit_count": 0, "bytes": b""}
    if frames > 1:
        # 动图（GIF/WebP/APNG）：OCR 只看得到第一帧。实测敏感值只在第 2 帧时被判「干净」
        # 原样上行。逐帧扫描的代价与帧数线性、且这类图很少是业务截图，所以直接阻断。
        return {"mode": MODE_BLOCKED, "reason": BLOCK_ANIMATED, "stats": {"frames": frames},
                "hit_count": 0, "bytes": b""}
    if deadline is None:
        deadline = time.monotonic() + _OCR_TOTAL_BUDGET_S
    # 输出格式要在 convert 之前取：PIL 的 convert() 返回新对象，`.format` 会丢，
    # 之后就只能靠扩展名猜——JPEG 被写成 PNG 会让 Word/WPS 显示损坏图片。
    fmt_out = _output_format(img, hint_name)
    img = img.convert("RGB")

    try:
        blocks, info = detect_blocks(image_bytes, deadline=deadline, max_tokens=max_tokens)
    except _Blocked as e:
        return {"mode": MODE_BLOCKED, "reason": e.reason, "stats": {}, "hit_count": 0,
                "bytes": b""}

    img = img.convert("RGB") if img.mode not in ("RGB", "L") else img
    rects, locator_stats = _locator.locate(blocks, lambda t: _mask_text(tr, t, sid),
                                          img=img, recognize=_recognize, deadline=deadline)
    # 先铺后端信息（backend/orientation/ms/…），再叠加定位统计：
    # 两者都有 low_conf 这类同名键，**定位统计必须赢**（它才是"本次没被采纳的块"）。
    stats = dict(info)
    stats.update(locator_stats)

    # 元数据里的文字先替换（与像素是否命中无关）：只换命中的值，其余原样带回。
    # 判定异常 → 阻断（与像素判定同口径：不确定有没有就不放行）。
    meta_hits = 0
    if meta is not None:
        try:
            meta_hits = meta.mask(lambda t: _mask_text(tr, t, sid))
        except Exception:
            return {"mode": MODE_BLOCKED, "reason": BLOCK_METADATA, "stats": stats,
                    "hit_count": 0, "bytes": b""}
    if meta_hits:
        stats["metadata_masked"] = meta_hits

    if stats.get("failed"):
        if allow_cover:
            # 只给 PDF 页留这一级（整份文档阻断代价更高）；图片/OOXML 一律阻断。
            _paint(img, [(0, 0, img.size[0], img.size[1])])
            return _encoded_or_block(img, fmt_out, meta, {
                "mode": MODE_REDACTED, "format": fmt_out,
                "hit_count": stats.get("entities") or 1,
                "stats": dict(stats, covered=True), "reason": ""})
        return {"mode": MODE_BLOCKED, "reason": BLOCK_GEOMETRY, "stats": stats,
                "hit_count": 0, "bytes": b""}

    if not rects:
        if meta_hits:
            # 像素干净、元数据命中：像素不动，只换元数据里的那几个值。
            return _encoded_or_block(img, fmt_out, meta, {
                "mode": MODE_REDACTED, "format": fmt_out, "hit_count": meta_hits,
                "stats": stats, "reason": "", "items": ()})
        # 一个字都没命中：原字节返回（零触碰）
        return {"mode": MODE_CLEAN, "bytes": image_bytes, "format": "", "hit_count": 0,
                "stats": stats, "reason": "", "truncated": False}

    fmt = fmt_out
    if not _paint(img, [r.quad for r in rects]):
        return {"mode": MODE_BLOCKED, "reason": BLOCK_GEOMETRY, "stats": stats,
                "hit_count": 0, "bytes": b""}
    return _encoded_or_block(img, fmt, meta, {
        "mode": MODE_REDACTED, "format": fmt,
        "hit_count": len(rects) + meta_hits, "stats": stats, "reason": "",
        "items": tuple({"quad": r.quad, "span": r.charspan, "label": r.label,
                        "verified": r.verified, "fallback": r.fallback} for r in rects)})


def _encoded_or_block(img, fmt, meta, result):
    """带元数据编码；元数据写不回去时阻断（既不带原值、也不悄悄丢掉用户的元数据）。"""
    try:
        data = _encode(img, fmt, meta)
    except Exception:
        return {"mode": MODE_BLOCKED, "reason": BLOCK_METADATA,
                "stats": result.get("stats") or {}, "hit_count": 0, "bytes": b""}
    result["bytes"] = data
    return result


# 长数字串：OCR 常把空格吃掉（实测 `row00<号码>note-00` 粘连成一个串 →
# `row0013800138000note-00`），于是 `(?<!\d)` 这条边界失效、手机号规则不再命中——
# 那是**真漏遮**。所以对 OCR 文本补一道"数字串复判"：
#   ① 整段串先试一次（多数情况直接命中）；
#   ② 不命中就滑动窗口试 18/15/11 位（手机号/身份证就藏在前缀数字后面）；
#   ③ 窗口命中 → **把整段串替换成该窗口的占位符**（宁可多遮几个字符，也不留半截）。
# 引擎认不出的串（如 `20261031120000` 时间戳）保持原样，不制造误伤。
_DIGIT_RUN_RX = re.compile(r"\d{11,}")
_DIGIT_WINDOWS = (18, 15, 11)


def _mask_digit_run(run, mask_fn, sid):
    """返回该数字串的占位符（整段替换），或 None（引擎认为不敏感）。"""
    # 判定异常**上抛**（→ MaskFailed → 阻断）：静默保留原串就是放行未判定的号码。
    masked = mask_fn(run, sid)
    if masked != run:
        return masked
    for size in _DIGIT_WINDOWS:
        if size > len(run):
            continue
        for i in range(0, len(run) - size + 1):
            window = run[i:i + size]
            masked = mask_fn(window, sid)
            if masked != window:
                return masked
    return None


def _mask_text(tr, text, sid):
    """用项目已有的规则引擎判定（与文本链路同源）+ 数字串边界补偿。"""
    mask_fn = tr.mask if hasattr(tr, "mask") else tr.mask_body
    out = mask_fn(text, sid)
    if not _DIGIT_RUN_RX.search(out):
        return out

    def repl(m):
        replaced = _mask_digit_run(m.group(0), mask_fn, sid)
        return replaced if replaced else m.group(0)

    return _DIGIT_RUN_RX.sub(repl, out)


def _recognize(payload, deadline=None):
    """裁图复认。本地后端用 ocr_engine；HTTP 后端退回 query_local_ocr 的纯文本。"""
    import ocr_engine
    ok, _why = ocr_engine.available()
    if ok and engine_pref() in ("auto", "local"):
        return ocr_engine.recognize(payload, deadline=deadline)
    text, info = query_local_ocr(payload, timeout=None)
    if text is None:
        raise _Blocked(info.get("reason") or BLOCK_UNAVAILABLE)
    return _plain_text(text)


# ---------------------------------------------------------------------------
# 对外三种载体：独立图片 / 内嵌图 / data URL
# ---------------------------------------------------------------------------

def process_image_multimodal(image_bytes, sid, tr, deadline=None, max_tokens=None,
                            allow_cover=False):
    """独立图片（上传/截图/图片消息）。

    `allow_cover` 只给 PDF 页用：定位失败时整页遮盖而不是阻断（整份文档阻断代价更高）。
    图片与 OOXML 内嵌图一律传 False —— 宁可阻断，也不给一张看不懂的废图。
    """
    return redact_image_bytes(image_bytes, sid, tr, deadline=deadline,
                              max_tokens=max_tokens, allow_cover=allow_cover)


def mask_embedded_image_bytes(image_bytes, sid, tr, deadline=None, hint_name=""):
    """Office 内嵌媒体：`(新字节, 命中数, 状态)`。

    与独立图片同一条链路；差别只有失败语义：载体本身不支持（矢量图/损坏图）
    仍然换**占位图**（像素零保留、文档结构不坏），而"有敏感内容但定位失败"一律阻断。
    """
    ext = os.path.splitext(hint_name or "")[1].lower()
    if ext and ext not in RASTER_IMAGE_EXTS:
        image, _draw = _pil()
        if image is None:
            return image_bytes, 0, BLOCK_PILLOW_MISSING
        placeholder = image.new("RGB", (480, 320), _FILL)
        buf = io.BytesIO()
        placeholder.save(buf, "PNG")
        return buf.getvalue(), 1, ST_COVER_UNSUPPORTED

    res = redact_image_bytes(image_bytes, sid, tr, deadline=deadline, hint_name=hint_name)
    mode = res.get("mode")
    if mode == MODE_BLOCKED:
        return image_bytes, 0, res.get("reason") or BLOCK_GEOMETRY
    if mode == MODE_CLEAN:
        return image_bytes, 0, ST_CLEAN
    stats = res.get("stats") or {}
    status = ST_COVER_UNLOCALIZED if stats.get("covered") else ST_MASKED
    return res.get("bytes") or image_bytes, int(res.get("hit_count") or 1), status


def mask_data_url(value, sid, tr, deadline=None, max_bytes=None, stats_out=None):
    """`data:image/...;base64,` 里的像素脱敏（代理链路 / 扩展链路共用）。

    返回 `(新值, 命中数, 状态)`；状态见模块常量。非图片载体返回 `ST_NOT_APPLICABLE`，
    调用方保持原有豁免逻辑。
    """
    if not isinstance(value, str):
        return value, 0, ST_NOT_APPLICABLE
    m = _DATA_URL_RX.match(value)
    if not m:
        return value, 0, ST_NOT_APPLICABLE
    mime = m.group(1).lower()
    params = (m.group(2) or "").lower()
    payload = m.group(3) or ""
    if "base64" not in params:
        return value, 0, ST_NOT_APPLICABLE
    if not mime.startswith("image/"):
        return value, 0, ST_NOT_APPLICABLE
    if mime not in _RASTER_MIMES:
        return value, 0, BLOCK_UNSUPPORTED
    limit = MAX_DATA_URL_IMAGE_BYTES if max_bytes is None else max(1024, int(max_bytes))
    if len(payload) * 3 // 4 > limit:
        return value, 0, BLOCK_TOO_LARGE
    try:
        raw = base64.b64decode(payload, validate=False)
    except Exception:
        return value, 0, BLOCK_DECODE
    if len(raw) > limit:
        return value, 0, BLOCK_TOO_LARGE

    res = redact_image_bytes(raw, sid, tr, deadline=deadline)
    mode = res.get("mode")
    if mode == MODE_BLOCKED:
        return value, 0, res.get("reason") or BLOCK_GEOMETRY
    if mode == MODE_CLEAN:
        return value, 0, ST_CLEAN
    out = res.get("bytes") or b""
    if not out:
        return value, 0, BLOCK_DECODE
    if stats_out is not None:
        # 把定位统计（自校验/退整行）带给调用方：代理链路的 "已遮但退成整行" 必须在
        # 事件里看得见，否则用户只看到"日志里一个数字"。
        stats_out.update(res.get("stats") or {})
    return "data:%s;base64,%s" % (mime, base64.b64encode(out).decode("ascii")), \
        int(res.get("hit_count") or 1), ST_MASKED


def is_ok_status(status):
    return status in _OK_STATUSES
