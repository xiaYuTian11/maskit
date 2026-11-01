"""本地 OCR 引擎（det + rec，进程内，零出网）。

## 为什么是 det+rec，而不是"让视觉模型报坐标"

2026-10-31 受控实测（真值 y=50/200/350）：

| 来源 | 返回 | 判定 |
|---|---|---|
| 网关上的 `OCR` / `xiaomi-ocr-0`（聊天包装） | y=190/390/590（等步长）、或 100/200/300 | **按行号编造**，不是检测 |
| PaddleOCR `<\\|det\\|>` 原生 token | `\\| \\| \\| \\|` | 网关吞掉了 det token |
| **本模块（PP-OCR det+rec）** | y=56/205/357 | 真检测，误差 3~8px |

坐标不可信 → 打码只有两条死路：框错（漏遮）或整图变灰（废图）。所以坐标必须来自
检测头，文字来自识别头，判定交给项目已有的规则引擎（`transparent.mask()`）。

## 设计要点（每条都有实测依据）

1. **方向兜底**：实测 0/180/270 可读、**90° 严重降级**（cls 只纠 180°）。所以 0° 先跑，
   只在"结果为空/过短/全低分"时才试 90/180/270，取文本量最大者。正常图不付 4× 代价。
2. **降采样**：8.6MP（4K 截图）实测 4.9s，降到 1600px 宽约 1s。超过 4MP 才降，
   且**框必须映射回原图坐标**（否则打码会飘）。
3. **少量 worker + 有界等待**：后端 `intra_op=1`，每个 worker 只占 1 核。2026-11 压测
   （12 核，20 并发×20 张）：2 worker 墙钟 9.1s、4 worker 6.2s，无一失败；再多收益递减且
   抢面板/代理链路的 CPU。worker 数取 `min(4, cpu//2)`，至少 1。排队超过
   `QUEUE_WAIT_S` 就 `ocr_busy` 阻断（实测 ≤20 并发 0 失败，50 并发约半数 busy）。
4. **低分块不参与判定但计数**：`MIN_SCORE` 以下的块不拿来打码（避免把噪点当文字），
   但要计数上报——"可能有内容没扫清"必须可见，不能静默。
5. **异常一律映射成原因码**：损坏图片、依赖缺失、超时都不向调用方抛裸异常，
   由上层按 fail-closed 处理。

## 后端

`rapidocr-onnxruntime`（PP-OCR det+rec，Apache-2.0 系；模型 13.1MB，常驻 ~100MB）。
它**不随主包分发**（见 DESIGN-multimodal-ocr-2026-10-31.md §8 运行时包方案），
所以本模块必须能"没装也不炸"：`available()` 返回不可用原因，上层据此把开关降级。
"""

import io
import os
import threading
import time
from dataclasses import dataclass

# ---- 常量（阈值都来自实测，改动请连带更新 DESIGN 文档与 tests）----
MIN_SCORE = 0.5                    # 低于此分的块不参与打码判定
MAX_SIDE_PX = 1600                 # 降采样目标（长边）
DOWNSAMPLE_ABOVE_PX = 4_000_000    # 超过 4MP 才降（小图降采样得不偿失）
MAX_PIXELS = 16_000_000            # 像素上限（16MP）。**字节数挡不住纯色大图**
                                   # （6000x3000 白底 PNG 只有几百 KB，解码后是 54MB 位图×2）。
                                   # 超过直接阻断，原因码 image_too_large。
MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 与 visual_redactor 的 data URL 上限一致
ORIENTATIONS = (0, 90, 180, 270)
LOW_TEXT_CHARS = 4                 # 0° 结果少于这么多字符 → 认为不可信，试方向
# 长图必须切片：整图缩到 1600px 长边时，1080x8640 的聊天长截图里 24px 的字只剩 4.4px，
# 实测 80 行里漏 8 行的号码（漏检=泄露）。切 1600px 高、120px 重叠后 80/80 全中。
TILE_HEIGHT = 1600
TILE_OVERLAP = 120
MAX_TILES = 16
# det 召回空洞（2026-11-01 实测）：rapidocr 默认对**宽高比 > 8** 的图跳过检测、把整图
# 当一行送识别——拿不到行框，后面的实体定位只能失败；而宽高比 7~10、文字贴近上下边
# 的单行截图（如 1100x120 里一行 30px 字），det 直接返回空 → 误判「干净」原图上行。
# 16 组合扫描里原样漏 5、只关比例闸漏 6、只加白边漏 3；两者同时做 77 组合 0 漏。
# 白边取 `clamp(短边, 32, 96)`：实测 44px 字在 57px 高的图上要 ≥48px 白边才稳。
# 加在送检前、框再减回偏移，所以对调用方透明。
DET_PAD_MIN = 32
DET_PAD_MAX = 96
QUEUE_WAIT_S = 10.0                # 等 worker 的上限；等不到 = 忙（提高到 10s，支持高并发排队）

# 失败原因（与 panel/visual_redactor 的 BLOCK_* 同名字符串）
REASON_RUNTIME_MISSING = "ocr_runtime_missing"
REASON_DECODE = "image_decode_failed"
REASON_TIMEOUT = "ocr_timeout"
REASON_BUSY = "ocr_busy"
REASON_TOO_LARGE = "image_too_large"
REASON_ENGINE_ERROR = "ocr_engine_error"  # 推理期崩溃（onnxruntime 内部异常、模型文件中途损坏）
REASON_EMPTY = ""                  # 不报错：图里就是没文字


class OcrError(Exception):
    """带原因码的 OCR 失败。reason 直接用 BLOCK_* 口径，便于事件与提示复用。"""

    def __init__(self, reason, detail=""):
        self.reason = str(reason or REASON_DECODE)
        self.detail = str(detail or "")
        super().__init__(self.reason + ((": " + self.detail) if self.detail else ""))


@dataclass(frozen=True)
class Block:
    """一个文本块。`quad` 是**原图像素**坐标 (x1, y1, x2, y2)，原点左上。"""

    quad: tuple
    text: str
    score: float


@dataclass(frozen=True)
class DetectResult:
    blocks: tuple
    orientation: int          # 实际采用的方向（0/90/180/270）
    ms: float
    downscaled: bool          # 是否走过降采样（便于定位"小字漏检"）

    @property
    def text(self):
        return "".join(b.text for b in self.blocks)

    @property
    def low_conf(self):
        return tuple(b for b in self.blocks if b.score < MIN_SCORE)


# ---- 后端单例与串行化 ----
_ENGINE = None
_ENGINE_LOCK = threading.Lock()
# 并发度：按核数自适应、上限 4。
# 实测（12 核）：4 个并发调用的**总墙钟 2709ms**，而单次调用就要 ~2700ms ——
# 也就是说 4 张图在"一张的工夫"里跑完了，吞吐 ≈ 4×（早前把这条读成"并发不加速"
# 是误读，据此写的 WORKERS=1 会让 20 并发请求排成 2s×N，直接撞 ocr_busy）。
# 上限 4 而不是吃满核数：每个并发调用都持有一张解码后的图（内存 ∝ 并发），
# 且面板/代理链路与它同进程，不能让 OCR 把核占完。
WORKERS = max(1, min(4, (os.cpu_count() or 2) // 2))
_SEM = threading.Semaphore(WORKERS)
_WARMED = [False]
# 最近一次后端加载失败的真实异常（诊断用）：此前 `except Exception: return
# REASON_RUNTIME_MISSING` 把它吞掉，冻结引擎上组件 import 失败只能看到
# 「ocr_runtime_missing」，分不清是路径没挂上、缺标准库模块还是 DLL 加载失败
# （2026-11-01 实测：官方引擎自检失败，真实异常无任何整条链路可见）。
# 只取类型名与消息前 200 字，不携带路径之外的敏感信息。
_LOAD_ERROR = ""


def _load_backend():
    """惰性加载后端。返回 (engine, "") 或 (None, reason)。"""
    global _ENGINE, _LOAD_ERROR
    if _ENGINE is not None:
        return _ENGINE, ""
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE, ""
        # 组件可能装在数据目录（可选运行时包，见 ocr_runtime.py）：先把它的
        # site-packages 挂进 sys.path，再尝试导入。系统里预装（服务器/Docker）时
        # 这一步是 no-op。
        try:
            import ocr_runtime
            ocr_runtime._ensure_on_syspath()
        except Exception:
            pass
        try:
            from rapidocr_onnxruntime import RapidOCR   # noqa: F401
        except Exception as e:
            _LOAD_ERROR = "%s: %s" % (type(e).__name__, str(e)[:200])
            return None, REASON_RUNTIME_MISSING
        try:
            # intra_op=1：实测与默认线程数的单次耗时相同（787 vs 799ms），
            # 但 CPU 占用低得多 —— 面板与代理链路是同一个进程，别让它抢核。
            # width_height_ratio=-1：关掉「宽图跳过检测」，理由见 DET_PAD_MIN。
            _ENGINE = RapidOCR(intra_op_num_threads=1, width_height_ratio=-1)
        except Exception as e:
            _LOAD_ERROR = "init: %s: %s" % (type(e).__name__, str(e)[:200])
            return None, REASON_RUNTIME_MISSING
    return _ENGINE, ""


def available():
    """(是否可用, 不可用原因码)。开关降级与自检都读这里。

    原因码保持**纯净**（降级逻辑按字面比较，不能追加详情）；真实异常
    （如冻结引擎上组件 import 失败的 ModuleNotFoundError）在 `_LOAD_ERROR`，
    由 `ocr_runtime.status` 与 OcrError.detail 透出。
    """
    engine, why = _load_backend()
    return (engine is not None), why


def warmup():
    """预热：把 0.6s 的模型加载与首帧开销挪出第一个用户请求。幂等、可重复调用。"""
    engine, _why = _load_backend()
    if engine is None:
        return False
    if _WARMED[0]:
        return True
    try:
        from PIL import Image
        img = Image.new("RGB", (16, 16), (255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        engine(buf.getvalue())
        _WARMED[0] = True
    except Exception:
        return False
    return True


def reset_for_tests():
    """测试用：清后端与预热标记（子进程里也会重新加载模型）。"""
    global _ENGINE
    with _ENGINE_LOCK:
        _ENGINE = None
    _WARMED[0] = False


# ---- 图像处理 ----

def _decode(image_bytes):
    from PIL import Image, ImageOps
    try:
        img = Image.open(io.BytesIO(image_bytes))
        # 像素上限必须在 load() 之前判：open() 只读文件头就有尺寸，load() 才真正解码。
        # 先 load 再判，一张 8MB 的 PNG 解压炸弹（如 30000x30000 纯色）会先吃掉 2.7GB 内存。
        w, h = img.size
        if w * h > MAX_PIXELS:
            raise OcrError(REASON_TOO_LARGE, f"{w}x{h}")
        img.load()
        # 按 EXIF 摆正：手机照片普遍带 Orientation 标签，PIL 默认**不**应用它。
        # 不摆正的后果有两层：① 我们按原始像素算框，用户看到的是转过的图，框会错位；
        # ② 重新编码时不保留 EXIF，落盘图会"躺倒"，客户端看到的方向与上传前不一致。
        img = ImageOps.exif_transpose(img) or img
    except OcrError:
        raise
    except Image.DecompressionBombError as e:
        # PIL 自带的炸弹闸（>178MP）在 open() 里就抛，比我们的 16MP 闸更早；归到同一个原因码。
        raise OcrError(REASON_TOO_LARGE, type(e).__name__)
    except Exception as e:
        raise OcrError(REASON_DECODE, type(e).__name__)
    return img


def _to_rgb_bytes(img):
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PNG")
    return buf.getvalue()


def _det_pad(img):
    return max(DET_PAD_MIN, min(DET_PAD_MAX, min(img.size)))


def _run_padded(engine, img, deadline):
    """补白边后送检，框减回偏移并夹回原图范围（见 DET_PAD_MIN 的实测）。"""
    from PIL import ImageOps
    pad = _det_pad(img)
    # 白边用白色：OCR 模型对白底训练最充分；深色背景图实测同样不受影响
    # （深色图的文字区域与白边之间多一条强边缘，但 det 只检文字形状）。
    padded = ImageOps.expand(img.convert("RGB"), pad, (255, 255, 255))
    w, h = img.size
    out = []
    for (x1, y1, x2, y2), text, score in _run_engine(engine, _to_rgb_bytes(padded), deadline):
        box = (min(max(0.0, x1 - pad), w), min(max(0.0, y1 - pad), h),
               min(max(0.0, x2 - pad), w), min(max(0.0, y2 - pad), h))
        if box[2] <= box[0] or box[3] <= box[1]:
            continue   # 整个落在白边里的框（噪点）
        out.append((box, text, score))
    return out


def _map_back(boxes, angle, width, height):
    """把"旋转后图像"里的框映射回原图坐标。

    PIL 的 `rotate(θ)` 是逆时针。θ=90 时旋转图尺寸为 (h, w)，坐标关系：
        x' = y,  y' = w - 1 - x      →  反解：x = w - 1 - y',  y = x'
    θ=270（等价顺时针 90）：
        x' = h - 1 - y,  y' = x      →  反解：x = y',  y = h - 1 - x'
    θ=180：x = w - 1 - x',  y = h - 1 - y'
    半像素误差无关紧要（后面还要 pad 再自校验）。
    """
    if angle == 0:
        return boxes
    out = []
    for x1, y1, x2, y2 in boxes:
        pts = [(x1, y1), (x2, y1), (x2, y2), (x1, y2)]
        mapped = []
        for x, y in pts:
            if angle == 90:
                mx, my = width - 1 - y, x
            elif angle == 180:
                mx, my = width - 1 - x, height - 1 - y
            else:  # 270
                mx, my = y, height - 1 - x
            mapped.append((mx, my))
        xs = [p[0] for p in mapped]
        ys = [p[1] for p in mapped]
        out.append((max(0.0, min(xs)), max(0.0, min(ys)),
                    min(float(width), max(xs)), min(float(height), max(ys))))
    return out


def _run_engine(engine, image_bytes, deadline):
    """一次后端调用，返回 [(quad, text, score)]（原图坐标未处理）。"""
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OcrError(REASON_TIMEOUT)
        if not _SEM.acquire(timeout=min(QUEUE_WAIT_S, remaining)):
            raise OcrError(REASON_BUSY)
    else:
        if not _SEM.acquire(timeout=QUEUE_WAIT_S):
            raise OcrError(REASON_BUSY)
    try:
        res, _elapse = engine(image_bytes)
    except Exception as e:
        # 推理期异常不能以裸异常漏给上层：上层只认 OcrError，漏出去会丢原因码。
        raise OcrError(REASON_ENGINE_ERROR, type(e).__name__)
    finally:
        _SEM.release()
    out = []
    for item in (res or []):
        try:
            box, text, score = item[0], item[1], float(item[2])
        except Exception:
            continue
        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        text = str(text or "").strip()
        if not text:
            continue
        out.append(((min(xs), min(ys), max(xs), max(ys)), text, score))
    return out


def _tile_ranges(height):
    """长图切片的 y 区间（带重叠）。短图返回单区间。"""
    if height <= TILE_HEIGHT:
        return [(0, height)]
    step = TILE_HEIGHT - TILE_OVERLAP
    out, y = [], 0
    while y < height and len(out) < MAX_TILES:
        out.append((y, min(height, y + TILE_HEIGHT)))
        if y + TILE_HEIGHT >= height:
            break
        y += step
    return out


def _dedupe(boxes):
    """重叠区两片都会扫到同一行：同文本、y 中心接近、x 重叠 → 留高分那条。"""
    kept = []
    for box, text, score in boxes:
        dup = False
        for i, (kb, kt, ks) in enumerate(kept):
            if kt != text:
                continue
            cy1 = (box[1] + box[3]) / 2.0
            cy2 = (kb[1] + kb[3]) / 2.0
            ox = min(box[2], kb[2]) - max(box[0], kb[0])
            if abs(cy1 - cy2) <= 24 and ox > 0.5 * min(box[2] - box[0], kb[2] - kb[0]):
                if score > ks:
                    kept[i] = (box, text, score)
                dup = True
                break
        if not dup:
            kept.append((box, text, score))
    return kept


def detect(image_bytes, *, deadline=None, allow_rotation=True):
    """核心入口：`DetectResult`。

    - `deadline`：`time.monotonic()` 的绝对时刻；超了立刻 `ocr_timeout`；
    - `allow_rotation`：是否允许方向兜底（PDF 页等已知正立的图可关掉省时间）。
    """
    if not image_bytes:
        raise OcrError(REASON_DECODE, "empty")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise OcrError(REASON_TOO_LARGE, str(len(image_bytes)))
    engine, why = _load_backend()
    if engine is None:
        raise OcrError(why or REASON_RUNTIME_MISSING, _LOAD_ERROR)

    t0 = time.perf_counter()
    img = _decode(image_bytes)
    width, height = img.size
    if width <= 0 or height <= 0:
        raise OcrError(REASON_DECODE, "zero-size")
    if width * height > MAX_PIXELS:
        raise OcrError(REASON_TOO_LARGE, "%dx%d" % (width, height))
    # （_decode 里 load 前已判过一次；这里保留是纵深防御——防未来有人改 _decode 的调用方绕过解码入口）

    # 长图优先切片（见 TILE_HEIGHT 注释）；切片时不再整体降采样，
    # 否则等于把"切了但看不清"的问题原样搬回来。
    ranges = _tile_ranges(height) if (height > TILE_HEIGHT and height >= width) else [(0, height)]

    downscaled = False
    scale = 1.0
    work = img
    if len(ranges) == 1 and width * height > DOWNSAMPLE_ABOVE_PX:
        from PIL import Image as _Image
        longest = max(width, height)
        scale = MAX_SIDE_PX / float(longest)
        if scale < 1.0:
            work = img.resize((max(1, int(width * scale)), max(1, int(height * scale))),
                              _Image.LANCZOS)
            downscaled = True
    if len(ranges) > 1:
        merged = []
        for y0, y1 in ranges:
            tile = img.crop((0, y0, width, y1))
            tw, th = tile.size
            tscale = min(1.0, MAX_SIDE_PX / float(max(tw, th)))
            twork = tile if tscale >= 1.0 else tile.resize(
                (max(1, int(tw * tscale)), max(1, int(th * tscale))))
            part = _run_padded(engine, twork, deadline)
            for box, text, score in part:
                if tscale < 1.0:
                    box = tuple(v / tscale for v in box)
                merged.append(((box[0], box[1] + y0, box[2], box[3] + y0), text, score))
        raw = _dedupe(merged)
        # 切片都没读到字（超长图且整页无文字/侧向长图）→ 退回单次整体识别（带方向兜底）
        if sum(len(t) for _b, t, _s in raw) < LOW_TEXT_CHARS:
            work = img if width * height <= DOWNSAMPLE_ABOVE_PX else img.resize(
                (max(1, int(width * (MAX_SIDE_PX / float(max(width, height))))),
                 max(1, int(height * (MAX_SIDE_PX / float(max(width, height)))))))
            scale = 1.0 if work is img else work.size[0] / float(width)
            raw = _run_padded(engine, work, deadline)
            ranges = [(0, height)]
    else:
        raw = _run_padded(engine, work, deadline)

    def _score(boxes):
        return (sum(len(t) for _b, t, _s in boxes), sum(s for _b, _t, s in boxes))

    orientation = 0
    best = raw
    # 方向兜底：只在 0° 明显不可信时才付 4× 代价。判据用"文本量"，不用"有无框"——
    # 90° 的图常常还能检出几个碎片，但内容全错，那比空结果更危险。
    # 小于 48px 的图（图标/logo）不试方向：4× 代价换来的是噪声，且真实场景里
    # 这类图不会有可打码的正文。
    small = min(width, height) < 48
    if allow_rotation and not small and _score(raw)[0] < LOW_TEXT_CHARS:
        base = work
        for angle in ORIENTATIONS[1:]:
            rotated = base.rotate(angle, expand=True)
            cand = _run_padded(engine, rotated, deadline)
            if _score(cand) > _score(best):
                best, orientation = cand, angle
            if _score(best)[0] >= LOW_TEXT_CHARS and orientation != 0:
                break

    # 坐标：先按降采样比例放大回原图，再按方向反算
    boxes = [b for b, _t, _s in best]
    if scale < 1.0:
        boxes = [(x1 / scale, y1 / scale, x2 / scale, y2 / scale) for x1, y1, x2, y2 in boxes]
    boxes = _map_back(boxes, orientation, width, height)

    blocks = tuple(
        Block(quad=tuple(float(v) for v in box), text=text, score=score)
        for box, (_b, text, score) in zip(boxes, best)
    )
    return DetectResult(blocks=blocks, orientation=orientation,
                        ms=(time.perf_counter() - t0) * 1000.0, downscaled=downscaled)


def recognize(image_bytes, *, deadline=None):
    """只做"重新识别一遍"，供实体定位的自校验用（裁出来的一小块图）。

    实现上仍走完整 det+rec：小图的 det 只要 30~60ms，比另开一个"只 rec"通道简单可靠
    （1.2.3 的 `use_det=False` 实际不生效，实测仍会跑检测）。
    """
    res = detect(image_bytes, deadline=deadline, allow_rotation=False)
    return res.text
