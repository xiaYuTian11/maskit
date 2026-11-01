"""PDF 载体脱敏：整页渲染 → 本机 OCR → 页内打码 → 重建。

## 为什么是"渲染 + 重建"，而不是"改文本层"或"抠内嵌图"

PDF 的可见内容有三条来源：文本层、内嵌图片、矢量图形（含被转成曲线的字、被拍成
截图的表格）。只改文本层，扫不到图片里的字；只抠内嵌图，扫不到转曲的字；
两条都做，仍然漏掉"文字其实是图形"的那一类。

唯一可靠的判据是**渲染出来的那一页像素**——用户和模型看到什么，我们就扫什么。
所以这里的工作方式是：把每页画成位图 → 送本机 OCR → 命中敏感文字就涂掉。

## 策略：干净页保持原样（这是关键取舍）

- 每页渲染 → OCR 判定 → **命中**：该页内容换成打码后的位图（页对象本身保留：
  注释、超链接、表单控件、书签跳转都还在）；
- **没命中**：该页**原样保留**（矢量文字、链接、表单、书签、体积都不动）；
- 页面之外的文字（文档信息、XMP、书签标题、注释正文、表单值、文本类附件）**只替换
  命中的值**，与文字链路同口径（占位符可还原），其余内容原样保留；
- 整份都没命中：**原始字节直接返回**（零触碰，与 OOXML/图片同口径）。

为什么不是"整份都重建成图片"：一份 30 页的合同里可能只有 1 页有手机号，把 30 页
全变成位图会让文档失去可选中文字（上游若按文本抽取正文，等于把整份文档废掉）、
体积涨十倍。只牺牲真正含敏感信息的那几页，是覆盖与可用性的平衡点。

## 失败语义（与图片同一条红线）

渲染失败 / 加密 / 超页数或像素预算 / OCR 不可用 / OCR 输出被截断 → 一律**阻断**
（`BLOCK_*`），绝不放行"没扫过的页"。含敏感文字却又拿不到坐标的页面退化为
**整页遮盖**（保页数、去内容），而不是原样保留。唯一放行的是**二进制附件**（压缩包、
图片、Office 等扫不了的类型）：按用户定案放行，但计数上报 `attachments_unscanned`。
"""

import io
import os
import threading
import time

# 依赖懒加载：`pypdfium2`（渲染，Apache-2.0 / PDFium BSD）与 `pypdf`（合并，BSD）。
# 缺任何一个都只是这个能力不可用，不能让引擎起不来 —— 与 visual_redactor 同一口径。
try:
    import pypdfium2 as _pdfium
    import pypdfium2.raw as _pdfium_raw
    from pypdf import PdfReader as _PdfReader
    from pypdf import PdfWriter as _PdfWriter
except Exception:      # pragma: no cover - 只在缺依赖的环境走到
    _pdfium = None
    _pdfium_raw = None
    _PdfReader = None
    _PdfWriter = None

import locator as _locator
import visual_redactor as _vr

# 状态串（与 visual_redactor 的 ST_* 同一套命名习惯）
ST_CLEAN = "clean"
ST_MASKED = "masked"

BLOCK_DEPS_MISSING = "pdf_dependency_missing"
BLOCK_UNREADABLE = "pdf_unreadable"
BLOCK_EMPTY = "pdf_empty"
BLOCK_TOO_MANY_PAGES = "pdf_too_many_pages"
BLOCK_PIXEL_BUDGET = "pdf_pixel_budget"
BLOCK_RENDER_FAILED = "pdf_render_failed"
BLOCK_ENCRYPTED = "pdf_encrypted"
BLOCK_HIDDEN_UNREADABLE = "pdf_hidden_content_unreadable"

_OK_STATUSES = frozenset({ST_CLEAN, ST_MASKED})

# 单份 PDF 的页数上限。再大就不是"聊天里的附件"了，而且本地 OCR 是逐页串行的：
# 40 页 × 约 1.5s ≈ 60s，正好用满 `_PDF_OCR_BUDGET_S`。超了明确阻断并提示拆分，
# 不做"只扫前 N 页"——那等于后面的页明文上行。
MAX_PAGES = 40
# 单页 OCR 的输出预算。比单张图片大得多：一页 A4 满页正文 ≈ 1500~2500 token，
# 而每行还要 4 个 `<loc_xxxxxxxx>` 标记。用 2048 卡会被截断，而截断 = 阻断整份 PDF，
# 结果就是“内容多的页传不上去”——恰好是合同/发票这类最需要它的场景。
PAGE_OCR_MAX_TOKENS = 6144
# 单页渲染宽度上限（像素）。1600 约等于 A4@138 DPI，正文小字仍可识别；
# 再高只是把 OCR 时间线性拉长。
RENDER_MAX_WIDTH_PX = 1600
# 渲染缩放钳位：极小页面（如 200pt 宽的小票）不要放大到模糊，极大页面不要爆内存。
MIN_RENDER_SCALE = 0.6
MAX_RENDER_SCALE = 2.2
# 整份 PDF 的渲染像素总预算（约 40 页 A4@1600px）。超出即阻断，防止内存被打爆。
MAX_TOTAL_PIXELS = 150_000_000


def available():
    """(是否可用, 不可用原因)。"""
    ok, why = _vr.available()
    if not ok:
        return False, why
    if _pdfium is None or _PdfReader is None or _PdfWriter is None:
        return False, BLOCK_DEPS_MISSING
    return True, ""


def is_ok_status(status):
    return status in _OK_STATUSES


# 文本层字符框外扩（占字高比例）。pdfium 的字符框是字形紧框，不含上下伸部余量。
TEXT_BOX_PAD = 0.25


def _page_text_layer(page):
    """`(text, boxes)`：逐字符的 Unicode 与字符框（pt，左下原点），索引一一对应。

    不用 `get_text_range()`：它返回的串与字符索引不保证对齐，对不齐就画错位置。
    """
    tp = page.get_textpage()
    try:
        n = tp.count_chars()
        chars, boxes = [], []
        for i in range(max(0, n)):
            code = _pdfium_raw.FPDFText_GetUnicode(tp.raw, i)
            chars.append(chr(code) if 0 < code < 0x110000 else " ")
            try:
                boxes.append(tp.get_charbox(i))
            except Exception:
                boxes.append(None)
        return "".join(chars), boxes
    finally:
        try:
            tp.close()
        except Exception:
            pass


def _text_layer_hits(page, sid, tr):
    """扫本页文本层。返回 `[(start, end), ...]` 与字符框。

    为什么光扫像素不够：干净页会**原样保留**（含文本层），而文本层里可以有
    看不见的字——渲染模式 3（不可见）、白字、被图片盖住、扫描件的 OCR 层。
    OCR 读不到它们，上游却能原样抽取。实测：一页不可见的号码在修复前被判干净并上行。
    判定异常上抛 `MaskFailed`（→ 阻断）。
    """
    text, boxes = _page_text_layer(page)
    if not text.strip():
        return [], boxes
    spans = _locator.spans_from_mask(text, lambda t: _vr._mask_text(tr, t, sid))
    return [(s, e) for s, e, _label in spans], boxes


def _text_rects_px(spans, boxes, page, scale):
    """把文本层命中映射到渲染图像素。无法可靠映射时返回 None（调用方整页遮盖）。"""
    try:
        if page.get_rotation() % 360:
            # 旋转页的坐标变换容易写错，写错就是漏遮；整页遮盖更稳妥。
            return None
        left, _bottom, _right, top = page.get_cropbox()
    except Exception:
        return None
    rects = []
    for start, end in spans:
        cur = None
        for i in range(start, min(end, len(boxes))):
            box = boxes[i]
            if not box:
                continue
            l, b, r, t = box
            if r <= l or t <= b:
                continue  # 生成字符（换行/空格）没有字形
            h = t - b
            if cur and abs(b - cur[1]) <= h * 0.5 and l >= cur[0] - h:
                cur = [min(cur[0], l), min(cur[1], b), max(cur[2], r), max(cur[3], t)]
            else:
                if cur:
                    rects.append(cur)
                cur = [l, b, r, t]
        if cur:
            rects.append(cur)
        if not any(boxes[i] for i in range(start, min(end, len(boxes)))):
            return None  # 命中了却一个字形框都没有：画不了就整页盖
    out = []
    for l, b, r, t in rects:
        pad = (t - b) * TEXT_BOX_PAD
        out.append((int((l - pad - left) * scale), int((top - t - pad) * scale),
                    int((r + pad - left) * scale) + 1, int((top - b + pad) * scale) + 1))
    return out


def _jpeg(img):
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _paint_jpeg(jpeg, rects):
    """在 JPEG 上涂色；`rects=None` 表示整页遮盖。返回新 JPEG（失败 None）。"""
    image_mod, _draw = _vr._pil()
    if image_mod is None:
        return None
    try:
        img = image_mod.open(io.BytesIO(jpeg)).convert("RGB")
    except Exception:
        return None
    if rects is None:
        rects = [(0, 0, img.size[0], img.size[1])]
    if not _vr._paint(img, rects):
        return None
    return _jpeg(img)


def _open_document(raw_bytes):
    """打开 PDF：返回 (doc, 页数) 或抛异常由调用方归类原因。"""
    return _pdfium.PdfDocument(raw_bytes)


# ---------------------------------------------------------------------------
# 页面之外的文字载体：只替换命中的值，结构与其余内容原样保留
# ---------------------------------------------------------------------------
#
# 载体：文档信息（作者/标题/主题…）、XMP、书签标题、注释正文与表单值、文本类附件。
# 为什么不删：它们是用户文件的一部分（超链接就是注释，表单是用户填的内容）。
# 打码只该动敏感值——与文字链路同口径：换成占位符（可被还原），其余字节不动。
# 附件不是文本（压缩包/图片/二进制）时扫不了：按用户定案放行，但计数上报
# （`attachments_unscanned`），不静默。

# 注释/表单字段里的文字键。/RC 是富文本（XHTML），按纯文本整段替换即可：占位符
# 是 `{{LABEL_xxxxxx}}`，不含尖括号，不会破坏标签结构。
_ANNOT_TEXT_KEYS = ("/Contents", "/V", "/DV", "/TU", "/RC", "/Subj", "/T")
# 文本类附件：按扩展名 + 能否 UTF-8 解码两道判断。
_TEXT_ATTACHMENT_EXTS = (".txt", ".csv", ".tsv", ".json", ".xml", ".md", ".log", ".ini",
                         ".yaml", ".yml", ".html", ".htm", ".vcf", ".eml", ".sql")
_MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024


class _HiddenMasker(object):
    """在 pypdf 对象树上就地替换命中值。`mask_fn(text) -> text` 异常上抛（由调用方阻断）。"""

    def __init__(self, mask_fn):
        self.mask_fn = mask_fn
        self.hits = 0
        self.attachments_unscanned = 0
        self.widget_hit = False

    def _text(self, value):
        """`TextStringObject`/`str` → 替换后的新对象；未命中返回 None（调用方不写回）。"""
        from pypdf.generic import TextStringObject
        try:
            text = str(value)
        except Exception:
            return None
        if not text.strip():
            return None
        new = self.mask_fn(text)
        if new == text:
            return None
        self.hits += 1
        return TextStringObject(new)

    def dict_keys(self, obj, keys):
        """替换 `obj` 里这些键的文字，返回本对象是否有命中。"""
        from pypdf.generic import NameObject, TextStringObject, ByteStringObject
        before = self.hits
        for key in keys:
            if key not in obj:
                continue
            val = obj[key]
            try:
                val = val.get_object()
            except Exception:
                pass
            if isinstance(val, (TextStringObject, ByteStringObject, str)):
                new = self._text(val)
                if new is not None:
                    obj[NameObject(key)] = new
            elif hasattr(val, "get_data") and key == "/RC":
                self.stream(val)
        return self.hits > before

    @staticmethod
    def _drop_appearance(annot):
        """注释正文被替换后，它的外观流（/AP，预先渲染好的旧样子）还画着原值。

        只删命中的那条注释的 /AP：阅读器会按新正文重新生成外观。外观流里的字是按字体
        编码的，没法可靠地在里面做文字替换。
        """
        if "/AP" in annot:
            del annot["/AP"]

    def stream(self, stream_obj, encoding="utf-8"):
        data = stream_obj.get_data()
        text = data.decode(encoding, "replace") if isinstance(data, bytes) else str(data)
        new = self.mask_fn(text)
        if new != text:
            stream_obj.set_data(new.encode(encoding))
            self.hits += 1

    # ---- 各载体 ----

    def info(self, writer):
        from pypdf.generic import NameObject
        info = writer._info
        if info is None:
            return
        info = info.get_object()
        for key in list(info.keys()):
            if key in ("/CreationDate", "/ModDate", "/Trapped"):
                continue
            new = self._text(info[key])
            if new is not None:
                info[NameObject(key)] = new

    def xmp(self, writer):
        meta = writer._root_object.get("/Metadata")
        if meta is not None:
            self.stream(meta.get_object())

    def outline(self, writer):
        from pypdf.generic import NameObject
        root = writer._root_object.get("/Outlines")
        if root is None:
            return
        seen = set()
        stack = [root.get_object().get("/First")]
        while stack:
            ref = stack.pop()
            if ref is None:
                continue
            key = getattr(ref, "idnum", id(ref))
            if key in seen:
                continue          # 恶意环引用
            seen.add(key)
            node = ref.get_object()
            if "/Title" in node:
                new = self._text(node["/Title"])
                if new is not None:
                    node[NameObject("/Title")] = new
            stack.append(node.get("/Next"))
            stack.append(node.get("/First"))

    def annots(self, page):
        for ref in page.get("/Annots") or []:
            a = ref.get_object()
            if self.dict_keys(a, _ANNOT_TEXT_KEYS):
                self._drop_appearance(a)
                if a.get("/Subtype") == "/Widget":
                    self.widget_hit = True
            popup = a.get("/Popup")
            if popup is not None:
                popup = popup.get_object()
                if self.dict_keys(popup, _ANNOT_TEXT_KEYS):
                    self._drop_appearance(popup)

    def form(self, writer):
        from pypdf.generic import BooleanObject, NameObject
        form = writer._root_object.get("/AcroForm")
        if form is None:
            return
        form = form.get_object()
        seen = set()
        stack = list(form.get("/Fields") or [])
        while stack:
            ref = stack.pop()
            key = getattr(ref, "idnum", id(ref))
            if key in seen:
                continue
            seen.add(key)
            field = ref.get_object()
            if self.dict_keys(field, _ANNOT_TEXT_KEYS):
                self._drop_appearance(field)
                self.widget_hit = True
            stack.extend(field.get("/Kids") or [])
        if self.widget_hit:
            # 表单值换了、旧外观删了：让阅读器按新值重绘控件
            form[NameObject("/NeedAppearances")] = BooleanObject(True)

    def attachments(self, writer):
        from pypdf.generic import NameObject
        names = writer._root_object.get("/Names")
        if names is None:
            return
        ef_tree = names.get_object().get("/EmbeddedFiles")
        if ef_tree is None:
            return
        stack = [ef_tree.get_object()]
        while stack:
            node = stack.pop()
            stack.extend(k.get_object() for k in (node.get("/Kids") or []))
            arr = node.get("/Names") or []
            for i in range(1, len(arr), 2):
                spec = arr[i].get_object()
                self.dict_keys(spec, ("/Desc",))
                filename = str(spec.get("/UF") or spec.get("/F") or "")
                for key in ("/UF", "/F"):
                    if key in spec:
                        new = self._text(spec[key])
                        if new is not None:
                            spec[NameObject(key)] = new
                ef = spec.get("/EF")
                if ef is None:
                    continue
                ef = ef.get_object()
                for key in ("/F", "/UF"):
                    if key in ef:
                        self._attachment_stream(ef[key].get_object(), filename)
                        break

    def _attachment_stream(self, stream_obj, filename):
        try:
            data = stream_obj.get_data()
        except Exception:
            self.attachments_unscanned += 1
            return
        is_text_name = filename.lower().endswith(_TEXT_ATTACHMENT_EXTS)
        if len(data) > _MAX_ATTACHMENT_BYTES:
            self.attachments_unscanned += 1
            return
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if not is_text_name:
                # 二进制附件（压缩包/图片/Office）：扫不了，按定案放行并计数。
                self.attachments_unscanned += 1
                return
            text = data.decode("utf-8", "replace")
        if "\x00" in text:
            self.attachments_unscanned += 1
            return
        new = self.mask_fn(text)
        if new != text:
            stream_obj.set_data(new.encode("utf-8"))
            # /Params 里的 /Size /CheckSum 是旧内容的：删掉而不是留一份对不上的校验值
            params = stream_obj.get("/Params")
            if params is not None:
                params = params.get_object()
                for key in ("/Size", "/CheckSum"):
                    if key in params:
                        del params[key]
            self.hits += 1

    def all(self, writer):
        self.info(writer)
        self.xmp(writer)
        self.outline(writer)
        for page in writer.pages:
            self.annots(page)
        self.form(writer)
        self.attachments(writer)
        return self.hits


def _mask_hidden(writer, sid, tr):
    """`(命中数, 未扫描附件数)`。判定异常上抛。"""
    masker = _HiddenMasker(lambda t: _vr._mask_text(tr, t, sid))
    masker.all(writer)
    return masker.hits, masker.attachments_unscanned


def mask_pdf_bytes(raw_bytes, sid, tr, deadline=None):
    """PDF 脱敏主入口：`(新字节, 命中数, 状态)`。

    状态为 `ST_CLEAN` / `ST_MASKED` 时字节可直接回给客户端；
    其余（`BLOCK_*`）必须当失败处理并阻断整份文件——与 `mask_embedded_image_bytes`
    同一套契约（见 panel 的 `_mask_embedded_media`）。
    """
    ok, why = available()
    _LAST_STATS.value = {}
    if not ok:
        return raw_bytes, 0, why

    try:
        doc = _open_document(raw_bytes)
    except Exception:
        return raw_bytes, 0, BLOCK_UNREADABLE

    try:
        try:
            pages = len(doc)
        except Exception:
            return raw_bytes, 0, BLOCK_UNREADABLE
        if pages <= 0:
            return raw_bytes, 0, BLOCK_EMPTY
        if pages > MAX_PAGES:
            return raw_bytes, 0, BLOCK_TOO_MANY_PAGES

        hits_total = 0
        text_layer_pages = 0
        total_pixels = 0
        rendered = []            # 与页序一一对应：None = 保留原页；bytes = 打码后的 JPEG

        for index in range(pages):
            if deadline is not None and time.monotonic() >= deadline:
                return raw_bytes, 0, _vr.BLOCK_BUDGET
            width_pt, height_pt = doc.get_page_size(index)
            if width_pt <= 0 or height_pt <= 0:
                return raw_bytes, 0, BLOCK_RENDER_FAILED
            scale = max(MIN_RENDER_SCALE,
                        min(MAX_RENDER_SCALE, RENDER_MAX_WIDTH_PX / float(width_pt)))
            try:
                page = doc[index]
                # 注释不画进位图：它们保留在页上（文字另行替换），画进去会把未替换的
                # 旧外观（例如自由文本注释里的号码）烤进像素，叠在保留的注释下面。
                bitmap = page.render(scale=scale, draw_annots=False)
                image = bitmap.to_pil().convert("RGB")
            except Exception:
                return raw_bytes, 0, BLOCK_RENDER_FAILED
            try:
                tl_spans, tl_boxes = _text_layer_hits(page, sid, tr)
            except _locator.MaskFailed:
                return raw_bytes, 0, _vr.BLOCK_GEOMETRY
            except Exception:
                # 文本层读不出来却保留原页 = 放行未扫描的字；阻断。
                return raw_bytes, 0, BLOCK_RENDER_FAILED

            total_pixels += image.size[0] * image.size[1]
            if total_pixels > MAX_TOTAL_PIXELS:
                return raw_bytes, 0, BLOCK_PIXEL_BUDGET

            # 统一转成 JPEG 再进图片脱敏链路：页面本来就是像素，JPEG 足够（体积小、
            # 送入 OCR 的 data URL 不会被撑爆），而重编码损失对"打码判定"没有影响。
            buf = io.BytesIO()
            image.save(buf, format="JPEG", quality=90)
            page_jpeg = buf.getvalue()

            # allow_cover=True：整页里"确认有敏感内容但定位不全"时盖整页，
            # 而不是把整份文档打回去（见 visual_redactor 模块注释）。
            res = _vr.process_image_multimodal(page_jpeg, sid, tr, deadline=deadline,
                                               max_tokens=PAGE_OCR_MAX_TOKENS,
                                               allow_cover=True)
            mode = str(res.get("mode") or _vr.MODE_BLOCKED)
            page_out = None          # None = 保留原页；bytes = 换成这张 JPEG
            if mode == _vr.MODE_BLOCKED:
                reason = str(res.get("reason") or _vr.BLOCK_UNAVAILABLE)
                if reason != _vr.BLOCK_GEOMETRY:
                    return raw_bytes, 0, reason
                # 识别到敏感文字但画不上：整页遮盖（保页数、去内容）。独立图片这里是阻断的，
                # 但一页定位失败就打回整份 30 页合同，用户只能拆文件。
                page_out = _paint_jpeg(page_jpeg, None)
                if page_out is None:
                    return raw_bytes, 0, _vr.BLOCK_GEOMETRY
                hits_total += 1
            elif mode == _vr.MODE_REDACTED:
                hits_total += int(res.get("hit_count") or 1)
                page_out = res.get("bytes") or b""
                if not page_out:
                    return raw_bytes, 0, _vr.BLOCK_GEOMETRY
            if tl_spans:
                # 文本层命中：本页必须栅格化（去掉文本层），并把可见的那部分按字符框涂掉
                # ——OCR 漏读的字也一并盖住。画不准（旋转页等）就整页遮盖。
                rects = _text_rects_px(tl_spans, tl_boxes, page, scale)
                page_out = _paint_jpeg(page_out or page_jpeg, rects)
                if page_out is None:
                    return raw_bytes, 0, _vr.BLOCK_GEOMETRY
                hits_total += len(tl_spans) if mode != _vr.MODE_REDACTED else 0
                text_layer_pages += 1
            rendered.append(None if page_out is None else (page_out, image.size))

        # 页面之外的载体（注释/表单值/文档信息/XMP/书签/文本附件）：在「克隆整份文档」的
        # 写入器上只替换命中值。实测这些地方的号码与邮箱曾在「干净」判定下原字节上行。
        try:
            writer = _PdfWriter(clone_from=_PdfReader(io.BytesIO(raw_bytes)))
            hidden_hits, unscanned = _mask_hidden(writer, sid, tr)
        except Exception:
            # 读不出 / 判定异常：不确定有没有敏感值，阻断（与像素判定同口径）。
            return raw_bytes, 0, BLOCK_HIDDEN_UNREADABLE
        _LAST_STATS.value = {"attachments_unscanned": unscanned, "hidden_masked": hidden_hits}

        if hits_total <= 0 and hidden_hits <= 0:
            return raw_bytes, 0, ST_CLEAN
        hits_total += hidden_hits

        out = _compose(writer, rendered, doc)
        if out is None:
            return raw_bytes, 0, BLOCK_RENDER_FAILED
        return out, hits_total, ST_MASKED
    finally:
        try:
            doc.close()
        except Exception:
            pass


# 最近一次 mask_pdf_bytes 的附加统计（未扫描附件数等）。不改三元组返回值，以免动调用方。
# 线程局部：面板在线程池里并发处理多份 PDF，共享字典会互相覆盖。
_LAST_STATS = threading.local()


def last_stats():
    return dict(getattr(_LAST_STATS, "value", None) or {})


def _compose(writer, rendered, doc):
    """在克隆的整份文档上换页：只替换「打码页」的内容流，其它一切原样保留。

    打码页保留页对象本身（注释/超链接/表单控件/书签跳转目标都还指向它），
    只把 /Contents 换成「铺满整页的打码位图」、/Resources 换成只含这张位图。
    旧内容流（含矢量文字与文本层）因此不再被引用，写出时一并清掉。
    """
    from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject, NameObject,
                               NumberObject, StreamObject)
    try:
        for index, replacement in enumerate(rendered):
            if replacement is None:
                continue
            jpeg, (width_px, height_px) = replacement
            page = writer.pages[index]
            width_pt, height_pt = doc.get_page_size(index)
            image = StreamObject()
            image._data = jpeg
            image.update({
                NameObject("/Type"): NameObject("/XObject"),
                NameObject("/Subtype"): NameObject("/Image"),
                NameObject("/Width"): NumberObject(width_px),
                NameObject("/Height"): NumberObject(height_px),
                NameObject("/ColorSpace"): NameObject("/DeviceRGB"),
                NameObject("/BitsPerComponent"): NumberObject(8),
                NameObject("/Filter"): NameObject("/DCTDecode"),
            })
            image_ref = writer._add_object(image)
            # 位图铺满可见区域（CropBox，缺省 = MediaBox）：渲染时就是按它出的图。
            left, bottom = float(page.cropbox.left), float(page.cropbox.bottom)
            content = DecodedStreamObject()
            content.set_data(("q %.4f 0 0 %.4f %.4f %.4f cm /MaskitIm0 Do Q"
                              % (width_pt, height_pt, left, bottom)).encode())
            page[NameObject("/Contents")] = writer._add_object(content)
            page[NameObject("/Resources")] = DictionaryObject({
                NameObject("/XObject"): DictionaryObject({NameObject("/MaskitIm0"): image_ref}),
            })
            # 旋转：渲染出的位图已经是旋转后的视觉方向，且 pdfium 的 `get_page_size` 返回的也是
            # 旋转后的宽高（实测 600x200 + /Rotate 90 → (200, 600)）。所以去掉 /Rotate、
            # 把页面框改成旋转后的尺寸，位图按原样铺满，否则阅读器会再转一次。
            if "/Rotate" in page:
                del page["/Rotate"]
                for box in (page.mediabox, page.cropbox):
                    box.lower_left = (left, bottom)
                    box.upper_right = (left + width_pt, bottom + height_pt)
            # 页缩略图是未打码的旧渲染：去掉（阅读器会按需重新生成，不是用户内容）。
            for key in ("/Thumb", "/PieceInfo"):
                if key in page:
                    del page[key]
        # 去掉不再被引用的旧内容流（含命中页的矢量文字）。不合并重复对象：那会改写用户内容的结构。
        writer.compress_identical_objects(remove_duplicates=False, remove_unreferenced=True)
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue()
    except Exception:
        return None


def looks_like_pdf(raw_bytes):
    """魔数判定：扩展名可能被抹掉（"attachment.bin"），内容不会。"""
    return raw_bytes[:5] == b"%PDF-"


def extension_of(filename):
    name = (filename or "").strip().lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""
