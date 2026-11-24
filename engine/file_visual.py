"""文件脱敏工作台 · 视觉类载体（file-workbench-visual，2026-11-24）。

PDF 与图片的两阶段 scan/apply：
  · scan 在 transparent.file_store_scope 内渲染页图落盘、抽文本层/隐藏文字命中、
    mode=auto 时跑本机 OCR 出框；只产页图 + 命中清单，不改原文件。
  · apply 按用户确认的框/文本整页栅格化涂黑（D6），清文档信息/附件/图片元数据，
    隐藏文字按注册表 orig→最终文本替换，不重跑识别（G789）。

复用 pdf_redactor（渲染/文本层/隐藏文字/合成）与 visual_redactor（OCR/编解码），
**不改 mask_pdf_bytes / redact_image_bytes 的签名与行为**（扩展链路）。
错误码 FILE_78xx 与守卫 G781~G793 一一对应。
"""

import base64
import io
import json
import os
import re
import shutil

import transparent as tr
import file_workbench as fw
import file_carriers as fc

import pdf_redactor as pr
import visual_redactor as vr

# ── 错误码（G781~G793）──────────────────────────────────────────────────────
E_CARRIER = "FILE_7801"     # 加密/损坏/页数超限/图片超上限
E_BUDGET = "FILE_7802"      # 渲染/磁盘预算
E_COORD = "FILE_7803"       # 坐标非法
E_OCR = "FILE_7804"         # OCR 未就绪
E_TEXTLAYER = "FILE_7805"   # 文本层命中
E_HIDDEN = "FILE_7806"      # 隐藏文字命中
E_DETECT = "FILE_7807"      # 图片自动框选
E_RASTER = "FILE_7808"      # 栅格化
E_APPLY = "FILE_7809"       # apply 不重扫
E_DOCINFO = "FILE_7810"     # 文档信息/附件
E_META = "FILE_7811"        # 图片元数据
E_COVERAGE = "FILE_7812"    # 覆盖声明
E_PREVIEW = "FILE_7813"     # 预览/取消

PDF_EXTS = {"pdf"}
IMAGE_EXTS = {"png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"}

_PREVIEW_MAX = 2000          # 预览最长边
_PAGE_WIDTH = 1600           # PDF 页渲染宽（与 pr.RENDER_MAX_WIDTH_PX 同口径）
_MAX_AREAS_PER_PAGE = 500
_MIN_AREA = 0.001
_FILL = getattr(vr, "_FILL", (120, 120, 120))


class PageOcrFailed(Exception):
    """单页 OCR 失败：该页整页 full 框 + 告警（G785）。"""


def _max_pages(cfg=None):
    try:
        return int((cfg or {}).get("files_max_pages", 1000))
    except Exception:
        return 1000


def _max_image_mp(cfg=None):
    try:
        return int((cfg or {}).get("files_max_image_mp", 32))
    except Exception:
        return 32


def _disk_free(path):
    try:
        return shutil.disk_usage(path).free
    except Exception:
        return 1 << 60


_OCR_READY_CACHE = {}


def _ocr_ready():
    """(是否可用, 原因)。只判本机 OCR，不判代理链路的 multimodal 开关。"""
    try:
        return vr.available()
    except Exception:
        return False, "ocr_unavailable"


def _detect_boxes(image_bytes, img, sid, deadline=None):
    """OCR 出框（不涂黑）。返回 [{'rect':[x,y,w,h], 'label':.., 'text':..}]。

    单页失败抛 PageOcrFailed，由 scan 转整页 full + 告警。
    """
    try:
        blocks, _info = vr.detect_blocks(image_bytes, deadline=deadline)
    except Exception as e:
        raise PageOcrFailed(str(e))
    try:
        rects, stats = vr._locator.locate(
            blocks, lambda t: tr.mask_body(t, sid), img=img,
            recognize=vr._recognize, deadline=deadline)
    except Exception as e:
        raise PageOcrFailed(str(e))
    if stats.get("failed"):
        raise PageOcrFailed("locate_failed")
    width, height = img.size
    out = []
    for r in rects:
        quad = r.quad
        x1, y1, x2, y2 = float(quad[0]), float(quad[1]), float(quad[2]), float(quad[3])
        x1, x2 = sorted((x1, x2))
        y1, y2 = sorted((y1, y2))
        out.append({"rect": [max(0.0, x1 / width), max(0.0, y1 / height),
                            min(1.0, (x2 - x1) / width), min(1.0, (y2 - y1) / height)],
                    "label": getattr(r, "label", "") or "", "text": ""})
    return out


# ── 预检（G781）────────────────────────────────────────────────────────────
def probe(src_path, carrier, cfg=None):
    """返回 (ok, page_count, error_code)。不通过一律 failed，绝不原样放行。"""
    # @guard G781 加密/损坏/页数超限/图片超上限一律 fail-closed
    if carrier == "image":
        return _probe_image(src_path, cfg)
    if carrier == "pdf":
        return _probe_pdf(src_path, cfg)
    return False, None, E_CARRIER


def _probe_pdf(src_path, cfg=None):
    try:
        with open(src_path, "rb") as f:
            raw = f.read()
    except Exception:
        return False, None, E_CARRIER
    if not pr.looks_like_pdf(raw):
        return False, None, E_CARRIER
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        if getattr(reader, "is_encrypted", False):
            return False, None, E_CARRIER
        pages = len(reader.pages)
    except Exception:
        return False, None, "pdf_parse_failed"
    if pages <= 0:
        return False, None, E_CARRIER
    if pages > _max_pages(cfg):
        return False, None, E_CARRIER
    try:
        doc = pr._open_document(raw)
        doc.close()
    except Exception:
        return False, None, "pdf_parse_failed"
    return True, pages, ""


def _probe_image(src_path, cfg=None):
    image, _draw = vr._pil()
    if image is None:
        return False, None, E_CARRIER
    try:
        with image.open(src_path) as img:
            width, height = img.size
            if width * height > _max_image_mp(cfg) * 1000 * 1000:
                return False, None, E_CARRIER
            if int(getattr(img, "n_frames", 1) or 1) > 1:
                return False, None, E_CARRIER
            img.load()
    except Exception:
        return False, None, E_CARRIER
    return True, 1, ""


# ── 坐标模型（G787）────────────────────────────────────────────────────────
def _norm_rect(rect):
    """归一化并裁剪；过小返回 None（吸附为点击点）。"""
    try:
        x, y, w, h = [float(v) for v in rect]
    except Exception:
        raise fw.FileWorkbenchError(E_COORD, 400)
    if w <= _MIN_AREA or h <= _MIN_AREA:
        return None
    x2 = min(1.0, x + w)
    y2 = min(1.0, y + h)
    x = max(0.0, min(1.0, x))
    y = max(0.0, min(1.0, y))
    w = round(max(0.0, x2 - x), 6)
    h = round(max(0.0, y2 - y), 6)
    if w <= 0 or h <= 0:
        raise fw.FileWorkbenchError(E_COORD, 400)
    return [round(x, 6), round(y, 6), w, h]


def _validate_redactions(redactions, page_count):
    # @guard G787 单页 ≤500、坐标归一化裁剪、full 互斥
    by_page = {}
    for item in redactions or []:
        try:
            page = int(item.get("page", 1))
        except Exception:
            raise fw.FileWorkbenchError(E_COORD, 400)
        if page < 1 or page > int(page_count or 1):
            raise fw.FileWorkbenchError(E_COORD, 400)
        kind = item.get("kind") or "rect"
        if kind not in ("rect", "path", "full"):
            raise fw.FileWorkbenchError(E_COORD, 400)
        by_page.setdefault(page, []).append(item)
        if len(by_page[page]) > _MAX_AREAS_PER_PAGE:
            raise fw.FileWorkbenchError(E_COORD, 400)
    return by_page


def _page_redactions(redactions, page):
    items = [r for r in (redactions or []) if int(r.get("page", 1)) == page]
    if any(r.get("kind") == "full" for r in items):
        return [{"kind": "full"}]
    out = []
    for r in items:
        if r.get("kind") == "rect":
            rect = _norm_rect(r.get("rect") or [])
            if rect:
                out.append({"kind": "rect", "rect": rect})
        elif r.get("kind") == "path":
            pts = []
            for p in r.get("points") or []:
                try:
                    pts.append((max(0.0, min(1.0, float(p[0]))),
                                max(0.0, min(1.0, float(p[1])))))
                except Exception:
                    raise fw.FileWorkbenchError(E_COORD, 400)
            if len(pts) >= 2:
                out.append({"kind": "path", "points": pts,
                            "width": float(r.get("width") or 0.006)})
    return out


def _paint(img, boxes):
    """在 PIL 图上按归一化框/路径/整页涂黑。"""
    image_mod, ImageDraw = vr._pil()
    if ImageDraw is None:
        raise fw.FileWorkbenchError(E_RASTER, 422)
    draw = ImageDraw.Draw(img)
    width_px, height_px = img.size
    for b in boxes:
        if b.get("kind") == "full":
            draw.rectangle([0, 0, width_px - 1, height_px - 1], fill=_FILL)
            continue
        if b.get("kind") == "path":
            pts = [(p[0] * width_px, p[1] * height_px) for p in b["points"]]
            w = max(1, int(float(b.get("width") or 0.006) * width_px))
            draw.line(pts, fill=_FILL, width=w, joint="curve")
            continue
        x, y, w, h = b["rect"]
        draw.rectangle([x * width_px, y * height_px,
                        max(x * width_px, (x + w) * width_px - 1),
                        max(y * height_px, (y + h) * height_px - 1)], fill=_FILL)
    return img


# ── 注册表 ─────────────────────────────────────────────────────────────────
def _collect_new(tables, before, text, loc, locations, counts):
    for orig in tables.fwd.keys() - before:
        locations.setdefault(orig, set()).add(loc)
    if text:
        for orig in tables.fwd:
            if orig and orig in text:
                counts[orig] = counts.get(orig, 0) + text.count(orig)


def _final_text(hit, edit):
    if edit is not None and edit.get("action") == "keep":
        return getattr(hit, "_orig", None) or hit.original or hit.token
    if edit is not None and edit.get("action") == "replace":
        return edit.get("text") or hit.token
    return hit.token


def _attach_origins(tables, hits):
    by_token = {rec[0]: orig for orig, rec in tables.fwd.items()}
    for hit in hits:
        hit._orig = by_token.get(hit.token)


def _build_manifest_hits(tables, locations, counts, max_hits):
    hits = fc._build_hits(tables, locations, counts, max_hits)
    _attach_origins(tables, hits)
    return hits


# ── PDF scan（G782/G783/G784/G785/G792）────────────────────────────────────
def scan_pdf(job, src, staged, opts, cancel):
    # @guard G782 逐页渲染落盘 + 磁盘预算
    # @guard G783 文本层命中（Tier0，不跑 OCR 也出框）
    # @guard G784 隐藏文字命中并入清单
    # @guard G785 OCR 未就绪/单页失败
    # @guard G792 覆盖声明
    cfg = fc.job_cfg(job)
    with open(src, "rb") as f:
        raw = f.read()
    try:
        doc = pr._open_document(raw)
    except Exception:
        raise fw.FileWorkbenchError(E_CARRIER, 422)
    pages = len(doc)
    if pages <= 0 or pages > _max_pages(cfg):
        raise fw.FileWorkbenchError(E_CARRIER, 400)
    job_dir = os.path.dirname(staged)
    preview_dir = os.path.join(job_dir, "preview")
    shutil.rmtree(preview_dir, ignore_errors=True)
    os.makedirs(preview_dir, exist_ok=True)
    tables = tr._tables()
    before_all = set(tables.fwd)
    locations, counts = {}, {}
    page_meta = []
    warnings = []
    text_layer_hits = 0
    hidden_hits = 0
    skipped_ocr = 0
    mode = str(opts.get("mode") or "manual")

    if mode == "auto":
        ok, why = _ocr_ready()
        if not ok:
            doc.close()
            raise fw.FileWorkbenchError(E_OCR, 503)

    try:
        for index in range(pages):
            if cancel is not None and cancel.is_set():
                raise fw.FileWorkbenchError(E_PREVIEW, 409)
            width_pt, height_pt = doc.get_page_size(index)
            if width_pt <= 0 or height_pt <= 0:
                raise fw.FileWorkbenchError(E_BUDGET, 507)
            scale = max(pr.MIN_RENDER_SCALE,
                        min(pr.MAX_RENDER_SCALE, _PAGE_WIDTH / float(width_pt)))
            need = int(width_pt * scale) * int(height_pt * scale) * 3
            if _disk_free(job_dir) < need * 2:
                raise fw.FileWorkbenchError(E_BUDGET, 507)
            try:
                page = doc[index]
                bitmap = page.render(scale=scale, draw_annots=False)
                image = bitmap.to_pil().convert("RGB")
            except Exception:
                raise fw.FileWorkbenchError(E_BUDGET, 507)
            page_jpeg = pr._jpeg(image)
            preview_name = "page-%04d.jpg" % (index + 1)
            with open(os.path.join(preview_dir, preview_name), "wb") as f:
                f.write(page_jpeg)
            boxes = []
            page_hit_ids = set()
            # 文本层（Tier 0）
            try:
                text, char_boxes = pr._page_text_layer(page)
            except Exception:
                raise fw.FileWorkbenchError(E_TEXTLAYER, 422)
            if text.strip():
                b = set(tables.fwd)
                tr.mask_body(text, job.id)
                _collect_new(tables, b, text, "第%d页文本层" % (index + 1), locations, counts)
                spans = []
                for orig in tables.fwd.keys() - b:
                    start = 0
                    while True:
                        pos = text.find(orig, start)
                        if pos < 0:
                            break
                        spans.append((pos, pos + len(orig)))
                        start = pos + len(orig)
                if spans:
                    rects = pr._text_rects_px(spans, char_boxes, page, scale)
                    if rects is None:
                        boxes.append({"kind": "full", "source": "auto"})
                        warnings.append("page_%d_full_cover" % (index + 1))
                    else:
                        for l, t, r, btm in rects:
                            boxes.append({"kind": "rect",
                                          "rect": [l / image.size[0], t / image.size[1],
                                                   (r - l) / image.size[0],
                                                   (btm - t) / image.size[1]],
                                          "source": "text_layer", "orig": "", "label": ""})
                        text_layer_hits += len(spans)
                        for orig in tables.fwd.keys() - b:
                            page_hit_ids.add(orig)
            # OCR 自动框选
            if mode == "auto":
                try:
                    detected = _detect_boxes(page_jpeg, image, job.id)
                except PageOcrFailed:
                    detected = [{"kind": "full", "source": "auto"}]
                    warnings.append("page_%d_ocr_failed_full_cover" % (index + 1))
                    skipped_ocr += 1
                b = set(tables.fwd)
                texts = " ".join(x.get("text") or "" for x in detected)
                texts = texts.strip()
                if texts:
                    tr.mask_body(texts, job.id)
                    _collect_new(tables, b, texts,
                                 "第%d页自动识别" % (index + 1), locations, counts)
                for box in detected:
                    if box.get("kind") == "full" or "rect" not in box:
                        boxes.append({"kind": "full", "source": "auto"})
                        continue
                    boxes.append({"kind": "rect", "rect": box["rect"],
                                  "source": "auto", "orig": box.get("text") or "",
                                  "label": box.get("label") or ""})
                for orig in tables.fwd.keys() - b:
                    locations.setdefault(orig, set()).add("第%d页自动识别" % (index + 1))
                    page_hit_ids.add(orig)
            page_meta.append({"page": index + 1, "w": image.size[0], "h": image.size[1],
                              "preview": preview_name, "boxes": boxes,
                              "text_hit_origs": sorted(page_hit_ids)})
    except Exception:
        doc.close()
        raise
    # 隐藏文字（文档信息/XMP/书签/注释/表单/附件）
    hidden_hits = _scan_hidden(job.id, raw, locations, counts)
    final_hits = _build_manifest_hits(tables, locations, counts,
                                      int(cfg.get("files_max_hits", 20000)))
    token_to_id = {h.token: h.hit_id for h in final_hits}
    orig_to_id = {getattr(h, "_orig", None): h.hit_id for h in final_hits
                  if getattr(h, "_orig", None)}
    for page in page_meta:
        for box in page["boxes"]:
            orig = box.get("orig")
            if box.get("source") == "text_layer" and not orig:
                # 文本层整页覆盖时无法精确归属：标到页内全部文本命中 id
                continue
            if orig and orig in orig_to_id:
                box["hit_id"] = orig_to_id[orig]
                box["orig"] = ""
        page["text_hit_ids"] = [orig_to_id[o] for o in page["text_hit_origs"]
                                if o in orig_to_id]
        page.pop("text_hit_origs", None)
    manifest = {"kind": "pdf", "pages": page_meta,
                "attachments": _attachment_count(raw),
                "hidden_hits": hidden_hits,
                "text_layer_hits": text_layer_hits,
                "skipped_ocr_pages": skipped_ocr,
                "warnings": warnings}
    with open(staged, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False)
    doc.close()
    coverage = {"rendered_pages": pages, "rasterized_pages": 0,
                "text_layer_hits": text_layer_hits, "hidden_hits": hidden_hits,
                "skipped_ocr_pages": skipped_ocr,
                "attachments_stripped": 0, "warnings": warnings}
    return {"hits": final_hits, "coverage": coverage, "warnings": warnings}


class _TaggingMasker(pr._HiddenMasker):
    """继承隐藏文字掩码器，记录「哪个载体命中了哪个原文」。"""

    def __init__(self, fn):
        pr._HiddenMasker.__init__(self, fn)
        self.tag = ""
        self.tags = {}

    def _text(self, value):
        try:
            text = str(value)
        except Exception:
            text = ""
        new = pr._HiddenMasker._text(self, value)
        if new is not None:
            for orig in tr._tables().fwd:
                if orig and orig in text:
                    self.tags.setdefault(orig, set()).add(self.tag)
        return new


def _scan_hidden(sid, raw, locations, counts):
    """把文档信息/XMP/书签/注释/表单/附件扫一遍，命中登记到 locations。"""
    from pypdf import PdfReader, PdfWriter
    try:
        reader = PdfReader(io.BytesIO(raw))
        writer = PdfWriter(clone_from=reader)
    except Exception:
        raise fw.FileWorkbenchError(E_HIDDEN, 422)
    masker = _TaggingMasker(lambda t: tr.mask_body(t, sid))
    total = 0

    def run(tag, call):
        nonlocal total
        tables = tr._tables()
        b = set(tables.fwd)
        before = masker.hits
        masker.tag = tag
        call()
        total += masker.hits - before
        for orig in tables.fwd.keys() - b:
            locations.setdefault(orig, set()).add(tag)
            counts[orig] = counts.get(orig, 0) + 1
        for orig, tags in masker.tags.items():
            if orig in tables.fwd:
                locations.setdefault(orig, set()).update(tags)

    try:
        run("文档信息", lambda: masker.info(writer))
        run("文档信息", lambda: masker.xmp(writer))
        run("书签", lambda: masker.outline(writer))
        for page in writer.pages:
            run("注释", lambda p=page: masker.annots(p))
        run("表单", lambda: masker.form(writer))
        run("附件", lambda: masker.attachments(writer))
    except fw.FileWorkbenchError:
        raise
    except Exception:
        raise fw.FileWorkbenchError(E_HIDDEN, 422)
    return total


def _attachment_count(raw):
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        root = reader.trailer.get("/Root") or {}
        names = root.get("/Names")
        if names is None:
            return 0
        names = names.get_object()
        tree = names.get("/EmbeddedFiles")
        if tree is None:
            return 0
        count = 0
        stack = [tree.get_object()]
        while stack:
            node = stack.pop()
            stack.extend(k.get_object() for k in (node.get("/Kids") or []))
            arr = node.get("/Names") or []
            count += len(arr) // 2
        return count
    except Exception:
        return 0


# ── PDF apply（G788/G789/G790/G792）────────────────────────────────────────
def apply_pdf(job, staged, out, edits, redactions, options):
    # @guard G788 栅格化判据：有框/未保留文本层命中→整页栅格化；全保留无框→原页+告警
    # @guard G789 隐藏文字按注册表替换，不重扫
    # @guard G790 文档信息清空 + XMP 删除 + 附件剥离
    cfg = fc.job_cfg(job)
    with open(staged, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    hits = fc.job_hits(job)
    hits_by_id = {h.hit_id: h for h in hits}
    fc._validate_edits(edits, hits_by_id)
    kept = {e.get("hit_id") for e in (edits or []) if e.get("action") == "keep"}
    finals = {}
    for hit in hits:
        edit = next((e for e in (edits or []) if e.get("hit_id") == hit.hit_id), None)
        orig = getattr(hit, "_orig", None) or hit.original
        if orig:
            finals[orig] = _final_text(hit, edit)
    pages = manifest.get("pages") or []
    src = os.path.join(os.path.dirname(staged), "src.bin")
    with open(src, "rb") as f:
        raw = f.read()
    try:
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(io.BytesIO(raw))
        writer = PdfWriter(clone_from=reader)
        doc = pr._open_document(raw)
    except Exception:
        raise fw.FileWorkbenchError(E_APPLY, 422)
    warnings = list(manifest.get("warnings") or [])
    # 隐藏文字替换（长词优先）
    _apply_hidden(writer, finals)
    # 文档信息（默认清空）
    if options.get("clear_docinfo", bool(cfg.get("files_clear_pdf_docinfo", True))):
        _clear_docinfo(writer)
    # 附件
    keep_attachments = bool(options.get("keep_attachments"))
    stripped = kept_attachments = 0
    if keep_attachments:
        kept_attachments = int(manifest.get("attachments") or 0)
        if kept_attachments:
            warnings.append("attachments_kept_unscanned")
    else:
        stripped = _strip_attachments(writer)
    rendered = []
    rasterized = 0
    for page in pages:
        if not _page_needs_raster(page, kept, redactions, warnings):
            rendered.append(None)
            continue
        rasterized += 1
        preview = os.path.join(os.path.dirname(staged), "preview", page["preview"])
        try:
            with open(preview, "rb") as f:
                jpeg = f.read()
            image_mod, _ = vr._pil()
            image = image_mod.open(io.BytesIO(jpeg)).convert("RGB")
        except Exception:
            raise fw.FileWorkbenchError(E_RASTER, 422)
        boxes = []
        for b in page.get("boxes") or []:
            if b.get("kind") == "full":
                boxes.append({"kind": "full"})
            elif b.get("kind") == "rect":
                # 文本层框：只有未保留的命中才涂；保留的命中让原文字可见
                if b.get("source") == "text_layer" and b.get("hit_id") in kept:
                    continue
                boxes.append({"kind": "rect", "rect": b["rect"]})
        boxes.extend(_page_redactions(redactions, page.get("page")))
        _paint(image, boxes)
        rendered.append((pr._jpeg(image), image.size))
    out_bytes = pr._compose(writer, rendered, doc)
    doc.close()
    if out_bytes is None:
        raise fw.FileWorkbenchError(E_RASTER, 422)
    with open(out, "wb") as f:
        f.write(out_bytes)
    coverage = {"rendered_pages": len(pages), "rasterized_pages": rasterized,
                "text_layer_hits": manifest.get("text_layer_hits", 0),
                "hidden_hits": manifest.get("hidden_hits", 0),
                "skipped_ocr_pages": manifest.get("skipped_ocr_pages", 0),
                "attachments_stripped": stripped,
                "attachments_kept_unscanned": kept_attachments,
                "warnings": warnings}
    return coverage


def _page_needs_raster(page, kept, redactions, warnings):
    if _page_redactions(redactions, page.get("page")):
        return True
    for box in page.get("boxes") or []:
        if box.get("kind") == "full":
            return True
        if box.get("kind") == "rect" and box.get("source") != "text_layer":
            return True
    ids = page.get("text_hit_ids") or []
    if ids and any(i not in kept for i in ids):
        return True
    if ids and all(i in kept for i in ids):
        if "page_kept_with_unmasked_hits" not in warnings:
            warnings.append("page_kept_with_unmasked_hits")
    return False


def _apply_hidden(writer, finals):
    if not finals:
        return
    ordered = sorted(finals.items(), key=lambda kv: len(kv[0]), reverse=True)

    def repl(text):
        for orig, new in ordered:
            if orig and orig in text:
                text = text.replace(orig, new)
        return text

    masker = pr._HiddenMasker(repl)
    try:
        masker.info(writer)
        masker.xmp(writer)
        masker.outline(writer)
        for page in writer.pages:
            masker.annots(page)
        masker.form(writer)
    except Exception:
        raise fw.FileWorkbenchError(E_APPLY, 422)


def _clear_docinfo(writer):
    from pypdf.generic import NameObject, TextStringObject
    try:
        info = writer._info
        if info is not None:
            info = info.get_object()
            for key in ("/Author", "/Title", "/Subject", "/Keywords", "/Creator", "/Producer"):
                if key in info:
                    info[NameObject(key)] = TextStringObject("")
            for key in ("/CreationDate", "/ModDate"):
                if key in info:
                    del info[NameObject(key)]
        root = writer._root_object
        if "/Metadata" in root:
            del root[NameObject("/Metadata")]
    except Exception:
        raise fw.FileWorkbenchError(E_DOCINFO, 422)


def _strip_attachments(writer):
    from pypdf.generic import NameObject
    names = writer._root_object.get("/Names")
    if names is None:
        return 0
    names = names.get_object()
    tree = names.get("/EmbeddedFiles")
    if tree is None:
        return 0
    count = 0
    stack = [tree.get_object()]
    while stack:
        node = stack.pop()
        stack.extend(k.get_object() for k in (node.get("/Kids") or []))
        count += len(node.get("/Names") or []) // 2
    del names[NameObject("/EmbeddedFiles")]
    return count


# ── 图片 scan/apply（G786/G787/G791/G792）─────────────────────────────────
def scan_image(job, src, staged, opts, cancel):
    # @guard G786 自动框选只出框；预览最长边 ≤2000
    cfg = fc.job_cfg(job)
    with open(src, "rb") as f:
        raw = f.read()
    img, why, _meta, frames = vr._load_image_ex(raw)
    if img is None:
        raise fw.FileWorkbenchError(E_CARRIER, 422)
    if frames > 1:
        raise fw.FileWorkbenchError(E_CARRIER, 400)
    job_dir = os.path.dirname(staged)
    preview_dir = os.path.join(job_dir, "preview")
    shutil.rmtree(preview_dir, ignore_errors=True)
    os.makedirs(preview_dir, exist_ok=True)
    preview = img.copy()
    preview.thumbnail((_PREVIEW_MAX, _PREVIEW_MAX))
    with open(os.path.join(preview_dir, "page-0001.jpg"), "wb") as f:
        f.write(pr._jpeg(preview))
    tables = tr._tables()
    locations, counts = {}, {}
    boxes = []
    warnings = []
    skipped = 0
    mode = str(opts.get("mode") or "manual")
    if mode == "auto":
        ok, rwhy = _ocr_ready()
        if not ok:
            raise fw.FileWorkbenchError(E_OCR, 503)
        try:
            detected = _detect_boxes(raw, img, job.id)
            b = set(tables.fwd)
            texts = " ".join(x.get("text") or "" for x in detected).strip()
            if texts:
                tr.mask_body(texts, job.id)
                _collect_new(tables, b, texts, "图片自动识别", locations, counts)
            for box in detected:
                boxes.append({"kind": "rect", "rect": box["rect"], "source": "auto",
                              "label": box.get("label") or "", "orig": box.get("text") or ""})
        except PageOcrFailed:
            boxes.append({"kind": "full", "source": "auto"})
            warnings.append("image_ocr_failed_full_cover")
            skipped = 1
    hits = _build_manifest_hits(tables, locations, counts,
                                int(cfg.get("files_max_hits", 20000)))
    orig_to_id = {getattr(h, "_orig", None): h.hit_id for h in hits
                  if getattr(h, "_orig", None)}
    for box in boxes:
        if box.get("orig") and box["orig"] in orig_to_id:
            box["hit_id"] = orig_to_id[box["orig"]]
    manifest = {"kind": "image", "pages": [{"page": 1, "w": img.size[0], "h": img.size[1],
                                            "preview": "page-0001.jpg", "boxes": boxes,
                                            "text_hit_ids": []}],
                "attachments": 0, "hidden_hits": 0}
    with open(staged, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False)
    coverage = {"rendered_pages": 1, "rasterized_pages": 0,
                "text_layer_hits": 0, "hidden_hits": 0, "skipped_ocr_pages": skipped,
                "attachments_stripped": 0, "warnings": warnings}
    return {"hits": hits, "coverage": coverage, "warnings": warnings}


def apply_image(job, staged, out, edits, redactions, options):
    # @guard G791 EXIF/XMP 剥离、方向先应用、输出不透明 RGB
    with open(staged, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    hits = fc.job_hits(job)
    fc._validate_edits(edits, {h.hit_id: h for h in hits})
    src = os.path.join(os.path.dirname(staged), "src.bin")
    with open(src, "rb") as f:
        raw = f.read()
    img, why, meta, _frames = vr._load_image_ex(raw)
    if img is None:
        raise fw.FileWorkbenchError(E_META, 422)
    # 透明底填白（不透明 RGB）
    if img.mode in ("RGBA", "LA") or "transparency" in (img.info or {}):
        from PIL import Image
        rgba = img.convert("RGBA")
        base = Image.new("RGB", rgba.size, (255, 255, 255))
        base.paste(rgba, mask=rgba.split()[-1])
        img = base
    else:
        img = img.convert("RGB")
    _paint(img, _page_redactions(redactions, 1))
    ext = os.path.splitext(job.filename)[1].lstrip(".").lower()
    fmt = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "webp": "WEBP",
           "bmp": "BMP", "tif": "TIFF", "tiff": "TIFF"}.get(ext, "PNG")
    keep_icc = bool(options.get("keep_icc"))
    icc = (meta.binary_info.get("icc_profile") if meta is not None else None)
    buf = io.BytesIO()
    try:
        if keep_icc and icc:
            if fmt == "JPEG":
                img.save(buf, format=fmt, quality=95, subsampling=0, icc_profile=icc)
            else:
                img.save(buf, format=fmt, icc_profile=icc)
        elif fmt == "JPEG":
            img.save(buf, format=fmt, quality=95, subsampling=0)
        else:
            img.save(buf, format=fmt)
    except Exception:
        raise fw.FileWorkbenchError(E_META, 422)
    with open(out, "wb") as f:
        f.write(buf.getvalue())
    warnings = []
    coverage = {"rendered_pages": 1, "rasterized_pages": 1,
                "text_layer_hits": 0, "hidden_hits": 0, "skipped_ocr_pages": 0,
                "attachments_stripped": 0, "warnings": warnings}
    return coverage


# ── 预览（G793）────────────────────────────────────────────────────────────
def preview_data_url(job, page=1):
    # @guard G793 仅 ready/review 可读；返回 data URL
    if job.status not in (fw.ST_READY, fw.ST_REVIEW):
        raise fw.FileWorkbenchError(E_PREVIEW, 409)
    try:
        page = int(page)
    except Exception:
        raise fw.FileWorkbenchError(E_PREVIEW, 400)
    job_dir = None
    mgr = getattr(job, "_mgr", None)
    if mgr is not None:
        job_dir = str(mgr.job_dir(job.id))
    if not job_dir:
        raise fw.FileWorkbenchError(E_PREVIEW, 400)
    path = os.path.join(job_dir, "preview", "page-%04d.jpg" % page)
    if not os.path.isfile(path):
        _lazy_preview(job, job_dir, page)
    if not os.path.isfile(path):
        raise fw.FileWorkbenchError(E_PREVIEW, 400)
    with open(path, "rb") as f:
        data = f.read()
    return "data:image/jpeg;base64," + base64.b64encode(data).decode("ascii")


def _lazy_preview(job, job_dir, page):
    os.makedirs(os.path.join(job_dir, "preview"), exist_ok=True)
    src = os.path.join(job_dir, "src.bin")
    path = os.path.join(job_dir, "preview", "page-%04d.jpg" % page)
    try:
        if job.carrier == "image":
            with open(src, "rb") as f:
                img, _why, _meta, _frames = vr._load_image_ex(f.read())
            if img is None:
                return
            img = img.convert("RGB")
            img.thumbnail((_PREVIEW_MAX, _PREVIEW_MAX))
            with open(path, "wb") as f:
                f.write(pr._jpeg(img))
        elif job.carrier == "pdf":
            with open(src, "rb") as f:
                raw = f.read()
            doc = pr._open_document(raw)
            try:
                index = page - 1
                if index < 0 or index >= len(doc):
                    return
                width_pt, _height = doc.get_page_size(index)
                scale = max(pr.MIN_RENDER_SCALE,
                            min(pr.MAX_RENDER_SCALE, _PAGE_WIDTH / float(width_pt)))
                image = doc[index].render(scale=scale, draw_annots=False).to_pil().convert("RGB")
                with open(path, "wb") as f:
                    f.write(pr._jpeg(image))
            finally:
                doc.close()
    except Exception:
        return


def register(mgr):
    mgr.register_carrier("pdf", scan_pdf, apply_pdf)
    mgr.register_carrier("image", scan_image, apply_image)
