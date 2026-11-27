"""文件脱敏工作台 · 文字类载体（file-workbench-text，2026-11-24）。

OOXML（docx/xlsx/pptx）与纯文本的两阶段 scan/apply：
  · scan 在 transparent.file_store_scope 内调 tr.mask_body，产「已打码 staged + 命中注册表」；
  · apply 在 staged 上做确定性 token→最终文本替换（长词优先），不重跑识别（D10）。

复用 tr.mask_body 核心脱敏与 mask_ooxml_bytes（panel.py:8151）的叶子遍历/跨 run 合并范式，
但**不改 mask_ooxml_bytes 的签名/行为**（扩展链路）。嵌入对象默认剥离在 apply 落成品时执行
（D9）——scan 自动跑于上传时、keep_embedded_objects 是 apply 选项，故剥离必须在 apply。

错误码 FILE_76xx 与规约守卫 G761~G772 一一对应。
"""

import os
import io
import re
import time
import zipfile
import hashlib
import shutil
import xml.etree.ElementTree as ET
from collections import Counter

import transparent as tr
from credential_labels import is_credential
import file_workbench as fw

# ── 错误码（G761~G772）──────────────────────────────────────────────────────
E_CARRIER = "FILE_7601"     # 非 zip/加密/宏/旧格式/损坏
E_ZIPBOMB = "FILE_7602"     # zip 解压防线
E_SCAN = "FILE_7603"        # scan 两阶段
E_DOCPROPS = "FILE_7604"    # docProps 全覆盖
E_EMBED = "FILE_7605"       # 嵌入剥离
E_APPLY = "FILE_7606"       # 确定性替换
E_EDIT = "FILE_7607"        # 编辑校验
E_ZERO = "FILE_7608"        # 零命中字节一致
E_TEXT = "FILE_7609"        # 纯文本载体
E_HITS = "FILE_7610"        # 命中上限
E_CRED = "FILE_7611"        # 凭据隐私
E_COVERAGE = "FILE_7612"    # 覆盖声明

OOXML_EXTS = {"docx", "xlsx", "pptx"}
TEXT_EXTS = {"txt", "md", "json", "csv", "log", "xml", "yaml", "yml", "html"}

# zip 解压防线（G762）
_MAX_ENTRY = 512 * 1024 * 1024        # 单条目 512MB
_MAX_TOTAL = 4 * 1024 * 1024 * 1024   # 总量 4GB
_BOMB_RATIO = 200
_BOMB_SIZE = 100 * 1024 * 1024

_EDIT_MAX = 64


def carrier_for(filename):
    ext = os.path.splitext(filename or "")[1].lstrip(".").lower()
    if ext in OOXML_EXTS:
        return "ooxml"
    if ext in TEXT_EXTS:
        return "text"
    return ""


def _part_label(fn):
    fn = fn.lower()
    if fn.startswith("docprops/"):
        return "文档属性"
    if "header" in fn or "footer" in fn:
        return "页眉页脚"
    if fn.startswith("word/"):
        return "正文"
    if fn.startswith("xl/"):
        return "工作表"
    if fn.startswith("ppt/"):
        return "幻灯片"
    return "正文"


def _is_media(fn):
    fn = fn.lower()
    if "/media/" not in fn or "." not in fn:
        return False
    return fn.rsplit(".", 1)[-1] in (
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "emf", "wmf", "svg",
    )


def _sync_visual_cfg(cfg, vr):
    if not isinstance(cfg, dict):
        return
    kw = {}
    if "ocr_endpoint" in cfg:
        ep = str(cfg.get("ocr_endpoint") or "").strip()
        if ep != vr._CONFIGURED_ENDPOINT:
            kw["ocr_endpoint"] = ep
    if "ocr_allow_remote" in cfg:
        ar = bool(cfg.get("ocr_allow_remote", False))
        if ar != bool(vr._ALLOW_REMOTE):
            kw["allow_remote"] = ar
    if "ocr_engine" in cfg:
        eng = str(cfg.get("ocr_engine") or "auto").strip().lower()
        eng = eng if eng in ("auto", "local", "http") else "auto"
        if eng != vr._ENGINE_PREF:
            kw["engine"] = eng
    if kw:
        vr.configure(**kw)


def _ocr_ready(cfg=None):
    """判定工作台视觉/内嵌图 OCR 是否可用。不把默认环回占位地址误当已配置。"""
    try:
        import visual_redactor as vr
    except Exception:
        return False, "ocr_unavailable"
    img_mod, _draw = vr._pil()
    if img_mod is None:
        return False, vr.BLOCK_PILLOW_MISSING
    _sync_visual_cfg(cfg, vr)
    pref = vr.engine_pref()
    if pref in ("auto", "local"):
        try:
            import ocr_engine
            ok, why = ocr_engine.available()
            if ok:
                return True, ""
            if pref == "local":
                return False, why or vr.BLOCK_RUNTIME_MISSING
        except Exception:
            if pref == "local":
                return False, vr.BLOCK_RUNTIME_MISSING
    has_explicit_http = bool(
        (os.environ.get(vr.OCR_ENDPOINT_ENV) or "").strip()
        or str((cfg or {}).get("ocr_endpoint") or "").strip()
        or vr._CONFIGURED_ENDPOINT
    )
    if pref == "http" or has_explicit_http:
        url, why = vr.ocr_endpoint()
        if url:
            return True, ""
        return False, why or vr.BLOCK_UNAVAILABLE
    return False, vr.BLOCK_RUNTIME_MISSING


def _placeholder_image_bytes(image_bytes, fn, vr):
    """为无法识别、损坏、动图或矢量内嵌媒体生成中性灰占位图（剥离元数据）。"""
    img_mod, _draw = vr._pil()
    if img_mod is None:
        raise fw.FileWorkbenchError(E_SCAN, 422)
    ext = os.path.splitext(fn or "")[1].lower().lstrip(".")
    size = (480, 320)
    fmt = vr._EXT_TO_FORMAT.get(ext, "PNG")
    if ("." + ext) in vr.RASTER_IMAGE_EXTS:
        decoded, _why, _meta, _frames = vr._load_image_ex(image_bytes)
        if decoded is not None:
            size = (max(1, decoded.size[0]), max(1, decoded.size[1]))
            fmt = vr._output_format(decoded, fn)
    placeholder = img_mod.new("RGB", size, vr._FILL)
    buf = io.BytesIO()
    placeholder.save(buf, fmt)
    return buf.getvalue()


def _progress(job, stage, current, total, pct=None, indeterminate=False):
    mgr = getattr(job, "_mgr", None)
    if mgr is not None and hasattr(mgr, "set_progress"):
        mgr.set_progress(job.id, stage, current, total, pct=pct, indeterminate=indeterminate)


def _is_non_image_media(fn):
    low = fn.lower()
    return "/media/" in low and not low.endswith("/") and not _is_media(fn)


def _mask_embedded_image(content, fn, job, cfg):
    """在嵌套任务作用域内脱敏 OOXML 内嵌图，返回 `(bytes, hits, status)`。"""
    import visual_redactor as vr
    _sync_visual_cfg(cfg, vr)
    ext = os.path.splitext(fn or "")[1].lower()
    max_px = int((cfg or {}).get("files_max_image_mp", 32) or 32) * 1_000_000
    if ext and ext not in vr.RASTER_IMAGE_EXTS:
        return _placeholder_image_bytes(content, fn, vr), 1, vr.ST_COVER_UNSUPPORTED

    sub_id = job.id + ":media"
    try:
        with tr.file_store_scope(sub_id):
            res = vr.redact_image_bytes(
                content, sub_id, tr, deadline=time.monotonic() + 180.0, hint_name=fn,
                allow_cover=True, cover_on_scan_fail=False, use_cache=False,
                max_pixels=max_px,
                max_bytes=max(vr.MAX_DATA_URL_IMAGE_BYTES, len(content) + 1),
                max_tiles=64,
            )
    finally:
        tr.file_suffix_unregister(sub_id)

    mode = res.get("mode")
    if mode == vr.MODE_CLEAN:
        return content, 0, vr.ST_CLEAN
    if mode == vr.MODE_REDACTED:
        stats = res.get("stats") or {}
        status = vr.ST_COVER_UNLOCALIZED if stats.get("covered") else vr.ST_MASKED
        return res.get("bytes") or content, int(res.get("hit_count") or 1), status

    reason = res.get("reason") or vr.BLOCK_GEOMETRY
    if reason in (vr.BLOCK_UNAVAILABLE, vr.BLOCK_RUNTIME_MISSING, vr.BLOCK_NOT_LOOPBACK):
        return content, 0, reason
    return _placeholder_image_bytes(content, fn, vr), 1, vr.ST_COVER_UNSUPPORTED


def _is_embedding(fn):
    return "/embeddings/" in fn.lower()


def _docprops_entry(fn):
    fn = fn.lower()
    return fn in ("docprops/core.xml", "docprops/app.xml", "docprops/custom.xml")


def _should_mask(fn, ext):
    fn = fn.lower()
    if _docprops_entry(fn):
        return True
    if ext == "docx" and fn.startswith("word/") and fn.endswith(".xml"):
        return True
    if ext == "xlsx" and fn.startswith("xl/") and fn.endswith(".xml"):
        return True
    if ext == "pptx" and fn.startswith("ppt/") and fn.endswith(".xml"):
        return True
    return False


# ── 预检（G761/G762）─────────────────────────────────────────────────────────
# 纯文本载体上限：scan_text 是**整文件**读入 + 解码 + mask_body（全程多份副本）。
# 实测 16 MiB 文本 → 3.3s / 峰值 +139 MB；若沿用 1 GiB 的通用上限，线性外推就是
# ~3.5 分钟 / ~9 GB 内存 —— 一份大日志就能把引擎顶到 OOM（2026-11-26 实测）。
# 默认 128 MiB 由 `files_max_text_mb` 配置，仍同时受 `files_max_size_mb` 约束。
_TEXT_LIMIT_MB_DEFAULT = 128


def _probe_text(src_path, cfg=None):
    """文本载体只做尺寸闸：超限 fail-closed，不产成品（其余校验由载体本身负责）。"""
    try:
        size = os.path.getsize(src_path)
    except OSError:
        return False, None, E_CARRIER
    limit_mb = int((cfg or {}).get("files_max_text_mb", _TEXT_LIMIT_MB_DEFAULT))
    if size > limit_mb * 1024 * 1024:
        return False, None, fw.E_TOO_LARGE
    return True, None, ""


def probe(src_path, carrier, cfg=None):
    """返回 (ok, page_count, error_code)。不通过一律 failed，绝不原样放行。"""
    # @guard G761 非 zip/加密/宏/旧格式 fail-closed
    # @guard G762 zip 解压防线
    if carrier == "text":
        return _probe_text(src_path, cfg)
    if carrier != "ooxml":
        return False, None, E_CARRIER
    try:
        if not zipfile.is_zipfile(src_path):
            return False, None, E_CARRIER          # 非 zip（含旧格式/加密包）
        with zipfile.ZipFile(src_path) as z:
            names = [n.lower() for n in z.namelist()]
            if any(n.endswith("vbaproject.bin") for n in names):
                return False, None, E_CARRIER      # 含宏
            if any("encryptedpackage" in n for n in names):
                return False, None, E_CARRIER      # 加密 OOXML
            total = 0
            for i in z.infolist():
                if i.flag_bits & 0x1:
                    return False, None, E_CARRIER  # zip 加密位
                if i.file_size > _MAX_ENTRY:
                    return False, None, E_ZIPBOMB
                total += i.file_size
                if i.compress_size > 0 and i.file_size / i.compress_size > _BOMB_RATIO \
                        and i.file_size > _BOMB_SIZE:
                    return False, None, E_ZIPBOMB
            if total > _MAX_TOTAL:
                return False, None, E_ZIPBOMB
        return True, None, ""
    except zipfile.BadZipFile:
        return False, None, "office_parse_failed"
    except Exception:
        return False, None, "office_parse_failed"


# ── 注册表构建 ──────────────────────────────────────────────────────────────
def _build_hits(tables, locations, counts, max_hits, only_observed=False):
    # @guard G771 凭据只 preview+digest、不可编辑保留
    # @guard G770 超上限失败
    cw_keys = set(getattr(tr, "CUSTOM_WORDS", None) or ())
    groups = {}
    order = []
    for orig, rec in tables.fwd.items():
        if only_observed and orig not in counts and orig not in locations:
            continue
        token, label = rec[0], rec[1]
        cred = bool(is_credential(label))
        digest = hashlib.sha256(orig.encode("utf-8", "replace")).hexdigest()[:16] if cred else ""
        if cred:
            gkey = ("cred", digest)
        else:
            norm = (orig or "").strip().casefold()
            gkey = ("text", norm or orig)
        if gkey not in groups:
            groups[gkey] = {
                "label": label,
                "cred": cred,
                "digest": digest,
                "origs": [],
                "tokens": [],
                "locs": set(),
                "count": 0,
                "custom": False,
            }
            order.append(gkey)
        g = groups[gkey]
        g["origs"].append(orig)
        g["tokens"].append(token)
        g["locs"].update(locations.get(orig, set()) or ())
        occ = counts.get(orig)
        if occ is None:
            occ = 1 if (not only_observed or orig in locations) else 0
        g["count"] += int(occ or 0)
        if orig in cw_keys:
            g["custom"] = True

    hits = []
    for gkey in order:
        g = groups[gkey]
        origs = g["origs"]
        clean = [o for o in origs if o and o == o.strip()]
        rep_orig = clean[0] if clean else ((origs[0].strip() or origs[0]) if origs else "")
        locs = sorted(g["locs"]) or ["正文"]
        cred = g["cred"]
        h = fw.FileHit(
            hit_id="h%d" % (len(hits) + 1),
            token=g["tokens"][0],
            label=g["label"],
            source="custom" if g["custom"] else "builtin",
            original=None if cred else rep_orig,
            count=max(1, g["count"]),
            locations=locs,
            editable=not cred,
            can_keep=not cred,
            credential=cred,
            tokens=list(g["tokens"]),
            orig_variants=[] if cred else list(origs),
        )
        if cred:
            h.preview = (rep_orig[:4] + "***") if rep_orig else ""
            h.digest = g["digest"]
        hits.append(h)
    if len(hits) > max_hits:
        raise fw.FileWorkbenchError(E_HITS, 400)
    return hits


def _accumulate(tables, before, orig_text, loc, locations, counts, masked_text=None):
    if isinstance(before, (set, frozenset)):
        new_keys = tables.fwd.keys() - before
    else:
        before_n = int(before or 0)
        if len(tables.fwd) > before_n:
            new_keys = list(tables.fwd.keys())[before_n:]
        else:
            new_keys = ()

    if masked_text is not None:
        if masked_text == orig_text and not new_keys:
            return
        rev_map = getattr(tables, "rev", None) or {}
        tok_counts = Counter(tr._PLACEHOLDER_RX.findall(masked_text))
        if tok_counts and "{{" in orig_text:
            orig_toks = Counter(tr._PLACEHOLDER_RX.findall(orig_text))
            for t, c in orig_toks.items():
                if t in tok_counts:
                    tok_counts[t] -= c
        seen_origs = set()
        for tok, delta in tok_counts.items():
            if delta <= 0:
                continue
            rec = rev_map.get(tok)
            if not rec:
                continue
            orig = rec[0]
            if not orig:
                continue
            seen_origs.add(orig)
            locations.setdefault(orig, set()).add(loc)
            counts[orig] = counts.get(orig, 0) + delta
        for orig in new_keys:
            if not orig:
                continue
            locations.setdefault(orig, set()).add(loc)
            if orig not in seen_origs:
                counts[orig] = counts.get(orig, 0) + 1
        return

    for orig in new_keys:
        locations.setdefault(orig, set()).add(loc)
    for orig in tables.fwd:
        if not orig:
            continue
        cnt = orig_text.count(orig)
        if cnt == 0:
            cnt = len(re.findall(re.escape(orig), orig_text, re.I))
        if cnt:
            locations.setdefault(orig, set()).add(loc)
            counts[orig] = counts.get(orig, 0) + cnt


def _mask_xml(content, ext, fn, locations, counts, sid, cancel=None, progress_cb=None):
    """叶子遍历 + Word 跨 run 合并（参照 mask_ooxml_bytes，不改其本体）。"""
    for event, (prefix, uri) in ET.iterparse(io.BytesIO(content), events=("start-ns",)):
        ET.register_namespace(prefix, uri)
    tree = ET.fromstring(content)
    loc = _part_label(fn)
    last_cb = [0.0]

    def _check_cancel():
        if cancel is not None and cancel.is_set():
            raise fw.FileWorkbenchError("canceled", 409)

    def _tick(done, total):
        if progress_cb is None:
            return
        now = time.monotonic()
        if done >= total or (now - last_cb[0]) >= 0.12:
            last_cb[0] = now
            progress_cb(done, total)

    if _docprops_entry(fn):
        # @guard G764 docProps core/app/custom 全覆盖：掩全部文本叶子（Company/Manager/自定义属性等）
        nodes = [n for n in tree.iter() if n.text and n.text.strip()]
        total = max(1, len(nodes))
        for idx, n in enumerate(nodes, 1):
            _check_cancel()
            b = len(tr._tables().fwd)
            m = tr.mask_body(n.text, sid)
            _accumulate(tr._tables(), b, n.text, loc, locations, counts, masked_text=m)
            if m != n.text:
                n.text = m
            _tick(idx, total)
        return ET.tostring(tree, encoding="utf-8", xml_declaration=True)
    if ext == "docx" and fn.lower().startswith("word/"):
        p_nodes = [p for p in tree.iter() if p.tag.split("}")[-1] == "p"]
        total = max(1, len(p_nodes))
        for idx, p in enumerate(p_nodes, 1):
            _check_cancel()
            t_nodes = [n for n in p.iter() if n.tag.split("}")[-1] == "t"]
            if not t_nodes:
                _tick(idx, total)
                continue
            touched = False
            for n in t_nodes:
                if n.text:
                    b = len(tr._tables().fwd)
                    m = tr.mask_body(n.text, sid)
                    _accumulate(tr._tables(), b, n.text, loc, locations, counts, masked_text=m)
                    if m != n.text:
                        n.text = m
                        touched = True
            if not touched and len(t_nodes) > 1:
                full = "".join(n.text or "" for n in t_nodes)
                b = len(tr._tables().fwd)
                m = tr.mask_body(full, sid)
                _accumulate(tr._tables(), b, full, loc, locations, counts, masked_text=m)
                if m != full:
                    t_nodes[0].text = m
                    for n in t_nodes[1:]:
                        n.text = ""
            _tick(idx, total)
    else:
        skip_v_ids = set()
        if ext == "xlsx" and fn.lower().startswith("xl/worksheets/"):
            for elem in tree.iter():
                if elem.tag.split("}")[-1] == "c" and elem.attrib.get("t") == "s":
                    for child in elem:
                        if child.tag.split("}")[-1] == "v":
                            skip_v_ids.add(id(child))
        nodes = []
        for n in tree.iter():
            if id(n) in skip_v_ids:
                continue
            tag = n.tag.split("}")[-1]
            if (tag in ("t", "creator", "lastModifiedBy", "v") or tag.endswith("Text")) and n.text:
                nodes.append(n)
        total = max(1, len(nodes))
        for idx, n in enumerate(nodes, 1):
            _check_cancel()
            b = len(tr._tables().fwd)
            m = tr.mask_body(n.text, sid)
            _accumulate(tr._tables(), b, n.text, loc, locations, counts, masked_text=m)
            if m != n.text:
                n.text = m
            _tick(idx, total)
    return ET.tostring(tree, encoding="utf-8", xml_declaration=True)


# ── OOXML scan（G763/G764/G765/G770/G771/G772）──────────────────────────────
def scan_ooxml(job, src, staged, opts, cancel):
    # @guard G763 隔离内产已打码 staged + 注册表，token 落单叶子，scan 不改原文件
    # @guard G772 覆盖声明计数（skipped 内嵌图 / 嵌入对象）
    ext = os.path.splitext(job.filename)[1].lstrip(".").lower()
    cfg = job_cfg(job)
    scan_embedded = bool(opts.get("scan_embedded", True))
    locations, counts = {}, {}
    skipped_images = 0
    scanned_images = 0
    masked_images = 0
    covered_images = 0
    embedded_image_hits = 0
    embedded_present = 0
    non_image_media_present = 0
    masked_entries = 0
    media_modified = False
    warnings = []
    ocr_checked = False
    ocr_ok = False
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        items = zin.infolist()
        part_items = [i for i in items if _should_mask(i.filename, ext)]
        media_items = [i for i in items if _is_media(i.filename)]
        total_parts = len(part_items)
        total_media = len(media_items)
        total_weight = sum(max(1, i.file_size) for i in part_items) + sum(max(1, i.file_size) for i in media_items)
        total_weight = max(1, total_weight)
        done_weight = 0
        cur_part = 0
        cur_media = 0
        for item in items:
            if cancel is not None and cancel.is_set():
                raise fw.FileWorkbenchError("canceled", 409)
            content = zin.read(item.filename)
            fn = item.filename
            if _is_embedding(fn):
                embedded_present += 1
            elif _is_non_image_media(fn):
                non_image_media_present += 1
                if "non_image_media_unscanned" not in warnings:
                    warnings.append("non_image_media_unscanned")
            elif _is_media(fn):
                cur_media += 1
                item_w = max(1, item.file_size)
                _progress(job, "ooxml_media", cur_media, max(1, total_media),
                          pct=min(99, int(done_weight * 100 / total_weight)))
                if not scan_embedded:
                    skipped_images += 1
                else:
                    if not ocr_checked:
                        ocr_ok, _ = _ocr_ready(cfg)
                        ocr_checked = True
                    if not ocr_ok:
                        skipped_images += 1
                        if "embedded_images_ocr_unavailable" not in warnings:
                            warnings.append("embedded_images_ocr_unavailable")
                    else:
                        new_img, img_hits, status = _mask_embedded_image(content, fn, job, cfg)
                        if status in ("ocr_unavailable", "ocr_runtime_missing", "ocr_not_loopback"):
                            skipped_images += 1
                            if "embedded_images_ocr_unavailable" not in warnings:
                                warnings.append("embedded_images_ocr_unavailable")
                        else:
                            scanned_images += 1
                            if status == "masked":
                                masked_images += 1
                                embedded_image_hits += int(img_hits or 0)
                                content = new_img
                                media_modified = True
                            elif status in ("full_cover_unlocalized", "full_cover_unsupported"):
                                covered_images += 1
                                content = new_img
                                media_modified = True
                                if "embedded_images_covered" not in warnings:
                                    warnings.append("embedded_images_covered")
                done_weight += item_w
                _progress(job, "ooxml_media", cur_media, max(1, total_media),
                          pct=min(99, int(done_weight * 100 / total_weight)))
            elif _should_mask(fn, ext):
                cur_part += 1
                item_w = max(1, item.file_size)
                _progress(job, "ooxml_parts", cur_part, max(1, total_parts),
                          pct=min(99, int(done_weight * 100 / total_weight)))

                def _xml_progress(done_nodes, total_nodes, _dw=done_weight, _iw=item_w, _cp=cur_part):
                    sub = (_iw * done_nodes) / max(1, total_nodes)
                    _progress(job, "ooxml_parts", _cp, max(1, total_parts),
                              pct=min(99, int((_dw + sub) * 100 / total_weight)))

                try:
                    new = _mask_xml(content, ext, fn, locations, counts, job.id,
                                    cancel=cancel, progress_cb=_xml_progress)
                    if new != content:
                        masked_entries += 1
                    content = new
                except fw.FileWorkbenchError:
                    raise
                except Exception:
                    raise fw.FileWorkbenchError("office_parse_failed", 422)
                done_weight += item_w
                _progress(job, "ooxml_parts", cur_part, max(1, total_parts),
                          pct=min(99, int(done_weight * 100 / total_weight)))
            zout.writestr(item, content)
    tables = tr._tables()
    max_hits = int(cfg.get("files_max_hits", 20000))
    hits = _build_hits(tables, locations, counts, max_hits, only_observed=bool(getattr(job, "batch_id", "")))
    # 零命中且内嵌图片未改动：staged 直接用原文件字节（G768 字节一致的前提）。
    if not hits and not media_modified:
        with open(src, "rb") as f:
            data = f.read()
        with open(staged, "wb") as f:
            f.write(data)
    coverage = {
        "scanned": masked_entries,
        "masked": len(hits),
        "scanned_embedded_images": scanned_images,
        "masked_embedded_images": masked_images,
        "covered_embedded_images": covered_images,
        "embedded_image_hits": embedded_image_hits,
        "skipped_embedded_images": skipped_images,
        "embedded_objects_present": embedded_present,
        "non_image_media_present": non_image_media_present,
    }
    return {"hits": hits, "coverage": coverage, "warnings": warnings}


def job_cfg(job):
    mgr = getattr(job, "_mgr", None)
    if mgr is not None and hasattr(mgr, "current_cfg"):
        return mgr.current_cfg()
    return getattr(mgr, "cfg", {}) or {}


# ── 编辑校验（G767）─────────────────────────────────────────────────────────
def _validate_edits(edits, hits_by_id):
    # @guard G767 replace 非空≤64无换行无花括号不撞原文；keep 仅 can_keep。
    originals = set()
    for h in hits_by_id.values():
        if h.original:
            originals.add(h.original)
        for v in (getattr(h, "orig_variants", None) or ()):
            if v:
                originals.add(v)
    for e in edits or []:
        hid = e.get("hit_id")
        h = hits_by_id.get(hid)
        if h is None:
            raise fw.FileWorkbenchError(E_EDIT, 400)
        action = e.get("action")
        if action == "keep":
            if not h.can_keep:
                raise fw.FileWorkbenchError(E_EDIT, 400)
        elif action == "replace":
            text = e.get("text")
            if not text or len(text) > _EDIT_MAX or "\n" in text or "\r" in text \
                    or "{{" in text or "}}" in text or text in originals:
                raise fw.FileWorkbenchError(E_EDIT, 400)
        else:
            raise fw.FileWorkbenchError(E_EDIT, 400)


def _final_map(edits, hits_by_id):
    """token→最终文本。未编辑的 hit 保持 token；replace=用户文本；keep=orig；凭据不动。"""
    final = {}
    edit_by_id = {e.get("hit_id"): e for e in (edits or [])}
    for hid, h in hits_by_id.items():
        e = edit_by_id.get(hid)
        if h.credential:
            continue                       # 凭据 token 不动（G771）
        tokens = getattr(h, "tokens", None) or [h.token]
        variants = getattr(h, "orig_variants", None) or []
        if e and e.get("action") == "replace":
            rep_txt = e.get("text")
            for tok in tokens:
                final[tok] = rep_txt
        elif e and e.get("action") == "keep":
            if len(variants) == len(tokens):
                for tok, orig_v in zip(tokens, variants):
                    final[tok] = orig_v
            else:
                for tok in tokens:
                    final[tok] = h.original
        # 无编辑：保持 token（staged 已打码）
    return final


def _replace_tokens(text, final):
    if not final or not text:
        return text
    for token in sorted(final, key=len, reverse=True):   # 长词优先，杜绝子串误伤
        if token in text:
            text = text.replace(token, final[token])
    return text


def _replace_xml_leaves(content, final):
    for event, (prefix, uri) in ET.iterparse(io.BytesIO(content), events=("start-ns",)):
        ET.register_namespace(prefix, uri)
    tree = ET.fromstring(content)
    for n in tree.iter():
        if n.text:
            n.text = _replace_tokens(n.text, final)
    return ET.tostring(tree, encoding="utf-8", xml_declaration=True)


# ── OOXML apply（G766/G765/G768/G772）───────────────────────────────────────
def apply_ooxml(job, staged, out, edits, redactions, options):
    # @guard G766 确定性 token→最终文本替换，长词优先，不重跑识别
    # @guard G765 嵌入默认剥离/保留告警
    # @guard G768 零编辑无选项字节一致
    hits = job_hits(job)
    hits_by_id = {h.hit_id: h for h in hits}
    _validate_edits(edits, hits_by_id)
    final = _final_map(edits, hits_by_id)
    keep_embedded = bool(options.get("keep_embedded_objects"))
    strip_media = bool(options.get("strip_non_image_media"))
    # 无编辑无选项且无嵌入/音视频需剥离：直接复制 staged，保证字节一致（G768），不重压缩。
    if not final and not keep_embedded and not options.get("clear_docinfo") and not strip_media:
        with zipfile.ZipFile(staged) as z:
            has_emb = any(_is_embedding(n) for n in z.namelist())
        if not has_emb:
            shutil.copyfile(staged, out)
            return {"embedded_objects_stripped": 0, "embedded_objects_kept_unscanned": 0,
                    "non_image_media_stripped": 0, "warnings": []}
    stripped = kept = media_stripped = 0
    warnings = []
    if keep_embedded:
        warnings.append("embedded_objects_kept_unscanned")
    with zipfile.ZipFile(staged) as zin, \
            zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            fn = item.filename
            if _is_embedding(fn):
                if keep_embedded:
                    kept += 1
                    zout.writestr(item, zin.read(fn))
                else:
                    stripped += 1
                continue
            if strip_media and _is_non_image_media(fn):
                media_stripped += 1
                continue
            content = zin.read(fn)
            if final and fn.lower().endswith(".xml"):
                try:
                    content = _replace_xml_leaves(content, final)
                except Exception:
                    pass
            zout.writestr(item, content)
    coverage = {"embedded_objects_stripped": stripped, "embedded_objects_kept_unscanned": kept,
                "non_image_media_stripped": media_stripped, "warnings": warnings}
    return coverage


def job_hits(job):
    mgr = getattr(job, "_mgr", None)
    if mgr is None:
        return []
    reg = mgr._registries.get(job.id) or {}
    return list(reg.values())


def _detect_text_encoding(raw):
    """按 BOM → UTF-8 → GB18030 自动探测文本编码，避免中文误用 replace 变乱码。"""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig"), "utf-8-sig", False
        except UnicodeDecodeError:
            pass
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16"), "utf-16", False
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc, "strict"), enc, False
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), "utf-8", True


def _split_text_chunks(text, target_chars=65536):
    if not text or len(text) <= target_chars:
        return [text]
    chunks = []
    start = 0
    n = len(text)
    while start < n:
        end = min(n, start + target_chars)
        if end < n:
            nl = text.rfind("\n", start, end)
            if nl > start:
                end = nl + 1
        chunks.append(text[start:end])
        start = end
    return chunks


# ── 纯文本 scan/apply（G769）────────────────────────────────────────────────
def scan_text(job, src, staged, opts, cancel):
    # @guard G769 纯文本整文本 mask_body 产打码 staged + 注册表。
    with open(src, "rb") as f:
        raw = f.read()
    text, enc, enc_fallback = _detect_text_encoding(raw)
    enc_path = os.path.join(os.path.dirname(staged), "encoding.txt")
    with open(enc_path, "w", encoding="utf-8") as f:
        f.write(enc)
    locations, counts = {}, {}
    chunks = _split_text_chunks(text)
    out_parts = []
    total_chunks = max(1, len(chunks))
    for idx, chunk in enumerate(chunks, 1):
        if cancel is not None and cancel.is_set():
            raise fw.FileWorkbenchError("canceled", 409)
        _progress(job, "text_chunks", idx, total_chunks,
                  pct=min(99, int(((idx - 1) * 100) / total_chunks)))
        b = len(tr._tables().fwd)
        masked_chunk = tr.mask_body(chunk, job.id)
        _accumulate(tr._tables(), b, chunk, "正文", locations, counts, masked_text=masked_chunk)
        out_parts.append(masked_chunk)
        _progress(job, "text_chunks", idx, total_chunks,
                  pct=min(99, int((idx * 100) / total_chunks)))
    masked = "".join(out_parts)
    tables = tr._tables()
    max_hits = int(job_cfg(job).get("files_max_hits", 20000))
    hits = _build_hits(tables, locations, counts, max_hits, only_observed=bool(getattr(job, "batch_id", "")))
    with open(staged, "wb") as f:
        f.write(masked.encode("utf-8"))
    warnings = ["text_encoding_fallback"] if enc_fallback else []
    return {"hits": hits,
            "coverage": {"scanned": 1, "masked": len(hits), "encoding": enc},
            "warnings": warnings}


def apply_text(job, staged, out, edits, redactions, options):
    hits = job_hits(job)
    hits_by_id = {h.hit_id: h for h in hits}
    _validate_edits(edits, hits_by_id)
    final = _final_map(edits, hits_by_id)
    with open(staged, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    text = _replace_tokens(text, final)
    enc_path = os.path.join(os.path.dirname(staged), "encoding.txt")
    enc = "utf-8"
    if os.path.isfile(enc_path):
        try:
            with open(enc_path, "r", encoding="utf-8") as f:
                enc = (f.read() or "utf-8").strip() or "utf-8"
        except Exception:
            enc = "utf-8"
    warnings = []
    try:
        out_bytes = text.encode(enc)
    except UnicodeEncodeError:
        out_bytes = text.encode("utf-8")
        warnings.append("text_encoding_utf8_fallback")
    with open(out, "wb") as f:
        f.write(out_bytes)
    cov = {"masked": len(hits)}
    if warnings:
        cov["warnings"] = warnings
    return cov


def register(mgr):
    mgr.register_carrier("ooxml", scan_ooxml, apply_ooxml)
    mgr.register_carrier("text", scan_text, apply_text)