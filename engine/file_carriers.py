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
import zipfile
import hashlib
import shutil
import xml.etree.ElementTree as ET

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
    return "/media/" in fn and fn.rsplit(".", 1)[-1] in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "emf", "wmf")


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
def _build_hits(tables, locations, counts, max_hits):
    # @guard G771 凭据只 preview+digest、不可编辑保留
    # @guard G770 超上限失败
    hits = []
    for orig, rec in tables.fwd.items():
        token, label = rec[0], rec[1]
        cred = bool(is_credential(label))
        locs = sorted(locations.get(orig, set())) or ["正文"]
        h = fw.FileHit(
            hit_id="h%d" % (len(hits) + 1), token=token, label=label,
            source="builtin", original=orig, count=counts.get(orig, 1),
            locations=locs, editable=not cred, can_keep=not cred, credential=cred,
        )
        if cred:
            h.preview = (orig[:4] + "***") if orig else ""
            h.digest = hashlib.sha256(orig.encode("utf-8", "replace")).hexdigest()[:16]
            h.original = None
        hits.append(h)
    if len(hits) > max_hits:
        raise fw.FileWorkbenchError(E_HITS, 400)
    return hits


def _accumulate(tables, before, orig_text, loc, locations, counts):
    for orig in tables.fwd.keys() - before:
        locations.setdefault(orig, set()).add(loc)
    for orig in tables.fwd:
        if orig and orig in orig_text:
            counts[orig] = counts.get(orig, 0) + orig_text.count(orig)


def _mask_xml(content, ext, fn, locations, counts, sid):
    """叶子遍历 + Word 跨 run 合并（参照 mask_ooxml_bytes，不改其本体）。"""
    before = set(tr._tables().fwd)
    for event, (prefix, uri) in ET.iterparse(io.BytesIO(content), events=("start-ns",)):
        ET.register_namespace(prefix, uri)
    tree = ET.fromstring(content)
    loc = _part_label(fn)
    if _docprops_entry(fn):
        # @guard G764 docProps core/app/custom 全覆盖：掩全部文本叶子（Company/Manager/自定义属性等）
        for n in tree.iter():
            if n.text and n.text.strip():
                b = set(tr._tables().fwd)
                m = tr.mask_body(n.text, sid)
                _accumulate(tr._tables(), b, n.text, loc, locations, counts)
                if m != n.text:
                    n.text = m
        return ET.tostring(tree, encoding="utf-8", xml_declaration=True)
    if ext == "docx" and fn.lower().startswith("word/"):
        for p in tree.iter():
            if p.tag.split("}")[-1] != "p":
                continue
            t_nodes = [n for n in p.iter() if n.tag.split("}")[-1] == "t"]
            if not t_nodes:
                continue
            touched = False
            for n in t_nodes:
                if n.text:
                    b = set(tr._tables().fwd)
                    m = tr.mask_body(n.text, sid)
                    _accumulate(tr._tables(), b, n.text, loc, locations, counts)
                    if m != n.text:
                        n.text = m
                        touched = True
            if not touched and len(t_nodes) > 1:
                full = "".join(n.text or "" for n in t_nodes)
                b = set(tr._tables().fwd)
                m = tr.mask_body(full, sid)
                _accumulate(tr._tables(), b, full, loc, locations, counts)
                if m != full:
                    t_nodes[0].text = m
                    for n in t_nodes[1:]:
                        n.text = ""
    else:
        for n in tree.iter():
            tag = n.tag.split("}")[-1]
            if (tag in ("t", "creator", "lastModifiedBy", "v") or tag.endswith("Text")) and n.text:
                b = set(tr._tables().fwd)
                m = tr.mask_body(n.text, sid)
                _accumulate(tr._tables(), b, n.text, loc, locations, counts)
                if m != n.text:
                    n.text = m
    return ET.tostring(tree, encoding="utf-8", xml_declaration=True)


# ── OOXML scan（G763/G764/G765/G770/G771/G772）──────────────────────────────
def scan_ooxml(job, src, staged, opts, cancel):
    # @guard G763 隔离内产已打码 staged + 注册表，token 落单叶子，scan 不改原文件
    # @guard G772 覆盖声明计数（skipped 内嵌图 / 嵌入对象）
    ext = os.path.splitext(job.filename)[1].lstrip(".").lower()
    locations, counts = {}, {}
    skipped_images = 0
    embedded_present = 0
    masked_entries = 0
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if cancel is not None and cancel.is_set():
                raise fw.FileWorkbenchError("canceled", 409)
            content = zin.read(item.filename)
            fn = item.filename
            if _is_embedding(fn):
                embedded_present += 1
            elif _is_media(fn):
                if not opts.get("scan_embedded"):
                    skipped_images += 1
            elif _should_mask(fn, ext):
                try:
                    new = _mask_xml(content, ext, fn, locations, counts, job.id)
                    if new != content:
                        masked_entries += 1
                    content = new
                except fw.FileWorkbenchError:
                    raise
                except Exception:
                    raise fw.FileWorkbenchError("office_parse_failed", 422)
            zout.writestr(item, content)
    tables = tr._tables()
    max_hits = int(job_cfg(job).get("files_max_hits", 20000))
    hits = _build_hits(tables, locations, counts, max_hits)
    # 零命中：staged 直接用原文件字节（G768 字节一致的前提）。
    if not hits:
        with open(src, "rb") as f:
            data = f.read()
        with open(staged, "wb") as f:
            f.write(data)
    coverage = {
        "scanned": masked_entries, "masked": len(hits),
        "skipped_embedded_images": skipped_images,
        "embedded_objects_present": embedded_present,
    }
    return {"hits": hits, "coverage": coverage, "warnings": []}


def job_cfg(job):
    mgr = getattr(job, "_mgr", None)
    return getattr(mgr, "cfg", {}) or {}


# ── 编辑校验（G767）─────────────────────────────────────────────────────────
def _validate_edits(edits, hits_by_id):
    # @guard G767 replace 非空≤64无换行无花括号不撞原文；keep 仅 can_keep。
    originals = {h.original for h in hits_by_id.values() if h.original}
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
        if e and e.get("action") == "replace":
            final[h.token] = e.get("text")
        elif e and e.get("action") == "keep":
            final[h.token] = h.original
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
    # 无编辑无选项且无嵌入需剥离：直接复制 staged，保证字节一致（G768），不重压缩。
    if not final and not keep_embedded and not options.get("clear_docinfo"):
        with zipfile.ZipFile(staged) as z:
            has_emb = any(_is_embedding(n) for n in z.namelist())
        if not has_emb:
            shutil.copyfile(staged, out)
            return {"embedded_objects_stripped": 0, "embedded_objects_kept_unscanned": 0, "warnings": []}
    stripped = kept = 0
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
            content = zin.read(fn)
            if final and fn.lower().endswith(".xml"):
                try:
                    content = _replace_xml_leaves(content, final)
                except Exception:
                    pass
            zout.writestr(item, content)
    coverage = {"embedded_objects_stripped": stripped, "embedded_objects_kept_unscanned": kept,
                "warnings": warnings}
    return coverage


def job_hits(job):
    mgr = getattr(job, "_mgr", None)
    if mgr is None:
        return []
    reg = mgr._registries.get(job.id) or {}
    return list(reg.values())


# ── 纯文本 scan/apply（G769）────────────────────────────────────────────────
def scan_text(job, src, staged, opts, cancel):
    # @guard G769 纯文本整文本 mask_body 产打码 staged + 注册表。
    with open(src, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", "replace")
    locations, counts = {}, {}
    b = set(tr._tables().fwd)
    masked = tr.mask_body(text, job.id)
    _accumulate(tr._tables(), b, text, "正文", locations, counts)
    tables = tr._tables()
    max_hits = int(job_cfg(job).get("files_max_hits", 20000))
    hits = _build_hits(tables, locations, counts, max_hits)
    with open(staged, "wb") as f:
        f.write(masked.encode("utf-8"))
    return {"hits": hits, "coverage": {"scanned": 1, "masked": len(hits)}, "warnings": []}


def apply_text(job, staged, out, edits, redactions, options):
    hits = job_hits(job)
    hits_by_id = {h.hit_id: h for h in hits}
    _validate_edits(edits, hits_by_id)
    final = _final_map(edits, hits_by_id)
    with open(staged, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    text = _replace_tokens(text, final)
    with open(out, "wb") as f:
        f.write(text.encode("utf-8"))
    return {"masked": len(hits)}


def register(mgr):
    mgr.register_carrier("ooxml", scan_ooxml, apply_ooxml)
    mgr.register_carrier("text", scan_text, apply_text)