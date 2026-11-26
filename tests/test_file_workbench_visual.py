"""file-workbench-visual（2026-11-24）守卫 G781~G793 的 1:1 真测试。

PDF 用 pypdf 现造（文本层/文档信息/书签/附件）；图片用 Pillow 现造。
OCR 在 CI 无模型，测试通过 `fv._detect_boxes` 注入确定性框；敏感样例一律明显假串。
"""

import os
import sys
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import file_workbench as fw         # noqa: E402
import file_job_store as fjs        # noqa: E402
import file_visual as fv            # noqa: E402

PHONE = "13800000000"   # 明显假号码


def _sync(fn):
    fn()


def make_mgr(tmp, cfg=None):
    hist = fjs.HistoryStore(tmp)
    mgr = fw.JobManager(tmp, cfg=cfg or {}, history=hist, executor=_sync)
    fv.register(mgr)
    return mgr


def make_pdf(path, pages=1, text="联系电话" + PHONE, meta=None, outline=None, attach=None,
             encrypted=False):
    from pypdf import PdfWriter
    from pypdf.generic import (DecodedStreamObject, DictionaryObject, NameObject)
    w = PdfWriter()
    for _ in range(pages):
        page = w.add_blank_page(width=595, height=842)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                 NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        font_ref = w._add_object(font)
        page[NameObject("/Resources")] = DictionaryObject(
            {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})})
        content = DecodedStreamObject()
        content.set_data(("BT /F1 14 Tf 40 780 Td (%s) Tj ET" % text).encode("utf-8"))
        page[NameObject("/Contents")] = w._add_object(content)
    if meta:
        w.add_metadata(meta)
    if outline:
        for title in outline:
            w.add_outline_item(title, 0)
    if attach:
        for name, data in attach:
            w.add_attachment(name, data)
    if encrypted:
        w.encrypt("pw")
    with open(path, "wb") as f:
        w.write(f)


def make_png(path, size=(400, 200), orientation=None, extra_exif=None):
    from PIL import Image, ImageDraw
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    d.rectangle([20, 20, 120, 80], fill="black")
    kw = {}
    if orientation or extra_exif:
        ex = Image.Exif()
        if orientation:
            ex[0x0112] = orientation
        for k, v in (extra_exif or {}).items():
            ex[k] = v
        kw["exif"] = ex
    img.save(path, format="PNG", **kw)


def ready(mgr, filename, carrier, builder):
    job = mgr.create_job(filename, 100, carrier)
    src = mgr.job_dir(job.id) / "src.bin"
    builder(src)
    ok, pc, err = fv.probe(str(src), carrier)
    mgr.probe_result(job.id, ok, page_count=pc, error=err)
    return job


def scan(mgr, job, mode="manual"):
    mgr.request_scan(job.id, mode=mode)
    return mgr.get_job(job.id)


def apply(mgr, job, edits=None, redactions=None, options=None):
    mgr.request_apply(job.id, edits=edits, redactions=redactions, options=options)
    return mgr.get_job(job.id)


def out_bytes(mgr, job):
    out_dir = mgr.job_dir(job.id) / "out"
    files = list(out_dir.glob("*"))
    return files[0].read_bytes() if files else b""


def hits(mgr, job):
    return mgr.hits(job.id)


class VisualTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fw-vis-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── G781 ────────────────────────────────────────────────────────────
    def test_g781_probe_failclosed(self):
        """Case G781: 加密 PDF / 非 PDF / 页数超限 / 超 32MP 图片均 failed 不产成品。"""
        self.assertEqual(fv.E_CARRIER, "FILE_7801")
        mgr = make_mgr(self.tmp)
        p = Path(self.tmp) / "enc.pdf"
        make_pdf(p, encrypted=True)
        ok, pc, err = fv.probe(str(p), "pdf")
        self.assertFalse(ok)
        self.assertEqual(err, fv.E_CARRIER)
        bad = Path(self.tmp) / "bad.pdf"
        bad.write_bytes(b"not a pdf")
        ok, _, err = fv.probe(str(bad), "pdf")
        self.assertFalse(ok)
        self.assertEqual(err, fv.E_CARRIER)
        # 页数超限
        many = Path(self.tmp) / "many.pdf"
        make_pdf(many, pages=3)
        old = fv._max_pages
        try:
            fv._max_pages = lambda cfg=None: 2
            ok, _, err = fv.probe(str(many), "pdf")
            self.assertFalse(ok)
            self.assertEqual(err, fv.E_CARRIER)
        finally:
            fv._max_pages = old
        # 超 32MP 图片（高度靠解压炸弹阈值前先读尺寸）
        big = Path(self.tmp) / "big.png"
        from PIL import Image
        Image.new("RGB", (6400, 5200), "white").save(big)
        ok, _, err = fv.probe(str(big), "image")
        self.assertFalse(ok)
        self.assertEqual(err, fv.E_CARRIER)
        # 正常
        good = ready(mgr, "合同.pdf", "pdf", lambda s: make_pdf(s, pages=2))
        self.assertEqual(good.status, fw.ST_READY)
        self.assertEqual(good.page_count, 2)

    # ── G782 ────────────────────────────────────────────────────────────
    def test_g782_render_budget(self):
        """Case G782: 逐页落盘；磁盘预算不足判 disk_full；不引用扩展链路累计帽。"""
        self.assertEqual(fv.E_BUDGET, "FILE_7802")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "三页.pdf", "pdf", lambda s: make_pdf(s, pages=3))
        scan(mgr, job)
        self.assertEqual(job.status, fw.ST_REVIEW)
        previews = list((mgr.job_dir(job.id) / "preview").glob("page-*.jpg"))
        self.assertEqual(len(previews), 3)
        src = (ROOT / "engine" / "file_visual.py").read_text(encoding="utf-8")
        self.assertNotIn("MAX_TOTAL_PIXELS", src)
        # 磁盘不足：下一次扫描直接失败
        job2 = ready(mgr, "缺盘.pdf", "pdf", lambda s: make_pdf(s))
        old = fv._disk_free
        try:
            fv._disk_free = lambda p: 0
            scan(mgr, job2)
        finally:
            fv._disk_free = old
        self.assertEqual(job2.status, fw.ST_FAILED)
        self.assertEqual(job2.error, fv.E_BUDGET)

    # ── G783 ────────────────────────────────────────────────────────────
    def test_g783_text_layer_manual(self):
        """Case G783: mode=manual 也抽文本层命中并进清单，不调用 OCR。"""
        self.assertEqual(fv.E_TEXTLAYER, "FILE_7805")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "数字版.pdf", "pdf", lambda s: make_pdf(s))
        old = fv._detect_boxes

        def boom(*a, **k):
            raise AssertionError("manual 不应调用 OCR")
        try:
            fv._detect_boxes = boom
            scan(mgr, job, mode="manual")
        finally:
            fv._detect_boxes = old
        self.assertEqual(job.status, fw.ST_REVIEW)
        hs = hits(mgr, job)
        self.assertTrue(any(PHONE == h.get("original") for h in hs))
        self.assertGreater(job.coverage.get("text_layer_hits"), 0)
        locs = [l for h in hs for l in h.get("locations") or []]
        self.assertTrue(any("页文本层" in l for l in locs))

    # ── G784 ────────────────────────────────────────────────────────────
    def test_g784_hidden_hits(self):
        """Case G784: 文档信息/书签命中进清单并标注位置。"""
        self.assertEqual(fv.E_HIDDEN, "FILE_7806")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "隐藏.pdf", "pdf", lambda s: make_pdf(
            s, meta={"/Author": "张" + PHONE, "/Title": "标题"}, outline=[PHONE]))
        scan(mgr, job, mode="manual")
        hs = hits(mgr, job)
        self.assertTrue(hs)
        locs = [l for h in hs for l in h.get("locations") or []]
        self.assertTrue(any("文档信息" in l for l in locs))
        self.assertTrue(any("书签" in l for l in locs))

    # ── G785 ────────────────────────────────────────────────────────────
    def test_g785_ocr_gate_and_page_fail(self):
        """Case G785: OCR 未就绪 auto 回 FILE_7804；单页失败整页 full + 告警。"""
        self.assertEqual(fv.E_OCR, "FILE_7804")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "扫描件.pdf", "pdf", lambda s: make_pdf(s))
        old_ready, old_detect = fv._ocr_ready, fv._detect_boxes
        try:
            fv._ocr_ready = lambda: (False, "no_model")
            scan(mgr, job, mode="auto")
            self.assertEqual(job.status, fw.ST_FAILED)
            self.assertEqual(job.error, fv.E_OCR)
            # 单页失败 → 整页 full + warning
            fv._ocr_ready = lambda: (True, "")

            def fail(*a, **k):
                raise fv.PageOcrFailed("page")
            fv._detect_boxes = fail
            job2 = ready(mgr, "失败页.pdf", "pdf", lambda s: make_pdf(s, text="干净页"))
            scan(mgr, job2, mode="auto")
            self.assertEqual(job2.status, fw.ST_REVIEW)
            self.assertTrue(job2.coverage.get("warnings"))
        finally:
            fv._ocr_ready, fv._detect_boxes = old_ready, old_detect

    # ── G786 ────────────────────────────────────────────────────────────
    def test_g786_image_detect_and_preview(self):
        """Case G786: 自动框选只出框不改源图；预览最长边 ≤2000。"""
        self.assertEqual(fv.E_DETECT, "FILE_7807")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "大图.png", "image", lambda s: make_png(s, size=(3000, 1000)))
        before = (mgr.job_dir(job.id) / "src.bin").read_bytes()
        old = fv._detect_boxes
        try:
            fv._detect_boxes = lambda image_bytes, img, sid, deadline=None: [
                {"rect": [0.1, 0.1, 0.3, 0.2], "label": "PHONE",
                 "text": "联系电话" + PHONE}]
            scan(mgr, job, mode="auto")
        finally:
            fv._detect_boxes = old
        self.assertEqual(job.status, fw.ST_REVIEW)
        self.assertEqual((mgr.job_dir(job.id) / "src.bin").read_bytes(), before)
        hs = hits(mgr, job)
        self.assertTrue(hs)
        from PIL import Image
        with Image.open(mgr.job_dir(job.id) / "preview" / "page-0001.jpg") as im:
            self.assertLessEqual(max(im.size), 2000)

    # ── G787 ────────────────────────────────────────────────────────────
    def test_g787_coord_model(self):
        """Case G787: 越界裁剪、过小吸附、>500 拒绝、full 与其它互斥。"""
        self.assertEqual(fv.E_COORD, "FILE_7803")
        self.assertEqual(fv._norm_rect([-0.2, 0.5, 1.4, 0.1]),
                         [0.0, 0.5, 1.0, 0.1])
        self.assertIsNone(fv._norm_rect([0.5, 0.5, 0.0001, 0.0001]))
        with self.assertRaises(fw.FileWorkbenchError) as cm:
            fv._validate_redactions([{"id": "r%d" % i, "page": 1, "kind": "rect",
                                      "rect": [0.1, 0.1, 0.1, 0.1]} for i in range(501)],
                                    page_count=2)
        self.assertEqual(cm.exception.code, fv.E_COORD)
        self.assertFalse(any(r["kind"] != "full" for r in fv._page_redactions(
            [{"id": "a", "page": 1, "kind": "full"},
             {"id": "b", "page": 1, "kind": "rect", "rect": [0, 0, .1, .1]}], 1)))

    # ── G788 ────────────────────────────────────────────────────────────
    def test_g788_raster_rule(self):
        """Case G788: 有未保留命中页栅格化；全保留无框页保留原页 + 告警。"""
        self.assertEqual(fv.E_RASTER, "FILE_7808")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "两页.pdf", "pdf", lambda s: make_pdf(s, pages=2, text="电话" + PHONE))
        scan(mgr, job, mode="manual")
        h = [x for x in mgr.hits(job.id) if x.get("original") == PHONE][0]
        apply(mgr, job, edits=[{"hit_id": h["hit_id"], "action": "replace", "text": "客户A"}])
        self.assertEqual(job.status, fw.ST_DONE)
        # 两页都含命中且替换 → 两页栅格化，文本层抽不出
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(out_bytes(mgr, job)))
        self.assertEqual(len(r.pages), 2)
        self.assertEqual((r.pages[0].extract_text() or "").strip(), "")
        # keep → 原页保留，文本仍可抽
        job2 = ready(mgr, "保留.pdf", "pdf", lambda s: make_pdf(s))
        scan(mgr, job2, mode="manual")
        h2 = [x for x in mgr.hits(job2.id) if x.get("original") == PHONE][0]
        apply(mgr, job2, edits=[{"hit_id": h2["hit_id"], "action": "keep"}])
        r2 = PdfReader(io.BytesIO(out_bytes(mgr, job2)))
        self.assertIn(PHONE, r2.pages[0].extract_text() or "")
        self.assertIn("page_kept_with_unmasked_hits", job2.coverage.get("warnings") or [])

    # ── G789 ────────────────────────────────────────────────────────────
    def test_g789_apply_no_rescan(self):
        """Case G789: 隐藏文字按注册表替换/保留，凭据 token 不动。"""
        self.assertEqual(fv.E_APPLY, "FILE_7809")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "书签.pdf", "pdf",
                    lambda s: make_pdf(s, outline=[PHONE], meta={"/Author": "API_KEY sk-test-0000"}))
        scan(mgr, job, mode="manual")
        ph = [x for x in mgr.hits(job.id) if x.get("original") == PHONE][0]
        apply(mgr, job, edits=[{"hit_id": ph["hit_id"], "action": "replace", "text": "客户A"}])
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(out_bytes(mgr, job)))
        titles = []

        def walk(node):
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return
            if hasattr(node, "get") and node.get("/Title"):
                titles.append(str(node["/Title"]))
            if hasattr(node, "get") and node.get("/First"):
                walk(node["/First"])
        walk(r.outline)
        self.assertTrue(any("客户A" in t for t in titles))
        # keep → 原文仍在
        job2 = ready(mgr, "保留书签.pdf", "pdf", lambda s: make_pdf(s, outline=[PHONE]))
        scan(mgr, job2, mode="manual")
        ph2 = [x for x in mgr.hits(job2.id) if x.get("original") == PHONE][0]
        apply(mgr, job2, edits=[{"hit_id": ph2["hit_id"], "action": "keep"}])
        r2 = PdfReader(io.BytesIO(out_bytes(mgr, job2)))
        t2 = []

        def walk2(node):
            if isinstance(node, list):
                for item in node:
                    walk2(item)
                return
            if hasattr(node, "get") and node.get("/Title"):
                t2.append(str(node["/Title"]))
            if hasattr(node, "get") and node.get("/First"):
                walk2(node["/First"])
        walk2(r2.outline)
        self.assertIn(PHONE, "".join(t2))

    # ── G790 ────────────────────────────────────────────────────────────
    def test_g790_docinfo_attachments(self):
        """Case G790: 文档信息清空、XMP 删除、附件默认剥离计数；keep 保留 + 告警。"""
        self.assertEqual(fv.E_DOCINFO, "FILE_7810")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "信息.pdf", "pdf", lambda s: make_pdf(
            s, meta={"/Author": "张三", "/Title": "合同", "/Creator": "WPS",
                     "/Producer": "PDF", "/Subject": "x", "/Keywords": "k"},
            attach=[("备注.txt", b"hello " + PHONE.encode())]))
        scan(mgr, job, mode="manual")
        apply(mgr, job)
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(out_bytes(mgr, job)))
        md = r.metadata or {}
        for key in ("/Author", "/Title", "/Creator", "/Producer", "/Subject", "/Keywords"):
            self.assertFalse(str(md.get(key) or ""), key)
        self.assertNotIn("/Metadata", r.trailer["/Root"])
        self.assertEqual(len(list(r.attachments)), 0)
        self.assertGreaterEqual(job.coverage.get("attachments_stripped", 0), 1)
        # keep
        job2 = ready(mgr, "留附件.pdf", "pdf", lambda s: make_pdf(
            s, attach=[("备注.txt", b"hello")]))
        scan(mgr, job2, mode="manual")
        apply(mgr, job2, options={"keep_attachments": True})
        self.assertIn("attachments_kept_unscanned", job2.coverage.get("warnings") or [])

    # ── G791 ────────────────────────────────────────────────────────────
    def test_g791_image_meta_orientation(self):
        """Case G791: EXIF 剥离、方向先应用、输出不透明 RGB。"""
        self.assertEqual(fv.E_META, "FILE_7811")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "手机拍.jpg", "image",
                    lambda s: make_png(s, size=(400, 200), orientation=6))
        scan(mgr, job, mode="manual")
        apply(mgr, job, redactions=[{"id": "r1", "page": 1, "kind": "rect",
                                     "rect": [0.05, 0.1, 0.5, 0.4], "source": "manual"}])
        self.assertEqual(job.status, fw.ST_DONE)
        from PIL import Image
        with Image.open(io.BytesIO(out_bytes(mgr, job))) as im:
            self.assertEqual(im.mode, "RGB")
            self.assertEqual(im.size, (200, 400))   # Orientation=6 转正后宽高互换
            ex = im.getexif()
            self.assertEqual(len(dict(ex)), 0)

    # ── G792 ────────────────────────────────────────────────────────────
    def test_g792_coverage(self):
        """Case G792: coverage 各计数与 warnings 齐全。"""
        self.assertEqual(fv.E_COVERAGE, "FILE_7812")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "覆盖.pdf", "pdf", lambda s: make_pdf(s, pages=2))
        scan(mgr, job, mode="manual")
        cov = job.coverage or {}
        for key in ("rendered_pages", "rasterized_pages", "text_layer_hits",
                    "hidden_hits", "skipped_ocr_pages", "attachments_stripped", "warnings"):
            self.assertIn(key, cov)
        self.assertEqual(cov["rendered_pages"], 2)
        self.assertGreater(cov["text_layer_hits"], 0)

    # ── G793 ────────────────────────────────────────────────────────────
    def test_g793_preview_and_cancel(self):
        """Case G793: preview 返回 data URL；非 ready/review 回 409；取消清理页图。"""
        self.assertEqual(fv.E_PREVIEW, "FILE_7813")
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "预览.pdf", "pdf", lambda s: make_pdf(s))
        url = fv.preview_data_url(job, 1)
        self.assertTrue(url.startswith("data:image/jpeg;base64,"))
        # 非 ready/review
        job2 = mgr.create_job("新建.pdf", 10, "pdf")
        with self.assertRaises(fw.FileWorkbenchError) as cm:
            fv.preview_data_url(job2, 1)
        self.assertEqual(cm.exception.code, fv.E_PREVIEW)
        self.assertEqual(cm.exception.http, 409)
        # 清理：页图随任务目录删除
        job3 = ready(mgr, "取消.pdf", "pdf", lambda s: make_pdf(s, pages=2))
        scan(mgr, job3, mode="manual")
        self.assertTrue(list((mgr.job_dir(job3.id) / "preview").glob("page-*.jpg")))
        mgr.delete(job3.id)
        self.assertFalse(mgr.job_dir(job3.id).exists())

    def test_multipage_pdf_repeated_sensitive_value_masked_on_all_pages(self):
        """多页 PDF 在第 2 页起重复出现同一敏感值时也必须建框、归属位置并栅格化。"""
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "多页重复.pdf", "pdf", lambda s: make_pdf(s, pages=2, text="Phone " + PHONE))
        scan(mgr, job, mode="manual")
        hs = [x for x in hits(mgr, job) if x.get("original") == PHONE]
        self.assertTrue(hs)
        locs = set(hs[0].get("locations") or [])
        self.assertIn("第1页文本层", locs)
        self.assertIn("第2页文本层", locs)
        apply(mgr, job)
        self.assertEqual(job.status, fw.ST_DONE)
        self.assertEqual(job.coverage.get("rasterized_pages"), 2)
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(out_bytes(mgr, job)))
        self.assertEqual((r.pages[0].extract_text() or "").strip(), "")
        self.assertEqual((r.pages[1].extract_text() or "").strip(), "")

    def test_image_auto_scan_boxes_applied_and_warnings_preserved(self):
        """图片自动扫描产出的检测框与 OCR 失败兜底全图遮盖必须在 apply_image 中实际涂黑并保留告警。"""
        from PIL import Image
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "自动框.png", "image", lambda s: make_png(s, size=(200, 100)))
        old_ready, old_detect = fv._ocr_ready, fv._detect_boxes
        try:
            fv._ocr_ready = lambda: (True, "")
            fv._detect_boxes = lambda image_bytes, img, sid, deadline=None: [
                {"rect": [0.0, 0.0, 1.0, 1.0], "label": "PHONE", "text": "tel " + PHONE}
            ]
            scan(mgr, job, mode="auto")
        finally:
            fv._ocr_ready, fv._detect_boxes = old_ready, old_detect
        apply(mgr, job, redactions=[])
        self.assertEqual(job.status, fw.ST_DONE)
        with Image.open(io.BytesIO(out_bytes(mgr, job))) as im:
            self.assertEqual(im.getpixel((190, 90)), fv._FILL)

        job2 = ready(mgr, "失败兜底.png", "image", lambda s: make_png(s, size=(200, 100)))
        try:
            fv._ocr_ready = lambda: (True, "")

            def boom(*a, **k):
                raise fv.PageOcrFailed("ocr fail")

            fv._detect_boxes = boom
            scan(mgr, job2, mode="auto")
        finally:
            fv._ocr_ready, fv._detect_boxes = old_ready, old_detect
        apply(mgr, job2, redactions=[])
        self.assertEqual(job2.status, fw.ST_DONE)
        self.assertIn("image_ocr_failed_full_cover", job2.warnings)
        self.assertIn("image_ocr_failed_full_cover", job2.coverage.get("warnings") or [])
        with Image.open(io.BytesIO(out_bytes(mgr, job2))) as im:
            self.assertEqual(im.getpixel((190, 90)), fv._FILL)

    def test_apply_rejects_invalid_redactions(self):
        """apply_pdf 与 apply_image 必须拒绝越界页码与超限遮盖区域（FILE_7803）。"""
        mgr = make_mgr(self.tmp)
        pdf_job = ready(mgr, "校验.pdf", "pdf", lambda s: make_pdf(s, pages=1))
        scan(mgr, pdf_job, mode="manual")
        apply(mgr, pdf_job, redactions=[{"id": "r1", "page": 99, "kind": "rect", "rect": [0.1, 0.1, 0.2, 0.2]}])
        self.assertEqual(pdf_job.status, fw.ST_FAILED)
        self.assertEqual(pdf_job.error, fv.E_COORD)

        img_job = ready(mgr, "校验.png", "image", lambda s: make_png(s, size=(200, 100)))
        scan(mgr, img_job, mode="manual")
        too_many = [{"id": f"r{i}", "page": 1, "kind": "rect", "rect": [0.1, 0.1, 0.1, 0.1]} for i in range(501)]
        apply(mgr, img_job, redactions=too_many)
        self.assertEqual(img_job.status, fw.ST_FAILED)
        self.assertEqual(img_job.error, fv.E_COORD)

    def test_pdf_custom_word_case_variant_masked_in_text_layer_and_outline(self):
        """PDF 文本层与书签中的自定义敏感词大小写变体必须无需预热即可命中、栅格化并替换。"""
        import subprocess
        script = r"""
import io, json, os, sys, tempfile, shutil
from pathlib import Path

root = Path(sys.argv[1])
tmp = Path(tempfile.mkdtemp(prefix="fw-pdfcw-"))
try:
    (tmp / "config.json").write_text(json.dumps({
        "custom_words": {"AcmeCorp": "COMPANY"}
    }, ensure_ascii=False), encoding="utf-8")
    os.environ["LLM_SHIELD_DATA_DIR"] = str(tmp)
    sys.path.insert(0, str(root / "engine"))
    sys.path.insert(0, str(root))

    import file_workbench as fw
    import file_visual as fv
    import file_job_store as fjs
    from pypdf import PdfReader
    from tests.test_file_workbench_visual import make_pdf

    mgr = fw.JobManager(tmp, cfg={}, history=fjs.HistoryStore(tmp), executor=lambda fn: fn())
    fv.register(mgr)
    job = mgr.create_job("cw.pdf", 128, "pdf")
    src = mgr.job_dir(job.id) / "src.bin"
    make_pdf(src, pages=1, text="Client acmecorp report", outline=["acmecorp summary"])
    ok, pc, err = fv.probe(str(src), "pdf")
    assert ok, err
    mgr.probe_result(job.id, ok, page_count=pc, error=err)
    mgr.request_scan(job.id, mode="manual")
    hs = mgr.hits(job.id)
    assert any(h.get("original") == "AcmeCorp" and h.get("source") == "custom" for h in hs), hs

    mgr.request_apply(job.id)
    out_files = list((mgr.job_dir(job.id) / "out").glob("*"))
    r = PdfReader(io.BytesIO(out_files[0].read_bytes()))
    assert (r.pages[0].extract_text() or "").strip() == "", "含自定义词变体的页必须整页栅格化"
    titles = []
    def walk(node):
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if hasattr(node, "get") and node.get("/Title"):
            titles.append(str(node["/Title"]))
        if hasattr(node, "get") and node.get("/First"):
            walk(node["/First"])
    walk(r.outline)
    assert titles and all("acmecorp" not in t.lower() for t in titles), f"书签未脱敏: {titles}"
finally:
    shutil.rmtree(tmp, ignore_errors=True)
"""
        proc = subprocess.run([sys.executable, "-c", script, str(ROOT)],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)

    def test_preview_boxes_and_manifest_strip_plaintext(self):
        """preview_boxes 必须返回脱敏页级检测框且 staged.bin 清单不得残留 orig 原文。"""
        mgr = make_mgr(self.tmp)
        job = ready(mgr, "含框.pdf", "pdf", lambda s: make_pdf(s, pages=1, text="Phone " + PHONE))
        scan(mgr, job, mode="manual")
        manifest = json.loads((mgr.job_dir(job.id) / "staged.bin").read_text(encoding="utf-8"))
        for p in manifest.get("pages") or []:
            for b in p.get("boxes") or []:
                self.assertNotIn("orig", b)
        boxes = fv.preview_boxes(job, 1)
        self.assertTrue(boxes)
        self.assertEqual(boxes[0]["kind"], "rect")
        self.assertEqual(boxes[0]["source"], "text_layer")
        self.assertIn("hit_id", boxes[0])
        self.assertEqual(len(boxes[0]["rect"]), 4)
        self.assertNotIn("orig", boxes[0])
        apply(mgr, job)
        self.assertEqual(fv.preview_boxes(job, 1), [])


if __name__ == "__main__":
    unittest.main()
