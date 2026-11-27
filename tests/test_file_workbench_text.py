"""file-workbench-text（2026-11-24）守卫 G761~G772 的 1:1 真测试。

OOXML 用 zipfile 现造最小 docx 夹具；scan/apply 经 JobManager（同步执行器 + 注册载体）
端到端验收，隔离由 file_store_scope 保证。敏感样例一律明显假串（13800000000）。
"""

import os
import sys
import time
import shutil
import zipfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as tr            # noqa: E402
import file_workbench as fw         # noqa: E402
import file_carriers as fc          # noqa: E402
import file_job_store as fjs        # noqa: E402

PHONE = "13800000000"   # 明显假号码

DOC_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>联系电话' + PHONE + '</w:t></w:r></w:p></w:body></w:document>'
)
CROSS_RUN_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>138000</w:t></w:r><w:r><w:t>00000</w:t></w:r></w:p></w:body></w:document>'
)
CLEAN_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>你好世界</w:t></w:r></w:p></w:body></w:document>'
)
APP_XML = (
    '<?xml version="1.0"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    '<Company>' + PHONE + '</Company></Properties>'
)
CUSTOM_XML = (
    '<?xml version="1.0"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">'
    '<property name="k"><vt:lpstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    + PHONE + '</vt:lpstr></property></Properties>'
)


def _sync(fn):
    fn()


def make_docx(path, entries=None, extra=None):
    base = {"word/document.xml": DOC_XML.encode("utf-8"),
            "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'}
    if entries is not None:
        base = dict(entries)
    if extra:
        base.update(extra)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in base.items():
            z.writestr(name, data)


def make_mgr(tmp, cfg=None):
    hist = fjs.HistoryStore(tmp)
    mgr = fw.JobManager(tmp, cfg=cfg or {}, history=hist, executor=_sync)
    fc.register(mgr)
    return mgr


def ready_docx(mgr, filename="合同.docx", entries=None, extra=None):
    job = mgr.create_job(filename, 100, "ooxml")
    make_docx(mgr.job_dir(job.id) / "src.bin", entries=entries, extra=extra)
    ok, pc, err = fc.probe(str(mgr.job_dir(job.id) / "src.bin"), "ooxml")
    mgr.probe_result(job.id, ok, page_count=pc, error=err)
    return job


def scan(mgr, job):
    mgr.request_scan(job.id)
    return mgr.get_job(job.id)


def apply(mgr, job, edits=None, options=None):
    mgr.request_apply(job.id, edits=edits, options=options)
    return mgr.get_job(job.id)


def out_bytes(mgr, job):
    out_dir = mgr.job_dir(job.id) / "out"
    files = list(out_dir.glob("*"))
    return files[0].read_bytes() if files else b""


class CarrierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fw-text-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_g761_failclosed(self):
        """Case G761: 非 zip/含宏/加密一律 failed 不产成品（FILE_7601）；正常 docx ready。"""
        mgr = make_mgr(self.tmp)
        # 非 zip 的 .docx
        job = mgr.create_job("假.docx", 10, "ooxml")
        (mgr.job_dir(job.id) / "src.bin").write_bytes(b"not a zip")
        ok, _, err = fc.probe(str(mgr.job_dir(job.id) / "src.bin"), "ooxml")
        self.assertFalse(ok)
        self.assertEqual(err, fc.E_CARRIER)
        # 含宏
        p = Path(self.tmp) / "macro.docx"
        make_docx(p, extra={"word/vbaProject.bin": b"macro"})
        ok, _, err = fc.probe(str(p), "ooxml")
        self.assertFalse(ok)
        self.assertEqual(err, fc.E_CARRIER)
        # 正常 docx
        good = ready_docx(mgr)
        self.assertEqual(good.status, fw.ST_READY)

    def test_g762_zipbomb(self):
        """Case G762: 超体积/高压缩比条目判 zip_bomb_suspected（FILE_7602）。"""
        p = Path(self.tmp) / "big.docx"
        make_docx(p)
        old = fc._MAX_ENTRY
        try:
            fc._MAX_ENTRY = 10        # 触发单条目上限分支
            ok, _, err = fc.probe(str(p), "ooxml")
            self.assertFalse(ok)
            self.assertEqual(err, fc.E_ZIPBOMB)
        finally:
            fc._MAX_ENTRY = old

    def test_text_size_cap_fails_closed(self):
        """纯文本载体上限（2026-11-26）：scan_text 整文件读入 → 解码 → mask_body，
        一份大日志就能把引擎顶到 OOM，所以超限必须在 probe 阶段 failed（不产成品）。"""
        p = Path(self.tmp) / "big.log"
        p.write_bytes(b"x" * (2 * 1024 * 1024))
        ok, _, err = fc.probe(str(p), "text", cfg={"files_max_text_mb": 1})
        self.assertFalse(ok)
        self.assertEqual(err, fw.E_TOO_LARGE)
        # 阈值刚好覆盖时放行；默认 128 MB 不得误伤普通小文件
        ok, _, err = fc.probe(str(p), "text", cfg={"files_max_text_mb": 2})
        self.assertTrue(ok, err)
        ok, _, err = fc.probe(str(p), "text")
        self.assertTrue(ok, err)

    def test_g763_scan_staged(self):
        """Case G763: scan 产已打码 staged + 注册表，src 未改，跨 run token 落单叶子（FILE_7603）。"""
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr)
        src_before = (mgr.job_dir(job.id) / "src.bin").read_bytes()
        j = scan(mgr, job)
        self.assertEqual(j.status, fw.ST_REVIEW)
        self.assertGreater(j.hit_count, 0)
        staged = (mgr.job_dir(job.id) / "staged.bin").read_bytes()
        self.assertNotIn(PHONE.encode(), staged)
        self.assertEqual((mgr.job_dir(job.id) / "src.bin").read_bytes(), src_before)
        # 跨 run
        job2 = ready_docx(mgr, filename="跨.docx", entries={"word/document.xml": CROSS_RUN_XML.encode()})
        scan(mgr, job2)
        staged2 = (mgr.job_dir(job2.id) / "staged.bin").read_bytes()
        self.assertNotIn(PHONE.encode(), staged2)
        self.assertGreater(mgr.get_job(job2.id).hit_count, 0)

    def test_g764_docprops(self):
        """Case G764: docProps/app.xml 与 custom.xml 的敏感值被扫到（FILE_7604）。"""
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr, entries={"word/document.xml": CLEAN_XML.encode()},
                         extra={"docProps/app.xml": APP_XML.encode(),
                                "docProps/custom.xml": CUSTOM_XML.encode()})
        j = scan(mgr, job)
        self.assertGreater(j.hit_count, 0)
        hits = mgr.hits(job.id)
        self.assertTrue(any("文档属性" in h["locations"] for h in hits))

    def test_g765_embedded(self):
        """Case G765: 默认剥离嵌入对象计数；keep_embedded_objects 保留 + 告警（FILE_7605）。"""
        mgr = make_mgr(self.tmp)
        extra = {"word/embeddings/oleObject1.bin": b"OLEDATA"}
        job = ready_docx(mgr, extra=extra)
        scan(mgr, job)
        apply(mgr, job)
        with zipfile.ZipFile(mgr.job_dir(job.id) / "out" / "masked.docx") as z:
            self.assertFalse(any("embeddings" in n for n in z.namelist()))
        self.assertEqual(mgr.get_job(job.id).coverage.get("embedded_objects_stripped"), 1)
        # keep
        job2 = ready_docx(mgr, filename="保.docx", extra=extra)
        scan(mgr, job2)
        apply(mgr, job2, options={"keep_embedded_objects": True})
        with zipfile.ZipFile(mgr.job_dir(job2.id) / "out" / "masked.docx") as z:
            self.assertTrue(any("embeddings" in n for n in z.namelist()))
        self.assertIn("embedded_objects_kept_unscanned", mgr.get_job(job2.id).coverage.get("warnings", [])
                      or mgr.get_job(job2.id).warnings)

    def test_g766_apply_deterministic(self):
        """Case G766: apply token→用户文本/keep→orig/凭据不动，不重跑识别（FILE_7606）。"""
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr)
        scan(mgr, job)
        hit = mgr.hits(job.id)[0]
        apply(mgr, job, edits=[{"hit_id": hit["hit_id"], "action": "replace", "text": "客户A"}])
        with zipfile.ZipFile(mgr.job_dir(job.id) / "out" / "masked.docx") as z:
            data = z.read("word/document.xml")
        self.assertIn("客户A".encode(), data)
        self.assertNotIn(hit["token"].encode(), data)
        self.assertNotIn(PHONE.encode(), data)
        # keep
        job2 = ready_docx(mgr, filename="留.docx")
        scan(mgr, job2)
        h2 = mgr.hits(job2.id)[0]
        apply(mgr, job2, edits=[{"hit_id": h2["hit_id"], "action": "keep"}])
        with zipfile.ZipFile(mgr.job_dir(job2.id) / "out" / "masked.docx") as z:
            self.assertIn(PHONE.encode(), z.read("word/document.xml"))

    def test_g767_edit_validation(self):
        """Case G767: 非法 replace 与 keep 凭据回 FILE_7607。"""
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr)
        scan(mgr, job)
        hid = mgr.hits(job.id)[0]["hit_id"]
        for bad in ("", "x" * 65, "a\nb", "{{X}}", PHONE):
            with self.assertRaises(fw.FileWorkbenchError) as ctx:
                fc._validate_edits([{"hit_id": hid, "action": "replace", "text": bad}],
                                   {h.hit_id: h for h in mgr._registries[job.id].values()})
            self.assertEqual(ctx.exception.code, fc.E_EDIT)
        # keep 凭据拒绝
        cred = fw.FileHit(hit_id="hc", token="{{API_KEY_bcdfgh}}", label="API_KEY",
                          credential=True, editable=False, can_keep=False)
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            fc._validate_edits([{"hit_id": "hc", "action": "keep"}], {"hc": cred})
        self.assertEqual(ctx.exception.code, fc.E_EDIT)

    def test_g768_zero_hit_identical(self):
        """Case G768: 零命中无选项成品 sha256 == 原文件（FILE_7608）。"""
        import hashlib
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr, entries={"word/document.xml": CLEAN_XML.encode()})
        src = (mgr.job_dir(job.id) / "src.bin").read_bytes()
        j = scan(mgr, job)
        self.assertEqual(j.hit_count, 0)
        self.assertEqual((mgr.job_dir(job.id) / "staged.bin").read_bytes(), src)
        apply(mgr, job)
        self.assertEqual(hashlib.sha256(out_bytes(mgr, job)).hexdigest(),
                         hashlib.sha256(src).hexdigest())

    def test_g769_text(self):
        """Case G769: 纯文本整文本打码产 staged + 注册表（FILE_7609）。"""
        mgr = make_mgr(self.tmp)
        job = mgr.create_job("note.txt", 50, "text")
        (mgr.job_dir(job.id) / "src.bin").write_bytes(("电话" + PHONE).encode())
        mgr.probe_result(job.id, True)
        j = scan(mgr, job)
        self.assertEqual(j.status, fw.ST_REVIEW)
        self.assertGreater(j.hit_count, 0)
        self.assertNotIn(PHONE.encode(), (mgr.job_dir(job.id) / "staged.bin").read_bytes())
        hid = mgr.hits(job.id)[0]["hit_id"]
        apply(mgr, job, edits=[{"hit_id": hid, "action": "replace", "text": "客户B"}])
        self.assertIn("客户B".encode(), out_bytes(mgr, job))

    def test_g770_max_hits(self):
        """Case G770: 命中超 files_max_hits 回 FILE_7610。"""
        mgr = make_mgr(self.tmp, cfg={"files_max_hits": 0})
        job = ready_docx(mgr)
        mgr.request_scan(job.id)
        self.assertEqual(mgr.get_job(job.id).status, fw.ST_FAILED)
        self.assertEqual(mgr.get_job(job.id).error, fc.E_HITS)

    def test_g771_credential_privacy(self):
        """Case G771: 凭据项只 preview+digest，editable/can_keep=false（FILE_7611）。"""
        class _T:
            fwd = {"sk-secret-value": ["{{API_KEY_bcdfgh}}", "API_KEY", time.time()]}
        hits = fc._build_hits(_T(), {}, {}, 100)
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertTrue(h.credential)
        self.assertFalse(h.editable)
        self.assertFalse(h.can_keep)
        view = h.api_view()
        self.assertNotIn("original", view)
        self.assertIn("preview", view)
        self.assertIn("digest", view)

    def test_g772_coverage(self):
        """Case G772: coverage 含 skipped/stripped 计数与保留告警（FILE_7612）。"""
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr, extra={"word/media/image1.png": b"PNG",
                                     "word/embeddings/o.bin": b"O"})
        mgr.request_scan(job.id, scan_embedded=False)
        j = mgr.get_job(job.id)
        cov = j.coverage
        self.assertEqual(cov.get("skipped_embedded_images"), 1)
        self.assertEqual(cov.get("embedded_objects_present"), 1)
        apply(mgr, job)
        merged = mgr.get_job(job.id).coverage
        self.assertEqual(merged.get("skipped_embedded_images"), 1)
        self.assertEqual(merged.get("embedded_objects_stripped"), 1)

    def test_ooxml_embedded_image_masked_by_default_and_fallbacks(self):
        """OOXML 默认扫描内嵌图：敏感图打码不回退、干净图保字节一致、矢量/坏图遮盖、无 OCR 跳过告警。"""
        import io
        from types import SimpleNamespace
        from PIL import Image
        import visual_redactor as vr

        def make_png_bytes(size=(200, 100), color="white"):
            im = Image.new("RGB", size, color)
            b = io.BytesIO()
            im.save(b, format="PNG")
            return b.getvalue()

        old_ready = fc._ocr_ready
        old_vr_avail = vr.available
        old_vr_blocks = vr.detect_blocks
        old_eng_avail = __import__("ocr_engine").available
        try:
            # 0. _ocr_ready 在无本地 OCR 且未显式配置端点时必须回 False（不能被默认 127.0.0.1:8082 误导）
            ocr_mod = __import__("ocr_engine")
            ocr_mod.available = lambda: (False, "ocr_runtime_missing")
            ok_empty, _ = fc._ocr_ready({"ocr_engine": "auto", "ocr_endpoint": ""})
            self.assertFalse(ok_empty)

            # 1. OCR 可用 + 正文 0 命中 + 内嵌图含敏感信息 → 像素打码且 staged 不回退为原图
            vr.available = lambda: (True, "")
            fc._ocr_ready = lambda cfg=None: (True, "")
            vr.detect_blocks = lambda image_bytes, deadline=None, max_tokens=None: (
                [SimpleNamespace(text=PHONE, quad=(20, 20, 180, 60), score=0.95)],
                {"backend": "local"},
            )
            clean_entries = {
                "word/document.xml": CLEAN_XML.encode("utf-8"),
                "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
            }
            j1 = ready_docx(make_mgr(self.tmp), filename="图含敏.docx",
                            entries=clean_entries,
                            extra={"word/media/image1.png": make_png_bytes()})
            mgr1 = j1._mgr
            before_recent = dict(tr._RECENT_FWD)
            scan(mgr1, j1)
            self.assertEqual(j1.status, fw.ST_REVIEW)
            self.assertEqual(j1.coverage.get("scanned_embedded_images"), 1)
            self.assertEqual(j1.coverage.get("masked_embedded_images"), 1)
            self.assertGreaterEqual(j1.coverage.get("embedded_image_hits"), 1)
            self.assertEqual(j1.coverage.get("skipped_embedded_images"), 0)
            self.assertEqual(mgr1.hits(j1.id), [])
            self.assertEqual(tr._RECENT_FWD, before_recent)
            apply(mgr1, j1)
            with zipfile.ZipFile(io.BytesIO(out_bytes(mgr1, j1))) as zout:
                with Image.open(io.BytesIO(zout.read("word/media/image1.png"))) as masked_im:
                    self.assertEqual(masked_im.getpixel((100, 40)), vr._FILL)

            # 2. OCR 可用 + 正文与图片均干净 → 成品与原包 SHA-256 一致
            vr.detect_blocks = lambda image_bytes, deadline=None, max_tokens=None: (
                [SimpleNamespace(text="普通说明文字", quad=(20, 20, 180, 60), score=0.95)],
                {"backend": "local"},
            )
            j2 = ready_docx(mgr1, filename="全干净.docx",
                            entries=clean_entries,
                            extra={"word/media/image1.png": make_png_bytes()})
            src2 = (mgr1.job_dir(j2.id) / "src.bin").read_bytes()
            scan(mgr1, j2)
            self.assertEqual(j2.coverage.get("scanned_embedded_images"), 1)
            self.assertEqual(j2.coverage.get("masked_embedded_images"), 0)
            apply(mgr1, j2)
            self.assertEqual(out_bytes(mgr1, j2), src2)

            # 3. 矢量格式(.emf)与损坏 PNG → 替换成中性灰占位图并带告警
            j3 = ready_docx(mgr1, filename="矢量损坏.docx",
                            entries=clean_entries,
                            extra={"word/media/image1.emf": b"FAKEEMF",
                                   "word/media/image2.png": b"CORRUPT"})
            scan(mgr1, j3)
            self.assertEqual(j3.coverage.get("covered_embedded_images"), 2)
            self.assertIn("embedded_images_covered", j3.warnings)
            apply(mgr1, j3)
            with zipfile.ZipFile(io.BytesIO(out_bytes(mgr1, j3))) as zout:
                for mname in ("word/media/image1.emf", "word/media/image2.png"):
                    with Image.open(io.BytesIO(zout.read(mname))) as pim:
                        self.assertEqual(pim.getpixel((10, 10)), vr._FILL)

            # 4. OCR 不可用 → 跳过内嵌图并告警，但正文照常脱敏
            fc._ocr_ready = lambda cfg=None: (False, "ocr_runtime_missing")
            j4 = ready_docx(mgr1, filename="无OCR.docx",
                            extra={"word/media/image1.png": b"RAWIMG"})
            scan(mgr1, j4)
            self.assertEqual(j4.status, fw.ST_REVIEW)
            self.assertGreater(j4.hit_count, 0)
            self.assertEqual(j4.coverage.get("skipped_embedded_images"), 1)
            self.assertIn("embedded_images_ocr_unavailable", j4.warnings)
            apply(mgr1, j4)
            self.assertEqual(j4.coverage.get("skipped_embedded_images"), 1)
        finally:
            fc._ocr_ready = old_ready
            vr.available = old_vr_avail
            vr.detect_blocks = old_vr_blocks
            __import__("ocr_engine").available = old_eng_avail

    def test_custom_words_cold_start_and_hot_reload_from_config(self):
        """冷启动与运行期改写 config.json 后，文件脱敏无需预调 reload 即时复用敏感词与白名单且不污染全局表。"""
        import json
        import subprocess
        script = r"""
import json, os, sys, tempfile, shutil
from pathlib import Path

root = Path(sys.argv[1])
tmp = Path(tempfile.mkdtemp(prefix="fw-cw-"))
try:
    cfg_path = tmp / "config.json"
    cfg_path.write_text(json.dumps({
        "custom_words": {
            "AcmeCorp": "COMPANY",
            "re:PROJ-\\d{4}": "PROJECT",
        }
    }, ensure_ascii=False), encoding="utf-8")
    os.environ["LLM_SHIELD_DATA_DIR"] = str(tmp)
    sys.path.insert(0, str(root / "engine"))

    import transparent as tr
    import file_workbench as fw
    import file_carriers as fc
    import file_job_store as fjs

    assert tr.CUSTOM_WORDS == {}, f"import 期不应预载 config: {tr.CUSTOM_WORDS}"
    mgr = fw.JobManager(tmp, cfg={}, history=fjs.HistoryStore(tmp), executor=lambda fn: fn())
    fc.register(mgr)

    # 1. 冷启动：未手工调用 _maybe_reload，直接扫描即命中大小写变体、正则自定义词与内置规则
    j1 = mgr.create_job("c1.txt", 64, "text")
    (mgr.job_dir(j1.id) / "src.bin").write_bytes("客户 acmecorp 项目 PROJ-2026 电话 13800000000".encode("utf-8"))
    mgr.probe_result(j1.id, True)
    mgr.request_scan(j1.id)
    hits1 = mgr.hits(j1.id)
    origs1 = {h["original"]: h for h in hits1}
    assert "AcmeCorp" in origs1, f"冷启动未命中自定义词变体: {hits1}"
    assert origs1["AcmeCorp"]["source"] == "custom", origs1["AcmeCorp"]
    assert origs1["AcmeCorp"]["count"] == 1, origs1["AcmeCorp"]
    assert "PROJ-2026" in origs1, f"冷启动未命中正则自定义词: {hits1}"
    assert "13800000000" in origs1, f"冷启动未命中内置规则: {hits1}"
    # _maybe_reload 会把配置里的自定义词预同步进 _RECENT_FWD，但文件内容本身扫描到的原文绝不能进全局表
    assert "PROJ-2026" not in tr._RECENT_FWD, f"文件命中原文泄漏进全局表: {tr._RECENT_FWD}"
    assert "13800000000" not in tr._RECENT_FWD, f"文件命中号码泄漏进全局表: {tr._RECENT_FWD}"

    # 2. 运行期改配置：新增敏感词 + 白名单放行，不重启即生效
    cfg_path.write_text(json.dumps({
        "custom_words": {
            "AcmeCorp": "COMPANY",
            "BlueWhaleKey": "PROJECT",
        },
        "allow_values": ["AcmeCorp", "acmecorp"],
    }, ensure_ascii=False), encoding="utf-8")
    j2 = mgr.create_job("c2.txt", 64, "text")
    (mgr.job_dir(j2.id) / "src.bin").write_bytes("放行 acmecorp 拦截 BlueWhaleKey".encode("utf-8"))
    mgr.probe_result(j2.id, True)
    mgr.request_scan(j2.id)
    hits2 = mgr.hits(j2.id)
    origs2 = {h["original"]: h for h in hits2}
    assert "BlueWhaleKey" in origs2, f"热更新后未命中新敏感词: {hits2}"
    assert origs2["BlueWhaleKey"]["source"] == "custom", origs2["BlueWhaleKey"]
    assert "AcmeCorp" not in origs2, f"白名单词未放行: {hits2}"

    # 3. 配置未变时的后续扫描，全局 _RECENT_FWD 一条不增
    snap_recent = dict(tr._RECENT_FWD)
    j3 = mgr.create_job("c3.txt", 64, "text")
    (mgr.job_dir(j3.id) / "src.bin").write_bytes("二次 13900000000".encode("utf-8"))
    mgr.probe_result(j3.id, True)
    mgr.request_scan(j3.id)
    assert tr._RECENT_FWD == snap_recent, "隔离扫描改变了全局 _RECENT_FWD"
finally:
    shutil.rmtree(tmp, ignore_errors=True)
"""
        proc = subprocess.run([sys.executable, "-c", script, str(ROOT)],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)

    def test_text_encoding_auto_detection_chunk_progress_and_roundtrip(self):
        """GB18030 与 UTF-8-SIG 文本必须无乱码识别并按原编码回写，分块扫描需写入进度。"""
        mgr = make_mgr(self.tmp)
        for enc, name in (("gb18030", "老数据.csv"), ("utf-8-sig", "表格.csv")):
            src_text = "姓名,手机号,备注\n张三,%s,测试中文\n" % PHONE
            raw = src_text.encode(enc)
            job = mgr.create_job(name, len(raw), "text")
            (mgr.job_dir(job.id) / "src.bin").write_bytes(raw)
            mgr.probe_result(job.id, True)
            j = scan(mgr, job)
            self.assertEqual(j.status, fw.ST_REVIEW)
            self.assertEqual(j.coverage.get("encoding"), enc)
            hs = mgr.hits(job.id)
            h_phone = [h for h in hs if h.get("original") == PHONE][0]
            apply(mgr, job, edits=[{"hit_id": h_phone["hit_id"], "action": "replace", "text": "脱敏号"}])
            out = out_bytes(mgr, job)
            decoded_out = out.decode(enc)
            self.assertIn("测试中文", decoded_out)
            self.assertIn("脱敏号", decoded_out)
            self.assertNotIn(PHONE, decoded_out)

    def test_ooxml_non_image_media_warning_and_optional_strip(self):
        """OOXML 含音视频等非图片媒体时必须告警，开启选项时剥离并计数。"""
        import io
        mgr = make_mgr(self.tmp)
        job = ready_docx(mgr, extra={"word/media/video1.mp4": b"MP4DATA"})
        scan(mgr, job)
        self.assertEqual(job.coverage.get("non_image_media_present"), 1)
        self.assertIn("non_image_media_unscanned", job.warnings)
        apply(mgr, job, options={"strip_non_image_media": True})
        self.assertEqual(job.coverage.get("non_image_media_stripped"), 1)
        with zipfile.ZipFile(io.BytesIO(out_bytes(mgr, job))) as zout:
            self.assertNotIn("word/media/video1.mp4", zout.namelist())

    def test_xlsx_skips_shared_string_indices_and_progress_never_fakes_100(self):
        """xlsx 必须跳过 <c t='s'><v> 索引、细粒度进度封顶 <100 且支持节点级中途取消。"""
        ss_items = "".join(f"<si><t>138{i:08d}</t></si>" for i in range(120))
        ss_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            + ss_items + "</sst>"
        )
        rows = "".join(
            f'<row r="{r + 1}"><c r="A{r + 1}" t="s"><v>{r}</v></c></row>'
            for r in range(120)
        )
        sheet_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            + rows + "</sheetData></worksheet>"
        )
        mgr = make_mgr(self.tmp)
        job = ready_docx(
            mgr,
            filename="统计表.xlsx",
            entries={
                "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
                "xl/worksheets/sheet1.xml": sheet_xml.encode("utf-8"),
                "xl/sharedStrings.xml": ss_xml.encode("utf-8"),
            },
        )
        seen_inputs = []
        seen_pcts = []
        orig_mask_body = tr.mask_body
        orig_set_progress = mgr.set_progress

        def spy_mask(text, sid):
            seen_inputs.append(text)
            return orig_mask_body(text, sid)

        def spy_prog(jid, stage, cur, total, pct=None, indeterminate=False):
            if pct is not None:
                seen_pcts.append((cur, total, pct))
            return orig_set_progress(jid, stage, cur, total, pct=pct, indeterminate=indeterminate)

        tr.mask_body = spy_mask
        mgr.set_progress = spy_prog
        try:
            j = scan(mgr, job)
        finally:
            tr.mask_body = orig_mask_body
            mgr.set_progress = orig_set_progress

        self.assertEqual(j.status, fw.ST_REVIEW)
        self.assertEqual(j.hit_count, 120)
        # <c t="s"><v>0</v></c> ~ 119 索引绝不能喂给 mask_body
        self.assertFalse(any(x.isdigit() and len(x) <= 3 for x in seen_inputs))
        self.assertTrue(seen_pcts)
        # 扫描过程中不允许报出 100%，且最后一个 part 开始时应 < 100
        self.assertTrue(all(p < 100 for _, _, p in seen_pcts), seen_pcts)
        last_part_starts = [p for c, t, p in seen_pcts if c == t]
        self.assertTrue(last_part_starts and last_part_starts[0] < 100, seen_pcts)

        # 中途取消应能迅速中断扫描并落 canceled
        job_c = ready_docx(
            mgr,
            filename="取消表.xlsx",
            entries={
                "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
                "xl/worksheets/sheet1.xml": sheet_xml.encode("utf-8"),
                "xl/sharedStrings.xml": ss_xml.encode("utf-8"),
            },
        )
        calls = [0]

        def cancel_midway(text, sid):
            calls[0] += 1
            if calls[0] >= 5:
                mgr._cancel_flags[job_c.id].set()
            return orig_mask_body(text, sid)

        tr.mask_body = cancel_midway
        try:
            mgr.request_scan(job_c.id)
        finally:
            tr.mask_body = orig_mask_body
        self.assertEqual(mgr.get_job(job_c.id).status, fw.ST_CANCELED)

    def test_single_file_case_variants_dedup_replace_and_keep(self):
        """单文件内大小写变体敏感词合并为 1 条展示，替换全改、保留各还原原文。"""
        mgr = make_mgr(self.tmp)
        sample = "Alice@example.com 和 alice@example.com\n"
        j1 = mgr.create_job("mail1.txt", len(sample), "text")
        (mgr.job_dir(j1.id) / "src.bin").write_bytes(sample.encode("utf-8"))
        mgr.probe_result(j1.id, True)
        scan(mgr, j1)
        hs1 = mgr.hits(j1.id)
        self.assertEqual(len(hs1), 1, hs1)
        self.assertEqual(hs1[0]["count"], 2)
        apply(mgr, j1, edits=[{"hit_id": hs1[0]["hit_id"], "action": "replace", "text": "[EMAIL]"}])
        out1 = out_bytes(mgr, j1).decode("utf-8")
        self.assertEqual(out1.count("[EMAIL]"), 2)
        self.assertNotIn("example.com", out1)

        # keep 时两个不同大小写的占位符都要准确还原回各自原本大小写
        j2 = mgr.create_job("mail2.txt", len(sample), "text")
        (mgr.job_dir(j2.id) / "src.bin").write_bytes(sample.encode("utf-8"))
        mgr.probe_result(j2.id, True)
        scan(mgr, j2)
        hs2 = mgr.hits(j2.id)
        self.assertEqual(len(hs2), 1)
        apply(mgr, j2, edits=[{"hit_id": hs2[0]["hit_id"], "action": "keep"}])
        out2 = out_bytes(mgr, j2).decode("utf-8")
        self.assertEqual(out2, sample)


if __name__ == "__main__":
    unittest.main()