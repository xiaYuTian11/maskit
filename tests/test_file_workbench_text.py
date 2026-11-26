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
        j = scan(mgr, job)
        cov = j.coverage
        self.assertEqual(cov.get("skipped_embedded_images"), 1)
        self.assertEqual(cov.get("embedded_objects_present"), 1)
        apply(mgr, job)
        self.assertEqual(mgr.get_job(job.id).coverage.get("embedded_objects_stripped"), 1)


if __name__ == "__main__":
    unittest.main()