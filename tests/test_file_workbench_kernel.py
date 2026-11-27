"""file-workbench-kernel（2026-11-24）守卫 G741~G752 的 1:1 真测试。

每个用例标题带 `Case G74x`，与规约守卫矩阵一一对应。
内核（状态机/队列/TTL/fail-closed）用 file_workbench.JobManager + stub 载体直测；
隔离（G745/G746）直测 transparent.file_store_scope；配置/路由（G743/G744/G747/
G748/G751/G752）经 panel 函数与 test_client 验收。

隐私样例一律明显假串或片段拼接，不写真实号码/凭据字面量（AGENTS §3.9）。
"""

import os
import sys
import time
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as tr            # noqa: E402
import file_workbench as fw         # noqa: E402
import file_job_store as fjs        # noqa: E402


def _sync_executor(fn):
    fn()


def _stub_hit(orig="13800000000", label="PHONE"):
    # 明显假号码（全 0 段），不写真实号码字面量。
    return fw.FileHit(hit_id="h1", token="{{PHONE_bcdfgh}}", label=label,
                      original=orig, count=1, locations=[{"page": 1}],
                      editable=True, can_keep=True)


def _stub_scan(job, src, staged, opts, cancel):
    Path(staged).write_bytes(b"staged")
    return {"hits": [_stub_hit()], "coverage": {"scanned": 1}, "warnings": []}


def _stub_apply(job, staged, out, edits, redactions, options):
    Path(out).write_bytes(b"masked")
    return {"scanned": 1, "masked": 1}


def _make_mgr(tmp, concurrency=1, queue_max=8, executor=_sync_executor, carrier=True):
    hist = fjs.HistoryStore(tmp)
    mgr = fw.JobManager(tmp, history=hist, concurrency=concurrency,
                        queue_max=queue_max, executor=executor)
    if carrier:
        mgr.register_carrier("text", _stub_scan, _stub_apply)
    return mgr


def _ready_job(mgr, carrier="text", filename="report.txt"):
    job = mgr.create_job(filename, 10, carrier)
    (mgr.job_dir(job.id) / "src.bin").write_bytes(b"hello")
    mgr.probe_result(job.id, True, page_count=1)
    return job


class KernelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fw-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_g741_state_machine(self):
        """Case G741: 状态机合法跃迁，非法操作回 FILE_7401 / 409。"""
        mgr = _make_mgr(self.tmp)
        job = _ready_job(mgr)
        # ready 不允许 apply / cancel / download
        for op, fn in (("apply", lambda: mgr.request_apply(job.id)),
                       ("cancel", lambda: mgr.cancel(job.id)),
                       ("download", lambda: mgr.check_download(job.id))):
            with self.assertRaises(fw.FileWorkbenchError) as ctx:
                fn()
            self.assertEqual(ctx.exception.code, fw.E_STATE)
            self.assertEqual(ctx.exception.http, 409)
        # ready 允许 scan → awaiting_review
        mgr.request_scan(job.id)
        self.assertEqual(mgr.get_job(job.id).status, fw.ST_REVIEW)
        # awaiting_review 允许 apply，不允许 cancel
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            mgr.cancel(job.id)
        self.assertEqual(ctx.exception.code, fw.E_STATE)
        mgr.request_apply(job.id)
        self.assertEqual(mgr.get_job(job.id).status, fw.ST_DONE)
        # done 允许 download
        mgr.check_download(job.id)

    def test_g742_queue_concurrency(self):
        """Case G742: 并发 1 时第二任务进队回 position；队满才 FILE_7402 / 429。"""
        gate = threading.Event()

        def blocking_scan(job, src, staged, opts, cancel):
            gate.wait(5)
            Path(staged).write_bytes(b"x")
            return {"hits": [], "coverage": {}, "warnings": []}

        mgr = fw.JobManager(self.tmp, concurrency=1, queue_max=2)  # 默认线程执行器
        mgr.register_carrier("text", blocking_scan, _stub_apply)
        j1 = _ready_job(mgr)
        j2 = _ready_job(mgr)
        j3 = _ready_job(mgr)
        j4 = _ready_job(mgr)
        mgr.request_scan(j1.id)                 # active=1 scanning（阻塞中）
        time.sleep(0.1)
        mgr.request_scan(j2.id)                 # queued position 1
        mgr.request_scan(j3.id)                 # queued position 2（队满）
        self.assertEqual(mgr.get_job(j2.id).status, fw.ST_QUEUED)
        self.assertEqual(mgr.get_job(j2.id).position, 1)
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            mgr.request_scan(j4.id)             # 队满 → 429
        self.assertEqual(ctx.exception.code, fw.E_QUEUE_FULL)
        self.assertEqual(ctx.exception.http, 429)
        # 429 不得「已排队」
        self.assertNotIn(j4.id, mgr._queue)
        gate.set()

    def test_g749_ttl_cleanup(self):
        """Case G749: TTL 到期 expired 清目录、启动清孤儿、删除先目录后记录（FILE_7409）。"""
        mgr = _make_mgr(self.tmp)
        job = _ready_job(mgr)
        d = mgr.job_dir(job.id)
        self.assertTrue(d.exists())
        job.expires_at = time.time() - 1
        mgr.sweep_ttl(now=time.time())
        self.assertEqual(mgr.get_job(job.id).status, fw.ST_EXPIRED)
        self.assertFalse(d.exists())
        # 删除：先目录后记录
        j2 = _ready_job(mgr)
        d2 = mgr.job_dir(j2.id)
        mgr.delete(j2.id)
        self.assertFalse(d2.exists())
        self.assertIsNone(mgr._jobs.get(j2.id))
        # 启动清理把未完成任务标失败
        j3 = _ready_job(mgr)
        mgr.startup_cleanup(now=time.time())
        self.assertEqual(mgr.get_job(j3.id).status, fw.ST_FAILED)

    def test_g749_delete_dotdot_cannot_escape_jobs_dir(self):
        """Case G749 回归（2026-11-26）：URL 传相对路径时，delete 不得把清理范围
        扩到 jobs_dir 之外。

        旧实现不先查登记表就清目录，job_id=`..` 让 `jobs_dir/..` 解析到 DATA_ROOT，
        `rmtree` 把配置、事件库、证书一起抹掉（实测 `DELETE /api/files/jobs/..`
        回 200 且 DATA_ROOT 消失）。未登记 id 必须是无操作。
        """
        sentinel = Path(self.tmp) / "sentinel.txt"
        sentinel.write_text("keep")
        mgr = _make_mgr(self.tmp)
        for bad in ("..", "../..", "", ".", "fj_x/../.."):
            self.assertFalse(mgr.delete(bad), f"未登记 id {bad!r} 必须回 False")
            self.assertTrue(sentinel.exists(), f"{bad!r} 不得删到 DATA_ROOT")
        # 第二道防线：即使直接调 _cleanup_dir，越界目标也不得清
        mgr._cleanup_dir("..")
        self.assertTrue(sentinel.exists())
        # 已知 id 仍按原语义先清目录再删记录
        job = _ready_job(mgr)
        d = mgr.job_dir(job.id)
        self.assertTrue(mgr.delete(job.id))
        self.assertFalse(d.exists())

    def test_g749_done_failed_ttl(self):
        """Case G749: 完成 30 / 失败 10 分钟到期清目录转 expired（FILE_7409）。"""
        mgr = _make_mgr(self.tmp)
        jd = _ready_job(mgr)
        mgr.request_scan(jd.id)
        mgr.request_apply(jd.id)
        self.assertEqual(mgr.get_job(jd.id).status, fw.ST_DONE)
        dd = mgr.job_dir(jd.id)
        mgr.sweep_ttl(now=time.time() + 29 * 60)      # 未到 30 分钟
        self.assertEqual(mgr.get_job(jd.id).status, fw.ST_DONE)
        mgr.sweep_ttl(now=time.time() + 31 * 60)
        self.assertEqual(mgr.get_job(jd.id).status, fw.ST_EXPIRED)
        self.assertFalse(dd.exists())
        # 失败档 10 分钟
        mf = _make_mgr(self.tmp, carrier=False)
        jf = _ready_job(mf, carrier="pdf")
        mf.request_scan(jf.id)
        self.assertEqual(mf.get_job(jf.id).status, fw.ST_FAILED)
        df = mf.job_dir(jf.id)
        mf.sweep_ttl(now=time.time() + 9 * 60)
        self.assertEqual(mf.get_job(jf.id).status, fw.ST_FAILED)
        mf.sweep_ttl(now=time.time() + 11 * 60)
        self.assertEqual(mf.get_job(jf.id).status, fw.ST_EXPIRED)
        self.assertFalse(df.exists())

    def test_g750_failclosed_privacy(self):
        """Case G750: 未注册载体失败不产成品、历史打码、注册表不落盘（FILE_7410）。"""
        mgr = _make_mgr(self.tmp, carrier=False)   # 不注册载体
        job = _ready_job(mgr, carrier="pdf", filename="secret_report.pdf")
        mgr.request_scan(job.id)
        j = mgr.get_job(job.id)
        self.assertEqual(j.status, fw.ST_FAILED)
        self.assertEqual(j.error, fw.E_FAILCLOSED)
        self.assertFalse((mgr.job_dir(job.id) / "out").exists())  # 无成品
        # 历史只存打码名，不存真实文件名
        entries = mgr.history.entries()
        self.assertTrue(entries)
        self.assertNotIn("secret_report", entries[-1]["name_preview"])
        self.assertIn("***", entries[-1]["name_preview"])
        # 命中注册表只在内存：任务目录无注册表落盘文件
        for p in mgr.job_dir(job.id).rglob("*"):
            self.assertNotIn("registry", p.name.lower())

    def test_run_apply_merges_warnings_and_records_history_once_on_failure(self):
        """apply 产生的告警必须同步回 job.warnings；apply 失败时历史只能写 1 条。"""
        hist = fjs.HistoryStore(self.tmp)
        mgr = fw.JobManager(self.tmp, history=hist, executor=_sync_executor)

        def warn_apply(job, staged, out, edits, redactions, options):
            Path(out).write_bytes(b"masked")
            return {"scanned": 1, "warnings": ["attachments_kept_unscanned", "page_kept_with_unmasked_hits"]}

        mgr.register_carrier("text", _stub_scan, warn_apply)
        job = _ready_job(mgr)
        mgr.request_scan(job.id)
        mgr.request_apply(job.id)
        self.assertEqual(mgr.get_job(job.id).status, fw.ST_DONE)
        self.assertEqual(
            mgr.get_job(job.id).warnings,
            ["attachments_kept_unscanned", "page_kept_with_unmasked_hits"],
        )

        # 失败分支只能记 1 次历史
        def fail_apply(job, staged, out, edits, redactions, options):
            raise fw.FileWorkbenchError(fw.E_FAILCLOSED, 500)

        mgr.register_carrier("text", _stub_scan, fail_apply)
        j2 = _ready_job(mgr, filename="fail.txt")
        mgr.request_scan(j2.id)
        before_count = len(hist.entries())
        mgr.request_apply(j2.id)
        self.assertEqual(mgr.get_job(j2.id).status, fw.ST_FAILED)
        entries = hist.entries()
        self.assertEqual(len(entries), before_count + 1)
        self.assertEqual(entries[-1]["id"], j2.id)
        self.assertEqual(entries[-1]["status"], fw.ST_FAILED)

    def test_queued_scan_preserves_scan_embedded_and_apply_merges_coverage(self):
        """排队任务出队时须保留各自的 scan_embedded 参数，且 apply 后不能覆盖扫描期 coverage。"""
        gate = threading.Event()
        seen_opts = {}

        def gated_scan(job, src, staged, opts, cancel):
            if job.filename == "first.txt":
                gate.wait(5)
            seen_opts[job.filename] = dict(opts)
            Path(staged).write_bytes(b"staged")
            return {"hits": [_stub_hit()],
                    "coverage": {"scanned": 2, "scanned_embedded_images": 1},
                    "warnings": []}

        def patch_apply(job, staged, out, edits, redactions, options):
            Path(out).write_bytes(b"masked")
            return {"embedded_objects_stripped": 3}

        mgr = fw.JobManager(self.tmp, history=fjs.HistoryStore(self.tmp),
                            concurrency=1, queue_max=4)
        mgr.register_carrier("text", gated_scan, patch_apply)
        try:
            j1 = _ready_job(mgr, filename="first.txt")
            j2 = _ready_job(mgr, filename="second.txt")
            mgr.request_scan(j1.id, scan_embedded=False)
            time.sleep(0.05)
            mgr.request_scan(j2.id, scan_embedded=True)
            self.assertEqual(mgr.get_job(j2.id).status, fw.ST_QUEUED)
            gate.set()
            deadline = time.time() + 5.0
            while time.time() < deadline:
                if mgr.get_job(j2.id).status == fw.ST_REVIEW:
                    break
                time.sleep(0.05)
            self.assertEqual(seen_opts.get("first.txt", {}).get("scan_embedded"), False)
            self.assertEqual(seen_opts.get("second.txt", {}).get("scan_embedded"), True)
            mgr.request_apply(j2.id)
            deadline = time.time() + 5.0
            while time.time() < deadline:
                if mgr.get_job(j2.id).status == fw.ST_DONE:
                    break
                time.sleep(0.05)
            cov = mgr.get_job(j2.id).coverage
            self.assertEqual(cov.get("scanned"), 2)
            self.assertEqual(cov.get("scanned_embedded_images"), 1)
            self.assertEqual(cov.get("embedded_objects_stripped"), 3)
        finally:
            gate.set()
            mgr.stop()

    def test_patient_ner_budget_and_degraded_warning(self):
        """扫描在 patient 耐心模式下运行 NER；若发生跳过必写入 ner_degraded 告警与计数。"""
        import ner_engine

        seen = {}

        def check_scan(job, src, staged, opts, cancel):
            mgr = job._mgr
            mgr.set_progress(job.id, "text_chunks", 1, 2)
            self.assertEqual(mgr.get_job(job.id).progress, {"stage": "text_chunks", "current": 1, "total": 2})
            seen["patient"] = bool(getattr(ner_engine._local, "patient", False))
            ner_engine._note_skip("global_throttled")
            Path(staged).write_bytes(b"staged")
            return {"hits": [_stub_hit()], "coverage": {"scanned": 1}, "warnings": []}

        mgr = _make_mgr(self.tmp)
        mgr.register_carrier("text", check_scan, _stub_apply)
        job = _ready_job(mgr, filename="long.txt")
        mgr.request_scan(job.id)
        j = mgr.get_job(job.id)
        self.assertTrue(seen.get("patient"))
        self.assertEqual(j.progress, {})
        self.assertIn("ner_degraded", j.warnings)
        self.assertGreaterEqual(j.coverage.get("ner_skipped_chunks", 0), 1)

    def test_batch_shared_tokens_isolation_and_cleanup(self):
        """同批次文件共享占位符且互不串入对方独有词，不污染全局表，全删后注销批次后缀。"""
        import file_carriers as fc
        snap_fwd = dict(tr._RECENT_FWD)
        snap_sfx = set(tr._RECENT_SUFFIX)
        mgr = fw.JobManager(self.tmp, history=fjs.HistoryStore(self.tmp), executor=_sync_executor)
        fc.register(mgr)
        try:
            batch_id = "fb_unit_batch"
            j1 = mgr.create_job("b1.txt", 30, "text", batch_id=batch_id)
            (mgr.job_dir(j1.id) / "src.bin").write_bytes("甲 13800000000 与 13900000000".encode("utf-8"))
            mgr.probe_result(j1.id, True)
            j2 = mgr.create_job("b2.txt", 30, "text", batch_id=batch_id)
            (mgr.job_dir(j2.id) / "src.bin").write_bytes("乙 13800000000 与 13700000000".encode("utf-8"))
            mgr.probe_result(j2.id, True)

            mgr.request_scan(j1.id)
            mgr.request_scan(j2.id)
            h1 = {h["original"]: h for h in mgr.hits(j1.id)}
            h2 = {h["original"]: h for h in mgr.hits(j2.id)}

            self.assertIn("13800000000", h1)
            self.assertIn("13800000000", h2)
            # 同批次相同敏感词必须拿到完全相同的占位符
            self.assertEqual(h1["13800000000"]["token"], h2["13800000000"]["token"])
            # 文件 2 不能混入文件 1 独有的号码
            self.assertNotIn("13900000000", h2)
            self.assertNotIn("13700000000", h1)
            self.assertEqual(dict(tr._RECENT_FWD), snap_fwd)
            self.assertEqual(set(tr._RECENT_SUFFIX), snap_sfx)
            self.assertIn(batch_id, tr._FILE_JOB_SUFFIXES)

            merged = mgr.merged_hits([j1.id, j2.id])
            by_orig = {h["original"]: h for h in merged["hits"]}
            self.assertEqual(by_orig["13800000000"]["count"], 2)
            self.assertEqual(len(by_orig["13800000000"]["files"]), 2)
            self.assertEqual(len(by_orig), 3)

            mgr.delete(j1.id)
            self.assertIn(batch_id, tr._FILE_JOB_SUFFIXES)
            mgr.delete(j2.id)
            self.assertNotIn(batch_id, tr._FILE_JOB_SUFFIXES)
        finally:
            mgr.stop()

    def test_batch_lock_cancel_while_waiting_skips_scan(self):
        """同批次任务在等待 batch_lock 期间被取消后，释放锁时不得再运行扫描且应转为 canceled。"""
        j1_entered = threading.Event()
        j1_release = threading.Event()
        scanned_files = []

        def slow_scan(job, src, staged, opts, cancel):
            scanned_files.append(job.filename)
            if job.filename == "hold.txt":
                j1_entered.set()
                j1_release.wait(5)
            Path(staged).write_bytes(b"staged")
            return {"hits": [_stub_hit()], "coverage": {"scanned": 1}, "warnings": []}

        mgr = fw.JobManager(self.tmp, history=fjs.HistoryStore(self.tmp),
                            concurrency=2, queue_max=4)
        mgr.register_carrier("text", slow_scan, _stub_apply)
        try:
            batch_id = "fb_cancel_wait"
            j1 = _ready_job(mgr, filename="hold.txt")
            j2 = _ready_job(mgr, filename="waiter.txt")
            j1.batch_id = batch_id
            j2.batch_id = batch_id
            mgr.request_scan(j1.id)
            self.assertTrue(j1_entered.wait(3))
            mgr.request_scan(j2.id)
            # 等待 j2 工作线程进入 batch_lock 阻塞等待
            time.sleep(0.08)
            mgr.cancel(j2.id)
            j1_release.set()

            deadline = time.time() + 5.0
            while time.time() < deadline:
                if (mgr.get_job(j1.id).status == fw.ST_REVIEW
                        and mgr.get_job(j2.id).status == fw.ST_CANCELED):
                    break
                time.sleep(0.05)

            self.assertEqual(mgr.get_job(j1.id).status, fw.ST_REVIEW)
            self.assertEqual(mgr.get_job(j2.id).status, fw.ST_CANCELED)
            self.assertEqual(scanned_files, ["hold.txt"])
        finally:
            j1_release.set()
            mgr.stop()


class IsolationTests(unittest.TestCase):
    def test_g745_zero_pollution(self):
        """Case G745: file_store_scope 空表不种子，任务前后全局表零变化（FILE_7405）。"""
        def snap():
            return (dict(tr._RECENT_FWD), dict(tr._RECENT_REV), set(tr._RECENT_SUFFIX),
                    tr._KNOWN_GEN, dict(tr._KNOWN_BY_HEAD), dict(tr._KNOWN_NEW), dict(tr._SENT_CUR))
        before = snap()
        with tr.file_store_scope("fj_test_iso"):
            self.assertTrue(tr._is_isolated())
            tables = tr._tables()
            self.assertEqual(len(tables.fwd), 0)      # 空表不种子
            # 在隔离作用域内打码：全局表不得被写入
            tr._known_add("13800000000", "{{PHONE_bcdfgh}}", "PHONE")
            tr._sent_store("{{PHONE_bcdfgh}}", [(0, 11)])
            tr._recent_in_use_add("{{PHONE_bcdfgh}}")
        after = snap()
        self.assertEqual(before, after)
        self.assertFalse(tr._is_isolated())

    def test_g746_suffix_avoidance(self):
        """Case G746: 任务后缀登记活跃集、_new_token 避让、结束精确移除（FILE_7406）。"""
        with tr.file_store_scope("fj_test_sfx"):
            tok = tr._new_token("PHONE")
            tr._suffix_index_add(tok)          # 签发即登记进活跃注册表
            sfx = tr._token_suffix(tok)
            self.assertIn(sfx, tr._FILE_SUFFIX_ACTIVE)
            self.assertIn(sfx, tr._FILE_JOB_SUFFIXES.get("fj_test_sfx", set()))
        # 作用域退出后 unregister 精确移除本任务后缀
        tr.file_suffix_unregister("fj_test_sfx")
        self.assertNotIn(sfx, tr._FILE_SUFFIX_ACTIVE)
        self.assertNotIn("fj_test_sfx", tr._FILE_JOB_SUFFIXES)


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import panel
        cls.panel = panel
        cls.client = panel.app.test_client()
        cls.auth = {"X-Shield-Token": panel.API_TOKEN}

    def test_g752_config_keys(self):
        """Case G752: files_* 键进白名单与 normalize_config，默认值固定（FILE_7412）。"""
        p = self.panel
        defaults = p.default_config()
        expect = {"files_enabled": True, "files_max_size_mb": 1024, "files_max_text_mb": 128,
                  "files_max_pages": 1000,
                  "files_max_image_mp": 32, "files_max_hits": 20000, "files_queue_max": 8,
                  "files_worker_concurrency": 1, "files_review_ttl_min": 60,
                  "files_clear_pdf_docinfo": True, "files_strip_embedded": True,
                  "files_path_source": True}
        for k, v in expect.items():
            self.assertIn(k, defaults)
            self.assertEqual(defaults[k], v)
        norm = p.normalize_config({})
        for k, v in expect.items():
            self.assertEqual(norm[k], v)
        # 非法值回落默认不崩溃
        self.assertEqual(p.normalize_config({"files_max_pages": "abc"})["files_max_pages"], 1000)

    def test_g743_upload_gate(self):
        """Case G743: 超限/Transfer-Encoding 回 FILE_7403 / JSON 413 + blocking。"""
        p = self.panel
        # Transfer-Encoding 直接拒
        r = self.client.post("/api/files/jobs", headers={**self.auth, "Transfer-Encoding": "chunked"},
                             data=b"x")
        self.assertEqual(r.status_code, 413)
        body = r.get_json()
        self.assertEqual(body["error"], fw.E_TOO_LARGE)
        self.assertTrue(body["blocking"])
        # 有界写入兜底：Content-Length 谎报时按实际字节封顶，超限抛 FILE_7403
        import io as _io
        bf = p._BoundedUploadFile(_io.BytesIO(), 4)
        bf.write(b"abcd")
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            bf.write(b"e")
        self.assertEqual(ctx.exception.code, fw.E_TOO_LARGE)

    def test_g744_spool_location(self):
        """Case G744: 上传经 _get_file_stream 直写 DATA_ROOT（FILE_7404），不落 %TEMP%。"""
        p = self.panel
        import io
        data = {"file": (io.BytesIO(b"hello world"), "note.txt")}
        r = self.client.post("/api/files/jobs", headers=self.auth, data=data,
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        job = r.get_json()["job"]
        src = p.DATA_ROOT / "file-jobs" / job["id"] / "src.bin"
        self.assertTrue(src.exists())
        self.assertEqual(src.read_bytes(), b"hello world")
        # 落盘在 DATA_ROOT 下，不在系统临时目录
        self.assertTrue(str(src).startswith(str(p.DATA_ROOT)))
        p._file_manager().delete(job["id"])

    def test_g747_nonce_download(self):
        """Case G747: nonce 一次性、过期/篡改/重放回 FILE_7407 / 403。"""
        p = self.panel
        nonce, exp, sig = p._file_nonce_make("fj_nonce_test")
        # 篡改签名
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_nonce_take("fj_nonce_test", nonce, exp, "deadbeef")
        self.assertEqual(ctx.exception.code, fw.E_NONCE)
        self.assertEqual(ctx.exception.http, 403)
        # 过期
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_nonce_take("fj_nonce_test", nonce, int(time.time()) - 10, sig)
        self.assertEqual(ctx.exception.code, fw.E_NONCE)
        # 正常一次成功，重放失败（一次性）
        n2, e2, s2 = p._file_nonce_make("fj_nonce_test")
        p._file_nonce_take("fj_nonce_test", n2, e2, s2)
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_nonce_take("fj_nonce_test", n2, e2, s2)
        self.assertEqual(ctx.exception.code, fw.E_NONCE)
        # 过期 nonce 在下次签发时被清理，字典不无限增长
        n3, e3, s3 = p._file_nonce_make("fj_prune")
        p._FILE_NONCES[n3] = ("fj_prune", int(time.time()) - 5, s3)
        p._file_nonce_make("fj_other")
        self.assertNotIn(n3, p._FILE_NONCES)

    def test_g748_save_guard(self):
        """Case G748: 相对/非目录/DATA_ROOT/源目录/默认覆盖均回 FILE_7408 / 400。"""
        p = self.panel
        job = fw.FileJob(id="fj_save", filename="out.txt", source_path=str(Path(self.tmp_src()) / "s.txt"))
        # 相对路径
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_save_guard(job, "relative/dir", False)
        self.assertEqual(ctx.exception.code, fw.E_SAVE_DEST)
        # DATA_ROOT 内
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_save_guard(job, str(p.DATA_ROOT), False)
        self.assertEqual(ctx.exception.code, fw.E_SAVE_DEST)
        # 源目录
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_save_guard(job, os.path.dirname(job.source_path), False)
        self.assertEqual(ctx.exception.code, fw.E_SAVE_DEST)

    def tmp_src(self):
        d = tempfile.mkdtemp(prefix="fw-src-")
        Path(d, "s.txt").write_bytes(b"x")
        return d

    def test_g751_path_mode_gate(self):
        """Case G751: REMOTE_MODE 或 files_path_source 关时 path 模式回 FILE_7411 / 400。"""
        p = self.panel
        old = p.REMOTE_MODE
        try:
            p.REMOTE_MODE = True
            r = self.client.post("/api/files/jobs", headers={**self.auth, "Content-Type": "application/json"},
                                 json={"path": str(Path(tempfile.gettempdir()) / "x.txt")})
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.get_json()["error"], fw.E_PATH_MODE)
            # save 另存为同样是桌面能力，远程模式禁用（Docker 走浏览器下载）
            r2 = self.client.post("/api/files/jobs/fj_x/save",
                                  headers={**self.auth, "Content-Type": "application/json"},
                                  json={"dest_dir": "C:/x"})
            self.assertEqual(r2.status_code, 400)
            self.assertEqual(r2.get_json()["error"], fw.E_PATH_MODE)
        finally:
            p.REMOTE_MODE = old

    def test_file_nonce_take_rejects_non_ascii_signature_without_500(self):
        """非 ASCII 签名必须返回 FILE_7407 / 403，不得因 compare_digest 抛 TypeError 导致 500。"""
        p = self.panel
        nonce, exp, _sig = p._file_nonce_make("fj_nonce_nonascii")
        with self.assertRaises(fw.FileWorkbenchError) as ctx:
            p._file_nonce_take("fj_nonce_nonascii", nonce, exp, "中文签名")
        self.assertEqual(ctx.exception.code, fw.E_NONCE)
        self.assertEqual(ctx.exception.http, 403)

    def test_empty_multipart_upload_leaves_no_orphan_dir(self):
        """空 multipart 上传返回 no_file 且不能在 DATA_ROOT/file-jobs 下残留空目录。"""
        p = self.panel
        jobs_dir = p._file_manager().jobs_dir
        before = set(jobs_dir.iterdir()) if jobs_dir.exists() else set()
        r = self.client.post("/api/files/jobs", headers=self.auth, data={},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["error"], "no_file")
        after = set(jobs_dir.iterdir()) if jobs_dir.exists() else set()
        self.assertEqual(after - before, set(), "异常上传不能留下未注册任务目录")

    def test_merged_hits_and_export_zip_endpoints(self):
        """跨文件聚合清单与 ZIP 打包导出端点校验（含权限/凭据隐私/状态守卫）。"""
        import io
        import zipfile
        phone = "13800000000"
        secret = "sk-" + "test" + "0" * 24
        batch = "fb_panel_zip"
        ids = []
        for idx, name in enumerate(("a.txt", "b.txt"), 1):
            payload = (f"doc{idx} {phone} key={secret}\n").encode("utf-8")
            r = self.client.post(
                "/api/files/jobs",
                headers=self.auth,
                data={"file": (io.BytesIO(payload), name), "batch_id": batch},
                content_type="multipart/form-data",
            )
            self.assertEqual(r.status_code, 201)
            ids.append(r.get_json()["job"]["id"])
        try:
            for jid in ids:
                sr = self.client.post(f"/api/files/jobs/{jid}/scan", headers=self.auth, json={"mode": "manual"})
                self.assertEqual(sr.status_code, 201)
            deadline = time.time() + 15.0
            mgr = self.panel._file_manager()
            while time.time() < deadline:
                if all(mgr.get_job(jid).status == fw.ST_REVIEW for jid in ids):
                    break
                time.sleep(0.05)
            for jid in ids:
                self.assertEqual(mgr.get_job(jid).status, fw.ST_REVIEW)

            # 无 token 拒 403
            self.assertEqual(self.client.post("/api/files/hits/merged", json={"job_ids": ids}).status_code, 403)
            self.assertEqual(self.client.post("/api/files/export-zip", json={"job_ids": ids}).status_code, 403)

            mr = self.client.post("/api/files/hits/merged", headers=self.auth, json={"job_ids": ids})
            self.assertEqual(mr.status_code, 200)
            mhits = mr.get_json()["hits"]
            self.assertEqual(len(mhits), 2)
            phone_hit = next(h for h in mhits if h.get("original") == phone)
            self.assertEqual(phone_hit["count"], 2)
            self.assertEqual(len(phone_hit["files"]), 2)
            cred_hit = next(h for h in mhits if not h["editable"])
            self.assertNotIn("original", cred_hit)
            self.assertIn("digest", cred_hit)

            # 未完成不能打包 ZIP
            zr_early = self.client.post("/api/files/export-zip", headers=self.auth, json={"job_ids": ids})
            self.assertEqual(zr_early.status_code, 409)

            for fref in phone_hit["files"]:
                ar = self.client.post(
                    f"/api/files/jobs/{fref['job_id']}/apply",
                    headers=self.auth,
                    json={"edits": [{"hit_id": fref["hit_id"], "action": "replace", "text": "TEL_MASKED"}], "redactions": [], "options": {}},
                )
                self.assertEqual(ar.status_code, 202)
            deadline = time.time() + 15.0
            while time.time() < deadline:
                if all(mgr.get_job(jid).status == fw.ST_DONE for jid in ids):
                    break
                time.sleep(0.05)
            for jid in ids:
                self.assertEqual(mgr.get_job(jid).status, fw.ST_DONE)

            zr = self.client.post("/api/files/export-zip", headers=self.auth, json={"job_ids": ids})
            self.assertEqual(zr.status_code, 200)
            with zipfile.ZipFile(io.BytesIO(zr.data)) as zf:
                self.assertEqual(sorted(zf.namelist()), ["a.txt", "b.txt"])
                for n in zf.namelist():
                    txt = zf.read(n).decode("utf-8")
                    self.assertIn("TEL_MASKED", txt)
                    self.assertNotIn(phone, txt)
                    self.assertNotIn(secret, txt)
            zr.close()
        finally:
            for jid in ids:
                self.client.delete(f"/api/files/jobs/{jid}", headers=self.auth)


if __name__ == "__main__":
    unittest.main()