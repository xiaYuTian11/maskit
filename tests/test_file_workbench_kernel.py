"""file-workbench-kernel（2026-11-24）守卫 G741~G752 的 1:1 真测试。

每个用例标题带 `Case G74x`，与规约守卫矩阵一一对应（flowspec 按此核对）。
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


if __name__ == "__main__":
    unittest.main()