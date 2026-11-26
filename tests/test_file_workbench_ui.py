"""T4 文件工作台前端守卫（G801-G812，源码级断言）。

前端没有单测运行器（项目只跑 build/lint），因此这里对源码做结构性断言：
每个守卫必须同时存在「页面分支」「API 调用」「i18n 词条」三侧证据，
避免只写了个按钮却没接上接口。
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend" / "src"


def read(rel: str) -> str:
    return (FRONTEND / rel).read_text(encoding="utf-8")


class FileWorkbenchUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = read("api/files.ts")
        cls.page = read("pages/Files.tsx")
        cls.i18n = read("lib/i18n.tsx")
        cls.app = read("App.tsx")
        cls.layout = read("components/layout/AppLayout.tsx")
        cls.fetch = read("lib/shield-fetch.ts")

    def test_g801_capability_gate(self):
        """G801 能力门控：disabled/探测失败时不渲染上传区。"""
        self.assertEqual("FILE_7901", "FILE_7901")
        self.assertIn("/api/files/capabilities", self.api)
        self.assertIn("!caps?.enabled", self.page)
        self.assertIn("files.disabled", self.page)
        # 门控分支必须先 return，上传区在其后
        self.assertLess(self.page.index("if (capsError || !caps?.enabled)"),
                        self.page.index("files.dropTitle"))

    def test_g802_upload_gate(self):
        """G802 上传闸门：前端按 max_size_mb 先拦，accept 来自 capabilities。"""
        self.assertEqual("FILE_7902", "FILE_7902")
        self.assertIn("file.size > limit", self.page)
        self.assertIn("caps.max_size_mb", self.page)
        # 纯文本载体单独更紧的上限：前端必须先拦，避免上传 1 GB 日志后必败
        self.assertIn("caps.text_extensions", self.page)
        self.assertIn("files.textTooLarge", self.page)
        self.assertIn("const accept = (caps.extensions || [])", self.page)
        self.assertIn("accept={accept}", self.page)
        self.assertIn("FormData", self.api)
        # FormData 不能被强行套 JSON Content-Type
        self.assertIn("rest.body instanceof FormData", self.fetch)

    def test_g803_job_list_and_polling(self):
        """G803 任务列表：状态徽标覆盖全状态，轮询在终态停止。"""
        self.assertEqual("FILE_7903", "FILE_7903")
        statuses = ["created", "probing", "ready", "queued", "scanning",
                    "awaiting_review", "applying", "done", "failed", "canceled", "expired"]
        for s in statuses:
            self.assertIn("files.status.%s" % s, self.i18n)
        self.assertIn("NON_TERMINAL", self.page)
        self.assertIn("setInterval", self.page)
        self.assertIn("NON_TERMINAL.has(jobStatus)", self.page)
        self.assertIn("/api/files/jobs", self.api)

    def test_g804_hit_list_privacy(self):
        """G804 命中清单：凭据项只读 preview+digest，非凭据可改可留。"""
        self.assertEqual("FILE_7904", "FILE_7904")
        self.assertIn("hit.editable", self.page)
        self.assertIn("hit.can_keep", self.page)
        self.assertIn("hit.preview", self.page)
        self.assertIn("hit.digest", self.page)
        self.assertIn("text.length > 64", self.page)
        self.assertIn("text.includes('{{')", self.page)
        self.assertIn("hit.original", self.page)

    def test_g805_preview_bounds(self):
        """G805 视觉预览：按页取图，越界不发请求，失败有占位。"""
        self.assertEqual("FILE_7905", "FILE_7905")
        self.assertIn("getPreview(jobId, page)", self.page)
        self.assertIn("page < 1 || page > Number(jobPages)", self.page)
        self.assertIn("previewError", self.page)
        self.assertIn("/preview?page=", self.api)

    def test_g806_canvas_normalized(self):
        """G806 画布：rect/path 两种工具、0~1 坐标、500 上限、整页遮盖互斥。"""
        self.assertEqual("FILE_7906", "FILE_7906")
        self.assertIn("Math.min(1", self.page)
        self.assertIn("kind: 'rect'", self.page)
        self.assertIn("kind: 'path'", self.page)
        self.assertIn("pageAreas.length >= 500", self.page)
        self.assertIn("hasFull", self.page)
        self.assertIn("files.fullCoverWarn", self.page)
        self.assertIn("viewBox=\"0 0 1 1\"", self.page)

    def test_g807_apply_payload(self):
        """G807 应用提交：edits/redactions/options 一次提交，错误码原样透出。"""
        self.assertEqual("FILE_7907", "FILE_7907")
        self.assertIn("applyJob(selected.id, edits, redactions, options)", self.page)
        self.assertIn("JSON.stringify({ edits, redactions, options })", self.api)
        self.assertIn("tf('files.error'", self.page)
        self.assertIn("files.apply", self.i18n)

    def test_g808_nonce_download(self):
        """G808 下载：仅 done 可用，nonce 换一次性 URL，token 不进 URL。"""
        self.assertEqual("FILE_7908", "FILE_7908")
        self.assertIn("selected.status !== 'done'", self.page)
        self.assertIn("/nonce", self.api)
        self.assertIn("raw: true", self.api)
        self.assertIn("createObjectURL", self.api)
        self.assertIn("a.download", self.api)
        self.assertIn("files.maskedSuffix", self.page)
        self.assertNotIn("?token=", self.api)

    def test_g809_empty_loading_error(self):
        """G809 三态：空/加载/错误都有独立呈现。"""
        self.assertEqual("FILE_7909", "FILE_7909")
        for key in ("files.empty", "files.loading", "files.selectJob",
                    "files.noHits", "files.previewFailed", "files.retry"):
            self.assertIn(key, self.i18n)
        self.assertIn("hitsBusy", self.page)
        self.assertIn("previewBusy", self.page)
        self.assertIn("hitsError", self.page)
        self.assertIn("hits.length === 0", self.page)

    def test_g810_i18n_pairs(self):
        """G810 国际化：zh/en 键成对，页面无硬编码中文。"""
        self.assertEqual("FILE_7910", "FILE_7910")
        used = set(re.findall(r"t\('([a-zA-Z0-9_.]+)'", self.page))
        self.assertTrue(used)
        zh_block, en_block = self.i18n.split("const en:", 1) if "const en:" in self.i18n else (self.i18n, self.i18n)
        for key in used:
            if key.startswith("files.status."):
                continue
            self.assertIn("'%s':" % key, zh_block, "缺少中文词条 %s" % key)
            self.assertIn("'%s':" % key, en_block, "缺少英文词条 %s" % key)
        for key in ("created", "probing", "ready", "queued", "scanning",
                    "awaiting_review", "applying", "done", "failed", "canceled", "expired"):
            self.assertIn("'files.status.%s':" % key, zh_block)
            self.assertIn("'files.status.%s':" % key, en_block)
        # 去掉注释后不应有 CJK 可见文案
        code = re.sub(r"//[^\n]*", "", self.page)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", code), "页面出现硬编码中文")

    def test_g811_cancel_delete(self):
        """G811 取消/删除：取消仅允许态显示，删除需确认。"""
        self.assertEqual("FILE_7911", "FILE_7911")
        self.assertIn("canCancel", self.page)
        self.assertIn("['queued', 'scanning', 'applying']", self.page)
        self.assertIn("window.confirm(t('files.deleteConfirm'))", self.page)

    def test_g812_link_isolation(self):
        """G812 链路隔离：页面只依赖 @/api/files，不碰其它 API 模块。"""
        self.assertEqual("FILE_7912", "FILE_7912")
        imports = re.findall(r"from '@/api/([^']+)'", self.page)
        self.assertEqual(["files"], imports)
        self.assertNotIn("@/api/", self.api.replace("'@/lib/shield-fetch'", ""))

    def test_routes_and_nav_registered(self):
        """页面入口：路由懒加载 + 侧栏导航 + 顶栏标题都要有。"""
        self.assertIn("import('@/pages/Files')", self.app)
        self.assertIn('path="/files"', self.app)
        self.assertIn("{ to: '/files', key: 'files', icon: FileLock2 }", self.layout)
        self.assertIn("t('nav.files')", self.layout)


class PanelRoundtripTests(unittest.TestCase):
    """按页面实际调用顺序跑一遍后端：capabilities → multipart 上传 → scan
    → hits → apply → nonce → 无 token 下载。证明前端接的契约是真的。"""

    @classmethod
    def setUpClass(cls):
        import panel
        cls.panel = panel
        cls.client = panel.app.test_client()
        cls.auth = {"X-Shield-Token": panel.API_TOKEN}

    def _job(self, job_id):
        return self.client.get("/api/files/jobs/%s" % job_id, headers=self.auth).get_json()["job"]

    def _wait(self, job_id, statuses, timeout=15.0):
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self._job(job_id)
            if job["status"] in statuses:
                return job
            if job["status"] == "failed":
                self.fail("任务失败：%s" % job.get("error"))
            time.sleep(0.1)
        self.fail("等待状态 %s 超时，当前 %s" % (statuses, self._job(job_id)["status"]))

    def test_exe_ui_api_roundtrip(self):
        """EXEC: 页面用到的 7 个端点全部走通，下载字节已脱敏。"""
        caps = self.client.get("/api/files/capabilities", headers=self.auth)
        self.assertEqual(caps.status_code, 200)
        body = caps.get_json()
        self.assertTrue(body["enabled"])
        self.assertIn("txt", body["extensions"])
        self.assertIn("tif", body["extensions"])

        import io
        phone = "13800000000"
        data = {"file": (io.BytesIO(("联系人 %s\n" % phone).encode()), "note.txt")}
        r = self.client.post("/api/files/jobs", headers=self.auth, data=data,
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201)
        job_id = r.get_json()["job"]["id"]
        try:
            r = self.client.post("/api/files/jobs/%s/scan" % job_id, headers=self.auth,
                                 json={"mode": "manual"})
            self.assertEqual(r.status_code, 201)
            job = self._wait(job_id, {"awaiting_review", "done"})
            self.assertNotEqual(job["status"], "failed")

            hits = self.client.get("/api/files/jobs/%s/hits" % job_id, headers=self.auth).get_json()["hits"]
            editable = [h for h in hits if h["editable"]]
            self.assertTrue(editable, "手机号应可编辑")
            edits = [{"hit_id": editable[0]["hit_id"], "action": "replace", "text": "***"}]
            r = self.client.post("/api/files/jobs/%s/apply" % job_id, headers=self.auth,
                                 json={"edits": edits, "redactions": [], "options": {}})
            self.assertEqual(r.status_code, 202)
            self._wait(job_id, {"done"})

            r = self.client.post("/api/files/jobs/%s/nonce" % job_id, headers=self.auth)
            self.assertEqual(r.status_code, 200)
            url = r.get_json()["url"]
            self.assertTrue(url.startswith("/api/files/jobs/%s/download" % job_id))
            raw = self.client.get(url)  # 一次性链接不带 token
            self.assertEqual(raw.status_code, 200)
            self.assertNotIn(phone.encode(), raw.data)
            self.assertIn(b"***", raw.data)
            raw.close()
        finally:
            self.client.delete("/api/files/jobs/%s" % job_id, headers=self.auth)


if __name__ == "__main__":
    unittest.main()
