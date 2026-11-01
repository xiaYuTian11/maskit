"""OCR 运行时组件（`engine/ocr_runtime.py`）的契约锁。

组件是"可选、按需下载"的：这里的每个用例都在验证同一件事——
**失败绝不留半装可用状态**（开关不是"看起来开着其实坏的"）。

测试替身：`_download` / `_selftest` / `ocr_engine.available` 都被替换，
本文件不依赖网络，也不依赖本机是否装了真 OCR 运行时。
"""
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

import ocr_engine  # noqa: E402
import ocr_runtime as R  # noqa: E402


def _pkg_zip(extra=(), layout_ok=True):
    buf = io.BytesIO()
    prefix = "site-packages/" if layout_ok else ""
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(prefix + "rapidocr_onnxruntime/__init__.py",
                   "class RapidOCR:\n    def __init__(self, *a, **k):\n        pass\n")
        z.writestr(prefix + "rapidocr_onnxruntime/models/m.onnx", b"\x00" * 32)
        for name, payload in extra:
            z.writestr(name, payload)
    return buf.getvalue()


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="maskit-ocr-rt-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for key, val in (("LLM_SHIELD_DATA_DIR", str(self.tmp)), (R.MANIFEST_ENV, None)):
            old = os.environ.get(key)
            self.addCleanup(self._restore_env, key, old)
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        # 引擎可用性：默认"组件目录存在才可用"，与真实世界一致，且不受本机预装影响
        self.engine_ok = None
        patcher = mock.patch.object(ocr_engine, "available", side_effect=self._fake_available)
        patcher.start()
        self.addCleanup(patcher.stop)
        # 真 warmup 会加载模型（0.6s/次），这里只验状态机
        warm = mock.patch.object(ocr_engine, "warmup", return_value=True)
        warm.start()
        self.addCleanup(warm.stop)
        self.addCleanup(R.reset_for_tests)
        R.reset_for_tests()

    @staticmethod
    def _restore_env(key, old):
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old

    def _fake_available(self):
        if self.engine_ok is not None:
            return self.engine_ok
        return (True, "") if R.resolve_runtime_path() else (False, "ocr_runtime_missing")

    def _patch_download(self, payload, manifest=None, progress_steps=(), gate=None):
        def fake(url, on_progress=None):
            if gate is not None:
                gate.wait(5)
            if manifest is not None and url.endswith(".json"):
                return json.dumps(manifest).encode()
            for n, t in progress_steps:
                if on_progress:
                    on_progress(n, t)
            return payload
        p = mock.patch.object(R, "_download", side_effect=fake)
        p.start()
        self.addCleanup(p.stop)

    def _patch_selftest(self, ok, why=""):
        p = mock.patch.object(R, "_selftest", return_value=(ok, why))
        p.start()
        self.addCleanup(p.stop)


class InstallTests(_Base):
    def test_starts_disabled_without_component(self):
        st = R.status()
        self.assertEqual(st["state"], R.STATE_DISABLED)
        self.assertEqual(st["path"], "")
        self.assertEqual(st["error"], "")

    def test_system_preinstalled_engine_reports_enabled(self):
        """服务器/Docker 的 pip 预装：没有组件目录也要显示已启用，不能诱导用户再下载。"""
        self.engine_ok = (True, "")
        st = R.status()
        self.assertEqual(st["state"], R.STATE_ENABLED)
        self.assertEqual(st["source"], "system")

    def test_install_success_enables_and_injects_syspath(self):
        payload = _pkg_zip()
        self._patch_download(payload)
        self._patch_selftest(True)
        st = R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        self.assertEqual(st["state"], R.STATE_ENABLED)
        self.assertEqual(st["version"], "v1")
        self.assertEqual(st["source"], "component")
        self.assertTrue(any("ocr-runtime" in p for p in sys.path), "没注入 sys.path")
        self.assertTrue((self.tmp / "ocr-runtime" / "v1" / "site-packages").is_dir())

    def test_uppercase_sha256_is_accepted(self):
        payload = _pkg_zip()
        self._patch_download(payload)
        self._patch_selftest(True)
        st = R.install(url="http://x/ocr.zip", sha256=_sha(payload).upper(), version="v1")
        self.assertEqual(st["state"], R.STATE_ENABLED)

    def test_checksum_mismatch_leaves_nothing(self):
        self._patch_download(_pkg_zip())
        self._patch_selftest(True)
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install(url="http://x/ocr.zip", sha256="0" * 64, version="v1")
        self.assertEqual(ctx.exception.reason, "checksum_mismatch")
        self.assertEqual(R.status()["state"], R.STATE_DISABLED)
        self.assertFalse((self.tmp / "ocr-runtime" / "v1").exists())

    def test_malformed_sha256_rejected_before_download(self):
        self._patch_download(_pkg_zip())
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install(url="http://x/ocr.zip", sha256="abc", version="v1")
        self.assertEqual(ctx.exception.reason, "manifest_invalid")
        R._download.assert_not_called()

    def test_zip_slip_is_rejected(self):
        payload = _pkg_zip(extra=[("../evil.py", "x")])
        self._patch_download(payload)
        self._patch_selftest(True)
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        self.assertEqual(ctx.exception.reason, "package_path_unsafe")
        self.assertEqual(R.status()["state"], R.STATE_DISABLED)
        self.assertFalse((self.tmp / "evil.py").exists())

    def test_path_traversal_in_version_is_rejected(self):
        payload = _pkg_zip()
        for bad in ("../x", "..", "a/b", "a\\b", "c:x"):
            with self.subTest(version=bad):
                self._patch_download(payload)
                with self.assertRaises(R.OcrRuntimeError) as ctx:
                    R.install(url="http://x/ocr.zip", sha256=_sha(payload), version=bad)
                self.assertEqual(ctx.exception.reason, "manifest_invalid")

    def test_wrong_layout_is_rejected(self):
        """zip 根下没有 site-packages/：原来会'装好但永远不可用'，现在直接拒绝。"""
        payload = _pkg_zip(layout_ok=False)
        self._patch_download(payload)
        self._patch_selftest(True)
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        self.assertEqual(ctx.exception.reason, "package_layout_invalid")
        self.assertFalse((self.tmp / "ocr-runtime" / "v1").exists())

    def test_selftest_failure_rolls_back(self):
        payload = _pkg_zip()
        self._patch_download(payload)
        self._patch_selftest(False, "text_mismatch")
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        self.assertEqual(ctx.exception.reason, "selftest_failed")
        self.assertEqual(R.status()["state"], R.STATE_DISABLED)
        self.assertFalse((self.tmp / "ocr-runtime" / "v1").exists(),
                         "自检失败必须清掉目录，不能留半装状态")

    def test_failed_reinstall_of_same_version_keeps_working_copy(self):
        """重装同一版本自检失败：原来先 rmtree 再装，失败后用户连旧的可用版都没了。"""
        payload = _pkg_zip()
        self._patch_download(payload)
        with mock.patch.object(R, "_selftest", return_value=(True, "")):
            R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        marker = self.tmp / "ocr-runtime" / "v1" / "site-packages" / "keep.txt"
        marker.write_text("old", encoding="utf-8")
        with mock.patch.object(R, "_selftest", return_value=(False, "boom")):
            with self.assertRaises(R.OcrRuntimeError):
                R.install(url="http://x/ocr.zip", sha256=_sha(payload), version="v1")
        self.assertTrue(marker.is_file(), "旧的可用目录必须被换回来")
        st = R.status()
        self.assertEqual((st["state"], st["version"]), (R.STATE_ENABLED, "v1"))
        self.assertFalse((self.tmp / "ocr-runtime" / "v1.previous").exists())

    def test_manifest_missing_refuses(self):
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install()
        self.assertEqual(ctx.exception.reason, "manifest_missing")

    def test_manifest_install_and_version_reporting(self):
        payload = _pkg_zip()
        manifest = {"version": "v2", "url": "http://x/ocr-2.zip", "sha256": _sha(payload)}
        self._patch_download(payload, manifest=manifest)
        os.environ[R.MANIFEST_ENV] = "http://x/manifest.json"
        self._patch_selftest(True)
        st = R.install()
        self.assertEqual((st["state"], st["version"]), (R.STATE_ENABLED, "v2"))
        self.assertFalse(R.check_update()["newer"], "同版本不该报可升级")


class DownloadTests(unittest.TestCase):
    """`_download` 自身：协议白名单、分块上限、错误映射、进度回调。"""

    def _resp(self, body, length=None):
        class Resp(io.BytesIO):
            def __init__(self, data, headers):
                super().__init__(data)
                self.headers = headers

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        headers = {} if length is None else {"Content-Length": str(length)}
        return Resp(body, headers)

    def test_file_scheme_is_refused(self):
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R._download("file:///etc/passwd")
        self.assertEqual(ctx.exception.reason, "download_failed")

    def test_network_error_maps_to_download_failed(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(R.OcrRuntimeError) as ctx:
                R._download("https://example.invalid/x.zip")
        self.assertEqual(ctx.exception.reason, "download_failed")

    def test_declared_length_over_limit_stops_before_reading(self):
        resp = self._resp(b"", length=R.MAX_PACKAGE_BYTES + 1)
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(R.OcrRuntimeError) as ctx:
                R._download("https://x/y.zip")
        self.assertEqual(ctx.exception.reason, "package_too_large")

    def test_body_over_limit_without_length_header(self):
        with mock.patch.object(R, "MAX_PACKAGE_BYTES", 1000), \
                mock.patch.object(R, "DOWNLOAD_CHUNK", 300), \
                mock.patch("urllib.request.urlopen", return_value=self._resp(b"x" * 5000)):
            with self.assertRaises(R.OcrRuntimeError) as ctx:
                R._download("https://x/y.zip")
        self.assertEqual(ctx.exception.reason, "package_too_large")

    def test_progress_callback_reports_bytes(self):
        seen = []
        with mock.patch.object(R, "DOWNLOAD_CHUNK", 100), \
                mock.patch("urllib.request.urlopen", return_value=self._resp(b"y" * 250, 250)):
            data = R._download("https://x/y.zip", on_progress=lambda n, t: seen.append((n, t)))
        self.assertEqual(len(data), 250)
        self.assertEqual(seen, [(100, 250), (200, 250), (250, 250)])


class BackgroundInstallTests(_Base):
    def test_background_install_reports_progress_then_enables(self):
        payload = _pkg_zip()
        gate = threading.Event()
        self._patch_download(payload, progress_steps=[(10, 100), (100, 100)], gate=gate)
        self._patch_selftest(True)
        started, st = R.start_install(url="http://x/a.zip", sha256=_sha(payload), version="v1")
        self.assertTrue(started)
        self.assertEqual(st["state"], R.STATE_INSTALLING)
        self.assertTrue(st["progress"]["active"])
        gate.set()
        self.assertTrue(R.wait_install(timeout=10))
        st = R.status()
        self.assertEqual(st["state"], R.STATE_ENABLED)
        self.assertFalse(st["progress"]["active"])
        self.assertEqual(st["progress"]["bytes"], 100)
        self.assertEqual(st["last_error"]["reason"], "")

    def test_second_install_while_running_is_refused(self):
        payload = _pkg_zip()
        gate = threading.Event()
        self._patch_download(payload, gate=gate)
        self._patch_selftest(True)
        self.assertTrue(R.start_install(url="http://x/a.zip", sha256=_sha(payload),
                                        version="v1")[0])
        started, _st = R.start_install(url="http://x/a.zip", sha256=_sha(payload), version="v1")
        self.assertFalse(started, "同时只能有一个安装")
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.uninstall()
        self.assertEqual(ctx.exception.reason, "install_in_progress")
        gate.set()
        self.assertTrue(R.wait_install(timeout=10))

    def test_background_failure_is_recorded_not_raised(self):
        payload = _pkg_zip()
        self._patch_download(payload)
        self._patch_selftest(True)
        R.start_install(url="http://x/a.zip", sha256="0" * 64, version="v1")
        self.assertTrue(R.wait_install(timeout=10))
        st = R.status()
        self.assertEqual(st["state"], R.STATE_DISABLED)
        self.assertEqual(st["last_error"]["reason"], "checksum_mismatch")
        self.assertGreater(st["last_error"]["at"], 0)


class LifecycleTests(_Base):
    def _install(self, ver):
        payload = _pkg_zip()
        with mock.patch.object(R, "_download", return_value=payload), \
                mock.patch.object(R, "_selftest", return_value=(True, "")):
            return R.install(url="http://x/%s.zip" % ver, sha256=_sha(payload), version=ver)

    def test_rollback_moves_to_previous_version(self):
        self._install("v1")
        self._install("v2")
        self.assertEqual(R.status()["version"], "v2")
        self.assertEqual(R.rollback()["version"], "v1")

    def test_rollback_from_oldest_does_not_wrap_to_newest(self):
        """原实现 index-1 在最旧版本上是 -1，会'回滚'到最新版。"""
        self._install("v1")
        self._install("v2")
        R.rollback()
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.rollback()
        self.assertEqual(ctx.exception.reason, "no_previous_version")
        self.assertEqual(R.status()["version"], "v1")

    def test_uninstall_disables(self):
        self._install("v1")
        self.assertEqual(R.uninstall()["state"], R.STATE_DISABLED)

    def test_deleted_component_reports_component_missing(self):
        self._install("v1")
        shutil.rmtree(self.tmp / "ocr-runtime" / "v1", ignore_errors=True)
        st = R.status()
        self.assertEqual((st["state"], st["error"]), (R.STATE_ERROR, "component_missing"))

    def test_broken_component_reports_component_damaged(self):
        self._install("v1")
        self.engine_ok = (False, "ocr_runtime_missing")
        st = R.status()
        self.assertEqual((st["state"], st["error"]), (R.STATE_ERROR, "component_damaged"))

    def test_version_comparison_is_numeric(self):
        self.assertTrue(R._is_newer("v1.10.0", "v1.9.0"))
        self.assertFalse(R._is_newer("v1.9.0", "v1.10.0"))
        self.assertFalse(R._is_newer("v1.0.0", "v1.0.0"))
        self.assertTrue(R._is_newer("v1", ""))
        self.assertTrue(R._is_newer("abc123", "def456"), "比不出大小时提示，由用户决定")


class PlatformSelectionTests(_Base):
    """多平台清单：客户端自动挑本机的包，没有就明确报错。"""

    def test_platform_key_shape(self):
        key = R.platform_key()
        os_name, arch, py = key.split("-")
        self.assertIn(os_name, ("win", "macos", "linux"))
        self.assertTrue(arch)
        self.assertEqual(py, "py%d%d" % sys.version_info[:2], "原生扩展绑定解释器小版本")

    def test_install_picks_own_platform(self):
        mine = _pkg_zip()
        other = _pkg_zip(extra=[("site-packages/other.txt", "x")])
        manifest = {"version": "1.0.0", "packages": {
            "other-arch-py00": {"url": "http://x/other.zip", "sha256": _sha(other)},
            R.platform_key(): {"url": "http://x/mine.zip", "sha256": _sha(mine)},
        }}
        fetched = []

        def fake(url, on_progress=None):
            fetched.append(url)
            if url.endswith(".json"):
                return json.dumps(manifest).encode()
            return mine if url.endswith("mine.zip") else other
        with mock.patch.object(R, "_download", side_effect=fake):
            self._patch_selftest(True)
            os.environ[R.MANIFEST_ENV] = "http://x/latest-ocr.json"
            st = R.install()
        self.assertEqual((st["state"], st["version"]), (R.STATE_ENABLED, "1.0.0"))
        self.assertEqual(fetched, ["http://x/latest-ocr.json", "http://x/mine.zip"])

    def test_missing_platform_is_refused_not_substituted(self):
        """清单里没有本机平台：拒绝安装，绝不退而求其次下别的平台。"""
        manifest = {"version": "1.0.0", "packages": {
            "other-arch-py00": {"url": "http://x/other.zip", "sha256": "0" * 64}}}
        self._patch_download(b"", manifest=manifest)
        os.environ[R.MANIFEST_ENV] = "http://x/latest-ocr.json"
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.install()
        self.assertEqual(ctx.exception.reason, "platform_unsupported")
        self.assertEqual(R._download.call_count, 1, "只读了清单，没下任何包")
        with self.assertRaises(R.OcrRuntimeError) as ctx:
            R.check_update()
        self.assertEqual(ctx.exception.reason, "platform_unsupported")

    def test_legacy_single_package_manifest_still_works(self):
        payload = _pkg_zip()
        manifest = {"version": "v3", "url": "http://x/a.zip", "sha256": _sha(payload)}
        self._patch_download(payload, manifest=manifest)
        os.environ[R.MANIFEST_ENV] = "http://x/latest-ocr.json"
        self._patch_selftest(True)
        self.assertEqual(R.install()["version"], "v3")

    def test_check_update_reports_platform(self):
        manifest = {"version": "2.0.0", "packages": {
            R.platform_key(): {"url": "http://x/m.zip", "sha256": "a" * 64}}}
        self._patch_download(b"", manifest=manifest)
        os.environ[R.MANIFEST_ENV] = "http://x/latest-ocr.json"
        upd = R.check_update()
        self.assertEqual((upd["platform"], upd["url"], upd["newer"]),
                         (R.platform_key(), "http://x/m.zip", True))


class ManifestMergeTests(unittest.TestCase):
    """构建脚本的 --merge：各平台片段合并成一份清单。"""

    def _load(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "scripts" / "build-ocr-runtime.py"
        spec = importlib.util.spec_from_file_location("build_ocr_runtime", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _frag(self, tmp, plat, ver="1.0.0"):
        p = Path(tmp) / ("%s.json" % plat)
        p.write_text(json.dumps({"version": ver, "platform": plat, "url": "u/" + plat,
                                 "sha256": "a" * 64, "size": 1}), encoding="utf-8")
        return str(p)

    def test_merge_produces_what_client_can_select(self):
        mod = self._load()
        with tempfile.TemporaryDirectory() as tmp:
            man = mod.merge_fragments([self._frag(tmp, "win-x64-py313"),
                                       self._frag(tmp, "linux-arm64-py313")])
        self.assertEqual(sorted(man["packages"]), ["linux-arm64-py313", "win-x64-py313"])
        pkg = R._select_package(man, key="linux-arm64-py313")
        self.assertEqual((pkg["url"], pkg["version"]), ("u/linux-arm64-py313", "1.0.0"))

    def test_merge_rejects_version_mismatch_and_duplicates(self):
        mod = self._load()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                mod.merge_fragments([self._frag(tmp, "win-x64-py313"),
                                     self._frag(tmp, "linux-x64-py313", ver="1.0.1")])
            a = self._frag(tmp, "win-x64-py313")
            with self.assertRaises(SystemExit):
                mod.merge_fragments([a, a])


if __name__ == "__main__":
    unittest.main()
