"""发布元数据脚本回归测试（`scripts/generate-latest-json.py`）。

这个脚本**只在签名发布那一刻**被 GitHub Actions 的 `release-draft` job 调用，
本地门禁完全覆盖不到它 —— 而 0.2.7 之前它是**真的坏的**：`c944e5e`（macOS DMG
支持）把 `repo` 与 `tag` 的赋值挪到了拼接下载 URL **之后**，只要存在 `.sig`
（即签名发布）就 `UnboundLocalError: cannot access local variable 'repo'` 直接崩，
而且没有任何门禁会报出来。

注意别把影响夸大：那笔回归发生在 v0.2.6 **之后**，v0.2.6 的 `latest.json` 是
正常生成的（线上可下载、签名正确）；只是 v0.2.7 正好落在这个窗口里，所以必须修。

所以这里锁的是三件事：
1. 有签名文件时必须能跑通（就是上面那个崩溃的回归）；
2. URL / 平台键 / 签名内容必须正确，且**能在嵌套目录里找到 `.sig`**
   （release job 用 `merge-multiple: false` 下载，文件落在 `release-assets/maskit-*/` 下）；
3. macOS 必须优先取 `*.app.tar.gz.sig` —— Tauri updater 要的是 `.app.tar.gz`，
   不是 `.dmg`，取错了自动更新会 404。
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

# 文件名带连字符，不能当模块 import，只能按路径加载
_spec = importlib.util.spec_from_file_location(
    "generate_latest_json", ROOT / "scripts" / "generate-latest-json.py"
)
glj = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(glj)


class GenerateLatestJsonTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _sig(self, rel, content="FAKE-SIG"):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def _run(self, argv, env=None):
        # GITHUB_* 必须显式清空：CI 里它们是真值，不清会污染用例
        base = {"GITHUB_REF_NAME": "", "GITHUB_REPOSITORY": ""}
        base.update(env or {})
        # 脚本自己会 print 生成结果，重定向掉，免得把 unittest 的输出刷乱
        with mock.patch.dict(os.environ, base), \
                mock.patch.object(sys, "argv", ["generate-latest-json.py"] + argv), \
                contextlib.redirect_stdout(io.StringIO()):
            return glj.main()

    def _latest(self):
        return json.loads((self.dir / "latest.json").read_text(encoding="utf-8"))

    # ---------- 1. 崩溃回归 ----------

    def test_signed_artifacts_do_not_crash(self):
        """有 .sig 时必须跑通 —— 0.2.7 前这里抛 UnboundLocalError。"""
        self._sig("Maskit_0.2.7_x64-setup.exe.sig", "WIN-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7"]), 0)
        self.assertTrue((self.dir / "latest.json").exists())

    # ---------- 2. 内容正确性 ----------

    def test_both_platforms_get_correct_urls_and_signatures(self):
        self._sig("Maskit_0.2.7_x64-setup.exe.sig", "WIN-SIG")
        self._sig("Maskit_0.2.7_aarch64.app.tar.gz.sig", "MAC-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7", "--repo", "o/r"]), 0)

        data = self._latest()
        self.assertEqual(data["version"], "v0.2.7")
        self.assertEqual(set(data["platforms"]), {"windows-x86_64", "darwin-aarch64"})
        self.assertEqual(data["platforms"]["windows-x86_64"], {
            "signature": "WIN-SIG",
            "url": "https://github.com/o/r/releases/download/v0.2.7/Maskit_0.2.7_x64-setup.exe",
        })
        self.assertEqual(data["platforms"]["darwin-aarch64"], {
            "signature": "MAC-SIG",
            "url": "https://github.com/o/r/releases/download/v0.2.7/Maskit_0.2.7_aarch64.app.tar.gz",
        })
        # pub_date 必须是 tauri updater 认的 RFC3339 UTC 形态
        self.assertRegex(data["pub_date"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_macos_prefers_app_tar_gz_over_dmg(self):
        """updater 要 .app.tar.gz；取成 .dmg 会让自动更新 404。"""
        self._sig("Maskit_0.2.7_aarch64.dmg.sig", "DMG-SIG")
        self._sig("Maskit_0.2.7_aarch64.app.tar.gz.sig", "UPDATER-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7"]), 0)

        mac = self._latest()["platforms"]["darwin-aarch64"]
        self.assertEqual(mac["signature"], "UPDATER-SIG")
        self.assertTrue(mac["url"].endswith("Maskit_0.2.7_aarch64.app.tar.gz"), mac["url"])

    def test_finds_signatures_in_nested_artifact_dirs(self):
        """release job 用 merge-multiple:false 下载，文件落在 maskit-*/ 子目录里。"""
        self._sig("maskit-windows-x64-signed/Maskit_0.2.7_x64-setup.exe.sig", "WIN-SIG")
        self._sig("maskit-macos-arm64-signed/Maskit_0.2.7_aarch64.app.tar.gz.sig", "MAC-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7"]), 0)
        self.assertEqual(set(self._latest()["platforms"]), {"windows-x86_64", "darwin-aarch64"})

    def test_only_windows_is_a_valid_signed_release(self):
        """只有 Windows 签名时也要能出 latest.json（macOS 缺失不该让整体失败）。"""
        self._sig("Maskit_0.2.7_x64-setup.exe.sig", "WIN-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7"]), 0)
        self.assertEqual(set(self._latest()["platforms"]), {"windows-x86_64"})

    # ---------- 3. tag 解析 ----------

    def test_tag_comes_from_env_when_flag_absent(self):
        self._sig("Maskit_0.2.7_x64-setup.exe.sig")
        self.assertEqual(self._run([str(self.dir)], {"GITHUB_REF_NAME": "v0.2.7"}), 0)
        self.assertEqual(self._latest()["version"], "v0.2.7")

    def test_tag_falls_back_to_version_in_filename(self):
        self._sig("Maskit_0.2.7_x64-setup.exe.sig")
        self.assertEqual(self._run([str(self.dir)]), 0)
        self.assertEqual(self._latest()["version"], "v0.2.7")

    def test_tag_falls_back_to_latest_when_no_version_anywhere(self):
        self._sig("Maskit-setup.exe.sig")
        self.assertEqual(self._run([str(self.dir)]), 0)
        self.assertEqual(self._latest()["version"], "latest")

    # ---------- 4. 空输入与错误路径 ----------

    def test_unsigned_run_skips_without_writing_latest_json(self):
        """没有 .sig（未签名发布）时必须静默跳过，不能生成半残的 latest.json。"""
        self._sig("Maskit_0.2.7_x64-setup.exe", "NOT-A-SIG")
        self.assertEqual(self._run([str(self.dir), "--tag", "v0.2.7"]), 0)
        self.assertFalse((self.dir / "latest.json").exists())

    def test_missing_directory_returns_error(self):
        missing = self.dir / "nope"
        self.assertEqual(self._run([str(missing), "--tag", "v0.2.7"]), 1)
        self.assertFalse((missing / "latest.json").exists())


if __name__ == "__main__":
    unittest.main()
