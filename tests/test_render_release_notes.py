"""`scripts/render-release-notes.py` 回归测试。

release.yml 的 release-draft job 用这个脚本从 CHANGELOG.md 取双语章节作为
Release body，本地门禁完全覆盖不到它 —— 如果脚本坏了，线上 Release 页会出现
空白 body 或者截到下一章节，发布流程会走完但用户看不到变更说明。

所以这里锁的是：
1. 给定真实版本号能取到双语正文（中英成对，不含 `## [version]` 标题本身，
   也不会跨过下一节标题）；
2. Unreleased 章节不会被错误地当作某个版本号返回（它面向下次发版）；
3. 找不到版本 / 章节为空都要 SystemExit，不要悄悄返回空字符串（否则 GitHub
   Release body 会变成空，看起来像发版出错）。
"""
import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 文件名带连字符，不能当模块 import，只能按路径加载
_spec = importlib.util.spec_from_file_location(
    "render_release_notes", ROOT / "scripts" / "render-release-notes.py"
)
rrn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rrn)


class RenderReleaseNotesTests(unittest.TestCase):
    def test_real_changelog_0_2_7_has_bilingual_body(self):
        """取真实 CHANGELOG.md 的 0.2.7 章节：双语成对、含三类分节。"""
        body = rrn.render("0.2.7", ROOT / "CHANGELOG.md")

        self.assertNotIn("## [0.2.7]", body, "不能包含自己的标题行（body 顶部不重复）")
        self.assertNotIn("## [0.2.6]", body, "不能跨进上一节或下一节")
        self.assertIn("### 新增 / Features", body)
        self.assertIn("### 修复 / Bug Fixes", body)
        self.assertIn("### 优化 / Improvements", body)
        # 双语：每条 feature/fix 都有中文条目 + 紧随其后的英文 *...*
        self.assertRegex(body, r"\*Fix: ")
        self.assertRegex(body, r"\*Feature: ")
        # 0.2.7 摘要（双语）
        self.assertIn("macOS (Apple Silicon) 原生 DMG", body)
        self.assertIn("Harden placeholder restoration", body)

    def test_real_changelog_0_2_6_does_not_leak_0_2_7(self):
        """取 0.2.6 章节：必须停在 ## [0.2.6] 之前，不应吞进 0.2.7 内容。"""
        body = rrn.render("0.2.6", ROOT / "CHANGELOG.md")
        self.assertNotIn("Harden placeholder restoration", body)
        self.assertNotIn("## [0.2.7]", body)
        # 0.2.6 的特征：CI 单测死锁修复
        self.assertIn("socketserver", body)

    def test_unreleased_is_not_pickable_as_a_version(self):
        """Unreleased 章节面向下次发版，不能通过 'Unreleased' 当成版本号取出来。"""
        with self.assertRaises(SystemExit):
            rrn.render("Unreleased", ROOT / "CHANGELOG.md")

    def test_missing_version_raises(self):
        """找不到版本号要 SystemExit，不能返回空字符串（否则 Release body 会空白）。"""
        with self.assertRaises(SystemExit):
            rrn.render("9.9.9-not-real", ROOT / "CHANGELOG.md")

    def test_empty_section_raises(self):
        """章节存在但内容为空要 SystemExit —— 不能让 GitHub Release body 变成空白。"""
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "CHANGELOG.md"
            fake.write_text(
                "## [Unreleased]\n\n## [1.0.0] - 2099-01-01\n## [0.9.0] - 2098-01-01\n"
                "old text\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                rrn.render("1.0.0", fake)

    def test_main_prints_body_and_exits_zero(self):
        """CLI：直接调用 main(argv) 应把 body 写到 stdout 并正常返回。"""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rrn.main(["0.2.7"])
        self.assertIsNone(rc)
        self.assertIn("Harden placeholder restoration", buf.getvalue())
        self.assertTrue(buf.getvalue().endswith("\n"), "输出末尾应有换行")


if __name__ == "__main__":
    unittest.main()