"""`scripts/generate-latest-json.py` 的 `_release_notes` 回归测试。

latest.json 的 `notes` 是**客户端更新弹窗**里唯一会显示给用户的文字。它此前被
写死成「Data Maskit vX.Y.Z 发布更新。」—— 用户点更新时看不到任何实际变更内容，
而 CHANGELOG 里明明写着中英双语的完整条目。现在改为从 CHANGELOG 的对应版本章节
统计「新增 / 修复 / 优化」条数，生成简短的双语摘要。

锁的是：

1. 有对应章节时给出双语摘要，且**条目计数与章节实际内容一致**（多算/少算都会
   让用户看到与实际不符的数字）；
2. 找不到该版本 / 章节里没有任何条目 / CHANGELOG 文件不存在，都必须**回退到
   通用文案** —— 说明文案不完整可以接受，但绝不能因此让发版流程失败，更不能产出
   空字符串（弹窗会是空白）；
3. 中英分节标题都要认：CHANGELOG 用的是「### 新增 / Added」这种写法，只匹配
   中文会漏掉英文标题的章节；
4. 只截取**本版本**章节，不能越过下一个 `## [` 标题把别的版本的条目算进来。
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 文件名带连字符，不能当模块 import，只能按路径加载
_spec = importlib.util.spec_from_file_location(
    "generate_latest_json", ROOT / "scripts" / "generate-latest-json.py"
)
glj = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(glj)


SAMPLE = """# Changelog

## [1.2.0] - 2026-01-02

### 新增 / Added
- 甲
  *A*
- 乙
  *B*
- 丙
  *C*

### 修复 / Bug Fixes
- 丁
  *D*
- 戊
  *E*

## [1.1.0] - 2026-01-01

### 新增 / Added
- 不属于 1.2.0 的条目
  *not part of 1.2.0*
"""


class ReleaseNotesTest(unittest.TestCase):
    def _write(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        return Path(tmp.name)

    def test_counts_and_bilingual(self):
        """有对应章节：计数准确且中英并存。"""
        p = self._write(SAMPLE)
        notes = glj._release_notes("v1.2.0", p)
        self.assertIn("新增 3 项", notes)
        self.assertIn("修复 2 项", notes)
        # 英文摘要同源同数
        self.assertIn("3 added", notes)
        self.assertIn("2 fixed", notes)
        # 不能把 1.1.0 的那条算进来（否则新增会变成 4）
        self.assertNotIn("4 added", notes)
        self.assertNotIn("新增 4 项", notes)
        self.assertNotIn("不属于 1.2.0", notes)

    def test_missing_version_falls_back(self):
        """章节不存在 → 通用文案，不抛异常。"""
        p = self._write(SAMPLE)
        notes = glj._release_notes("v9.9.9", p)
        self.assertEqual(notes, "Data Maskit v9.9.9 发布更新。")

    def test_missing_file_falls_back(self):
        """CHANGELOG 不存在 → 通用文案（发版不能因文档缺失而失败）。"""
        notes = glj._release_notes("v1.0.0", Path("__definitely_not_here__.md"))
        self.assertEqual(notes, "Data Maskit v1.0.0 发布更新。")

    def test_empty_section_falls_back(self):
        """章节存在但没有任何条目 → 回退，不能返回空串或只有标点的串。"""
        p = self._write("## [2.0.0] - 2026-01-03\n\n### 新增 / Added\n\n")
        notes = glj._release_notes("v2.0.0", p)
        self.assertEqual(notes, "Data Maskit v2.0.0 发布更新。")

    def test_english_only_heading(self):
        """只有英文分节标题的章节也要认。"""
        p = self._write("## [3.0.0] - 2026-01-04\n\n### Added\n- x\n  *X*\n")
        notes = glj._release_notes("v3.0.0", p)
        self.assertIn("新增 1 项", notes)

    def test_notes_are_multiline(self):
        """notes 必须是中文一行、英文一行的短文（弹窗放不下长文）。"""
        p = self._write(SAMPLE)
        notes = glj._release_notes("v1.2.0", p)
        lines = [x for x in notes.splitlines() if x.strip()]
        self.assertEqual(len(lines), 2, f"应为两行（中/英），实际：{lines}")


class PickSignableTests(unittest.TestCase):
    """`_pick_sig` 必须挑到**本次发布**的产物，而不是目录里最老的那个。

    2026-11-04 实测事故：本地 `build.ps1` 的产物目录累积了历史版本，
    `glob()` 顺序由文件系统决定，直接取 `[0]` 会挑到 `Maskit_0.1.0_*.sig`，
    于是 `latest.json` 把 `v0.15.0` 的下载地址指到 0.1.0 的包上——客户端点更新
    会拉到一个两年前的安装包。CI 的 `release-assets/` 只有本次产物，抓不到这个
    问题，所以只能靠这里的用例守。
    """

    def _sigs(self, *names):
        return [Path("/tmp/nsis") / n for n in names]

    def test_prefers_tag_match_over_filesystem_order(self):
        sigs = self._sigs(
            "Maskit_0.1.0_x64-setup.exe.sig",
            "Maskit_0.15.0_x64-setup.exe.sig",
            "Maskit_0.9.0_x64-setup.exe.sig",
        )
        self.assertEqual(glj._pick_sig(sigs, "v0.15.0").name,
                         "Maskit_0.15.0_x64-setup.exe.sig")

    def test_falls_back_to_highest_version(self):
        """目录里没有本版本（例如用旧目录试跑）时取版本号最大的，不取枚举首个。"""
        sigs = self._sigs(
            "Maskit_0.1.0_x64-setup.exe.sig",
            "Maskit_0.9.0_x64-setup.exe.sig",
            "Maskit_0.10.0_x64-setup.exe.sig",
        )
        self.assertEqual(glj._pick_sig(sigs, "v9.9.9").name,
                         "Maskit_0.10.0_x64-setup.exe.sig")

    def test_prerelease_suffix_is_kept_verbatim(self):
        sigs = self._sigs(
            "Maskit_0.5.0_x64-setup.exe.sig",
            "Maskit_0.5.0-beta.1_x64-setup.exe.sig",
        )
        self.assertEqual(glj._pick_sig(sigs, "v0.5.0-beta.1").name,
                         "Maskit_0.5.0-beta.1_x64-setup.exe.sig")

    def test_empty_input_returns_none(self):
        self.assertIsNone(glj._pick_sig([], "v1.0.0"))


if __name__ == "__main__":
    unittest.main()
