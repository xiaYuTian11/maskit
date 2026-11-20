"""G731~G734：README 首屏必须能看到「下载入口」，且中英两份不得漂移。

真机背景（2026-11-20）：中文第 145 行 / 英文第 145 行才是「下载与安装」。访客打开仓库页要先
滑过架构图、4 段亮点、5 段接入代码（45 行）、6 张截图，滑 4 屏才看到 `.exe / .dmg`。

用户原话：「README 是不是太长」。重排只改章节顺序与代码块压缩，不改任何事实性表述。

## 为什么是源码断言

文档结构没有运行时载体，而它出错的形态是「访客找不到下载」或「`<details>` 未闭合把后半篇
吞进折叠区」——两种都只有打开 GitHub 页面才看得出来，但可以精确地用标题顺序与计数钉住。
理由与 `tests/test_event_flagged_explain.py` 同源。

错误码是本仓既定格式：`<MODULE>_<4位>`，仅作台账标识。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README_ZH = ROOT / "README.md"
README_EN = ROOT / "README_EN.md"

# 五种接入方式与六张截图：重排只搬位置，任何一项消失都是信息丢失。
INTEGRATION_MARKERS = (
    "Cursor",
    "Claude Code",
    "OPENAI_BASE_URL",
    "OpenAI(",
    "extension.zip",
)
SCREENSHOTS = (
    "dashboard.png",
    "clients.png",
    "logs.png",
    "words.png",
    "stats.png",
    "audit.png",
)


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def _headings(text):
    """一级标题的 (emoji 槽位, 全文)，按出现顺序。"""

    out = []
    for line in text.splitlines():
        m = re.match(r"^##\s+(\S+)\s*(.*)$", line)
        if m:
            out.append((m.group(1), line.strip()))
    return out


class G731DownloadPlacementTests(unittest.TestCase):
    """G731 / DOC_7101：下载章节紧跟「效果对比」、排在「核心亮点」之前。"""

    def test_g731_error_code_is_fixed(self):
        self.assertEqual("DOC_7101", "DOC_7101")

    def test_g731_download_follows_comparison(self):
        for path in (README_ZH, README_EN):
            slots = [slot for slot, _ in _headings(_read(path))]
            self.assertIn("🔄", slots, "%s 缺少效果对比章节（DOC_7101）" % path.name)
            self.assertIn("🚀", slots, "%s 缺少下载章节（DOC_7101）" % path.name)
            self.assertEqual(
                slots.index("🚀"),
                slots.index("🔄") + 1,
                "%s 的下载章节必须紧跟效果对比（DOC_7101）" % path.name,
            )

    def test_g731_download_precedes_highlights(self):
        for path in (README_ZH, README_EN):
            slots = [slot for slot, _ in _headings(_read(path))]
            self.assertLess(
                slots.index("🚀"),
                slots.index("✨"),
                "%s 的下载章节必须排在核心亮点之前（DOC_7101）" % path.name,
            )


class G732ZhEnParityTests(unittest.TestCase):
    """G732 / DOC_7102：中英两份的一级标题槽位必须逐一相等。"""

    def test_g732_error_code_is_fixed(self):
        self.assertEqual("DOC_7102", "DOC_7102")

    def test_g732_heading_slots_match(self):
        zh = [slot for slot, _ in _headings(_read(README_ZH))]
        en = [slot for slot, _ in _headings(_read(README_EN))]
        self.assertEqual(zh, en, "中英两份的章节顺序已经漂移（DOC_7102）")


class G733NothingLostTests(unittest.TestCase):
    """G733 / DOC_7103：接入方式与截图引用一项都不能少。"""

    def test_g733_error_code_is_fixed(self):
        self.assertEqual("DOC_7103", "DOC_7103")

    def test_g733_integration_paths_survive(self):
        for path in (README_ZH, README_EN):
            text = _read(path)
            missing = [m for m in INTEGRATION_MARKERS if m not in text]
            self.assertEqual(missing, [], "%s 丢失接入方式：%s（DOC_7103）" % (path.name, missing))

    def test_g733_all_screenshots_referenced(self):
        for path in (README_ZH, README_EN):
            text = _read(path)
            missing = [name for name in SCREENSHOTS if name not in text]
            self.assertEqual(missing, [], "%s 丢失截图引用：%s（DOC_7103）" % (path.name, missing))
            for name in SCREENSHOTS:
                self.assertTrue(
                    (ROOT / "docs" / "screenshots" / name).exists(),
                    "截图文件不存在：docs/screenshots/%s（DOC_7103）" % name,
                )


class G734DetailsBalancedTests(unittest.TestCase):
    """G734 / DOC_7104：`<details>` 必须配平，否则后半篇被吞进折叠区。"""

    def test_g734_error_code_is_fixed(self):
        self.assertEqual("DOC_7104", "DOC_7104")

    def test_g734_details_tags_are_balanced(self):
        for path in (README_ZH, README_EN):
            text = _read(path)
            opened = text.count("<details>")
            closed = text.count("</details>")
            self.assertEqual(
                opened,
                closed,
                "%s 的 <details> 未配平：%d 开 / %d 闭（DOC_7104）" % (path.name, opened, closed),
            )
            self.assertGreater(opened, 0, "%s 应当至少保留一个折叠块（DOC_7104）" % path.name)


if __name__ == "__main__":
    unittest.main()