"""OCR 组件原因码三方一致：ocr_runtime（后端抛出）↔ ocr.ts（前端已知列表）↔ i18n（双语文案）。

漂移的后果是静默的：后端新增一个原因码，前端不认识就把裸码（`package_layout_invalid`）
直接显示给用户；i18n 缺一侧则英文界面出现中文或空白。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _backend_codes():
    src = (ROOT / "engine" / "ocr_runtime.py").read_text(encoding="utf-8")
    codes = set(re.findall(r'OcrRuntimeError\(\s*"([a-z_]+)"', src))
    codes |= set(re.findall(r'_record_error\(\s*"([a-z_]+)"', src))
    codes |= set(re.findall(r'"(component_(?:missing|damaged))"', src))
    return codes


def _frontend_codes():
    src = (ROOT / "frontend" / "src" / "api" / "ocr.ts").read_text(encoding="utf-8")
    block = re.search(r"OCR_REASON_CODES\s*=\s*\[(.*?)\]\s*as const", src, re.S)
    assert block, "ocr.ts 里找不到 OCR_REASON_CODES"
    return set(re.findall(r"'([a-z_]+)'", block.group(1)))


def _i18n_codes():
    src = (ROOT / "frontend" / "src" / "lib" / "i18n.tsx").read_text(encoding="utf-8")
    keys = re.findall(r"'settings\.extBridge\.ocrReason_([a-z_]+)'", src)
    return keys


class ReasonParityTests(unittest.TestCase):
    def test_every_backend_code_is_known_to_frontend(self):
        missing = sorted(_backend_codes() - _frontend_codes())
        self.assertEqual(missing, [], "后端会抛、前端 OCR_REASON_CODES 没登记")

    def test_every_frontend_code_has_both_languages(self):
        keys = _i18n_codes()
        for code in sorted(_frontend_codes()):
            with self.subTest(code=code):
                self.assertEqual(keys.count(code), 2, "中英各一条")

    def test_every_backend_code_has_panel_hint(self):
        import sys
        sys.path.insert(0, str(ROOT / "engine"))
        import panel
        missing = sorted(c for c in _backend_codes()
                         if c not in panel._VISUAL_BLOCK_HINTS and c != "install_failed")
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
