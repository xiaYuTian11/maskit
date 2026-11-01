"""OCR 组件损坏/缺失时的降级行为（P0.4）。

契约：组件出任何问题，只阻断当前这张图（带原因码），绝不以裸异常漏给上层，
也不影响引擎其它功能。上层只认 `OcrError` / `_Blocked`，裸异常会让原因码丢失、
事件归因变成"未知错误"。
"""
import builtins
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

_ENGINE = Path(__file__).parent.parent / 'engine'
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

from PIL import Image  # noqa: E402

import ocr_engine as E  # noqa: E402
import visual_redactor as vr  # noqa: E402


def _png(w=200, h=80):
    buf = io.BytesIO()
    Image.new('RGB', (w, h), 'white').save(buf, 'PNG')
    return buf.getvalue()


class _CrashingEngine:
    def __call__(self, *_a, **_k):
        raise RuntimeError('simulated onnxruntime crash')


class DegradationTests(unittest.TestCase):

    def setUp(self):
        self._saved_engine = E._ENGINE

    def tearDown(self):
        E._ENGINE = self._saved_engine
        E._WARMED[0] = False

    def test_missing_package_reports_runtime_missing(self):
        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name.startswith('rapidocr_onnxruntime'):
                raise ImportError('simulated missing dll')
            return real_import(name, *a, **k)

        E._ENGINE = None
        with mock.patch('builtins.__import__', fake_import):
            ok, why = E.available()
            self.assertFalse(ok)
            self.assertEqual(why, E.REASON_RUNTIME_MISSING)
            with self.assertRaises(E.OcrError) as ctx:
                E.detect(_png())
            self.assertEqual(ctx.exception.reason, E.REASON_RUNTIME_MISSING)

    def test_corrupt_model_constructor_reports_runtime_missing(self):
        import rapidocr_onnxruntime as R
        E._ENGINE = None
        with mock.patch.object(R, 'RapidOCR', side_effect=RuntimeError('model corrupt')):
            ok, why = E.available()
        self.assertFalse(ok)
        self.assertEqual(why, E.REASON_RUNTIME_MISSING)

    def test_inference_crash_becomes_reason_code(self):
        E._ENGINE = _CrashingEngine()
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(_png())
        self.assertEqual(ctx.exception.reason, E.REASON_ENGINE_ERROR)

    def test_inference_crash_releases_worker_slot(self):
        """崩溃后信号量必须归还，否则 WORKERS 次崩溃后引擎永久 busy。"""
        E._ENGINE = _CrashingEngine()
        for _ in range(E.WORKERS + 2):
            with self.assertRaises(E.OcrError) as ctx:
                E.detect(_png())
            self.assertEqual(ctx.exception.reason, E.REASON_ENGINE_ERROR)

    def test_inference_crash_blocks_image_not_raises(self):
        """走到产品入口：崩溃 = 这张图 BLOCKED，带原因码。"""
        import transparent as tr
        E._ENGINE = _CrashingEngine()
        with mock.patch.object(vr, 'engine_pref', return_value='local'):
            out = vr.process_image_multimodal(_png(), 'ext:degrade', tr)
        self.assertEqual(out['mode'], vr.MODE_BLOCKED)
        self.assertEqual(out['reason'], vr.BLOCK_ENGINE_ERROR)
        self.assertEqual(out['bytes'], b'')

    def test_engine_recovers_after_crash(self):
        E._ENGINE = _CrashingEngine()
        with self.assertRaises(E.OcrError):
            E.detect(_png())
        E._ENGINE = self._saved_engine
        if E._ENGINE is None:
            E.available()
        res = E.detect(_png())
        self.assertIsInstance(res, E.DetectResult)

    def test_oversize_blocked_by_redactor_decode_as_well(self):
        """HTTP 后端也会走 visual_redactor 的解码；像素闸不能只在 ocr_engine 一处。"""
        img, why = vr._load_image(_png(6000, 3000))
        self.assertIsNone(img)
        self.assertEqual(why, vr.BLOCK_TOO_LARGE)

    def test_every_reason_code_has_a_user_hint(self):
        import panel
        reasons = {E.REASON_RUNTIME_MISSING, E.REASON_DECODE, E.REASON_TIMEOUT,
                   E.REASON_BUSY, E.REASON_TOO_LARGE, E.REASON_ENGINE_ERROR}
        missing = sorted(r for r in reasons if r not in panel._VISUAL_BLOCK_HINTS)
        self.assertEqual(missing, [], '这些原因码没有用户可读提示')


if __name__ == '__main__':
    unittest.main()
