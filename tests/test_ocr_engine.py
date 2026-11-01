"""本地 OCR 引擎（`engine/ocr_engine.py`）的契约锁。

这里只锁**引擎自身**的行为：真框、坐标映射、方向兜底、失败原因码、串行化。
"打码准不准"由 `tests/test_locator.py` 与 `tests/test_visual_redaction.py` 负责。

> 为什么敢直接跑真模型：本文件用**合成图**（真值已知），断言的是"框落在文字上"
> 这类结构性事实，不是"识别率 99%"。真模型在本机约 0.6~1.2s/张，可接受。
"""
import io
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fonts  # noqa: E402

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

import ocr_engine as E  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _font(size, cjk=True):
    return _fonts.font(size, cjk)


def _png(im):
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def _text_image(lines, size=40, spacing=100, pad=50, wh=(1000, 520)):
    im = Image.new("RGB", wh, (255, 255, 255))
    d = ImageDraw.Draw(im)
    f = _font(size)
    truth = []
    y = pad
    for line in lines:
        d.text((60, y), line, fill=(0, 0, 0), font=f)
        truth.append(d.textbbox((60, y), line, font=f))
        y += spacing
    return im, truth


class EngineBasicsTests(unittest.TestCase):
    def test_available(self):
        ok, why = E.available()
        self.assertTrue(ok, "OCR 运行时不可用：%s" % why)

    def test_detect_reads_text_and_boxes(self):
        im, truth = _text_image(["AAAA", "BBBB", "CCCC"])
        res = E.detect(_png(im))
        self.assertEqual(res.orientation, 0)
        texts = [b.text for b in res.blocks]
        for want in ("AAAA", "BBBB", "CCCC"):
            self.assertTrue(any(want in t for t in texts), "漏识别 %s: %s" % (want, texts))
        # 框要落在对应文字上（允许 ±12px：检测框内缩/外扩都正常）
        for want, (tx1, ty1, tx2, ty2) in zip(("AAAA", "BBBB", "CCCC"), truth):
            blk = next(b for b in res.blocks if want in b.text)
            x1, y1, x2, y2 = blk.quad
            self.assertLess(abs(y1 - ty1), 12, "%s 的框 y 偏了: %s vs %s" % (want, y1, ty1))
            self.assertLess(abs(x1 - tx1), 12, "%s 的框 x 偏了: %s vs %s" % (want, x1, tx1))
            self.assertGreater(x2 - x1, (tx2 - tx1) * 0.6, "%s 的框太窄" % want)

    def test_determinism(self):
        raw = _png(_text_image(["手机：13800138000", "姓名：张测试"], size=30, spacing=70)[0])
        a = [b.text for b in E.detect(raw).blocks]
        b = [b.text for b in E.detect(raw).blocks]
        self.assertEqual(a, b)

    def test_corrupt_bytes_raise_decode_reason(self):
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        self.assertEqual(ctx.exception.reason, E.REASON_DECODE)

    def test_empty_bytes_raise(self):
        with self.assertRaises(E.OcrError):
            E.detect(b"")

    def test_oversize_bytes_raise_too_large(self):
        big = b"0" * (E.MAX_IMAGE_BYTES + 1)
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(big)
        self.assertEqual(ctx.exception.reason, E.REASON_TOO_LARGE)

    def test_busy_when_worker_held(self):
        """串行化：worker 被占住且等不到 → `ocr_busy`（不排队到超时）。

        必须**先预热**：首次调用含模型加载（约 1s），deadline 太小会先撞 `ocr_timeout`，
        测到的就不是忙等这条路了（本用例曾因此在全量跑里假失败）。
        """
        raw = _png(_text_image(["AAAA"])[0])
        self.assertTrue(E.warmup())
        # 并发度 >1（按核数自适应），必须占满**全部** worker 才会忙等
        held = 0
        for _ in range(E.WORKERS):
            self.assertTrue(E._SEM.acquire(timeout=5))
            held += 1
        try:
            with self.assertRaises(E.OcrError) as ctx:
                E.detect(raw, deadline=time.monotonic() + 5.0)
            self.assertEqual(ctx.exception.reason, E.REASON_BUSY)
        finally:
            for _ in range(held):
                E._SEM.release()

    def test_timeout_when_deadline_passed(self):
        raw = _png(_text_image(["AAAA"])[0])
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(raw, deadline=time.monotonic() - 1)
        self.assertEqual(ctx.exception.reason, E.REASON_TIMEOUT)


class DownscaleTests(unittest.TestCase):
    def test_large_image_is_downscaled_and_boxes_map_back(self):
        """4K 级图会降采样；框必须映射回**原图**坐标，否则打码会飘。"""
        im = Image.new("RGB", (4000, 2000), (255, 255, 255))
        d = ImageDraw.Draw(im)
        f = _font(60, cjk=False)
        # 故意放在右下角：只有坐标映射正确，框才落在这里
        d.text((3000, 1600), "BOTTOM RIGHT", fill=(0, 0, 0), font=f)
        res = E.detect(_png(im))
        self.assertTrue(res.downscaled, "4K 图应该走降采样")
        blk = next((b for b in res.blocks if "BOTTOM" in b.text), None)
        self.assertIsNotNone(blk, "降采样后漏识别：%s" % [b.text for b in res.blocks])
        x1, y1, _x2, _y2 = blk.quad
        self.assertLess(abs(x1 - 3000), 60, "x 没映射回原图：%s" % x1)
        self.assertLess(abs(y1 - 1600), 60, "y 没映射回原图：%s" % y1)


class RotationTests(unittest.TestCase):
    """方向映射是纯数学，单独锁死；方向兜底的状态机用假后端锁。"""

    def test_map_back_math(self):
        w, h = 1000.0, 600.0
        # 原图坐标系里的一个框
        box = (100.0, 100.0, 300.0, 160.0)
        # θ=90 正变换：x' = y, y' = w-1-x
        def fwd90(x, y):
            return y, w - 1 - x

        rot = [(*fwd90(box[0], box[1]), *fwd90(box[2], box[3]))]
        rot = [(min(rot[0][0], rot[0][2]), min(rot[0][1], rot[0][3]),
                max(rot[0][0], rot[0][2]), max(rot[0][1], rot[0][3]))]
        back = E._map_back(rot, 90, w, h)[0]
        for got, want in zip(back, box):
            self.assertLess(abs(got - want), 2, "90° 映射不闭合：%s vs %s" % (back, box))

    def test_orientation_fallback_picks_rotated_best(self):
        """0° 结果过短 → 试 90/180/270，取文本量最大的那个方向。"""
        raw = _png(_text_image(["AAAA"])[0])
        calls = []

        def fake_run(engine, payload, deadline):
            calls.append(payload)
            if len(calls) == 1:
                return []                                    # 0° 什么都没读到
            return [((110.0, 110.0, 120.0, 120.0), "手机13800138000", 0.9)]

        real = E._run_engine
        E._run_engine = fake_run
        try:
            res = E.detect(raw)
        finally:
            E._run_engine = real
        self.assertEqual(res.orientation, 90, "应该切到 90°")
        self.assertIn("13800138000", res.text)
        self.assertEqual(len(calls), 2, "拿到合格结果就该停，不要试满四个方向")

    def test_no_fallback_when_zero_degree_is_good(self):
        raw = _png(_text_image(["AAAA", "BBBB"])[0])
        calls = []
        real = E._run_engine
        E._run_engine = lambda engine, payload, deadline: (calls.append(1) or
                                                          [((101.0, 101.0, 102.0, 102.0), "AAAA", 0.9)])
        try:
            res = E.detect(raw)
        finally:
            E._run_engine = real
        self.assertEqual(res.orientation, 0)
        self.assertEqual(len(calls), 1, "正常图不该付 4× 代价")


class DetRecallHoleTests(unittest.TestCase):
    """det 召回空洞（2026-11-01 实测）：宽高比 7~10、文字贴近上下边的单行图，
    rapidocr 默认配置返回空 → 误判「干净」。修法是关宽高比闸 + 送检前补白边。"""

    def _line(self, w, h, size, x=20):
        im = Image.new("RGB", (w, h), (255, 255, 255))
        d = ImageDraw.Draw(im)
        f = _font(size)
        text = "手机 " + "138" + "0013" + "8000"
        bb = d.textbbox((0, 0), text, font=f)
        top = (h - (bb[3] - bb[1])) // 2 - bb[1]
        d.text((x, top), text, fill=(20, 20, 20), font=f)
        return im, d.textbbox((x, top), text, font=f)

    def test_wide_single_lines_are_detected(self):
        # 修复前这些尺寸全部返回空（或只拿到碎片）
        for w, h, size in ((1100, 120, 30), (1100, 126, 30), (1100, 80, 20),
                           (500, 66, 30), (700, 39, 30), (1100, 57, 44)):
            with self.subTest(size=(w, h, size)):
                im, _ = self._line(w, h, size)
                text = E.detect(_png(im), allow_rotation=False).text.replace(" ", "")
                self.assertIn("138" + "0013" + "8000", text)

    def test_padding_offset_is_removed_from_boxes(self):
        im, (tx1, ty1, tx2, ty2) = self._line(1100, 120, 30, x=60)
        res = E.detect(_png(im), allow_rotation=False)
        blk = next(b for b in res.blocks if "0013" in b.text)
        x1, y1, x2, y2 = blk.quad
        self.assertLess(abs(x1 - tx1), 12, "白边偏移没减回去：%s vs %s" % (x1, tx1))
        self.assertLess(abs(y1 - ty1), 12, "白边偏移没减回去：%s vs %s" % (y1, ty1))
        self.assertLessEqual(x2, 1100)
        self.assertLessEqual(y2, 120)


class LowScoreTests(unittest.TestCase):
    def test_low_conf_blocks_are_reported_not_silently_used(self):
        raw = _png(_text_image(["AAAA"])[0])
        real = E._run_engine
        E._run_engine = lambda engine, payload, deadline: [((101.0, 101.0, 102.0, 102.0), "AAAA", 0.2)]
        try:
            res = E.detect(raw)
        finally:
            E._run_engine = real
        self.assertEqual(len(res.low_conf), 1, "低分块要能被数出来")

    def test_min_score_constant_is_used_by_consumers(self):
        self.assertTrue(0.0 < E.MIN_SCORE < 1.0)


class WarmupTests(unittest.TestCase):
    def test_warmup_is_idempotent(self):
        self.assertTrue(E.warmup())
        self.assertTrue(E.warmup())


class TallImageTests(unittest.TestCase):
    """长截图必须切片：整图缩放到 1600px 长边会让正文小字糊掉（漏检 = 泄露）。"""

    def _tall(self, height, rows):
        im = Image.new("RGB", (1080, height), (255, 255, 255))
        d = ImageDraw.Draw(im)
        f = _font(24)
        step = height // max(1, rows)
        for i in range(rows):
            d.text((30, 20 + i * step), "手机：138001380%02d 姓名 张测试%d" % (i, i),
                   fill=(0, 0, 0), font=f)
        return _png(im)

    def test_long_screenshot_is_tiled_and_loses_nothing(self):
        raw = self._tall(4800, 48)
        res = E.detect(raw)
        hits = sum(1 for b in res.blocks if "138" in b.text)
        self.assertEqual(hits, 48, "长图漏检：%d/48（切片没生效？）" % hits)

    def test_tile_ranges_overlap_and_cover(self):
        ranges = E._tile_ranges(5000)
        self.assertGreater(len(ranges), 1)
        self.assertEqual(ranges[0][0], 0)
        self.assertEqual(ranges[-1][1], 5000)
        for (a0, a1), (b0, _b1) in zip(ranges, ranges[1:]):
            self.assertLess(b0, a1, "相邻切片必须有重叠，否则交界行会被切断")

    def test_dedupe_keeps_one_copy_in_overlap(self):
        boxes = [((0, 100, 200, 130), "手机13800138000", 0.9),
                 ((0, 108, 200, 138), "手机13800138000", 0.8)]
        kept = E._dedupe(boxes)
        self.assertEqual(len(kept), 1, "重叠区同一行不该出现两份")
        self.assertEqual(kept[0][2], 0.9, "应保留高分那条")


class ExifTests(unittest.TestCase):
    """手机照片带 EXIF Orientation：不摆正会让框错位、输出图"躺倒"。"""

    def _oriented_jpeg(self):
        upright = Image.new("RGB", (600, 200), (255, 255, 255))
        d = ImageDraw.Draw(upright)
        d.text((40, 70), "PHONE 13800138000", fill=(0, 0, 0), font=_font(40, cjk=False))
        sideways = upright.rotate(90, expand=True)
        exif = Image.Exif()
        exif[274] = 6          # Orientation=6：查看器顺时针转 90° 显示
        buf = io.BytesIO()
        sideways.save(buf, "JPEG", exif=exif.tobytes())
        return buf.getvalue()

    def test_detect_uses_display_orientation(self):
        res = E.detect(self._oriented_jpeg())
        self.assertTrue(res.blocks, "摆正后应该能读到文字")
        blk = res.blocks[0]
        w = blk.quad[2] - blk.quad[0]
        h = blk.quad[3] - blk.quad[1]
        self.assertGreater(w, h * 2, "框应该是横排（宽 >> 高），说明已按 EXIF 摆正")


class FormatMatrixTests(unittest.TestCase):
    """非常规像素模式都要能识别（打码不能因为格式直接失败）。"""

    def _img(self):
        im = Image.new("RGB", (400, 120), (255, 255, 255))
        d = ImageDraw.Draw(im)
        d.text((20, 40), "13800138000", fill=(0, 0, 0), font=_font(40, cjk=False))
        return im

    def test_common_modes(self):
        cases = (("RGBA", "PNG"), ("P", "PNG"), ("L", "PNG"), ("CMYK", "JPEG"))
        for mode, fmt in cases:
            im = self._img()
            conv = im.convert(mode) if mode != "P" else im.convert("P", palette=Image.ADAPTIVE)
            buf = io.BytesIO()
            conv.save(buf, fmt)
            res = E.detect(buf.getvalue())
            self.assertTrue(any("13800138000" in b.text for b in res.blocks),
                            "%s/%s 没识别出来：%s" % (mode, fmt, [b.text for b in res.blocks]))


if __name__ == "__main__":
    unittest.main()
