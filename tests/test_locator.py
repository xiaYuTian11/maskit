"""实体定位（`engine/locator.py`）的契约锁。

核心不变量只有一条：**最终画出来的矩形必须完整盖住敏感字符的字形**。
偏宽（多遮半个字）可以接受；偏窄（露出半个数字）绝对不行——所以这里的断言都是
"覆盖"而不是"近似"。
"""
import io
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fonts  # noqa: E402

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

import locator as L  # noqa: E402
import ocr_engine as E  # noqa: E402

PHONE = re.compile(r"1[3-9]\d{9}")
IDC = re.compile(r"\d{17}[\dXx]")


def _font(size, cjk=True):
    return _fonts.font(size, cjk)


def _render(lines, size=28, spacing=60, pad=40, width=1200):
    height = pad * 2 + spacing * len(lines)
    im = Image.new("RGB", (width, height), (255, 255, 255))
    d = ImageDraw.Draw(im)
    f = _font(size)
    truth = []
    y = pad
    for line in lines:
        d.text((60, y), line, fill=(0, 0, 0), font=f)
        bbox = d.textbbox((60, y), line, font=f)
        raw_hits = []
        for rx in (PHONE, IDC):
            for m in rx.finditer(line):
                raw_hits.append((m.start(), m.end(), m.group()))
        # 丢掉被更长匹配包含的片段：手机号形态会命中身份证里的 11 位子串，
        # 而真实规则引擎是按优先级/长度取最大匹配的（这里必须同口径）。
        raw_hits = [(a, b, t) for a, b, t in raw_hits
                    if not any(a2 <= a and b <= b2 and (b2 - a2) > (b - a)
                               for a2, b2, _t2 in raw_hits)]
        hits = []
        for start, end, txt in raw_hits:
            pre = d.textbbox((0, 0), line[:start], font=f)[2]
            sub = d.textbbox((0, 0), line[start:end], font=f)[2]
            hit_bbox = (bbox[0] + pre, bbox[1], bbox[0] + pre + sub, bbox[3])
            hits.append((txt, hit_bbox))
        truth.append((line, bbox, hits))
        y += spacing
    return im, truth


class SpanExtractionTests(unittest.TestCase):
    def test_single_hit(self):
        text = "手机：13800138000"

        def mask_fn(t):
            return t.replace("13800138000", "{{PHONE_abcdef}}")

        spans = L.spans_from_mask(text, mask_fn)
        self.assertEqual(len(spans), 1)
        s, e, label = spans[0]
        self.assertEqual(text[s:e], "13800138000")
        self.assertEqual(label, "PHONE")

    def test_multiple_hits_and_merge(self):
        text = "13800138000 与 110101199003074514"

        def mask_fn(t):
            return (t.replace("13800138000", "{{PHONE_abc}}")
                     .replace("110101199003074514", "{{IDCARD_def}}"))

        spans = L.spans_from_mask(text, mask_fn)
        self.assertEqual(len(spans), 2)
        self.assertEqual({lb for _s, _e, lb in spans}, {"PHONE", "IDCARD"})

    def test_no_change_no_spans(self):
        self.assertEqual(L.spans_from_mask("nothing here", lambda t: t), [])

    def test_mask_fn_raises_is_a_failure_not_a_pass(self):
        """判定抛异常必须**上抛**（`MaskFailed`）——当成"没命中"就是放行原图。"""
        def boom(_t):
            raise RuntimeError("x")

        with self.assertRaises(L.MaskFailed):
            L.spans_from_mask("13800138000", boom)

    def test_non_str_result_is_a_failure(self):
        with self.assertRaises(L.MaskFailed):
            L.spans_from_mask("13800138000", lambda _t: None)


class WidthMappingTests(unittest.TestCase):
    def test_char_x_stays_inside_line_box(self):
        quad = (100.0, 10.0, 500.0, 40.0)
        text = "手机：13800138000 姓名：张测试"
        x1, x2 = L.char_x(quad, text, 3, 14, pad_em=10.0)   # 极大的 pad
        self.assertGreaterEqual(x1, quad[0])
        self.assertLessEqual(x2, quad[2])

    def test_char_x_monotonic(self):
        quad = (0.0, 0.0, 400.0, 30.0)
        text = "abcdefghij"
        xs = [L.char_x(quad, text, i, i + 1)[0] for i in range(len(text))]
        self.assertEqual(xs, sorted(xs))


class CoverageTests(unittest.TestCase):
    """真实引擎 + 真实字体：最终框必须盖住字形。"""

    def _locate(self, lines, **kw):
        im, truth = _render(lines, **kw)
        raw = io.BytesIO()
        im.save(raw, "PNG")
        res = E.detect(raw.getvalue())
        img = Image.open(io.BytesIO(raw.getvalue())).convert("RGB")
        rects, stats = L.locate(res.blocks, lambda t: _fake_mask(t), img=img,
                                recognize=E.recognize)
        return rects, stats, truth

    def test_final_rects_cover_true_glyphs(self):
        lines = ["手机：13800138000 姓名：张测试",
                 "身份证：110101199003074514 部门：研发中心"]
        rects, stats, truth = self._locate(lines)
        self.assertGreaterEqual(stats["entities"], 2, stats)
        self.assertEqual(stats["failed"], 0, stats)
        for _line, _bbox, hits in truth:
            for needle, (tx1, ty1, tx2, ty2) in hits:
                covered = any(r.quad[0] <= tx1 + 2 and r.quad[2] >= tx2 - 2
                              and r.quad[1] <= ty1 + 4 and r.quad[3] >= ty2 - 4
                              for r in rects)
                self.assertTrue(covered, "%s 没被完整覆盖；rects=%s"
                                % (needle, [(round(r.quad[0]), round(r.quad[2])) for r in rects]))

    def test_verification_rate_is_reported(self):
        rects, stats, _truth = self._locate(["手机：13800138000"])
        self.assertEqual(stats["verified"] + stats["line_fallback"], stats["entities"])
        self.assertEqual(stats["failed"], 0)

    def test_entity_rect_is_narrower_than_line(self):
        """实体级打码的意义：框显著小于整行（否则就是把标签一起盖掉）。"""
        rects, _stats, _truth = self._locate(["手机：13800138000 姓名：张测试"])
        widths = [r.quad[2] - r.quad[0] for r in rects]
        self.assertTrue(widths)
        self.assertLess(max(widths), 260, "框太宽，疑似退回了整行：%s" % widths)


class VerticalPadTests(unittest.TestCase):
    """垂直留白（2026-10-30 实测）：实体框曾沿用 det 行框的 y1/y2，数字上弧与
    降部露出笔画残边。判据是像素：涂色后真字形框里不许有一个深色像素。"""

    def test_rect_extends_beyond_det_box(self):
        quad = (100.0, 40.0, 500.0, 80.0)
        img = Image.new("RGB", (600, 140), (255, 255, 255))
        block = E.Block(quad=quad, text="手机：13800138000", score=0.9)
        rects, stats = L.locate([block], lambda t: _fake_mask(t), img=img,
                                recognize=lambda payload, deadline=None: "13800138000")
        self.assertEqual(stats["verified"], 1, stats)
        # 固定下限（不读常量本身）：每侧至少 0.1em。合成图上 det 框本就盖住字形，
        # 像素测试在留白=0 时也会过（已实测），所以留白本身只能在这里钉住。
        self.assertLessEqual(rects[0].quad[1], 40 - 0.1 * 40)
        self.assertGreaterEqual(rects[0].quad[3], 80 + 0.1 * 40)
        self.assertGreater(rects[0].quad[1], 40 - 0.3 * 40, "留白过大会叠到相邻行")

    def test_no_dark_pixel_left_inside_true_glyphs(self):
        from visual_redactor import _paint
        for size in (20, 28, 40):
            with self.subTest(size=size):
                im, truth = _render(["手机：13800138000 姓名：张测试"], size=size,
                                    spacing=size * 2)
                raw = io.BytesIO()
                im.save(raw, "PNG")
                res = E.detect(raw.getvalue())
                rects, stats = L.locate(res.blocks, lambda t: _fake_mask(t), img=im,
                                        recognize=E.recognize)
                self.assertEqual(stats["failed"], 0, stats)
                _paint(im, [r.quad for r in rects])
                for _line, _bbox, hits in truth:
                    for needle, (tx1, ty1, tx2, ty2) in hits:
                        dark = [(x, y) for x in range(int(tx1), int(tx2))
                                for y in range(int(ty1), int(ty2))
                                if sum(im.getpixel((x, y))) < 3 * 100]
                        self.assertEqual(dark[:5], [], "%s 涂色后仍有笔画残边" % needle)


class FallbackTests(unittest.TestCase):
    def _img(self):
        im, _truth = _render(["手机：13800138000"])
        buf = io.BytesIO()
        im.save(buf, "PNG")
        return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")

    def _block(self, text="手机：13800138000 姓名：张测试", score=0.9):
        return E.Block(quad=(60.0, 40.0, 600.0, 70.0), text=text, score=score)

    def test_verify_failure_falls_back_to_line_box(self):
        """实体框复认失败、整行框复认成功 → 退到整行框（fallback="line"）。"""
        def picky(payload, deadline=None):
            # 只对"整行宽"的裁剪返回正确文本，模拟"实体框太窄、切掉了字"：
            # 实体框约 200px（只盖号码）、整行框约 560px。
            img = Image.open(io.BytesIO(payload))
            return "手机：13800138000" if img.size[0] >= 380 else ""

        rects, stats = L.locate([self._block()], lambda t: _fake_mask(t), img=self._img(),
                                recognize=picky)
        self.assertEqual(stats["entities"], 1)
        self.assertEqual(stats["line_fallback"], 1)
        self.assertEqual(stats["verified"], 0)
        self.assertEqual(rects[0].fallback, "line")
        self.assertFalse(rects[0].verified)

    def test_hard_failure_is_counted(self):
        """连整行框都复认不出来 → failed（上层据此阻断）。"""
        rects, stats = L.locate([self._block()], lambda t: _fake_mask(t), img=self._img(),
                                recognize=lambda payload, deadline=None: "")
        # 第一次（实体框）失败、第二次（整行框）也失败 → failed
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(rects[0].fallback, "failed")

    def test_low_score_blocks_are_skipped(self):
        rects, stats = L.locate([self._block(score=0.2)], lambda t: _fake_mask(t),
                                img=self._img(),
                                recognize=lambda payload, deadline=None: "13800138000")
        self.assertEqual(rects, [])
        self.assertEqual(stats["low_conf"], 1)
        self.assertEqual(stats["entities"], 0)


class MergeTests(unittest.TestCase):
    def test_adjacent_rects_merge(self):
        a = L.EntityRect((10, 10, 100, 30), (0, 5), "PHONE", True, "")
        b = L.EntityRect((101, 10, 200, 30), (5, 9), "PHONE", True, "")
        merged = L._merge([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].quad, (10, 10, 200, 30))

    def test_different_rows_not_merged(self):
        a = L.EntityRect((10, 10, 100, 30), (0, 5), "PHONE", True, "")
        b = L.EntityRect((10, 100, 100, 130), (0, 5), "PHONE", True, "")
        self.assertEqual(len(L._merge([a, b])), 2)


def _fake_mask(text):
    """只遮手机号/身份证，模拟项目规则引擎的判定。

    **顺序有意义**：先遮 18 位身份证，再遮 11 位手机号。反过来时，身份证里的
    11 位子串会先被当成手机号替换，导致后面的身份证规则再也匹配不上——
    这与真实引擎"取最长匹配"的口径必须一致。
    """
    out = IDC.sub("{{IDCARD_abcdef}}", text)
    out = PHONE.sub("{{PHONE_abcdef}}", out)
    return out


if __name__ == "__main__":
    unittest.main()
