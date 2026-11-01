"""难识别场景的召回率（小字 / 低对比度 / 轻度旋转 / 深色模式 / 混排 / 密集表格）。

漏检 = 漏遮，所以这里断言的是"敏感串被读出来"，不是整体 CER。

**手写体不在这里**：用印刷字体模拟不了手写，测了也是自欺。真实手写体的召回
无法用合成图保证，因此在 SECURITY.md 列为"不覆盖"。
"""
import io
import random
import sys
import unittest
from pathlib import Path

from PIL import Image, ImageDraw

_ENGINE = Path(__file__).parent.parent / 'engine'
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))
sys.path.insert(0, str(Path(__file__).parent))

import _fonts  # noqa: E402
import ocr_engine as E  # noqa: E402

PHONE = '1' + '3800138000'
PHONE2 = '1' + '3900139000'
IDNO = '1101011990' + '03074514'


def _png(im):
    buf = io.BytesIO()
    im.save(buf, 'PNG')
    return buf.getvalue()


def _detected(image_bytes):
    return ' '.join(b.text for b in E.detect(image_bytes).blocks)


@unittest.skipUnless(E.available()[0] and _fonts.HAS_CJK_FONT, _fonts.SKIP_REASON)
class HardCaseRecallTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        E.warmup()

    def _line(self, text, size=28, fg='black', bg='white', rotate=0, wh=(800, 200)):
        im = Image.new('RGB', wh, bg)
        ImageDraw.Draw(im).text((20, wh[1] // 2 - size), text, fill=fg, font=_fonts.font(size))
        if rotate:
            im = im.rotate(rotate, fillcolor=bg, expand=True)
        return _png(im)

    def test_small_font_12px(self):
        self.assertIn(PHONE, _detected(self._line('客户：李四 ' + PHONE, size=12, wh=(400, 150))))

    def test_low_contrast_gray_text(self):
        self.assertIn(PHONE, _detected(self._line('手机' + PHONE, fg=(160, 160, 160))))

    def test_rotated_5_degrees(self):
        self.assertIn(PHONE, _detected(self._line('手机' + PHONE, rotate=5)))

    def test_rotated_90_and_270_degrees_still_read(self):
        """侧向拍照的多行页面。只断言"敏感串被读出"；走不走方向兜底是实现细节
        （单行窄长文本在 0° 就能被读对，实测如此）。"""
        im = Image.new('RGB', (900, 300), 'white')
        d = ImageDraw.Draw(im)
        for i, line in enumerate(['客户资料登记表', '手机 ' + PHONE, '身份证 ' + IDNO]):
            d.text((20, 20 + i * 90), line, fill='black', font=_fonts.font(30))
        for rot in (90, 270):
            with self.subTest(rot=rot):
                text = E.detect(_png(im.rotate(rot, fillcolor='white', expand=True))).text
                self.assertIn(PHONE, text)
                self.assertIn(IDNO, text)

    def test_dark_mode_white_text_on_black(self):
        self.assertIn(PHONE, _detected(self._line('手机' + PHONE, fg='white', bg='black')))

    def test_mixed_cjk_ascii_numbers(self):
        text = _detected(self._line('订单号 Order-20240315-001 金额 1234.56'))
        self.assertIn('20240315', text)
        self.assertIn('1234.56', text)

    def test_dense_table_layout(self):
        im = Image.new('RGB', (800, 400), 'white')
        d = ImageDraw.Draw(im)
        for i, line in enumerate(['姓名    手机', '张三    ' + PHONE, '李四    ' + PHONE2]):
            d.text((20, 50 + i * 60), line, fill='black', font=_fonts.font(24))
        text = _detected(_png(im))
        self.assertIn(PHONE, text)
        self.assertIn(PHONE2, text)


@unittest.skipUnless(E.available()[0], '需要本机 OCR 运行时')
class EdgeInputTests(unittest.TestCase):

    def test_blank_image_yields_no_blocks(self):
        self.assertEqual(len(E.detect(_png(Image.new('RGB', (100, 100), 'white'))).blocks), 0)

    def test_pure_noise_does_not_crash(self):
        rnd = random.Random(7)
        im = Image.new('RGB', (200, 200))
        im.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
                    for _ in range(200 * 200)])
        self.assertIsInstance(E.detect(_png(im)).blocks, tuple)

    def test_gradient_does_not_crash(self):
        im = Image.linear_gradient('L').resize((512, 256)).convert('RGB')
        self.assertIsInstance(E.detect(_png(im)).blocks, tuple)

    def test_grayscale_and_rgba_inputs(self):
        for mode, color in (('L', 255), ('RGBA', (255, 255, 255, 0)), ('P', 0)):
            im = Image.new(mode, (300, 100), color)
            self.assertIsInstance(E.detect(_png(im)).blocks, tuple, mode)


if __name__ == '__main__':
    unittest.main()
