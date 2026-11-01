"""
超大图与解压炸弹闸门测试（P0.3）

验收标准：
- 16MP 边界可通过
- >16MP 阻断，原因码 image_too_large
- 解压炸弹被拦截（PIL 内置 + 我们的双层防护）
"""
import io
import sys
import unittest
from pathlib import Path
from PIL import Image

_ENGINE = Path(__file__).parent.parent / 'engine'
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

import ocr_engine as E


@unittest.skipUnless(E.available()[0], '需要本机 OCR 运行时')
class OversizeImageTests(unittest.TestCase):
    """超大图闸门测试"""

    def test_8mp_image_passes_with_downscale(self):
        """8MP（4K）通过，但降采样"""
        im = Image.new('RGB', (3840, 2160), 'white')
        buf = io.BytesIO()
        im.save(buf, 'PNG')
        
        result = E.detect(buf.getvalue())
        self.assertTrue(result.downscaled, '8MP 应该降采样')

    def test_16mp_boundary_passes(self):
        """16MP 边界可通过"""
        im = Image.new('RGB', (4000, 4000), 'white')
        buf = io.BytesIO()
        im.save(buf, 'PNG')
        
        result = E.detect(buf.getvalue())
        self.assertIsInstance(result, E.DetectResult)

    def test_18mp_blocked_with_correct_reason(self):
        """18MP 阻断，原因码正确"""
        im = Image.new('RGB', (6000, 3000), 'white')
        buf = io.BytesIO()
        im.save(buf, 'PNG')
        
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(buf.getvalue())
        
        self.assertEqual(ctx.exception.reason, 'image_too_large')
        self.assertIn('6000', ctx.exception.detail)

    def test_decompression_bomb_blocked(self):
        """解压炸弹被拦截（PIL 内置保护 + 我们的检查）"""
        # 30000×30000 纯色 PNG 压缩后约 2.6MB，解压后 2.7GB
        im = Image.new('RGB', (30000, 30000), (128, 128, 128))
        buf = io.BytesIO()
        im.save(buf, 'PNG', compress_level=9)
        
        file_size = len(buf.getvalue()) / 1024 / 1024
        self.assertLess(file_size, 10, '压缩后应 <10MB（炸弹特征）')
        
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(buf.getvalue())
        
        self.assertEqual(ctx.exception.reason, 'image_too_large')

    def test_zero_size_image_blocked(self):
        """非法字节阻断（PIL 写不出 0x0 PNG，用截断文件头代替）"""
        with self.assertRaises(E.OcrError) as ctx:
            E.detect(b'\x89PNG\r\n\x1a\n' + b'\x00' * 16)
        self.assertEqual(ctx.exception.reason, 'image_decode_failed')


if __name__ == '__main__':
    unittest.main()
