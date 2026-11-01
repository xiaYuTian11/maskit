"""
高并发稳定性测试（P0.2）

验收标准（2026-12 修订：ocr_busy 是设计内背压，不算失败）：
- 10 并发：真实失败率必须为 0（busy 允许，12 核实测 0）
- 20 并发：真实失败率必须为 0；busy 允许但应占少数
  （12 核实测 0~20%：队尾等待 ≈ (20/4-1)×单次耗时 ≈ 10s，恰在 QUEUE_WAIT_S 边界，
  所以 busy 率随机器负载抖动；断言只设 50% 护栏，不锁具体比例）
- 弱机器（WORKERS=1~2）busy 率会显著升高，属预期背压行为，不在本测试断言范围
"""
import io
import sys
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageDraw

_ENGINE = Path(__file__).parent.parent / 'engine'
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

import ocr_engine as E

sys.path.insert(0, str(Path(__file__).parent))
import _fonts  # noqa: E402


@unittest.skipUnless(E.available()[0] and _fonts.HAS_CJK_FONT,
                     "需要本机 OCR 运行时与 CJK 字体")
class ConcurrencyStressTests(unittest.TestCase):
    """高并发稳定性测试"""

    @classmethod
    def setUpClass(cls):
        E.warmup()
        # 生成测试图（复用避免重复渲染）
        im = Image.new('RGB', (800, 400), 'white')
        d = ImageDraw.Draw(im)
        font = _fonts.font(28)
        for i, line in enumerate(['客户通讯录', '手机：1' + '3800138000',
                                  '身份证：1101011990' + '03074514']):
            d.text((20, 60 + i * 60), line, fill='black', font=font)
        buf = io.BytesIO()
        im.save(buf, 'PNG')
        cls.test_image = buf.getvalue()

    def _worker(self, _):
        """单个并发任务"""
        try:
            result = E.detect(self.test_image)
            return {'success': True, 'blocks': len(result.blocks), 'busy': False}
        except E.OcrError as e:
            # ocr_busy 是排队上限的设计内背压（保护同进程的面板/代理链路 CPU），
            # 不是正确性失败；其余异常才是真失败。
            return {'success': False, 'error': str(e),
                    'busy': getattr(e, 'reason', '') == E.REASON_BUSY}
        except Exception as e:
            return {'success': False, 'error': str(e), 'busy': False}

    def _assert_no_real_failures(self, label, results, busy_bound=None):
        """不变量：并发下唯一被允许的非成功形态是 ocr_busy。"""
        real = [r for r in results if not r['success'] and not r['busy']]
        self.assertFalse(
            real,
            '%s 出现 %d 例真实失败（非 ocr_busy）：%s'
            % (label, len(real), [r.get('error') for r in real[:3]]))
        busy = sum(1 for r in results if r['busy'])
        print('PASS [%s] %d 任务无真实失败；ocr_busy %d 例（设计内背压，不计数）'
              % (label, len(results), busy))
        if busy_bound is not None:
            # 上界只是护栏：捕捉「引擎恒 busy」级别的回归，不锁具体背压率
            self.assertLess(busy / len(results), busy_bound,
                            '%s busy 率 %.0f%% 异常偏高，疑似引擎退化'
                            % (label, 100 * busy / len(results)))

    def test_10_concurrent_requests(self):
        """10 并发：真实失败必须为 0"""
        with ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(self._worker, range(20)))
        self._assert_no_real_failures('10 并发', results, busy_bound=0.25)

    def test_20_concurrent_requests(self):
        """20 并发：真实失败必须为 0；busy 占少数"""
        with ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(self._worker, range(40)))
        self._assert_no_real_failures('20 并发', results, busy_bound=0.5)

    def test_back_to_back_calls_are_deterministic(self):
        """连续调用结果一致（无竞态）"""
        results = [E.detect(self.test_image) for _ in range(3)]
        
        texts = [tuple(sorted(b.text for b in r.blocks)) for r in results]
        self.assertEqual(texts[0], texts[1])
        self.assertEqual(texts[1], texts[2])


if __name__ == '__main__':
    unittest.main()
