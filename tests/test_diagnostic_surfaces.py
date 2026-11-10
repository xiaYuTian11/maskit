"""G631~G633：三处诊断面必须真的被看到。

2026-11-10 排查「长会话偶发 27.6 s」时，三个信息缺口各多花了几十分钟：
  ① 引擎算了叶子缓存的 miss 归因，面板白名单把四个键裁掉了 → 自检看不到；
  ② 普通请求的连接观测恒显示「未知 / 未观测」（该字段只在取消/异常时采集）→ 看着像故障；
  ③ 事件库 7 天 198 MB，`/api/status` 的 `db_size_mib` 前端从来没渲染 → 只能去数据目录看文件。

三条都是展示层，不产生任何拒绝；用源码断言钉住，理由与 `test_connection_config.py` 里
那批「枚举必须过翻译器」的用例同源：面板文案与投影没有运行时单测可写（前端不跑在
Python 里），而它们出错的形态就是「界面上看不见」。
"""

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
import panel

DETAIL_TSX = ROOT / "frontend" / "src" / "components" / "events" / "EventDetailDialog.tsx"
SETTINGS_TSX = ROOT / "frontend" / "src" / "pages" / "Settings.tsx"
TYPES_TS = ROOT / "frontend" / "src" / "types" / "api.ts"
I18N_TSX = ROOT / "frontend" / "src" / "lib" / "i18n.tsx"

MISS_KEYS = ("miss_token_gone", "miss_identity", "miss_gen", "miss_scope")


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def _projection():
    """面板投影函数（名字可能变，按「返回 leaf_cache」的特征找）。"""
    for name, fn in vars(panel).items():
        if not callable(fn) or not name.startswith("_"):
            continue
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            continue
        if 'lc.get("hit")' in src and 'out["leaf_cache"]' in src:
            return fn
    raise AssertionError("找不到 leaf_cache 投影函数（面板把引擎快照裁白了）")


class G631LeafCacheProjectionTests(unittest.TestCase):
    """G631 / DIAG_6301：四个 miss 归因键必须外发到自检视图。"""

    ERROR_CODE = "DIAG_6301"

    def test_g631_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "DIAG_6301")

    def test_g631_projection_keeps_miss_attribution(self):
        snap = {"leaf_cache": {
            "enabled": True, "hit": 10, "miss": 4, "hit_rate": 0.7,
            "size": 3, "chars": 100, "max": 8192, "chars_max": 1000, "poison": 0,
            "miss_token_gone": 3, "miss_identity": 1, "miss_gen": 0, "miss_scope": 0,
        }}
        out = _projection()(snap)
        lc = out.get("leaf_cache")
        self.assertIsInstance(lc, dict, "投影没有输出 leaf_cache")
        for key in MISS_KEYS:
            self.assertIn(key, lc, "自检视图看不到 %s：又得去翻 engine-runtime.json" % key)
            self.assertIsInstance(lc[key], int)

    def test_g631_non_dict_is_skipped_not_faked(self):
        out = _projection()({"leaf_cache": "oops"})
        self.assertNotIn("leaf_cache", out,
                         "非 dict 时伪造了 leaf_cache：会把「没采到」和「采到 0」混为一谈")


class G632TransportCopyTests(unittest.TestCase):
    """G632 / DIAG_6302：无观测时必须说清「仅异常采集」。"""

    ERROR_CODE = "DIAG_6302"

    def test_g632_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "DIAG_6302")

    def test_g632_title_uses_dedicated_copy(self):
        src = _read(DETAIL_TSX)
        self.assertIn("detail.transportUncollected", src,
                      "无观测的标题行没有专用文案：会退回「未知 / 未观测」，读起来像故障")
        self.assertNotIn(": t('transport.unknown')}", src,
                         "标题行仍在用「未知 / 未观测」兜底")

    def test_g632_copy_exists_in_both_languages(self):
        src = _read(I18N_TSX)
        zh = src[src.index("const zh"):src.index("const en")]
        en = src[src.index("const en"):]
        key = "'detail.transportUncollected'"
        self.assertIn(key, zh, "中文缺文案")
        self.assertIn(key, en, "英文缺文案")


class G633DbSizeTests(unittest.TestCase):
    """G633 / DIAG_6303：占用数值只能来自 /api/status 的 db_size_mib。"""

    ERROR_CODE = "DIAG_6303"

    def test_g633_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "DIAG_6303")

    def test_g633_settings_renders_status_value(self):
        src = _read(SETTINGS_TSX)
        self.assertIn("db_size_mib", src,
                      "设置页没有渲染事件库占用：用户只能自己去数据目录看文件大小")

    def test_g633_type_still_declared(self):
        self.assertIn("db_size_mib", _read(TYPES_TS),
                      "类型里没有 db_size_mib：渲染它要 as any，违反类型安全")


if __name__ == "__main__":
    unittest.main()
