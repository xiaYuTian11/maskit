"""G711~G714：扩展文本打码的三道超时必须是「外 > 内」，且大文本不盲目重试。

真机约束（写在 `extension/bridge-main.js` 的文件/图片链路注释里，本次只是把它应用到文本）：
页↔SW 的超时**必须大于** SW→引擎那一道。反过来时，页面先 `resolve(null)`、调用方按
「没换成」当直通，而 SW 那边其实还在跑、它的成败结果没人接 —— 这是一条静默漏脱敏路径。

改造前文本链路正好是反的：页桥 6s < SW 15s。第 6 秒页面放弃并发起重试，于是引擎侧同时
有两个同负载请求争抢 `_MASK_POOL` 的全局锁；两次都超时后按直通处理，原文上行且回复不还原。

## 静态契约与行为回归

这里钉住常量关系与分支顺序；`scripts/check-extension.mjs` 另用原始 JS 函数和模拟引擎
验证超时、重试与阻断行为，不依赖真实浏览器或用户配置。短文本的内层预算必须保持后台
原有的 15s，不能为了「外 > 内」把它压成 3s，导致本可完成的调用提前直通。
"""

import re
import unittest
from pathlib import Path

from tests.test_event_flagged_explain import _block, _read

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_MAIN = ROOT / "extension" / "bridge-main.js"
BACKGROUND = ROOT / "extension" / "background.js"

# 引擎侧单请求 NER 总预算（`engine/transparent.py` 的 `_NER_REQ_BUDGET_MAX_DEFAULT_S`）。
ENGINE_NER_BUDGET_S = 10


def _const(source, name):
    """取 `const <name> = <整数>` 的数值；找不到直接失败（不许静默当 0）。"""
    m = re.search(r"const\s+%s\s*=\s*(\d+)" % re.escape(name), source)
    if not m:
        raise AssertionError("找不到常量 %s" % name)
    return int(m.group(1))


def _call_mask_body():
    return _block(_read(BRIDGE_MAIN), "const callMask = async (text) =>")


class G711OuterGreaterThanInnerTests(unittest.TestCase):
    """G711 / EXT_7101：页桥超时必须严格大于下发给 SW 的超时。"""

    def test_g711_error_code_is_fixed(self):
        self.assertEqual("EXT_7101", "EXT_7101")

    def test_g711_margin_is_positive_for_both_tiers(self):
        source = _read(BRIDGE_MAIN)
        margin = _const(source, "SW_MARGIN_MS")
        self.assertGreater(margin, 0, "SW_MARGIN_MS 必须为正（EXT_7101）")
        for tier in ("MASK_TIMEOUT_MS", "MASK_TIMEOUT_MS_LARGE"):
            page = _const(source, tier)
            self.assertGreater(page, margin, "%s 必须大于 SW_MARGIN_MS（EXT_7101）" % tier)

    def test_g711_mask_once_passes_inner_timeout_to_sw(self):
        body = _block(_read(BRIDGE_MAIN), "const maskOnce = (text) =>")
        self.assertRegex(
            body,
            r"timeoutMs:\s*pageMs\s*-\s*SW_MARGIN_MS",
            "下发给 SW 的超时必须是 pageMs - SW_MARGIN_MS（EXT_7101）",
        )
        self.assertRegex(
            body,
            r"bridge\.call\(\s*'mask'[^)]*pageMs\s*\)",
            "bridge.call 的第二个参数（页桥超时）必须传 pageMs（EXT_7101）",
        )


class ShortTextTimeoutBudgetTests(unittest.TestCase):
    def test_short_text_keeps_the_background_default_budget(self):
        main = _read(BRIDGE_MAIN)
        inner_ms = _const(main, "MASK_TIMEOUT_MS") - _const(main, "SW_MARGIN_MS")
        self.assertEqual(
            inner_ms,
            _const(_read(BACKGROUND), "CALL_TIMEOUT_MS"),
            "短文本必须保留后台默认预算，不能提前中止本可完成的脱敏",
        )

    def test_short_text_still_has_a_smaller_budget_than_large_text(self):
        main = _read(BRIDGE_MAIN)
        self.assertLess(_const(main, "MASK_TIMEOUT_MS"), _const(main, "MASK_TIMEOUT_MS_LARGE"))


class G712LargeTierCoversEngineBudgetTests(unittest.TestCase):
    """G712 / EXT_7102：大文本档要盖住引擎 NER 预算，且 SW 钳制上限不得更低。"""

    def test_g712_error_code_is_fixed(self):
        self.assertEqual("EXT_7102", "EXT_7102")

    def test_g712_large_tier_covers_engine_budget(self):
        large_ms = _const(_read(BRIDGE_MAIN), "MASK_TIMEOUT_MS_LARGE")
        self.assertGreaterEqual(
            large_ms,
            ENGINE_NER_BUDGET_S * 2000,
            "大文本档必须 ≥ 引擎 NER 预算的 2 倍（含正则扫描与排队）（EXT_7102）",
        )

    def test_g712_sw_clamp_is_not_tighter_than_large_tier(self):
        large_ms = _const(_read(BRIDGE_MAIN), "MASK_TIMEOUT_MS_LARGE")
        cap_ms = _const(_read(BACKGROUND), "CALL_TIMEOUT_MS_MAX")
        self.assertGreaterEqual(
            cap_ms,
            large_ms,
            "SW 钳制上限低于页桥大文本档会让「外 > 内」反转（EXT_7102）",
        )

    def test_g712_handle_mask_applies_the_clamp(self):
        source = _read(BACKGROUND)
        self.assertIn("payload.timeoutMs", source, "handleMask 必须读页面下发的超时（EXT_7102）")
        self.assertRegex(
            source,
            r"Math\.min\(\s*requested\s*,\s*CALL_TIMEOUT_MS_MAX\s*\)",
            "下发值必须被钳到 CALL_TIMEOUT_MS_MAX（EXT_7102）",
        )
        self.assertRegex(
            source,
            r"safeCall\(\s*'/api/ext/mask'[^)]*engineTimeoutMs\s*\)",
            "mask 调用必须把 engineTimeoutMs 传进 safeCall（EXT_7102）",
        )


class G713LargeTextNotRetriedTests(unittest.TestCase):
    """G713 / EXT_7103：大文本不重试，小文本保留一次重试。"""

    def test_g713_error_code_is_fixed(self):
        self.assertEqual("EXT_7103", "EXT_7103")

    def test_g713_large_text_returns_before_retry(self):
        body = _call_mask_body()
        guard_at = body.find("if (isLargeText(text)) return null;")
        self.assertGreaterEqual(guard_at, 0, "缺少「大文本不重试」分支（EXT_7103）")

        calls = [m.start() for m in re.finditer(r"maskOnce\(text\)", body)]
        self.assertEqual(len(calls), 2, "callMask 必须恰好两次调用 maskOnce（首次 + 小文本重试）（EXT_7103）")
        self.assertLess(
            guard_at,
            calls[1],
            "大文本返回必须排在第二次 maskOnce 之前，否则重试已经发生（EXT_7103）",
        )


class G714BlockingStaysFailClosedTests(unittest.TestCase):
    """G714 / EXT_7104：`blocking` 必须原样上抛、不得进入重试或直通。"""

    def test_g714_error_code_is_fixed(self):
        self.assertEqual("EXT_7104", "EXT_7104")

    def test_g714_blocking_branch_precedes_retry(self):
        body = _call_mask_body()
        blocking_at = body.find("first && first.blocking")
        self.assertGreaterEqual(blocking_at, 0, "缺少 blocking 分支（EXT_7104）")
        for later in ("if (first) return first;", "if (isLargeText(text)) return null;"):
            self.assertLess(blocking_at, body.find(later), "blocking 分支必须排在 %s 之前（EXT_7104）" % later)


if __name__ == "__main__":
    unittest.main()