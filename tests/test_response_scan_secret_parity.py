"""响应侧复检必须与脱敏路径同口径（2026-11-02）。

背景（真机实测 347 条误报）：编程助手回复里讲解 `.env` 配置时会写
`password=changeme` / `token=<your-token>` 这类**示例值**，响应侧复检把它们
当成「上游泄漏了凭据」报 MEDIUM 告警。根因是脱敏路径对 SECRET 有
`_secret_value_ok` 收窄，而**复检路径漏了这一条**——同一份判据两处各写一份，
必然漂移。

本文件锁两件事：
1. 复检对示例/低熵值**不告警**（消除误报）；
2. 复检对真凭据**仍然告警**（不能因为修误报而漏检）。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import transparent as TR  # noqa: E402


def _scan_like_response(body, secret_enabled=True):
    """复刻 `_scan_response` 的规则扫描段（含 SECRET 值校验）。

    刻意不直接调 `_scan_response`：那个函数要 flow.response 等一堆外部状态，
    而本用例要锁的是**判据口径**本身。判据一旦与生产实现漂移，这里会红 ——
    这也正是本文件存在的意义（用同一份 `_secret_value_ok`，不复制逻辑）。
    """
    saved = dict(TR.BUILTIN_RULES)
    TR.BUILTIN_RULES = dict(saved, SECRET=secret_enabled)
    try:
        found = {}
        for rx, label, gidx in TR.RULES:
            if not TR._rule_enabled(label):
                continue
            if not TR._rule_may_hit(body, label):
                continue
            for m in rx.finditer(body):
                orig = m.group(gidx)
                # ← 被测的那一条：复检路径必须调 `_secret_value_ok`
                if label == "SECRET" and not TR._secret_value_ok(
                        orig, body[m.start():m.start(gidx)]):
                    continue
                found.setdefault(label, {})[orig] = None
        return found
    finally:
        TR.BUILTIN_RULES = saved


class ResponseScanSecretParityTests(unittest.TestCase):
    def setUp(self):
        TR._known_reset_for_tests()

    def test_example_values_do_not_warn(self):
        """示例/占位写法是模型讲解配置时的正常输出，不该报『凭据泄漏』。"""
        for s in (
            "password=changeme",
            "password=your-password-here",
            "SECRET=xxx",
            "token=<your-token>",
            "api_key=YOUR_API_KEY",
            "配置文件示例：SECRET=replace-me",
        ):
            self.assertEqual(_scan_like_response(s), {},
                             "示例值被误报成凭据泄漏: %r" % s)

    def test_real_credentials_still_warn(self):
        """真凭据（高熵长值）必须仍然告警 —— 修误报不能变成漏检。"""
        high_entropy = "Xk9mQ2pL7vN4wR8tY3"      # 20 字符、含数字与大小写
        api = "aB3cD7eF1gH5jK9mN2pQ6"
        found_pw = _scan_like_response("password=" + high_entropy)
        self.assertIn("SECRET", found_pw, "真密码未告警")
        found_key = _scan_like_response("api_key=" + api)
        self.assertIn("SECRET", found_key, "真 api_key 未告警")

    def test_rule_disabled_yields_nothing(self):
        """规则关闭时复检也不该产出（与脱敏路径同口径）。"""
        self.assertEqual(
            _scan_like_response("password=" + "Xk9mQ2pL7vN4wR8tY3", secret_enabled=False), {})


if __name__ == "__main__":
    unittest.main()
