"""测试凭据前缀脱敏规则及误伤防护。

验证：
1. DEFAULT_SECRET_PREFIXES 中的安全前缀能正常识别；
2. 常见的代码/常量/SHA/UUID/Base64 等不会被误伤（特别防范 ASIA_EAST_1 等枚举误报）；
3. 值形态均使用片段拼接构造，避免触发敏感字面量扫描。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))

from shield_defaults import DEFAULT_SECRET_PREFIXES
import transparent


class TestSecretPrefixes(unittest.TestCase):
    def setUp(self):
        # 备份并替换 transparent 模块的 SECRET_PREFIXES
        self._orig_prefixes = list(transparent.SECRET_PREFIXES)
        transparent.SECRET_PREFIXES = list(DEFAULT_SECRET_PREFIXES)
        transparent._prefix_rx_cache = None
        transparent._prefix_rx_key = None

    def tearDown(self):
        transparent.SECRET_PREFIXES = self._orig_prefixes
        transparent._prefix_rx_cache = None
        transparent._prefix_rx_key = None

    def test_default_prefixes_hit(self):
        """测试 DEFAULT_SECRET_PREFIXES 中的各前缀均能成功命中。"""
        rx = transparent._prefix_secret_regex()
        self.assertIsNotNone(rx)

        # 构造各前缀的伪造凭据（片段拼接，不使用真实/明文字面量）
        sample_tail = "a1b2c3d4e5f6"
        for prefix in DEFAULT_SECRET_PREFIXES:
            sample = prefix + sample_tail
            match = rx.search("my_token = \"" + sample + "\"")
            self.assertIsNotNone(match, f"前缀 {prefix} 应能命中构造的凭据")
            self.assertEqual(match.group(0), sample)

    def test_no_false_positives_on_common_code_tokens(self):
        """测试代码中常见的区域常量、UUID、Git SHA、Base64 等不会被误伤。"""
        rx = transparent._prefix_secret_regex()
        self.assertIsNotNone(rx)

        non_secrets = [
            # 常见的 AWS 区域常量（绝不能误伤 ASIA_* 枚举）
            'AWS_REGION = "ASIA_EAST_1"',
            'region = "ASIA_PACIFIC_SOUTH"',
            'const REGION = "ASIA_NORTHEAST_1";',
            # Git commit SHA
            'commit = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"',
            # UUID
            'uuid = "123e4567-e89b-12d3-a456-426614174000"',
            # Base64 资产片段
            'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA"',
            # 普通标识符或文件名
            'path = "/var/log/app_trace_dump_2026.log"',
            'class AsiaPacificController:',
            # 2026-10-25 新增前缀的误伤面（必须继续放行）
            'task-queue-name = "worker-pool"',       # tk- 只认 tk-，不认 task
            'make-archive=2026',                     # ak- 不认 make-archive
            'peak-load = "12"',
            'speak-language = "zh-CN"',
            'safety-check = "on"',                   # SG. 不认 safety
            'sg.group = "ops"',                      # SG. 大小写敏感，sg. 不命中
            'hf_config = "default"',                 # hf_ 后需 ≥8 位尾，default 不足
            'gsk_docs = "v2"',                       # gsk_ 后仅 2 位，不命中
            'xai-models = "list"',                   # xai- 后仅 6 位，不命中
            'nvapi-version = "1"',
        ]

        for code in non_secrets:
            match = rx.search(code)
            self.assertIsNone(match, f"代码中的正常标识符不应被误判为凭据: {code}")

    def test_new_prefixes_are_covered(self):
        """2026-10-25 补齐的厂商前缀必须都在清单里（防「改了正则忘了清单」）。

        真机日志复盘结论：旧清单只有 9 个，HuggingFace / Groq / xAI / NVIDIA /
        Perplexity / DigitalOcean / SendGrid / OpenRouter / Anthropic 新版
        全部漏检。这些前缀是**公开格式标记**，误报风险极低。
        """
        required = {
            "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-", "sk-or-",
            "hf_", "gsk_", "xai-", "nvapi-", "pplx-", "dop_v1_", "SG.",
        }
        missing = required - set(DEFAULT_SECRET_PREFIXES)
        self.assertEqual(missing, set(), f"缺少这些厂商前缀：{sorted(missing)}")

    def test_new_prefixes_hit_end_to_end(self):
        """走完整 mask()（不只正则），确保标签与还原都对。"""
        sample_tail = "Ab9" + "Xy2" + "Zq7" + "Lm4"  # 12 位，均含字母数字
        for prefix in ("hf_", "gsk_", "xai-", "nvapi-", "pplx-", "dop_v1_", "sk-or-"):
            with self.subTest(prefix=prefix):
                sid = f"pfx-{prefix.strip('-_')}"
                transparent._new_session(sid)
                text = "token " + prefix + sample_tail
                out = transparent.mask(text, sid)
                self.assertNotIn(
                    prefix + sample_tail, out, f"前缀 {prefix} 端到端漏检：{out!r}"
                )
                self.assertIn("{{", out, f"前缀 {prefix} 未产生占位符：{out!r}")


if __name__ == "__main__":
    unittest.main()
