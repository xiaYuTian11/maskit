"""诊断包回归测试。

这个包是要**发给开发者**的，所以隐私要求比 /api/logs/export 更严：
export 只需保证不含还原正文，诊断包还要保证日志、崩溃现场这些自由文本
里的凭据与 PII 也被打码。

测试设计上有一条血的教训（见 AGENTS「E2E 假绿」）：先断言脏数据**确实进包了**，
再断言它被打码。否则某天 crash_dumps 因为路径变更取不到数据，
"没泄漏" 会变成一个永远通过的空测试。

端口查询一律 mock：真实 netstat 慢且结果不确定，且本机可能正跑着代理。
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import panel  # noqa: E402

# 临时数据目录只在用例里用 mock.patch 挂上去。
# **绝不能在 import 时改 LLM_SHIELD_DATA_DIR**：panel.DATA_ROOT 是 import 期定型的，
# 全量跑测试时本文件会先于 test_shield 被导入，把它的 DATA_ROOT 断言一起带崩
# （实测踩过：test_panel_event_store_uses_panel_data_root 失败）。
_TMP = tempfile.mkdtemp(prefix="maskit-diag-test-")

# 每条都是「真实日志里出现过的形态」，不是凭空编的
DIRTY = {
    "openai key": "sk-proj-AAAABBBBCCCCDDDDEEEE1234",
    "中转 key": "ah-9f8e7d6c5b4a3210deadbeef",
    "github pat": "ghp_1234567890abcdefghijklmnopqrstuv",
    "手机号": "13812345678",
    "身份证": "110101199003072316",
    "邮箱": "bob.smith@corp.example.com",
    "银行卡": "6222021234567890123",
    "本机用户名": "alice",
    "赋值口令": "hunter2xyz",
}

DIRTY_TEXT = (
    "Authorization: Bearer sk-proj-AAAABBBBCCCCDDDDEEEE1234\n"
    "api_key=ah-9f8e7d6c5b4a3210deadbeef\n"
    "token: ghp_1234567890abcdefghijklmnopqrstuv\n"
    "user 13812345678 idcard 110101199003072316 mail bob.smith@corp.example.com\n"
    "card 6222021234567890123\n"
    "password: hunter2xyz\n"
    r"path C:\Users\alice\AppData\Roaming\Maskit\config.json"
    "\n"
)


class ScrubTests(unittest.TestCase):
    def test_all_dirty_forms_scrubbed(self):
        out = panel._scrub_text(DIRTY_TEXT)
        for name, needle in DIRTY.items():
            self.assertNotIn(needle, out, f"{name} 未被打码：{out}")

    def test_scrub_keeps_diagnostic_value(self):
        """打码不能把有用信息也抹掉，否则诊断包就没意义了。"""
        out = panel._scrub_text(
            "[engine] upstream=deepseek port=18711 status=502 msg=connection reset")
        for keep in ("deepseek", "18711", "502", "connection reset"):
            self.assertIn(keep, out)

    def test_scrub_never_raises_and_never_returns_input_on_failure(self):
        """scrub 失败时放行原文是最坏结果，必须返回占位串。"""
        class Boom:
            def __str__(self):
                raise RuntimeError("boom")
        self.assertEqual(panel._scrub_text(Boom()), "<scrub failed>")

    def test_safe_target_strips_credentials(self):
        cases = [
            ("https://u:p@api.foo.com/v1?key=sk-secret123", "https://api.foo.com/v1"),
            ("https://api.foo.com:8443/v1", "https://api.foo.com:8443/v1"),
            ("", ""),
        ]
        for raw, want in cases:
            self.assertEqual(panel._safe_target(raw), want)


class DiagnosticsPayloadTests(unittest.TestCase):
    def setUp(self):
        dumps = Path(_TMP) / "crash-dumps"
        dumps.mkdir(exist_ok=True)
        (dumps / "crash-20260816-120000-crash.txt").write_text(DIRTY_TEXT, encoding="utf-8")
        panel.log_buf.append("[engine] password: hunter2xyz token=abcdefgh12345678")

    def _payload(self):
        # 端口查询 mock 掉：真实 netstat 慢、结果不确定，且本机可能正跑着代理
        with mock.patch.object(panel, "DATA_ROOT", Path(_TMP)),              mock.patch.object(panel, "_listening_port_pids", return_value={}):
            return panel._diagnostics_payload()

    def test_dirty_data_actually_reaches_the_bundle(self):
        """正对照。没有这条，下面的「无泄漏」可能只是因为数据压根没进包。"""
        p = self._payload()
        self.assertTrue(p["crash_dumps"], "崩溃现场没进包，泄漏检查会变成空测试")
        blob = json.dumps(p, ensure_ascii=False)
        self.assertTrue(
            "<redacted>" in blob or "<key>" in blob,
            "包里没有任何打码痕迹，说明 scrub 根本没跑到")

    def test_no_secret_leaks(self):
        blob = json.dumps(self._payload(), ensure_ascii=False)
        for name, needle in DIRTY.items():
            self.assertNotIn(needle, blob, f"诊断包泄漏 {name}")

    def test_no_restored_plaintext_fields(self):
        """还原正文类字段一个都不许出现——这是隐私政策的硬承诺。"""
        blob = json.dumps(self._payload(), ensure_ascii=False)
        for banned in ("dialog", "req_preview", "resp_preview", "original", "proxy_token"):
            self.assertNotIn(f'"{banned}"', blob, f"诊断包含禁用字段 {banned}")

    def test_custom_words_reported_as_count_only(self):
        """词库是用户要保护的内容本身（公司名、项目代号），只能报数量。"""
        cfg = panel.default_config()
        cfg["sensitive"] = {"客户": ["超级机密客户名", "另一个客户"]}
        with mock.patch.object(panel, "load_config", return_value=cfg):
            p = self._payload()
        blob = json.dumps(p, ensure_ascii=False)
        self.assertNotIn("超级机密客户名", blob)
        self.assertEqual(p["settings"]["custom_word_count"], 2)
        self.assertEqual(p["settings"]["custom_word_groups"], 1)

    def test_upstream_target_has_no_query(self):
        cfg = panel.default_config()
        cfg["upstreams"] = [{"name": "x", "port": 18799,
                             "target": "https://relay.example.com/v1?token=sk-leak0001"}]
        with mock.patch.object(panel, "load_config", return_value=cfg):
            p = self._payload()
        self.assertNotIn("sk-leak0001", json.dumps(p, ensure_ascii=False))
        self.assertEqual(p["upstreams"][0]["target"], "https://relay.example.com/v1")

    def test_payload_survives_broken_subsystem(self):
        """诊断包恰恰在系统半死不活时才用得上，某一节挂掉不能让整包生成失败。"""
        with mock.patch.object(panel, "today_stats", side_effect=RuntimeError("db gone")), \
             mock.patch.object(panel, "_listening_port_pids", side_effect=OSError("netstat gone")):
            p = panel._diagnostics_payload()
        self.assertIn("error", p["stats_today"])
        self.assertIn("error", p["ports"])
        self.assertEqual(p["app"]["version"], panel.__version__)

    def test_endpoint_returns_json_and_is_not_quota_gated(self):
        """诊断包返回合法 JSON，包含脱敏与架构信息。"""
        with mock.patch.object(panel, "_listening_port_pids", return_value={}):
            client = panel.app.test_client()
            r = client.get("/api/diagnostics",
                           headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(r.status_code, 200)
        body = json.loads(r.data.decode("utf-8"))
        self.assertTrue(body["masked"])
        self.assertEqual(body["schema"], 1)

    def test_endpoint_requires_token(self):
        """诊断包即便打过码也含端口/配置/错误信息，不能对无令牌请求开放。"""
        r = panel.app.test_client().get("/api/diagnostics")
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
