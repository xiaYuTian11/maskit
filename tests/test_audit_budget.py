"""A-1 审计扫描预算 + A-2 同 body findings 复用（0.6.0 契约）。

为什么这些断言必须存在：审计原本是**无预算**地扫全量 body，而 503 重试风暴
会把它线性放大成事件循环上的 CPU 黑洞（本次故障的主因之一）。预算与复用都是
"削掉工作量"的优化，最容易的失败方式是**悄悄削多了**（该报的不报）或
**缓存串味**（拿 A 请求的结论回答 B 请求）。下面每一条都锁住一个方向。

全部 mock（扫描函数 / 事件写库 / _emit），不碰真实端口、进程、DB。
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import transparent as tr


def _flow(body, status=200, ct="application/json", req=b'{"model":"gpt-4o","messages":[]}',
          sid="budget-sid", metadata=None):
    return SimpleNamespace(
        request=SimpleNamespace(method="POST", host="api.openai.com", pretty_host="api.openai.com",
                                path="/v1/chat/completions", headers={"content-type": "application/json"},
                                content=req),
        response=SimpleNamespace(status_code=status, headers={"content-type": ct}, content=body),
        metadata=dict(metadata or {}, session_id=sid),
    )


class AuditBudgetTests(unittest.TestCase):
    def setUp(self):
        # 预算也要钉住：本文件锁的是「超 AUDIT_PARSE_MAX 就跳过结构化解析」这条契约，
        # 而 AUDIT_PARSE_MAX/SCAN_MAX 是**可热重载的全局**（任何一次 _maybe_reload 都可能
        # 把它改成配置里的值）。不钉住时，全套跑会偶发失败、单独跑却全绿
        # （2026-10-31 实测：全量 5 跑中 2 跑红在这两条用例、单独跑 11/11 绿）。
        # 数据目录也要隔离：别的用例留下的后台线程可能在跑 `mask()` → `_maybe_reload()`
        # → 按 `<DATA_ROOT>/config.json` 把 AUDIT_ENABLED / AUDIT_PARSE_MAX 改掉。
        # 全量跑里偶发红、单独跑必绿，根因就是这种跨用例的全局竞态（2026-10-31 定位）。
        self._data_root = tr._DATA_ROOT
        self._tmp_root = Path(tempfile.mkdtemp(prefix="maskit-audit-"))
        self._reload = tr._maybe_reload
        tr._DATA_ROOT = self._tmp_root
        # 热重载直接掐断：隔离数据目录只防了「读到真配置」，防不了重载本身
        # 把预算重置成环境变量值（钉住后仍可能被中途改写，见 Oversize 类注释）。
        tr._maybe_reload = lambda force=False: None
        self._audit_budget = (tr.AUDIT_ENABLED, tr.AUDIT_PARSE_MAX, tr.AUDIT_SCAN_MAX)
        tr.AUDIT_ENABLED = True
        tr.AUDIT_PARSE_MAX = tr._ENV_AUDIT_PARSE_MAX
        tr.AUDIT_SCAN_MAX = tr._ENV_AUDIT_SCAN_MAX
        tr._AUDIT_FINDINGS_CACHE.clear()
        tr._AUDIT_CFG_FP[0] = None
        tr._AUDIT_WARNED.clear()
        tr._AUDIT_RUNTIME["truncated"] = 0
        tr._AUDIT_RUNTIME["parse_skipped"] = 0
        tr._AUDIT_RUNTIME["cache_hit"] = 0
        tr._AUDIT_RUNTIME["cache_miss"] = 0
        tr._AUDIT_RUNTIME["cache_store"] = 0
        self.captured = []
        self._enq = tr.enqueue_audit_event
        tr.enqueue_audit_event = lambda rec: self.captured.append(rec)

    def tearDown(self):
        tr.enqueue_audit_event = self._enq
        tr.AUDIT_ENABLED, tr.AUDIT_PARSE_MAX, tr.AUDIT_SCAN_MAX = self._audit_budget
        tr._DATA_ROOT = self._data_root
        tr._maybe_reload = self._reload
        try:
            self._tmp_root.rmdir()
        except Exception:
            pass
        tr._AUDIT_FINDINGS_CACHE.clear()
        tr._AUDIT_CFG_FP[0] = None

    def test_scan_window_uses_audit_max_and_not_command_window(self):
        """A-1：审计扫描窗口是 AUDIT_SCAN_MAX，且**不动**命令拦截用的 _SCAN_BODY_MAX。

        命令拦截走 `_cmd_find`，窗口是 `_SCAN_BODY_MAX`（512KB）。若把审计的
        收窄顺手施加到同一个常量上，等于缩小了"危险命令拦得住"的范围——安全
        判据不许被性能优化顺手削弱（设计文档 §3.2）。
        """
        seen = []

        def spy(text, *a, **k):
            seen.append(len(text))
            return []

        big = json.dumps({"choices": [{"message": {"content": "x" * (600 * 1024)}}]}).encode("utf-8")
        self.assertGreater(len(big), tr.AUDIT_SCAN_MAX)
        self.assertGreater(len(big), tr._SCAN_BODY_MAX)
        with mock.patch.object(tr._audit, "scan_response_poison", spy):
            tr._audit_response(_flow(big), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertTrue(seen, "S6 扫描器没被调用")
        self.assertLessEqual(max(seen), tr.AUDIT_SCAN_MAX,
                             "审计扫描窗口必须受 AUDIT_SCAN_MAX 约束")
        self.assertEqual(tr._SCAN_BODY_MAX, 512 * 1024,
                         "_SCAN_BODY_MAX 是命令拦截的窗口，A-1 不许动它")

    def test_huge_body_skips_structured_parse_and_records_it(self):
        """A-1：超 AUDIT_PARSE_MAX 的 body 跳过结构化解析，并留下 parse_skipped 痕迹。"""
        calls = []

        def spy_parse(text, ct):
            calls.append(len(text))
            return (["x"], "gpt-4o", [])

        body = json.dumps({"choices": [{"message": {"content": "y" * (tr.AUDIT_PARSE_MAX + 4096)}}]}).encode("utf-8")
        before = tr._AUDIT_RUNTIME["parse_skipped"]
        with mock.patch.object(tr, "_parse_response_payload", spy_parse):
            tr._audit_response(_flow(body), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertEqual(calls, [], "超大 body 不得进入结构化解析")
        self.assertGreater(tr._AUDIT_RUNTIME["parse_skipped"], before,
                           "跳过大 body 解析必须留痕（否则用户只会看到'换芯检测没了'）")

    def test_same_body_is_scanned_once(self):
        """A-2：同一 body + 同一请求 + 同一配置，30s 内只扫一次。"""
        n = []

        def spy(text, *a, **k):
            n.append(1)
            return []

        body = json.dumps({"choices": [{"message": {"content": "same-body"}}]}).encode("utf-8")
        with mock.patch.object(tr._audit, "scan_response_poison", spy):
            for _ in range(5):
                tr._audit_response(_flow(body), "budget-sid", "api.openai.com", "POST",
                                   "/v1/chat/completions", {})
        self.assertEqual(len(n), 1, "5 次相同 body 应只扫 1 次（实测 %d 次）" % len(n))
        self.assertGreaterEqual(tr._AUDIT_RUNTIME["cache_hit"], 4)

    def test_cache_key_separates_request_side_inputs(self):
        """A-2 的反面：请求体不同 → 不能复用（回声抑制依赖请求侧输入）。"""
        reqs = []

        def spy(text, req_text=None, *a, **k):
            reqs.append(req_text)
            return []

        body = json.dumps({"choices": [{"message": {"content": "same"}}]}).encode("utf-8")
        with mock.patch.object(tr._audit, "scan_response_poison", spy):
            tr._audit_response(_flow(body, req=b'{"model":"a"}'), "budget-sid", "api.openai.com",
                               "POST", "/v1/chat/completions", {})
            tr._audit_response(_flow(body, req=b'{"model":"b"}'), "budget-sid", "api.openai.com",
                               "POST", "/v1/chat/completions", {})
        self.assertEqual(len(reqs), 2, "请求体变了就必须重扫")

    def test_cache_key_covers_content_type_and_response_headers(self):
        """扫描输入必须**全部**进缓存键（0.6.0 补）：ct 与响应头曾经漏掉。

        为什么这两条必须各测一次：它们是**输入**而不是元数据 —— `ct` 决定 S2/S4 是否
        走结构化解析分支，响应头是 S1「凭据出现在响应头里」的唯一来源。漏进键里
        就等于"输入变了、结论没变"：同 body 的第二次请求会拿到第一次的干净结论，
        把新出现的 `Set-Cookie: session=...` 漏报 30 秒。
        """
        n = []

        def spy(text, *a, **k):
            n.append(1)
            return []

        body = json.dumps({"choices": [{"message": {"content": "hdr"}}]}).encode("utf-8")
        with mock.patch.object(tr._audit, "scan_response_poison", spy):
            tr._audit_response(_flow(body), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
            # ① 同 body，content-type 不同
            tr._audit_response(_flow(body, ct="text/plain"), "budget-sid", "api.openai.com",
                               "POST", "/v1/chat/completions", {})
            # ② 同 body 同 ct，响应头不同
            flow3 = _flow(body)
            flow3.response.headers = {"content-type": "application/json",
                                      "set-cookie": "session=SUPERSECRET12345"}
            tr._audit_response(flow3, "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertEqual(len(n), 3,
                         "content-type 或响应头变了就必须重扫（实测只扫了 %d 次）" % len(n))

    def test_cache_invalidated_when_signals_change(self):
        """A-2 的反面：用户改了信号开关 → 不能拿旧配置的结论糊上去。"""
        n = []

        def spy(text, *a, **k):
            n.append(1)
            return []

        body = json.dumps({"choices": [{"message": {"content": "same"}}]}).encode("utf-8")
        with mock.patch.object(tr._audit, "scan_response_poison", spy):
            tr._audit_response(_flow(body), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
            with mock.patch.object(tr, "AUDIT_SIGNALS",
                                   dict(tr.DEFAULT_AUDIT_SIGNALS, dangerous_action=False)):
                tr._audit_response(_flow(body), "budget-sid", "api.openai.com", "POST",
                                   "/v1/chat/completions", {})
        self.assertEqual(len(n), 2, "信号配置换代后必须失效缓存")

    def test_truncated_scan_is_not_cached(self):
        """A-2 的边界：被预算截断的结果是残缺的，绝不缓存（否则放大成 30s 漏检）。"""
        with mock.patch.object(tr, "AUDIT_TIME_BUDGET_S", -1.0):
            tr._audit_response(_flow(b'{"a":1}'), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertEqual(len(tr._AUDIT_FINDINGS_CACHE), 0, "截断结果不得进缓存")
        self.assertGreaterEqual(tr._AUDIT_RUNTIME["truncated"], 1, "截断必须计数")

    def test_audit_exception_is_swallowed_and_warned_once(self):
        """审计坏了不能影响流量，但也不能完全静默（抽函数时踩过 NameError 被吞）。"""
        def boom(*a, **k):
            raise RuntimeError("boom")

        with mock.patch.object(tr._audit, "scan_response_poison", boom):
            tr._audit_response(_flow(b'{"a":1}'), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
            tr._audit_response(_flow(b'{"b":2}'), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertIn("audit_error", tr._AUDIT_WARNED, "审计异常必须留下一次告警痕迹")

    def test_audit_event_carries_cost_fields(self):
        """C-1：审计条目要带本次耗时 / 扫描字节 / 是否截断，排障不必再猜。"""
        finding = [{"signal": "response_poison", "severity": tr._audit.HIGH,
                    "evidence": "e", "kind": "k"}]
        with mock.patch.object(tr._audit, "scan_response_poison", lambda *a, **k: list(finding)):
            tr._audit_response(_flow(b'{"a":1}'), "budget-sid", "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        self.assertTrue(self.captured)
        ev = self.captured[0]
        for key in ("audit_ms", "audit_scan_bytes", "audit_scan_truncated"):
            self.assertIn(key, ev, "审计事件缺字段 %s" % key)
        self.assertFalse(ev["audit_scan_truncated"])

    def test_runtime_stats_shape(self):
        """C-1 的取数接口：面板要读得到这些键，改结构必须同步改前端。"""
        st = tr.audit_runtime_stats()
        for key in ("count", "truncated", "parse_skipped", "cache_hit", "cache_miss",
                    "p50_ms", "p95_ms", "cache_size", "scan_max", "parse_max",
                    "time_budget_s"):
            self.assertIn(key, st)


class AuditCostPersistedTests(unittest.TestCase):
    """A-1 的可观测承诺：审计成本与截断标记必须**真的落库**。

    为什么单独一个类：既有用例把 `tr.enqueue_audit_event` 打桩成 list.append，
    只证明"发射了"，而这三个字段曾经因为 audit_events 表没有对应列**根本没写进库**
    （固定 11 列 INSERT）—— 打桩在前置边界上，看不见这件事。
    这里走真实 SQLite 往返。
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        import event_store as es
        self.es = es
        self._orig_db = es.DB_PATH
        self.tmp = _P(tempfile.mkdtemp())
        es.DB_PATH = self.tmp / "audit.sqlite3"
        es._ensure_db()

    def tearDown(self):
        self.es.DB_PATH = self._orig_db

    def test_cost_fields_round_trip_through_sqlite(self):
        self.es.append_audit_event({
            "ts": 100.0, "signal_type": "prompt_injection", "severity": "HIGH",
            "evidence": "e", "probe_id": "p",
            "audit_ms": 12.5, "audit_scan_bytes": 4096, "audit_scan_truncated": True,
        })
        rows = self.es.fetch_audit_events(since=0, limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["audit_ms"], 12.5)
        self.assertEqual(rows[0]["audit_scan_bytes"], 4096)
        self.assertIs(rows[0]["audit_scan_truncated"], True,
                      "截断标记必须是真布尔（A-1 的核心验收判据）")

    def test_old_rows_without_cost_fields_read_as_none(self):
        """老条目（升级前写入）读回是 None，而不是被伪装成 0/False：
        「没记录」与「没截断」是两件事。"""
        self.es.append_audit_event({"ts": 1.0, "signal_type": "X", "severity": "LOW"})
        rows = self.es.fetch_audit_events(since=0, limit=5)
        self.assertIsNone(rows[0]["audit_ms"])
        self.assertIsNone(rows[0]["audit_scan_truncated"])

    def test_bool_is_coerced_not_passed_raw(self):
        """sqlite3 不接受 bool：透传会抛 InterfaceError 并被 append 的 except 吞成 False。"""
        ok = self.es.append_audit_event({
            "ts": 2.0, "signal_type": "X", "severity": "LOW",
            "audit_ms": 1.0, "audit_scan_bytes": 8, "audit_scan_truncated": False})
        self.assertTrue(ok, "bool 透传给 sqlite3 会导致整条审计写不进去")


class AuditOversizeDecodeTests(unittest.TestCase):
    """超体积响应的审计：**哈希仍算全量**，只有"扫描窗口用不到的文本"不再解码。

    为什么这两件事必须分开锁：`response_hash` 是证据（它进缓存键、进事件库，用来判断
    "同一条响应"），而扫描窗口只有 128KB。当初的实现把两者捆在一起——为取 128KB 窗口
    把整份 body decode 成 str（4MB ≈ 3.6ms、16MB ≈ 11.5ms，且那份 str 会与 bytes
    同时常驻）。收掉这份白烧时，最容易的失手是把哈希一起收短——那就不是优化，
    是把证据定义改了（两条不同响应可能在截断后同哈希）。下面两条分别钉住两边。
    """

    def _run(self, body):
        import hashlib
        seen = {}
        real = tr._audit_scan_signals

        def spy(flow, status_code, ct, scan_text, scan_req_text, body_text, hdrs_text,
                deadline, stats, body_oversize=False):
            seen["text_len"] = len(body_text)
            seen["scan_text"] = scan_text
            seen["oversize"] = body_oversize
            out = real(flow, status_code, ct, scan_text, scan_req_text, body_text,
                       hdrs_text, deadline, stats, body_oversize=body_oversize)
            seen["parse_skipped"] = bool(stats.get("parse_skipped"))
            return out

        tr._audit_scan_signals = spy
        try:
            tr._audit_response(_flow(body), "s", "h", "POST", "/v1", {"kind": "t"})
        finally:
            tr._audit_scan_signals = real
        seen["expect_hash"] = hashlib.sha256(body).hexdigest()[:16]
        return seen

    def setUp(self):
        self._enabled = tr.AUDIT_ENABLED
        # 同上：预算被热重载改过时，这条用例会误报（详见 AuditBudgetTests.setUp）。
        # 2026-11-02 补齐另一半：只钉值不够 —— 后台线程的 `_maybe_reload` 可以在
        # 用例执行**中途**改写 AUDIT_PARSE_MAX（实测 parse_skipped 偶发丢失），
        # 直接把热重载指成空函数才断得了根。数据目录也一并隔离（同 Budget 类）。
        self._parse_max = tr.AUDIT_PARSE_MAX
        self._data_root = tr._DATA_ROOT
        self._tmp_root = Path(tempfile.mkdtemp(prefix="maskit-audit-od-"))
        self._reload = tr._maybe_reload
        tr._DATA_ROOT = self._tmp_root
        tr._maybe_reload = lambda force=False: None
        tr.AUDIT_ENABLED = True
        tr.AUDIT_PARSE_MAX = tr._ENV_AUDIT_PARSE_MAX

    def tearDown(self):
        tr.AUDIT_ENABLED = self._enabled
        tr.AUDIT_PARSE_MAX = self._parse_max
        tr._DATA_ROOT = self._data_root
        tr._maybe_reload = self._reload
        try:
            self._tmp_root.rmdir()
        except Exception:
            pass
        tr._AUDIT_FINDINGS_CACHE.clear()

    def test_time_budget_exit_before_parse_still_marks_skipped(self):
        """预算在解析段**之前**耗尽：parse_skipped 仍必须置位。

        满负载机器上 S1/S6/S9 扫描超过 250ms 预算时会从 before_scan/after_s1/
        after_scan 提前退出——此前这三条出口不置位 parse_skipped，「解析被跳过」
        的留痕在时间截断路径上丢失（全量门禁里偶发红、单独跑必绿的真因）。
        """
        body = json.dumps({"choices": [{"message": {"content": "z" * 64}}]}).encode()
        flow = _flow(body)
        stats = {"truncated": False, "parse_skipped": False, "cache_hit": False,
                 "cache_miss": False, "scan_bytes": 0}
        tr._audit_scan_signals(flow, 200, "application/json", "", "", "x",
                               "", time.perf_counter() - 1.0, stats)
        self.assertTrue(stats["truncated"], "时间预算截断必须留痕")
        self.assertTrue(stats["parse_skipped"],
                        "提前退出时本来会跑的结构化解析也要留解析跳过痕")
        # 非解析型载体（无结构化解析可跳）不置位，口径不扩大
        stats2 = {"truncated": False, "parse_skipped": False, "cache_hit": False,
                  "cache_miss": False, "scan_bytes": 0}
        tr._audit_scan_signals(flow, 200, "text/plain", "", "", "x",
                               "", time.perf_counter() - 1.0, stats2)
        self.assertFalse(stats2["parse_skipped"])

    def test_oversize_body_bounds_decode_but_keeps_full_hash(self):
        body = b'{"choices":[{"message":{"content":"' + b"x" * (tr.AUDIT_PARSE_MAX + 1024) + b'"}}]}'
        seen = self._run(body)
        self.assertTrue(seen["oversize"], "超过解析闸的 body 必须标 oversize")
        self.assertLessEqual(seen["text_len"], tr.AUDIT_SCAN_MAX * 4 + 8,
                             "超体积 body 不该再全量 decode（扫描窗口只有 128KB）")
        self.assertTrue(seen["parse_skipped"], "超闸的结构化解析必须留痕（口径不能变）")
        self.assertEqual(tr._hash_body(body), seen["expect_hash"],
                         "response_hash 必须仍是**全量** sha256（证据语义）")

    def test_within_parse_budget_still_decodes_fully_and_parses(self):
        body = json.dumps({"choices": [{"message": {"content": "短响应"}}]}).encode()
        seen = self._run(body)
        self.assertFalse(seen["oversize"])
        self.assertGreater(seen["text_len"], 0)
        self.assertFalse(seen["parse_skipped"], "未超闸时必须照旧尝试结构化解析")

    def test_signal_in_window_still_fires_for_oversize_body(self):
        """超体积 body 的前 128KB 里若有凭据，扫描窗口仍必须**看得见**它。

        这一条防的是"收掉白解时把窗口一起收小"：解码被限在前缀后，窗口内容
        必须与从前逐字节一致（否则 S1 error_leak 这类只看前段的信号会开始漏报）。
        """
        pem = "-----BEGIN RSA PRIVATE KEY-----" + "A" * 64
        body = (('{"choices":[{"message":{"content":"' + pem + '"}}]}')
                + " " * (tr.AUDIT_PARSE_MAX + 1024)).encode()
        seen = self._run(body)
        self.assertTrue(seen["oversize"])
        self.assertIn("BEGIN RSA PRIVATE KEY", seen["scan_text"],
                      "带哈希后的前缀解码弄丢/错位了窗口内容（信号会漏报）")
        self.assertLessEqual(len(seen["scan_text"]), tr.AUDIT_SCAN_MAX)


if __name__ == "__main__":
    unittest.main()
