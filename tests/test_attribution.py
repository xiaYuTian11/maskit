"""A-7（503 归因字段）+ A-8（兜底占位层加固）契约。

为什么要有"静态守卫"这类测试：本次故障里用户手里唯一的事件行是
`503 + 脱敏标签`，而它可能是**四种完全不同**的来源（上游返回 / 请求侧
fail-closed / 响应侧阻断 / 兜底占位）。字段白名单、发射点漏标这类错误
不会让任何单测变红，却会让排查重新回到"靠猜"。所以这里既测行为，
也**扫源码**把"新增发射点忘了标 source"变成一条会红的门禁。
"""
import ast
import io
import json
import re
import sys
import os
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import panel
import event_store
import transparent as tr

ALLOWED_SOURCES = {"upstream", "engine", "fallback"}


def _restore_summary_fields(tree):
    """Discover the worker-prepared RESTORE schema, not a hand-maintained list."""
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef) and fn.name == "_emit_restore_summary":
            for node in ast.walk(fn):
                if (isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "summary" for t in node.targets)
                        and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name) and node.value.func.id == "dict"):
                    return {kw.arg for kw in node.value.keywords if kw.arg}
    return set()


def _emit_calls(src, typ):
    """Return emitted keyword names, including the explicit prepared RESTORE builder."""
    tree = ast.parse(src)
    prepared = _restore_summary_fields(tree)
    out = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name)
                    or node.func.id != "_emit"):
                continue
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == typ:
                fields = {kw.arg for kw in node.keywords if kw.arg}
                if typ == "RESTORE" and fn.name in ("_emit_restore_summary", "response"):
                    if any(kw.arg is None and isinstance(kw.value, ast.Name)
                           and kw.value.id == "summary" for kw in node.keywords):
                        fields |= prepared
                out.append(fields)
    return out


class BlockSourceStaticGuardTests(unittest.TestCase):
    def setUp(self):
        self.tr_src = (ROOT / "engine" / "transparent.py").read_text(encoding="utf-8")
        self.panel_src = (ROOT / "engine" / "panel.py").read_text(encoding="utf-8")

    def test_every_block_emit_declares_block_source(self):
        """每个 BLOCK 发射点都必须写 block_source（漏一个就等于 503 归因缺一角）。"""
        calls = _emit_calls(self.tr_src, "BLOCK")
        self.assertGreaterEqual(len(calls), 6, "BLOCK 发射点变少了？先确认是不是合并了路径")
        missing = [i for i, kws in enumerate(calls) if "block_source" not in kws]
        self.assertEqual(missing, [], "第 %s 个 BLOCK 发射点缺少 block_source" % missing)

    def test_prepared_schema_discovery_does_not_hide_missing_source(self):
        sample = ('def _emit_restore_summary():\n'
                  '    summary = dict(block_source="upstream", new_field=1)\n'
                  '    _emit("RESTORE", **summary)\n')
        self.assertEqual(_emit_calls(sample, "RESTORE"), [{"block_source", "new_field"}])
        broken = sample.replace('block_source="upstream", ', '')
        self.assertNotIn("block_source", _emit_calls(broken, "RESTORE")[0])

    def test_restore_emit_declares_upstream_source(self):
        """RESTORE 的 503 来自上游，必须标 upstream（否则与引擎自己拦的混在一起）。"""
        calls = _emit_calls(self.tr_src, "RESTORE")
        self.assertTrue(calls, "RESTORE 发射点没找到")
        for kws in calls:
            self.assertIn("block_source", kws)

    def test_fallback_placeholder_event_declares_fallback(self):
        """兜底占位层的 503 必须标 fallback —— 这是"代理有没有在跑"的唯一机器读法。"""
        tree = ast.parse(self.panel_src)
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for arg in node.args:
                if not isinstance(arg, ast.Dict):
                    continue
                keys = [k.value for k in arg.keys if isinstance(k, ast.Constant)]
                if "reason" not in keys:
                    continue
                vals = {}
                for k, v in zip(arg.keys, arg.values):
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                        vals[k.value] = v.value
                if vals.get("reason") == "shield_unavailable":
                    found.append(vals.get("block_source"))
        self.assertEqual(found, ["fallback"],
                         "兜底占位事件必须带 block_source=fallback，实际 %r" % found)

    def test_sources_are_within_enum(self):
        """枚举就三个值：多写一个值会让前端的归因分支静默落空。"""
        vals = set(re.findall(r'block_source\s*=\s*"([a-z_]+)"', self.tr_src))
        vals |= set(re.findall(r'"block_source":\s*"([a-z_]+)"', self.tr_src))
        vals |= set(re.findall(r'"block_source":\s*"([a-z_]+)"', self.panel_src))
        self.assertTrue(vals, "没扫到任何 block_source 取值")
        self.assertTrue(vals <= ALLOWED_SOURCES, "越界取值：%r" % (vals - ALLOWED_SOURCES))

    def test_new_fields_are_registered_in_both_whitelists(self):
        """新字段必须同时登记导出白名单与诊断包白名单。

        `degraded` 丢过一次（0.1.14 补进事件、却一直不在白名单里）——
        那次之后，这类"发了但看不见"的字段改成显式清单 + 门禁。
        """
        must = ["block_source", "degraded", "stream_degraded_reason", "queue_wait_ms",
                "engine_queue_depth", "engine_busy", "ner_global_throttled", "ner_sem_wait_ms"]
        export_block = self.panel_src.split("_EXPORT_KEEP_FIELDS = {", 1)[1].split("}", 1)[0]
        diag_block = self.panel_src.split("keep = (", 1)[1].split(")", 1)[0]
        for field in must:
            self.assertIn('"%s"' % field, export_block, "导出白名单缺 %s" % field)
            self.assertIn('"%s"' % field, diag_block, "诊断包白名单缺 %s" % field)


class SniffModelTests(unittest.TestCase):
    def test_extracts_model_from_json_body(self):
        self.assertEqual(panel._sniff_model(b'{"model": "gpt-4o", "messages": []}'), "gpt-4o")
        self.assertEqual(panel._sniff_model(b'{"model":"claude-3-5-sonnet-20241022"}'),
                         "claude-3-5-sonnet-20241022")

    def test_survives_truncated_body(self):
        """截断的 body 解不出 JSON，但字面量已经出现——正则必须还能取到。"""
        raw = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "x" * 500}]}).encode()
        head = raw[:200]
        self.assertEqual(panel._sniff_model(head), "gpt-4o")

    def test_returns_empty_when_absent_or_garbage(self):
        for raw in (b"", b"not json", b'{"mod": "x"}', b'{"model": }'):
            self.assertEqual(panel._sniff_model(raw), "", "输入 %r" % raw)

    def test_does_not_decode_credentials(self):
        """只取 model 字段：体里带凭据也不该被带出来（A-8 的隐私面）。"""
        raw = b'{"model": "gpt-4o", "api_key": "sk-' + b"A" * 40 + b'"}'
        self.assertEqual(panel._sniff_model(raw), "gpt-4o")
        self.assertNotIn(b"sk-", panel._sniff_model(raw).encode())


class ChunkedDrainTests(unittest.TestCase):
    def _chunked(self, payload, chunk=16):
        out = io.BytesIO()
        for i in range(0, len(payload), chunk):
            part = payload[i:i + chunk]
            out.write(b"%x\r\n" % len(part) + part + b"\r\n")
        out.write(b"0\r\n\r\n")
        out.seek(0)
        return out

    def test_keep_truncates_but_still_drains(self):
        """keep 只影响"留下多少"，读掉的字节数不受影响（否则回 503 会触发 RST）。"""
        payload = b"x" * 5000
        rfile = self._chunked(payload)
        body = panel._read_chunked_body(rfile, limit=1 << 20, keep=100)
        self.assertEqual(len(body), 100, "只该留 100 字节")
        self.assertEqual(rfile.read(), b"", "必须把流读干净（否则客户端看到连接重置）")

    def test_limit_still_applies_to_total_consumed(self):
        """limit 约束的是**读掉的总量**，不是保留量（防"keep 小就能绕过上限"）。"""
        rfile = self._chunked(b"y" * 4096, chunk=1024)
        with self.assertRaises(ValueError):
            panel._read_chunked_body(rfile, limit=1024, keep=10)

    def test_default_keeps_everything_for_passthrough(self):
        """透传路径要完整 body 才能转发，keep=None 时必须全留。"""
        payload = b"z" * 300
        rfile = self._chunked(payload)
        self.assertEqual(panel._read_chunked_body(rfile), payload)


class PassthroughConcurrencyTests(unittest.TestCase):
    def test_slots_are_released_and_overflow_is_closed(self):
        """并发上限：抢不到槽位的连接被关掉并计数，抢到的正常收尾后释放。"""

        class _Handler(panel.http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()

        srv = panel._PassthroughHTTPServer(("127.0.0.1", 0), _Handler)
        try:
            # 人为把槽位缩到 1，并让等待窗口极短，制造"抢不到"的情形
            srv._slots = threading.BoundedSemaphore(1)
            old_wait = panel._PASSTHROUGH_SLOT_WAIT_S
            panel._PASSTHROUGH_SLOT_WAIT_S = 0.01
            try:
                srv._slots.acquire()          # 占满唯一槽位

                class _Sock:
                    closed = False

                    def close(self):
                        self.closed = True

                sock = _Sock()
                srv.process_request(sock, ("127.0.0.1", 1))
                self.assertTrue(sock.closed, "抢不到槽位必须关掉连接")
                self.assertEqual(srv.overloaded, 1, "过载计数要为自检留下痕迹")
                srv._slots.release()          # 归还，避免影响后续
            finally:
                panel._PASSTHROUGH_SLOT_WAIT_S = old_wait
        finally:
            srv.server_close()

    def test_default_concurrency_is_documented_bound(self):
        """默认上限必须是有限值：无上限等于重试风暴直接吃光线程。"""
        self.assertGreaterEqual(panel._PASSTHROUGH_CONCURRENCY, 8)
        self.assertLessEqual(panel._PASSTHROUGH_CONCURRENCY, 4096)


class FrontendFieldRegistrationTests(unittest.TestCase):
    """新增事件字段必须**同时**在前端登记，否则等于白做。

    这个坑踩过两次：`degraded`（注释写着"会进事件"，实际从没发过）与
    `block_source`（A-7 的核心交付物：区分 503 四种来源，Python 两处白名单都登记了，
    但 `frontend/src/types/api.ts` 与详情弹窗 0 处引用 → 用户在 UI 上看不到）。
    Python 白名单侧有 `test_new_fields_are_registered_in_both_whitelists` 守着，
    但"前端有没有登记"此前没有任何守卫，全靠人记 —— 所以在门禁里补上。
    """

    # UI 上必须有意义的字段（新增同类字段时加进来，这条测试就会替你盯着前端）
    UI_CRITICAL = (
        "block_source",
        "stream_degraded_reason",
        "queue_wait_ms",
        "aux_wait_ms",
        "upstream_idle_s",
        "engine_busy",
        "ner_global_throttled",
        "degraded",
    )

    def _read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_fields_declared_in_frontend_types(self):
        api_ts = self._read("frontend/src/types/api.ts")
        missing = [f for f in self.UI_CRITICAL if f not in api_ts]
        self.assertEqual(missing, [],
                         "字段进了 Python 白名单但前端类型里没有：%s（用户看不到等于没做）" % missing)

    def test_fields_are_rendered_or_have_labels(self):
        """类型声明之外还要真的被用到：详情弹窗渲染它，或至少有一处 i18n 文案。

        用**标识符边界**匹配（前后不能是 [A-Za-z0-9_]）而不是 `in`：子串匹配会让 `degraded` 被 `stream_degraded_reason`
        命中，于是字段一列都没渲染、守卫照样绿（本文件另一条按列名匹配的守卫就吃过这个
        亏：把 `audit_ms` 改名成 `audit_ms_x` 做注入验证时，因为 `_x` 里仍含原名字符串，
        红不了 —— 注入验证必须真的让名字消失）。
        """
        hay = (self._read("frontend/src/components/events/EventDetailDialog.tsx")
               + self._read("frontend/src/lib/i18n.tsx")).lower()
        missing = [f for f in self.UI_CRITICAL
                   if not re.search("(?<![A-Za-z0-9_])" + re.escape(f.lower())
                   + "(?![A-Za-z0-9_])", hay)]
        self.assertEqual(missing, [], "字段声明了但没有任何渲染/文案：%s" % missing)


#: 换行常量：这里刻意不直接写转义（本文件在多种 shell/编辑器下都会被读写，
#: 反斜杠 + n 的写法已被踩过一次——写成 chr(10) 最稳）。
NL = chr(10)

#: 合成进程表：(进程名, 命令行)。批量归类与逐 PID 判定都必须从**同一份**数据得出结论。
_FAKE_PROCS = {
    10: ("python.exe", "python -m mitmdump -p 18701 -s transparent.py"),
    11: ("python.exe", "python D:/x/engine/transparent.py"),
    12: ("maskitengine.exe", "MaskitEngine.exe"),
    13: ("python.exe", "python D:/work/engine/panel.py --port 5801"),
    14: ("chrome.exe", "chrome.exe --type=renderer"),
    15: ("py.exe", "py engine_entry.py"),
}


def _fake_run_console(procs=None):
    """把 tasklist / CIM / netstat 三种调用都指向合成进程表。

    ⚠️ 必须**尊重 `PID eq N` / `ProcessId=N` 过滤参**：被调函数拿到的就是单行，
    不回滤的全表会让「名字列」落到第一行别的进程上，测试就会得出假结论
    （第一版就这样误报过一次「判据漂移」）。
    """
    import re as _re
    table = _FAKE_PROCS if procs is None else procs

    def _run(cmd, timeout=None):
        argv = list(cmd) if isinstance(cmd, (list, tuple)) else [cmd]
        exe = (argv[0] or "").lower()
        joined = " ".join(str(x) for x in argv)
        asked = {int(x) for x in _re.findall(r"ProcessId=(\d+)", joined)}
        if exe == "tasklist":
            m = _re.search(r"PID eq (\d+)", joined)
            rows = [int(m.group(1))] if m else list(table)
            body = "".join('"%s","%d","Console","1","10,000 K"' % (table[p][0], p) + NL
                           for p in rows if p in table)
            return (0, body)
        if exe == "powershell":
            rows = asked or set(table)
            body = "".join("%d|%s" % (p, table[p][1] or "") + NL for p in rows if p in table)
            return (0, body)
        if exe == "netstat":
            body = "".join("  TCP    0.0.0.0:%d    0.0.0.0:0    LISTENING    %d" % (p, pid) + NL
                           for pid in table for p in (18701, 18702, 18703))
            return (0, body)
        return (0, "")
    return _run


class PidClassifyConsistencyTests(unittest.TestCase):
    """批量归类必须与逐 PID 判定**同判据**（0.6.0 新增）。

    背景：`_ports_snapshot` 原先对每个 (端口 × PID) 起 `tasklist`（认不出再拉 8s 超时的
    `Get-CimInstance`）—— 几十次子进程串在一次 UI 请求里。改成批量后判据是**重写**的，
    所以必须有对照测试，否则两边会悄悄漂移（一边认定 mitmdump、另一边认定面板）。

    两条路径读同一份合成进程表，逐条比对结论。
    """

    def setUp(self):
        import panel
        self.panel = panel
        self._orig = (panel._run_console, panel._read_process_cmdline,
                      dict(panel._PID_KIND_CACHE["data"]), panel._PID_KIND_CACHE["ts"])
        panel._run_console = _fake_run_console()
        panel._read_process_cmdline = lambda pid: (_FAKE_PROCS.get(int(pid), ("", ""))[1] or "")
        panel._PID_KIND_CACHE["ts"] = 0.0
        panel._PID_KIND_CACHE["data"] = {}

    def tearDown(self):
        panel = self.panel
        panel._run_console, panel._read_process_cmdline = self._orig[0], self._orig[1]
        panel._PID_KIND_CACHE["data"] = self._orig[2]
        panel._PID_KIND_CACHE["ts"] = self._orig[3]

    def test_batch_matches_per_pid_predicates(self):
        panel = self.panel
        batch = panel._classify_pids(list(_FAKE_PROCS), fresh=True)
        for pid in _FAKE_PROCS:
            single = ("mitmdump" if panel._is_mitmdump_pid(pid)
                      else "panel" if panel._is_shield_panel_pid(pid) else "other")
            self.assertEqual(batch[pid], single,
                             "PID %d 批量归类=%s 与逐 PID=%s 不一致（判据漂移）"
                             % (pid, batch[pid], single))
        self.assertEqual(batch[10], "mitmdump")
        self.assertEqual(batch[12], "panel")
        self.assertEqual(batch[14], "other")

    @unittest.skipUnless(sys.platform == "win32",
                         "判据基于 Windows 的 tasklist + PowerShell 路径；Linux/macOS 走 ps，不在本用例覆盖范围")
    def test_mitmdump_name_short_circuits_cim(self):
        """进程名就叫 mitmdump 时必须**不走** CIM（0.6.0 修列的 off-by-one）。

        原实现取 `split(",")[1]` 拿到的是 PID 字符串，于是 `"mitmdump" in name` 恒为假
        —— 每一次判定都白掉进 PowerShell `Get-CimInstance`（超时 8s）。这条守卫把
        "名字列 = 第 0 列" 钉住：名字命中就该短路，不命中才查命令行。
        """
        panel = self.panel
        procs = {90: ("mitmdump.exe", "mitmdump -p 18701"),
                 91: ("python.exe", "python -m mitmdump -p 18702")}
        panel._run_console = _fake_run_console(procs)
        panel._read_process_cmdline = lambda pid: (procs.get(int(pid), ("", ""))[1] or "")
        calls = []
        real = panel._run_console

        def counting(cmd, timeout=None):
            calls.append(cmd[0] if isinstance(cmd, (list, tuple)) else cmd)
            return real(cmd, timeout=timeout)

        panel._run_console = counting
        self.assertTrue(panel._is_mitmdump_pid(90), "名字含 mitmdump 应直接判真")
        self.assertEqual([c for c in calls if c == "powershell"], [],
                         "名字已命中还去查命令行（列序又错回 [1] 了？）")
        calls.clear()
        self.assertTrue(panel._is_mitmdump_pid(91), "python -m mitmdump 仍要靠命令行认定")
        self.assertTrue([c for c in calls if c == "powershell"],
                        "名字不含 mitmdump 时必须查命令行")

    @unittest.skipUnless(sys.platform == "win32",
                         "缓存与子进程计数走的是 Windows 的 tasklist/PowerShell 路径；Linux/macOS 走 ps")
    def test_batch_is_memoized(self):
        panel = self.panel
        calls = []
        real = panel._run_console

        def counting(cmd, timeout=None):
            calls.append((cmd[0] if isinstance(cmd, (list, tuple)) else cmd))
            return real(cmd, timeout=timeout)

        panel._run_console = counting
        panel._classify_pids([10], fresh=True)
        n = len(calls)
        self.assertGreater(n, 0)
        for _ in range(20):
            panel._classify_pids([10])
        self.assertEqual(len(calls), n, "缓存窗口内不该再起子进程")


class PortsSnapshotSubprocessBudgetTests(unittest.TestCase):
    """`_ports_snapshot` 的子进程次数必须有上限（防"每端口每 PID 一次"回归）。

    实测事故：UI 端点（一键自检/引擎指标）在这条路径上起几十次子进程，机器上端口
    一多就是几十秒的卡顿。批量归类后上限是 3 次（netstat + tasklist + CIM）。
    """

    def test_snapshot_uses_at_most_three_subprocesses(self):
        import panel
        cfg = panel.load_config()
        orig_run, orig_cache = panel._run_console, dict(panel._PID_KIND_CACHE["data"])
        calls = []

        def counting(cmd, timeout=None):
            calls.append(cmd[0] if isinstance(cmd, (list, tuple)) else cmd)
            return _fake_run_console()(cmd, timeout=timeout)

        panel._run_console = counting
        panel._PID_KIND_CACHE["ts"] = 0.0
        panel._PID_KIND_CACHE["data"] = {}
        try:
            out = panel._ports_snapshot(cfg, fresh=True)
        finally:
            panel._run_console = orig_run
            panel._PID_KIND_CACHE["data"] = orig_cache
        self.assertIsInstance(out, list, "端口快照不该出错：%r" % (out,))
        # 5 个监听 PID × 3 个端口在旧实现下至少 20+ 次。批量后的上限按平台取值：
        # Windows 走「netstat + tasklist + CIM」共 3 次；Linux/macOS 走 lsof + ss，
        # 3 个监听端口各一次 → 上界 6。两边都远小于“每端口每 PID 一次”。
        limit = 3 if sys.platform == "win32" else 6
        self.assertLessEqual(len(calls), limit,
                             "端口快照起了 %d 次子进程（上限 %d）：%s" % (len(calls), limit, calls))


class EmittedFieldRegistrationTests(unittest.TestCase):
    """发现式守卫：从 `_emit(...)` 调用点**发现**字段，逐个要求登记。

    与枚举式（手写 must / UI_CRITICAL 两份清单）的区别：手写清单看不见"新加了一个
    发射字段"。实战反例就是 `engine_queue_bytes` —— 当时已发射、已渲染，但两处 Python
    白名单都没登记，导出与诊断包里静默丢失，而守卫全绿（守卫检查的是它的清单，
    不是引擎的行为）。

    现在每个被发射的字段必须落在三处之一：
      ① 事件导出白名单 `_EXPORT_KEEP_FIELDS`（会进 CSV/JSON 导出）
      ② 诊断包 `keep = (...)`（会进诊断包）
      ③ `NOT_EXPORTED`：**显式**声明不外传，且必须写一句理由
    目的是让"不导出"变成一次决定，而不是一次遗漏。

    白名单与发射字段都用 AST 取：原实现用字符串切分（`split("keep = (")`），
    改个格式就会静默抓错区域或直接 IndexError —— 属维护陷阱，顺手换掉。
    """

    #: 刻意不进任何外传名单的字段（正文类含 PII 明文，见 panel.py 导出白名单的注释）。
    #: 每项一句理由；键必须仍是"被发射的字段"（有新字段忘登记时下面的断言会红）。
    NOT_EXPORTED = {
        "req_preview": "请求正文预览：含 PII 明文，导出即外泄",
        "resp_preview": "响应正文预览：还原后含 PII 明文",
        "dialog": "对话正文（还原后）：含 PII 明文",
        "dialog_req": "请求侧对话正文：含 PII 明文",
        "evidence": "审计证据串：可能含正文片段（审计条目另走 audit_events）",
        "signal": "审计标签：随 audit_events 走单独导出；事件导出保持最小元数据",
        "severity": "审计等级：同上（弹窗里可看）",
        "items": "打码条目：导出侧单独做 original 剔除后保留（见 panel.py 的 clean_items）",
        "restore_status": "还原态枚举：仅列表/弹窗展示",
        "unresolved": "未还原占位符数：仅展示与自检",
        "restored_unique": "还原去重数：仅展示",
        "masked_total": "本轮打码总数：仅展示",
        "new_count": "本轮新增映射数：仅展示",
        "suffix_reused": "后缀复用次数：仅诊断",
        "body_rewritten": "是否改写 body：仅诊断",
        "short_hits": "短命中统计：仅诊断",
        "scan_scope": "扫描范围：仅诊断",
        "first_diff_byte": "首个差异字节：仅诊断",
        "content_type": "内容类型：仅诊断（导出有 path/type 已够）",
        "success": "成功态布尔：仅展示（状态由 type/status 表达）",
        # 统一口径里唯一不外传的一项：标记是用户粘进来的**短效凭据**。
        # `onboarding.scrub(diagnostic=True)` 为诊断包剔的就是它，导出走同一口径。
        "verification": "接入验证证据（含入口标记与弱关联元数据）：标记不得外传（§E）",
    }

    def _emitted_fields(self):
        tree = ast.parse((ROOT / "engine" / "transparent.py").read_text(encoding="utf-8"))
        fields = _restore_summary_fields(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "_emit"):
                fields.update(k.arg for k in node.keywords if k.arg)
        self.assertGreater(len(fields), 20, "没从 _emit 里发现字段？AST 解析是不是失配了")
        return fields

    def _whitelists(self):
        tree = ast.parse((ROOT / "engine" / "panel.py").read_text(encoding="utf-8"))
        export, diag = set(), set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                if tgt.id == "_EXPORT_KEEP_FIELDS" and isinstance(node.value, ast.Set):
                    export = {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
                elif (tgt.id == "keep" and isinstance(node.value, (ast.Tuple, ast.List))):
                    got = {e.value for e in node.value.elts
                           if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                    if len(got) > len(diag):
                        diag = got
        self.assertGreater(len(export), 20, "没解析到导出白名单（改名了？）")
        self.assertGreater(len(diag), 15, "没解析到诊断包白名单（改名了？）")
        return export, diag

    def test_every_emitted_field_is_registered_or_explicitly_excluded(self):
        emitted = self._emitted_fields()
        export, diag = self._whitelists()
        unregistered = sorted(emitted - export - diag - set(self.NOT_EXPORTED))
        self.assertEqual(unregistered, [],
                         "这些字段既没进导出/诊断白名单，也没在 NOT_EXPORTED 里说明理由："
                         "%s（漏登记就会像 engine_queue_bytes 一样静默丢出导出）" % unregistered)

    def test_ner_inventory_reaches_every_projection_and_frontend_merge(self):
        fields = set(tr._NER_EVENT_METRICS)
        export, diag = self._whitelists()
        self.assertGreaterEqual(len(fields), 9)
        self.assertTrue(fields <= panel._TAIL_KEEP_FIELDS)
        self.assertTrue(fields <= export)
        self.assertTrue(fields <= diag)
        types = (ROOT / "frontend/src/types/api.ts").read_text(encoding="utf-8")
        merge = (ROOT / "frontend/src/lib/log-events.ts").read_text(encoding="utf-8")
        for field in fields:
            self.assertRegex(types, rf"\b{field}\?:\s*number")
            self.assertRegex(merge, rf"\b{field}:\s*r\.{field}\s*\?\?\s*m\.{field}")

    def test_not_exported_list_has_no_rot(self):
        """NOT_EXPORTED 不许留腐烂条目：字段改名/删掉后，这里必须同步（否则它会
        悄悄把"新字段"也算成已登记 —— 名字相同但语义已变）。"""
        emitted = self._emitted_fields()
        export, diag = self._whitelists()
        # 腐烂判据把「**能入库**的字段」也算作“确实存在”：统一口径那批是用
        # `**inspection.report(...)` 字典展开发射的，AST 扫不到它们的键（见下一条测试），
        # 只认 emitted 会把声明得好好的条目误判成腐烂。
        alive = emitted | set(event_store._SUMMARY_KEEP_FIELDS)
        stale = sorted(set(self.NOT_EXPORTED) - alive)
        self.assertEqual(stale, [], "NOT_EXPORTED 里这些字段已经不再被发射了：%s" % stale)
        overlap = sorted(set(self.NOT_EXPORTED) & (export | diag))
        self.assertEqual(overlap, [], "这几项既声明不外传、又在白名单里（自相矛盾）：%s" % overlap)

    def test_every_storable_field_is_exported_or_explicitly_excluded(self):
        """**能入库**的字段必须在导出/诊断白名单里，或在 NOT_EXPORTED 里声明。

        为什么不能只看上面那条守卫扫出的 `_emit` 字段：统一口径那批
        （`decision`/`completeness`/`reason_codes`/`signed_blocks_skipped`…）是通过
        `**inspection.report_for_mask(...)` **字典展开**发射的，AST 看不见它们的键 ——
        那条守卫对它们**完全无效**，而它们恰恰是“这条到底算不算扫干净了”的唯一
        机器可读结论。2026-10-04 实测：这批字段能入库、详情页看得见，**导出里一个都没有**
        （拿导出找人复盘，只能看到现象“命中 0 条”，看不到结论“直通未脱敏/检测不完整”）。
        以 `event_store._SUMMARY_KEEP_FIELDS`（能入库的全集）作源，盲区就补上了：
        新增一个能入库的字段，要么进白名单，要么在这里写下不外传的理由。
        """
        storable = set(event_store._SUMMARY_KEEP_FIELDS)
        export, diag = self._whitelists()
        unregistered = sorted(storable - export - diag - set(self.NOT_EXPORTED))
        self.assertEqual(unregistered, [],
                         "这些字段能入库，却既不在导出/诊断白名单、也没声明不外传：%s"
                         "（导出是出事时拿给人看的那份，漏了就是静默少一列）" % unregistered)


class AuditTunablePersistenceTests(unittest.TestCase):
    """`audit.scan_max` / `parse_max` / `time_budget_ms` 必须活过一次 load_config。

    这三个键引擎侧真的读（`transparent._read_settings` 的 `audit_scan_max` 等，自带上下限
    钳制），但 `_normalize_audit` 原先不返回它们 —— 而 `load_config` 在归一化产物与盘上
    内容有差异时会**写回磁盘**（`save_config(cfg, allow_shrink=True)`）。
    净结果：用户手改 config.json → 任何一次 load_config 把键抹掉 → 引擎回落默认窗口。
    最讽刺的是自检提示里正写着"可手改 config.json 的 audit.scan_max"，而自检自己就调
    load_config —— 等于照提示改、被自己抹。这里锁住"改了就留得住"。
    """

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {k: getattr(panel, k)
                       for k in ("ROOT", "CONFIG_PATH", "DATA_ROOT")}
        panel.ROOT = self.tmp
        panel.CONFIG_PATH = self.tmp / "config.json"
        panel.DATA_ROOT = self.tmp
        cfg = json.loads((ROOT / "engine" / "config.example.json").read_text(encoding="utf-8"))
        cfg.setdefault("audit", {})["scan_max"] = 524288
        cfg["audit"]["time_budget_ms"] = 500
        self._write(cfg)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(panel, k, v)

    def _write(self, cfg):
        panel.CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

    def _audit_block(self):
        return json.loads(panel.CONFIG_PATH.read_text(encoding="utf-8"))["audit"]

    def test_tunables_survive_load_config(self):
        panel.load_config()
        panel.load_config()          # 第二次是幂等的"回写"，正是原先抹键的时机
        blk = self._audit_block()
        self.assertEqual(blk.get("scan_max"), 524288, "手改的 scan_max 被归一化写回抹掉了")
        self.assertEqual(blk.get("time_budget_ms"), 500)

    def test_normalize_passes_through_tunables(self):
        out = panel._normalize_audit({"scan_max": 524288, "parse_max": 4194304,
                                      "time_budget_ms": 500})
        self.assertEqual((out.get("scan_max"), out.get("parse_max"), out.get("time_budget_ms")),
                         (524288, 4194304, 500))

    def test_normalize_drops_garbage_but_keeps_bools_out(self):
        """非数值不写回；bool 是 int 子类，必须显式排除（否则 True 会被当成字节数）。"""
        out = panel._normalize_audit({"scan_max": "很大", "parse_max": True})
        self.assertNotIn("scan_max", out)
        self.assertNotIn("parse_max", out)

    def test_absent_tunables_do_not_appear(self):
        """用户没写过就不该凭空长键（否则每份配置都会多三行噪音）。"""
        out = panel._normalize_audit({"enabled": True})
        self.assertEqual([k for k in ("scan_max", "parse_max", "time_budget_ms") if k in out], [])


class AuditColumnReachabilityTests(unittest.TestCase):
    """发现式守卫：`audit_events` 的每一列都要在前端审计弹窗里可达。

    为什么是发现式：枚举式清单（手写 UI_CRITICAL）**看不见新增列** —— 这正是
    `audit_ms`/`audit_scan_bytes`/`audit_scan_truncated` 的处境：后端落了库、
    `/api/audit/events` 也在 SELECT 里返回（event_store.py），但前端只有**事件**弹窗
    引用了它们（事件表根本没有这三列 → 死分支），而真正为审计行打开的
    `AuditEventDetailDialog` 一列都没渲染。A-1 的可观测承诺在 UI 上等于零。
    所以这里从 `CREATE TABLE audit_events` 反推列名，逐列要求"在审计弹窗里可达"。
    """

    #: 刻意不在审计弹窗里显示的列（元数据/内部标识），每项一句理由。
    NOT_SHOWN = {
        "id": "自增主键：接口按 seq 引用，弹窗不需要",
        "ts": "时间：弹窗标题右侧已显示（dayjs 格式化）",
        "sid": "会话 id：列表页用于分组，弹窗不重复",
        "request_hash": "指纹：供比对用，弹窗不展示（导出全量带）",
        "response_hash": "指纹：同上",
    }

    def _columns(self):
        src = (ROOT / "engine" / "event_store.py").read_text(encoding="utf-8")
        i = src.index("CREATE TABLE IF NOT EXISTS audit_events")
        body = src[i:src.index(")", src.index("(", i))]
        cols = []
        for raw in body.splitlines()[1:]:
            line = raw.strip()
            if not line or line.startswith("--"):      # SQL 注释行不是列定义
                continue
            name = line.split()[0].strip(",")
            if name and not name.startswith(("PRIMARY", "UNIQUE", "FOREIGN", "CHECK")):
                cols.append(name)
        self.assertIn("audit_ms", cols, "没解析到 audit_events 列名（表定义改了？）")
        return cols

    def _dialog_source(self):
        """只看**审计弹窗**：类型里声明了但没渲染，正是本轮要防的那件事。

        守卫第一版把 `types/api.ts` 也算进"可达"，结果注入验证时**没红** ——
        类型声明让所有列都"可达"，包括一列都没渲染的情形。收窄成只看渲染窗体后，
        删掉渲染就会红（已复核）。
        """
        return (ROOT / "frontend/src/components/audit/AuditEventDetailDialog.tsx").read_text(encoding="utf-8")

    def test_every_audit_column_is_shown_in_the_audit_dialog(self):
        hay = self._dialog_source()
        missing = [c for c in self._columns()
                   if c not in hay and c not in self.NOT_SHOWN]
        self.assertEqual(missing, [],
                         "这些 audit_events 列在前端审计弹窗/类型里都不可达：%s"
                         "（后端落了库也返回了，但用户在 UI 上看不到 → 等于没做）" % missing)

    def test_not_shown_list_has_no_rot(self):
        stale = sorted(set(self.NOT_SHOWN) - set(self._columns()))
        self.assertEqual(stale, [], "NOT_SHOWN 里这些列已不存在：%s" % stale)

    def test_these_fields_are_not_rendered_from_the_events_table(self):
        """反向守卫：事件弹窗不许再引用审计列（那是死分支，写过一次）。

        它们只存在于 audit_events；挂在事件弹窗上永远读到 undefined，
        看起来"渲染了"而用户永远看不到 —— 比不渲染更糟（骗过评审）。
        """
        ev = (ROOT / "frontend/src/components/events/EventDetailDialog.tsx").read_text(encoding="utf-8")
        for col in ("audit_scan_truncated", "audit_scan_bytes", "audit_ms"):
            self.assertNotIn(col, ev, "事件弹窗引用了审计列 %s（events 表没有它 → 死分支）" % col)


class PortHolderSelfClassificationTests(unittest.TestCase):
    """面板进程自己 bind 期望端口时，holder 必须判成 "panel"。

    面板会在自己进程内 bind 期望端口做 passthrough / 兜底 503（代理停止时的
    **默认态**），而 `_classify_pids` 与 `_is_shield_panel_pid` 都刻意排除自身 PID
    （它们服务于“清理占位进程”，把自己算进去会误杀）。若不在这里单独认一次自身，
    holder 会落进 "other" → 自检 S03 报「端口被其他进程占用，请关掉占用该端口的
    程序」—— 在完全正常的默认状态下吓用户，而且给出的动作无效。
    """

    def test_own_pid_is_classified_as_panel(self):
        me = os.getpid()
        cfg = {"capture_mode": "reverse",
               "upstreams": [{"port": 18841, "base_url": "https://api.openai.com"}]}
        with mock.patch.object(panel, "_listening_port_pids", return_value={18841: [me]}), \
             mock.patch.object(panel, "_classify_pids", return_value={}):
            out = panel._ports_snapshot(cfg, fresh=True)
        self.assertIsInstance(out, list, "端口快照不该出错：%r" % (out,))
        ports = {p["port"]: p for p in out}
        self.assertEqual(ports.get(18841, {}).get("holder"), "panel",
                         "面板自持端口被判成 other → 自检 S03 误报")

    def test_unknown_pid_still_reports_other(self):
        """反向守卫：真正的外部占位者仍必须报 other（别把修复做成无条件 panel）。"""
        cfg = {"capture_mode": "reverse",
               "upstreams": [{"port": 18842, "base_url": "https://api.openai.com"}]}
        with mock.patch.object(panel, "_listening_port_pids", return_value={18842: [999999]}), \
             mock.patch.object(panel, "_classify_pids", return_value={}):
            out = panel._ports_snapshot(cfg, fresh=True)
        ports = {p["port"]: p for p in out}
        self.assertEqual(ports.get(18842, {}).get("holder"), "other")


if __name__ == "__main__":
    unittest.main()