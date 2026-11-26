"""命令拦截（config.command_block）契约测试：W2-1 探测 / W2-2 改写 / W2-3 配置 / W2-4 阻断。

设计依据：DESIGN-audit-upgrade.md §6 / §7 W2。四条不可违反的口径：
1. **思考通道恒排除**——模型在思考里权衡「要不要 rm -rf /」不是下发命令，
   既不记录也不改写（但会用来压掉全量 S9 扫描的对应误报）；
2. **默认 observe**——只记录，响应字节零变化；
3. **删除不复活**——`patterns` 键缺失才灌内置种子，键存在（哪怕是 `[]`）一律尊重；
4. **回声抑制 > 白名单 > 黑名单**——请求里已出现的命令既不记录也不改写。
"""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))

import panel
import transparent as tr
from shield_defaults import BUILTIN_COMMAND_BLOCK_PATTERNS

BUILTINS = [dict(p) for p in BUILTIN_COMMAND_BLOCK_PATTERNS]


def _cfg(mode="observe", patterns=None, channels=("tool",), allow=None):
    """按 config.json 的形状构造 command_block 配置（走生产的解析路径）。"""
    return {
        "mode": mode,
        "patterns": BUILTINS if patterns is None else patterns,
        "channels": list(channels),
        "allow_patterns": list(allow or []),
    }


class CommandBlockTestBase(unittest.TestCase):
    SID = "cmd-block-test"

    def setUp(self):
        tr._new_session(self.SID)
        self._old_cb = tr.COMMAND_BLOCK
        self.addCleanup(self._restore_cb)

    def _restore_cb(self):
        tr.COMMAND_BLOCK = self._old_cb
        tr._drop(self.SID)

    def use(self, **kw):
        tr.COMMAND_BLOCK = tr._parse_command_block(_cfg(**kw))
        return tr.COMMAND_BLOCK

    def session(self):
        return tr.sessions[self.SID]


class DetectionTests(CommandBlockTestBase):
    """W2-1：槽位级探测（默认 observe：只记录、零改写）。"""

    def test_default_config_is_observe_and_records_tool_hits(self):
        self.use()
        text = "好的，现在执行 rm -rf / --no-preserve-root"
        self.assertEqual(tr._cmd_process(text, "c0.tool0", self.SID), text, "observe 必须零改写")
        hits = self.session().get("cmd_hits") or []
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["channel"], "tool")
        self.assertIn("rm -rf /", hits[0]["snippet"])
        self.assertIn("builtin-rm-root", hits[0]["kind"])

    def test_reason_channel_never_produces_items(self):
        """① 思考通道出现 rm -rf / → 零 finding、零改写（设计决定）。"""
        self.use(mode="rewrite")
        text = "我在考虑要不要 rm -rf / 但这样会删掉整个系统"
        self.assertEqual(tr._cmd_process(text, "c0.reason", self.SID), text)
        r2 = self.session()
        self.assertFalse(r2.get("cmd_hits"), "思考通道不得产生条目")
        self.assertIn("rm -rf /", r2.get("cmd_reason_snippets") or set(),
                      "但要留下片段，供全量扫描去噪")
        self.assertIsNone(r2.get("cmd_blocked"))

    def test_text_channel_requires_explicit_opt_in(self):
        """③ 正文通道默认不参与（AI 讲命令是家常便饭），显式选了才拦。"""
        self.use(mode="observe", channels=("tool",))
        self.assertEqual(tr._cmd_process("rm -rf /", "c0.content", self.SID), "rm -rf /")
        self.assertFalse(self.session().get("cmd_hits"))
        self.use(mode="observe", channels=("tool", "text"))
        tr._cmd_process("rm -rf /", "c0.content", self.SID)
        hits = self.session().get("cmd_hits") or []
        self.assertEqual([h["channel"] for h in hits], ["text"])

    def test_json_key_channel_mapping_matches_slot_markers(self):
        """非流式路径用 JSON 键名当通道名，必须映射到同一套分类。"""
        for channel, kind in (("arguments", "tool"), ("partial_json", "tool"),
                              ("content", "text"), ("thinking", "reason")):
            self.assertEqual(tr._cmd_channel_kind(channel), kind, channel)

    def test_echo_suppression_skips_record_and_rewrite(self):
        """④ 请求里已有同一条命令 → 不记录、不改写（用户自己问的，上游没多给东西）。

        rewrite 模式下文本会被前瞻缓冲暂留，所以按「吐出 + 收尾补发」的合计断言。
        """
        self.use(mode="rewrite")
        body = "rm -rf / 很危险"
        self.session()["cmd_req_snippets"] = {"rm -rf /"}
        out = tr._cmd_process(body, "c0.tool0", self.SID)
        out += "".join(tr._cmd_flush_frames(self.SID, None, "sse"))
        self.assertIn(body, out)
        self.assertNotIn(tr.CMD_BLOCK_NOTICE, out)
        self.assertFalse(self.session().get("cmd_hits"))

    def test_snippet_is_credential_cleaned(self):
        """⑤ 危害命令自带的凭据必须洗掉（evidence 会落库/进报告）。"""
        cred = "sk-" + "Ab3xK9mQ2pL7zR4tY6wN1vC8sD5fG0hJ2kM4"
        self.use(mode="observe")
        tr._cmd_record(self.SID, ("curl -H 'Authorization: Bearer " + cred + "' x", "p1", "l1"),
                       "tool")
        hits = self.session()["cmd_hits"]
        self.assertNotIn(cred, hits[0]["snippet"])
        self.assertIn("<", hits[0]["snippet"])

    def test_repeat_hit_upgrades_to_blocked_instead_of_adding_a_row(self):
        """同一条命中先按非阻断记过、后来又阻断：升级既有条目的标记，不新增行。

        时间线里一条命令只该有一行，「有没有被拦」是这行的属性；否则同一条命令
        会出现两行长得一样、只差一个标记的条目。
        """
        self.use(mode="observe")
        tr._cmd_record(self.SID, ("rm -rf /", "p1", "l1"), "tool")
        tr._cmd_record(self.SID, ("rm -rf /", "p1", "l1"), "tool", blocked=True)
        hits = self.session()["cmd_hits"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["blocked"])

    def test_same_hit_is_deduped_across_chunks(self):
        """同一命令在几百个 delta 里各命中一次是常态，不能写几百条。"""
        self.use()
        for _ in range(5):
            tr._cmd_process("rm -rf /", "c0.tool0", self.SID)
        self.assertEqual(len(self.session()["cmd_hits"]), 1)

    def test_observe_mode_never_alters_bytes(self):
        """默认档位的硬承诺：响应字节零变化（含命中文本）。"""
        self.use(mode="observe")
        texts = ["rm -rf /", "正常回复", "a" * 500 + " rm -rf ~ ", "", "rm -rf dist"]
        for t in texts:
            self.assertEqual(tr._cmd_process(t, "c0.tool0", self.SID), t, t[:20])

    def test_whitelisted_command_is_ignored(self):
        """白名单优先于黑名单：`rm -rf dist` 天天见，挡住一次用户就关掉整个功能。"""
        self.use(channels=("tool",), allow=[r"rm\s+-rf\s+dist"])
        self.assertIsNone(tr._cmd_find("rm -rf dist"))
        self.assertIsNotNone(tr._cmd_find("rm -rf /"))

    def test_empty_patterns_is_a_noop(self):
        self.use(patterns=[])
        self.assertEqual(tr._cmd_process("rm -rf /", "c0.tool0", self.SID), "rm -rf /")
        self.assertFalse(self.session().get("cmd_hits"))


class RewriteTests(CommandBlockTestBase):
    """W2-2：就地改写。核心风险是流式（跨 chunk）与 JSON 合法性。"""

    def test_cross_chunk_split_command_is_rewritten(self):
        """① 命令被刻意切成 3 块仍必须完整改写（有界前瞻缓冲的作用）。"""
        self.use(mode="rewrite")
        out = ""
        # 注意块间要有空白：`xxxrm -rf /` 里 `\brm` 不匹配（xxx 与 rm 都是词字符），
        # 那测的就不是跨块缓冲而是「拼接出的非命令」了
        for chunk in ("x" * 100 + " ", "rm -r", "f /", " 完成"):
            out += tr._cmd_process(chunk, "c0.tool0", self.SID)
        out += "".join(tr._cmd_flush_frames(self.SID, None, "sse"))
        self.assertIn(tr.CMD_BLOCK_NOTICE, out)
        self.assertNotIn("rm -rf /", out)
        self.assertIn("完成", out, "命令之后的正文不能被吞")

    def test_tail_is_released_so_nothing_is_swallowed(self):
        """② 绝不吞尾部：hold 住的尾巴在流末必须补发。"""
        self.use(mode="rewrite")
        body = "y" * 40  # 短于 hold（64），会被整段暂留
        self.assertEqual(tr._cmd_process(body, "c0.tool0", self.SID), "")
        self.assertTrue(self.session()["cmd_pend"]["c0.tool0"])
        # final=True 时一次性吐出（收尾帧文本常为空，不能因「空文本」早返回）
        self.assertEqual(tr._cmd_process("", "c0.tool0", self.SID, final=True), body)

    def test_rewrite_keeps_tool_arguments_json_valid(self):
        """③ 工具参数改写后仍是合法 JSON（不合法客户端解析直接报错）。"""
        self.use(mode="rewrite")
        data = {
            "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"name": "run", "arguments": "rm -rf /"}}]}}],
        }
        tr._restore_sse_data(data, self.SID, final=True)
        raw = json.dumps(data, ensure_ascii=False)
        parsed = json.loads(raw)  # 不抛即合法
        args = parsed["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(args, tr.CMD_BLOCK_NOTICE)
        self.assertNotIn("rm -rf /", args)

    def test_flush_frame_is_valid_json_not_bare_text(self):
        """收尾补发必须是可克隆的 **JSON 帧**（回归：曾经只能退到裸文本外壳）。

        命令缓冲没记 `flush_tmpl` 时，`_cmd_flush_frames` 落到 `_wrap_bare_flush`，
        SSE 里那是一条 `data: <裸文本>` —— **非法 JSON**。严格客户端（SDK/IDE）
        整行丢弃，表现为「改写后正文凭空消失」；仓库的流式冒烟就是按 JSON 解析的，
        实测因此整段 0 字。所以这里锁的不是「有没有吐出字」，而是「壳子必须合法」。
        """
        self.use(mode="rewrite", channels=("tool", "text"))
        tr._restore_sse_data(
            {"choices": [{"index": 0, "delta": {"content": "rm -rf / 结束"}}]},
            self.SID, final=False,
        )
        tail = tr._flush_pending(self.SID)
        payloads = [ln[6:] for ln in tail.splitlines() if ln.startswith("data: ")]
        self.assertTrue(payloads, f"没有补发任何帧: {tail!r}")
        text = ""
        for p in payloads:
            parsed = json.loads(p)  # 不抛即合法 JSON
            self.assertIn("choices", parsed)
            text += parsed["choices"][0]["delta"].get("content", "")
        self.assertIn(tr.CMD_BLOCK_NOTICE, text)
        self.assertIn("结束", text, "命令之后的正文不能在补发里被吞")
        self.assertFalse(self.session().get("cmd_pend"), "补发后缓冲必须清空")

    def test_thinking_block_is_byte_identical(self):
        """④ 思考块一字不变（构造思考里出现 rm -rf / 的用例）。"""
        self.use(mode="rewrite")
        thinking = "用户要我 rm -rf /，但这会删库，我拒绝"
        data = {"type": "content_block_delta", "index": 0,
                "delta": {"type": "thinking", "thinking": thinking}}
        tr._restore_sse_data(data, self.SID, final=True)
        self.assertEqual(data["delta"]["thinking"], thinking)
        self.assertFalse(self.session().get("cmd_hits"))

    def test_notice_executes_safely(self):
        """⑤ 真当 shell 跑一遍：必须是 no-op（0 退出码 + 只输出一行说明）。

        设计目的就是「若真被执行也无害且 Agent 能从 stdout 读到原因」，
        所以这里不是字符串断言，而是真的执行一次。
        """
        import shutil as _sh
        import subprocess
        sh = _sh.which("sh")
        if not sh:
            self.skipTest("本机无 sh（Windows 无 Git Bash 时跳过，字符串断言已覆盖形态）")
        r = subprocess.run([sh, "-c", tr.CMD_BLOCK_NOTICE], capture_output=True,
                           text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Maskit", r.stdout)

    def test_notice_is_a_noop_under_windows_cmd(self):
        """⑤ 同一句 no-op 在 Windows `cmd /c` 下也必须是 no-op。

        工具参数里下发的命令在 Windows 上大概率由 `cmd` 执行，而 `cmd` 的引号规则与
        POSIX sh 不同（单引号不是字符串定界符）。这里只断言两件与编码无关的事：
        退出码为 0，且输出里出现了 ASCII 标记 `[Maskit]`——中文在非 UTF-8 代码页下
        可能显示为乱码，那是显示层问题，不影响 no-op 语义（且我们不做任何拼接）。
        """
        if os.name != "nt":
            self.skipTest("仅在 Windows 上验 cmd")
        import subprocess
        r = subprocess.run(["cmd", "/c", tr.CMD_BLOCK_NOTICE], capture_output=True,
                           timeout=10)
        self.assertEqual(r.returncode, 0)
        out = r.stdout.decode("utf-8", errors="replace")
        if "[Maskit]" not in out:
            # 控制台代码页非 UTF-8（如 cp936）时改用本地代码页再解一次
            import locale
            out = r.stdout.decode(locale.getpreferredencoding(False), errors="replace")
        self.assertIn("[Maskit]", out, f"cmd 下未打印说明: {r.stdout!r}")
        self.assertNotIn("\x00", out)

    def test_notice_is_a_fixed_noop_string(self):
        """⑤ 改写文本无害性：固定 no-op，不拼任何变量。

        拼入被拦命令原文等于用我们自己的改写文本把命令重新引入——原文里的
        单引号一闭一开就能构造出 `echo '…' ; <危险命令> #`。
        """
        self.assertTrue(tr.CMD_BLOCK_NOTICE.startswith("echo '"))
        self.assertNotIn("{", tr.CMD_BLOCK_NOTICE)
        self.assertEqual(tr.CMD_BLOCK_NOTICE.count("'"), 2)
        self.assertNotIn("\\", tr.CMD_BLOCK_NOTICE)

    def test_duplicate_commands_in_one_payload_are_all_rewritten(self):
        self.use(mode="rewrite")
        out = tr._cmd_process("A" * 70 + " rm -rf / 然后 rm -rf ~ ", "c0.tool0", self.SID)
        # 尾巴还在前瞻缓冲里，走统一入口补发（同样要改写+留痕）
        out += "".join(tr._cmd_flush_frames(self.SID, None, "sse"))
        self.assertEqual(out.count(tr.CMD_BLOCK_NOTICE), 2)
        self.assertFalse(self.session().get("cmd_pend"))


class BlockTests(CommandBlockTestBase):
    """W2-4：block 模式（显式选择，非默认）。"""

    def test_block_suppresses_this_and_following_content(self):
        self.use(mode="block")
        # 命令必须在**扫描窗口之内**才会命中：窗口是「去掉最后 hold 个字符」的部分，
        # 所以这里把命令放开头、后面跟足正文（hold=最长模式源长−1，≤64）
        self.assertEqual(tr._cmd_process("rm -rf / " + "z" * 100, "c0.tool0", self.SID), "")
        self.assertTrue(self.session().get("cmd_blocked"))
        self.assertEqual(tr._cmd_process("之后的正常内容", "c0.tool0", self.SID), "")

    def test_block_never_rewrites_notice(self):
        """block 不等于 rewrite：命中即停止下发，不会把说明文本交给客户端。"""
        self.use(mode="block")
        out = tr._cmd_process("rm -rf / " + "q" * 100, "c0.tool0", self.SID)
        out += "".join(tr._cmd_flush_frames(self.SID, None, "sse"))
        self.assertNotIn(tr.CMD_BLOCK_NOTICE, out)
        self.assertNotIn("q" * 10, out, "已阻断的会话不该继续下发内容")

    def test_nonstream_response_is_replaced_with_structured_error(self):
        """非流式整包换成 503 + 结构化错误体（流式路径靠槽位置空截断，见 _cmd_process）。"""
        self.use(mode="block")
        sid = self.SID
        body = {"choices": [{"message": {"tool_calls": [
            {"function": {"name": "run", "arguments": "rm -rf /"}}]}}]}
        flow = SimpleNamespace(
            request=SimpleNamespace(host="api.openai.com", method="POST",
                                    path="/v1/chat/completions",
                                    content=json.dumps({"model": "gpt-4o"}).encode("utf-8")),
            response=SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                                     content=json.dumps(body).encode("utf-8")),
            metadata={"session_id": sid},
        )
        with mock.patch.object(tr, "is_target", lambda h, p: True), \
             mock.patch.object(tr, "_audit_response", lambda *a, **k: None), \
             mock.patch.object(tr, "_scan_response", lambda *a, **k: None):
            asyncio.run(tr.response(flow))
        self.assertEqual(flow.response.status_code, 503)
        payload = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(payload["error"]["code"], "shield_command_blocked")

    def test_block_emits_no_request_level_block_event(self):
        """阻断留痕**不得**写成 BLOCK 主事件（回归：曾如此，导致首页双计）。

        `event_store` 把 BLOCK 同时计入 requests 与 alerts，而这条请求早已按 MASK
        记过一次账；响应侧命令阻断发生在请求发出之后，再发 BLOCK 会让首页的
        请求数与告警数同时虚高。留痕走审计信号（另见 AuditMergeTests 的 [已阻断] 断言）。
        """
        self.use(mode="block")
        emitted = []
        with mock.patch.object(tr, "_emit", lambda typ, **kw: emitted.append(typ)):
            tr._cmd_process("rm -rf / " + "z" * 100, "c0.tool0", self.SID)
        self.assertNotIn("BLOCK", emitted, "响应侧阻断不是请求级 BLOCK")
        self.assertTrue(self.session()["cmd_hits"][0]["blocked"],
                        "但必须留下「已阻断」标记，否则用户不知道拦了什么")

    def test_pending_placeholder_tail_is_not_flushed_after_block(self):
        """阻断之后连占位符半截缓冲也不再补发（回归：曾会补出一帧残片）。

        `_cmd_flush_frames` 有 blocked 守卫，`pending` 那条补发路径当时没有——
        客户端会在「已停止下发」之后又收到一帧 `{{PHONE_zz` 之类的残片。
        """
        self.use(mode="block")
        self.session()["rev"] = {"{{PHONE_zzzzzz}}": "000-0000-0000"}
        # ① 正文通道留一个半截占位符在 pending（尚未流末）
        tr._restore_sse_data({"choices": [{"index": 0, "delta": {"content": "客户电话 {{PHONE_zz"}}]},
                             self.SID, final=False)
        self.assertTrue(self.session().get("pending"), "前置条件：确实有半截占位符")
        # ② 工具参数通道命中 block，此后不再有任何正文 delta
        tr._restore_sse_data({"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "rm -rf / " + "B" * 100}}]}}]},
            self.SID, final=False)
        self.assertTrue(self.session().get("cmd_blocked"), "前置条件：确实已阻断")
        self.assertEqual(tr._flush_pending(self.SID), "",
                         "已阻断的会话不得补发任何帧")
        self.assertFalse(self.session().get("pending"), "缓冲也要清掉，不留在会话里")


class EchoBaselineTests(CommandBlockTestBase):
    """回声基线的**惰性**性能契约（回归：曾在每个请求上扫满 512KB）。

    实测 7 条规则扫满窗口约 29µs/KB（512KB≈15ms，与既有 mask 主链路同阶），
    而它当时对**每个请求**都执行——绝大多数请求根本不会命中任何命令。
    现在请求期只暂存有界切片，首次真需要判定回声时才扫一次。
    """

    def test_request_time_only_stashes_a_bounded_window(self):
        self.use(mode="observe")
        tr._remember_request_cmd_snippets(self.SID, b"x" * 1000 + b" rm -rf / ")
        s = self.session()
        self.assertIn("cmd_req_window", s, "请求期只暂存窗口")
        self.assertNotIn("cmd_req_snippets", s, "请求期不得直接扫（那是每请求白加延迟）")
        self.assertTrue(tr._cmd_is_echo(self.SID, "rm -rf /"), "首次判定时才扫")
        self.assertNotIn("cmd_req_window", s, "算完即丢窗口，不驻留请求体")
        self.assertIsInstance(s["cmd_req_snippets"], set)

    def test_window_is_capped_and_only_computed_once(self):
        self.use(mode="observe")
        tr._remember_request_cmd_snippets(self.SID, b"x" * (tr._SCAN_BODY_MAX + 4096))
        self.assertEqual(len(self.session()["cmd_req_window"]), tr._SCAN_BODY_MAX,
                         "窗口必须有界（请求体上限 32MB，不能整份进会话）")
        tr._cmd_is_echo(self.SID, "rm -rf /")
        self.assertFalse(tr._cmd_is_echo(self.SID, "rm -rf / not-a-hit"))

    def test_no_patterns_keeps_no_window(self):
        self.use(mode="observe", patterns=[])
        tr._remember_request_cmd_snippets(self.SID, b" rm -rf / ")
        self.assertNotIn("cmd_req_window", self.session(), "没规则不必留窗口")
        self.assertFalse(tr._cmd_is_echo(self.SID, "rm -rf /"))


class NdjsonTests(CommandBlockTestBase):
    """Ollama/NDJSON 增量槽位：命令同样要**跨行拼接后再判**（回归：此前只测过 SSE）。"""

    def _line(self, content, final=False, done=False):
        return tr._restore_ndjson_line(
            json.dumps({"model": "m", "done": done, "message": {"content": content}}),
            self.SID, final=final)

    def test_cross_line_command_is_rewritten_and_frames_stay_valid_json(self):
        self.use(mode="rewrite", channels=("tool", "text"))
        lines = [self._line("先说明 rm"), self._line(" -rf /"), self._line(" 收尾", final=True)]
        body = "\n".join(lines) + "\n" + tr._flush_pending(self.SID, framing="ndjson")
        text = ""
        for ln in [x for x in body.splitlines() if x.strip()]:
            obj = json.loads(ln)  # 非法 JSON 会直接把断言打红
            text += (obj.get("message") or {}).get("content", "")
        self.assertNotIn("rm -rf /", text, "跨行切开的命令必须被改写")
        self.assertIn(tr.CMD_BLOCK_NOTICE, text)
        self.assertIn("先说明", text, "前后文本都要在，不吞字")
        self.assertIn("收尾", text)

    def test_block_mode_on_ndjson_stops_further_lines(self):
        self.use(mode="block", channels=("tool", "text"))
        first = json.loads(self._line("rm -rf / " + "z" * 100))["message"]["content"]
        self.assertEqual(first, "", "命中即置空（行本身仍是合法 JSON 外壳）")
        self.assertTrue(self.session().get("cmd_blocked"))
        later = json.loads(self._line("之后的正常内容", final=True))["message"]["content"]
        self.assertEqual(later, "", "已阻断的会话后续内容不再下发")


class AuditMergeTests(CommandBlockTestBase):
    """W2-1 G1：槽位级命中与全量 S9 扫描的合并口径。

    两条必须同时成立：
    ① 一条命令只写**一条**事件，且带通道标注（槽位级的记录更有信息量）；
    ② 只在思考通道出现过的命令**不写事件**（§6.4 的既有污染：S9 扫的是混了
       思考块的全量拼接文本，模型在思考里权衡「要不要 rm -rf /」本不该告警）。
    """

    def _run_audit(self, resp_text):
        captured = []
        sid = self.SID
        body = json.dumps({"choices": [{"message": {"content": resp_text}}]}).encode("utf-8")
        flow = SimpleNamespace(
            request=SimpleNamespace(
                host="api.openai.com", method="POST", path="/v1/chat/completions",
                content=json.dumps({"model": "gpt-4o",
                                    "messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
            ),
            response=SimpleNamespace(status_code=200,
                                     headers={"content-type": "application/json"},
                                     content=body),
            metadata={"session_id": sid},
        )
        with mock.patch.object(tr, "AUDIT_ENABLED", True), \
             mock.patch.object(tr, "enqueue_audit_event", lambda ev: captured.append(ev)), \
             mock.patch.object(tr, "_emit", lambda *a, **k: None):
            tr._audit_response(flow, sid, "api.openai.com", "POST",
                               "/v1/chat/completions", {})
        return [e for e in captured if e.get("signal_type") == "dangerous_action"]

    def test_slot_hit_wins_and_is_not_duplicated(self):
        self.use()
        tr._cmd_process("rm -rf / --no-preserve-root", "c0.tool0", self.SID)
        r = self._run_audit("好的，执行 rm -rf / --no-preserve-root")
        self.assertEqual(len(r), 1, f"应且仅应一条: {r}")
        self.assertIn("[通道=tool]", r[0]["evidence"])
        self.assertIn("builtin-rm-root", r[0]["evidence"])
        self.assertEqual(r[0]["severity"], "LOW", "与 S9 同档：只记不报")

    def test_thinking_only_mention_produces_no_event(self):
        self.use()
        tr._cmd_process("要不要 rm -rf / 呢", "c0.reason", self.SID)
        self.assertEqual(self._run_audit("要不要 rm -rf / 呢"), [],
                         "思考通道的命中不得变成告警")

    def test_fulltext_scan_still_catches_uncovered_channels(self):
        """槽位没盖到的形态仍由全量扫描兜底（不能因合并把检测能力削掉）。"""
        self.use()
        r = self._run_audit("执行 rm -rf / 完毕")
        self.assertEqual(len(r), 1)
        self.assertNotIn("[通道=", r[0]["evidence"])

    def test_blocked_hit_is_recorded_with_marker(self):
        """阻断也要可查：evidence 带 [已阻断]，用户才知道「这条被拦了」。"""
        self.use(mode="block")
        tr._cmd_process("rm -rf / " + "z" * 100, "c0.tool0", self.SID)
        r = self._run_audit("好的，执行 rm -rf / --no-preserve-root")
        self.assertEqual(len(r), 1, f"应且仅应一条: {r}")
        self.assertIn("[已阻断]", r[0]["evidence"])
        self.assertIn("[通道=tool]", r[0]["evidence"])


class ConfigTests(CommandBlockTestBase):
    """W2-3：配置 schema、种子语义、ReDoS 防护。"""

    def test_default_config_ships_builtins_in_observe_mode(self):
        """① 开箱即用：内置条目随包分发、可读可改（不是藏在代码里的黑箱）。"""
        cb = panel.default_config()["command_block"]
        self.assertEqual(cb["mode"], "observe")
        self.assertEqual(cb["channels"], ["tool"])
        self.assertEqual(len(cb["patterns"]), len(BUILTIN_COMMAND_BLOCK_PATTERNS))
        self.assertTrue(all(p["builtin"] for p in cb["patterns"]))

    def test_missing_patterns_key_seeds_builtins(self):
        out = panel._normalize_command_block({"mode": "observe"}, [])
        self.assertEqual(len(out["patterns"]), len(BUILTIN_COMMAND_BLOCK_PATTERNS))

    def test_deleted_patterns_are_not_resurrected(self):
        """② 硬验收：`patterns: []` 必须原样尊重 —— 删不掉比不提供更糟。"""
        warn = []
        out = panel._normalize_command_block({"mode": "observe", "patterns": []}, warn)
        self.assertEqual(out["patterns"], [])
        self.assertEqual(warn, [], "用户显式清空不是异常，不该有告警")

    def test_edited_builtin_is_preserved_verbatim(self):
        custom = [{"id": "builtin-rm-root", "label": "我改过的", "regex": r"rm\s+-rf\s+/tmp",
                   "enabled": True, "builtin": True}]
        out = panel._normalize_command_block({"mode": "rewrite", "patterns": custom}, [])
        self.assertEqual(len(out["patterns"]), 1)
        self.assertEqual(out["patterns"][0]["label"], "我改过的")
        self.assertEqual(out["patterns"][0]["regex"], r"rm\s+-rf\s+/tmp")

    def test_disabled_pattern_is_kept_but_inactive(self):
        pats = [{"id": "x", "label": "l", "regex": "rm -rf /", "enabled": False}]
        out = panel._normalize_command_block({"patterns": pats}, [])
        self.assertEqual(len(out["patterns"]), 1)
        self.assertFalse(out["patterns"][0]["enabled"])
        parsed = tr._parse_command_block(out)
        self.assertEqual([p[0] for p in parsed["patterns"]], [])

    def test_nested_quantifier_is_rejected_with_warning(self):
        warn = []
        pats = [{"id": "evil", "label": "坏正则", "regex": r"(a+)+$", "enabled": True}]
        out = panel._normalize_command_block({"patterns": pats}, warn)
        self.assertEqual(out["patterns"], [])
        self.assertTrue(any("嵌套量词" in w for w in warn), warn)

    def test_invalid_regex_is_rejected_with_warning(self):
        warn = []
        pats = [{"id": "bad", "label": "语法错", "regex": "(", "enabled": True}]
        out = panel._normalize_command_block({"patterns": pats}, warn)
        self.assertEqual(out["patterns"], [])
        self.assertTrue(any("正则非法" in w for w in warn), warn)

    def test_overlong_regex_is_rejected(self):
        warn = []
        pats = [{"id": "long", "label": "超长", "regex": "x" * 400, "enabled": True}]
        out = panel._normalize_command_block({"patterns": pats}, warn)
        self.assertEqual(out["patterns"], [])
        self.assertTrue(any("过长" in w for w in warn), warn)

    def test_unknown_mode_falls_back_to_observe(self):
        warn = []
        out = panel._normalize_command_block({"mode": "yolo"}, warn)
        self.assertEqual(out["mode"], "observe")
        self.assertTrue(any("observe" in w for w in warn), warn)

    def test_channels_fall_back_to_tool_only(self):
        out = panel._normalize_command_block({"channels": ["nope"]}, [])
        self.assertEqual(out["channels"], ["tool"])
        out2 = panel._normalize_command_block({"channels": ["tool", "text"]}, [])
        self.assertEqual(out2["channels"], ["tool", "text"])

    def test_runtime_parse_drops_hand_edited_bad_regex(self):
        """config.json 可被手改绕过 UI：运行时必须再校验一次。"""
        parsed = tr._parse_command_block({
            "mode": "rewrite",
            "patterns": [{"id": "ok", "label": "好", "regex": "rm -rf /", "enabled": True},
                         {"id": "bad", "label": "坏", "regex": "(", "enabled": True}],
            "channels": ["tool"],
        })
        self.assertEqual([p[0] for p in parsed["patterns"]], ["ok"])

    def test_duplicate_ids_do_not_swallow_entries(self):
        pats = [{"id": "same", "regex": "rm -rf /"},
                {"id": "same", "regex": "rm -rf ~"}]
        out = panel._normalize_command_block({"patterns": pats}, [])
        self.assertEqual(len(out["patterns"]), 2)
        self.assertEqual(len({p["id"] for p in out["patterns"]}), 2)

    def test_over_budget_rule_is_disabled_once(self):
        """⑤ 单次匹配超预算 → 停用该条并告警，且第二次不再付这个代价。

        不去构造真正的灾难性正则：Python 的 `re` 无法中途打断，那种用例会直接把
        测试挂死（这正是 `CMD_MATCH_BUDGET_MS` 注释里「不是本次不卡」的含义）。
        这里把预算压到必超，验的是**停用机制**本身。
        """
        self.use(channels=("tool",),
                 patterns=[{"id": "slow", "label": "慢规则", "regex": r"x*y", "enabled": True}])
        logs = []
        with mock.patch.object(tr, "CMD_MATCH_BUDGET_MS", -1), \
             mock.patch.object(tr, "_cmd_log_once", lambda m: logs.append(m)):
            self.assertIsNone(tr._cmd_find("hello"))
            self.assertIn("slow", tr.COMMAND_BLOCK["disabled"])
            self.assertIsNone(tr._cmd_find("hello"))
        self.assertEqual(len(logs), 1, f"超预算只能告警一次: {logs}")
        self.assertIn("超预算", logs[0])

    def test_match_timeout_is_a_budget_not_a_cure(self):
        """预算常量必须存在且为正：它只能做到「下次不再付」，删掉它就没任何兜底。"""
        self.assertGreater(tr.CMD_MATCH_BUDGET_MS, 0)
        self.assertGreater(tr.CMD_SCAN_MAX, 0)

    def test_config_example_matches_defaults(self):
        """`engine/config.example.json` 是随包分发的模板，必须与 default_config() 同源。

        两份各写一遍必然漂移（改了默认值却忘了改模板，新用户拿到的是旧口径）。
        """
        import json as _json
        ex = _json.loads((ROOT / "engine" / "config.example.json").read_text(encoding="utf-8"))
        dflt = panel.default_config()
        self.assertEqual(ex["command_block"]["mode"], dflt["command_block"]["mode"])
        self.assertEqual(ex["command_block"]["channels"], dflt["command_block"]["channels"])
        self.assertEqual(
            [(p["id"], p["regex"], p["enabled"]) for p in ex["command_block"]["patterns"]],
            [(p["id"], p["regex"], p["enabled"]) for p in dflt["command_block"]["patterns"]],
        )
        self.assertEqual(ex["audit"]["fail_closed"], dflt["audit"]["fail_closed"])
        # P0-a：单请求 NER 预算也是“模板 ↔ 默认”必须同源的一项（两份各写一遍
        # 必然漂移：改了默认值却忘了改模板，新用户拿到的是旧口径）。
        self.assertEqual(ex["ner_req_budget_s"], dflt["ner_req_budget_s"])
        self.assertEqual(ex["ner_enabled"], dflt["ner_enabled"])
        # 2026-11-26 补：光对比几个手挑的键盖不住新增默认（文件工作台 10 个 files_*
        # 就是这样漂的）。这里改成全量键集合断言，新增默认键漏写模板会直接变红。
        self.assertEqual(sorted(set(dflt) - set(ex)), [],
                         "config.example.json 缺键：随包模板必须与 default_config() 同源")

    def test_user_pattern_without_id_gets_stable_id(self):
        pats = [{"label": "无 id", "regex": "rm -rf /important"}]
        a = panel._normalize_command_block({"patterns": pats}, [])["patterns"][0]["id"]
        b = panel._normalize_command_block({"patterns": pats}, [])["patterns"][0]["id"]
        self.assertTrue(a.startswith("user-"))
        self.assertEqual(a, b, "id 必须可复现（不能用 hash()）")


class BuiltinPatternQualityTests(unittest.TestCase):
    """内置清单的质量门：真危害要命中，日常命令不能误伤。"""

    HAZARDS = {
        "builtin-rm-root": ["rm -rf /", "sudo rm -fr / --no-preserve-root"],
        "builtin-rm-home": ["rm -rf ~", "sudo rm -fr ~/"],
        "builtin-del-win": ["del /s /q " + "C:" + chr(92),
                            "Remove-Item -Recurse -Force " + "D:" + chr(92)],
        "builtin-format": ["mkfs.ext4 /dev/sda1", "format C:"],
        "builtin-drop-db": ["DROP DATABASE prod;", "TRUNCATE TABLE users"],
        "builtin-dd": ["dd if=/dev/zero of=/dev/sda bs=1M"],
        "builtin-forkbomb": [":(){ :|:& };:"],
    }
    DAILY = [
        "npm run build", "rm -rf node_modules", "rm -rf ./dist", "rm -rf /tmp/cache",
        "git push --force-with-lease", "git reset --hard HEAD~1",
        "SELECT * FROM users WHERE id = 1", "docker compose up -d",
        "del /s /q ." + chr(92) + "build",
    ]

    def _rx(self, pid):
        for p in BUILTIN_COMMAND_BLOCK_PATTERNS:
            if p["id"] == pid:
                return __import__("re").compile(p["regex"])
        raise AssertionError(pid)

    def test_every_builtin_matches_its_hazard_shapes(self):
        for pid, samples in self.HAZARDS.items():
            rx = self._rx(pid)
            for s in samples:
                with self.subTest(pid=pid, sample=s):
                    self.assertTrue(rx.search(s), f"{pid} 漏掉真实危害形态: {s}")

    def test_daily_commands_are_not_matched(self):
        for p in BUILTIN_COMMAND_BLOCK_PATTERNS:
            rx = __import__("re").compile(p["regex"])
            for s in self.DAILY:
                with self.subTest(rule=p["id"], sample=s):
                    self.assertFalse(rx.search(s), f"{p['id']} 误伤日常命令: {s}")

    def test_every_builtin_regex_passes_shared_validator(self):
        from shield_defaults import validate_command_regex
        for p in BUILTIN_COMMAND_BLOCK_PATTERNS:
            ok, why = validate_command_regex(p["regex"])
            self.assertTrue(ok, f"{p['id']}: {why}")


if __name__ == "__main__":
    unittest.main()
