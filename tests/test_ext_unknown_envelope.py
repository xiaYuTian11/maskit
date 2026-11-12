"""G614~G617：p/o/v 私有信封（豆包 / DeepSeek 网页端）的跨帧占位符必须能拼回。

2026-11-12 定位 issue #50（DeepSeek 网页端「脱敏后还原失败」）后的守卫。根因不是猜的：

  · DeepSeek 前端 bundle（端点 `/api/v0/chat/completion`）的流式协议是
    `{p: 路径, o: "SET"|"BATCH"|"APPEND", v: 值}`，与 `_sse_text_slots` 认识的三种形状都不同；
  · 于是每帧落到 `_restore_sse_data` 的整树兜底 → `restore_final()`（`final=True`，不缓冲）；
  · 被上游切成两段的占位符两半各自原样下发，**且 restored / degraded / unresolved 全是 0**
    —— 事件库里因此显示「已还原」，屏幕上却留着裸占位符。

本文件用「逐帧喂」的确定性写法钉住四件事：增量必须缓冲、快照不得扣留、
认不出的信封必须可观测、路径判定必须保守。

样例 token 与原文都是拼出来的假值（仓库红线：测试文件里不得出现占位符字面量）。
"""

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
import panel  # noqa: E402
import transparent as tr  # noqa: E402

_LB = "{" * 2
_RB = "}" * 2
TOK = _LB + "TERM_abcdef" + _RB          # 6 位 hex 后缀，符合占位符规范
ORIG = "样例词甲"                          # 明显伪造，不含真实业务数据
SID = "ext:0123456789abcdef"
CT = "text/event-stream"


def _sse(payload, event="delta"):
    """拼一帧标准 SSE。事件名取自客户端 `class xJ`：delta / ready / finish / close / title / toast。"""
    return "event: %s\ndata: %s\n\n" % (event, payload)


def _pov(path, op, value):
    """p/o/v 信封帧。path=None 表示上游省略 p（客户端语义：沿用上一个路径）。"""
    head = "" if path is None else ('"p": "%s", ' % path)
    return _sse("{" + head + '"o": "' + op + '", "v": ' + value + "}")


def _fresh_session():
    tr._new_session(SID)
    s = tr.sessions[SID]
    s["rev"][TOK] = ORIG
    s["fwd"][ORIG] = TOK
    return s


class PovEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.s = _fresh_session()

    def _feed(self, frames, stream_id):
        out = []
        for i, text in enumerate(frames):
            out.append(tr.restore_stream_chunk(text, SID, stream_id, content_type=CT,
                                               final=(i == len(frames) - 1)))
        return "".join(out)

    def _counter(self, key):
        return int(tr.restore_runtime_stats().get(key) or 0)

    # ── G614 ────────────────────────────────────────────────────────────────
    def test_g614_append_frames_are_buffered_per_path(self):
        """Case G614 两段 APPEND 把占位符切成两半 → 必须拼回并还原（RESTORE_6104）。"""
        out = self._feed([
            _pov("response/fragments/-1/content", "APPEND", '"前面的话 ' + TOK[:5] + '"'),
            _pov("response/fragments/-1/content", "APPEND", '"' + TOK[5:] + ' 后面"'),
            _sse("[DONE]"),
        ], "g614")
        self.assertIn(ORIG, out, "RESTORE_6104 跨帧占位符没拼回来（页面会留裸占位符）")
        self.assertNotIn(_LB, out, "RESTORE_6104 输出里仍留着双左花括号")
        self.assertGreaterEqual(int(self.s.get("restored") or 0), 1,
                                "RESTORE_6104 还原计数必须真的 +1（否则事件库看不见）")
        self.assertEqual(int(self.s.get("unresolved") or 0), 0,
                         "RESTORE_6104 拼回成功时不该计入未还原")

    # ── G615 ────────────────────────────────────────────────────────────────
    def test_g615_snapshot_frames_are_never_buffered(self):
        """Case G615 先 APPEND 留半截、再 SET 覆盖 → 半截必须丢弃，不得拼进新值（RESTORE_6105）。"""
        channel = "pov:" + "response/fragments/-1/content"
        out = self._feed([
            _pov("response/fragments/-1/content", "APPEND", '"旧值 ' + TOK[:5] + '"'),
            _pov("response/fragments/-1/content", "SET", '"全新值"'),
            _sse("[DONE]"),
        ], "g615")
        self.assertIn("全新值", out, "RESTORE_6105 快照帧的新值必须完整下发")
        self.assertNotIn(TOK[:5], out, "RESTORE_6105 旧值的半截不得拼进 SET 的新值")
        self.assertIsNone((self.s.get("pending") or {}).get(channel),
                          "RESTORE_6105 SET 之后该路径的滞留必须清空")

    # ── G616 ────────────────────────────────────────────────────────────────
    def test_g616_unknown_envelope_is_counted_and_projected(self):
        """Case G616 认不出的信封必须计数外发；识别成功的帧不得计入（RESTORE_6106）。"""
        stats = tr.restore_runtime_stats()
        for key in ("pov_frames", "pov_buffered", "unknown_envelope_frames"):
            self.assertIsInstance(stats.get(key), int, "RESTORE_6106 诊断三键必须齐全且为整数")

        before = self._counter("unknown_envelope_frames")
        self._feed([_pov("response/fragments/-1/content", "APPEND", '"正常帧"'),
                    _sse("[DONE]")], "g616-ok")
        self.assertEqual(self._counter("unknown_envelope_frames"), before,
                         "RESTORE_6106 识别成功的 p/o/v 帧不得计入未知信封")

        before = self._counter("unknown_envelope_frames")
        self._feed([_sse('{"weird": "shape", "no": "envelope"}'), _sse("[DONE]")], "g616-bad")
        self.assertEqual(self._counter("unknown_envelope_frames"), before + 1,
                         "RESTORE_6106 认不出的信封必须计入，否则这条路径永远不可观测")

        proj = panel._project_engine_metrics({"restore": {"pov_frames": 7, "pov_buffered": 2,
                                                          "unknown_envelope_frames": 3}})
        self.assertEqual(proj.get("restore"),
                         {"pov_frames": 7, "pov_buffered": 2, "unknown_envelope_frames": 3},
                         "RESTORE_6106 面板投影是显式白名单，不补就永远看不到")

    # ── G617 ────────────────────────────────────────────────────────────────
    def test_g617_path_resolution_is_conservative(self):
        """Case G617 没有可判定的路径就不缓冲；有上一个 p 就沿用；两条路径不得互相拼合。"""
        # (a) 无 p、无历史 p：退回不缓冲（宁可露出半截），并计一次未知信封
        before = self._counter("unknown_envelope_frames")
        out = self._feed([_pov(None, "APPEND", '"无路径 ' + TOK[:5] + '"'), _sse("[DONE]")], "g617a")
        self.assertNotIn(ORIG, out, "RESTORE_6107 路径不可判定时不得猜着拼合")
        self.assertEqual(self._counter("unknown_envelope_frames"), before + 1,
                         "RESTORE_6107 路径不可判定必须计数")

        # (b) 省略 p 的第二帧沿用上一帧路径（与客户端 sticky 语义一致）
        out = self._feed([
            _pov("response/fragments/-1/content", "APPEND", '"沿用 ' + TOK[:5] + '"'),
            _pov(None, "APPEND", '"' + TOK[5:] + '"'),
            _sse("[DONE]"),
        ], "g617b")
        self.assertIn(ORIG, out, "RESTORE_6107 缺省 p 必须沿用上一帧路径，否则拼不回来")

        # (c) 两条不同路径的半截不得互相拼合（跨字段串字比露占位符更糟）
        out = self._feed([
            _pov("response/thinking_content", "APPEND", '"思考 ' + TOK[:5] + '"'),
            _pov("response/fragments/-1/content", "APPEND", '"' + TOK[5:] + '"'),
            _sse("[DONE]"),
        ], "g617c")
        self.assertNotIn(ORIG, out, "RESTORE_6107 不同路径的半截被拼成了一体（跨字段串字）")

    # ── G614b ───────────────────────────────────────────────────────────────
    def test_g614b_omitted_op_and_path_continue_the_stream(self):
        """Case G614b 省略 o 的续帧（只有 v）必须沿用本流的 o/路径；结束帧前必须先补发（RESTORE_6104）。"""
        path = "response/fragments/-1/content"
        out = self._feed([
            _sse('{"p": "%s", "o": "APPEND", "v": "前面 ' % path + TOK[:5] + '"}'),
            _sse('{"v": "' + TOK[5:] + ' 后面"}'),          # 同时省略 p 与 o：协议允许（粘性）
            _sse("{}", event="finish"),
        ], "g614b")
        self.assertIn(ORIG, out, "RESTORE_6104 省略 o 的续帧没沿用上一个 o（半截因此拖到流末）")
        self.assertNotIn(_LB, out, "RESTORE_6104 输出里仍留着双左花括号")
        # 顺序：文本在 finish 之前
        self.assertLess(out.index(ORIG), out.index("event: finish"),
                        "RESTORE_6104 正文被排到结束帧之后（客户端会丢弃）")

    def test_g614b_leftover_is_flushed_before_finish_with_full_envelope(self):
        """Case G614b 流末残留必须在 finish 之前补发，且补发帧是完整信封（含 p 与 o）——RESTORE_6104。"""
        path = "response/fragments/-1/content"
        out = self._feed([
            _sse('{"v": "前 ' + TOK[:5] + '"}'),            # 没有任何 p/o（有粘性则沿用，没有则兜底）
            _sse('{"p": "%s", "o": "APPEND", "v": "尾 ' % path + TOK[:5] + '"}'),
            _sse("{}", event="finish"),
        ], "g614b2")
        self.assertLess(out.index("event: finish"), len(out))
        tail_pos = out.find('"p": "' + path + '"', out.find("event: finish") - 400)
        self.assertGreaterEqual(tail_pos, 0, "RESTORE_6104 补发帧丢了 p（客户端会写到别的路径）")
        flushed = out[:out.index("event: finish")]
        self.assertIn('"o": "APPEND"', flushed, "RESTORE_6104 补发帧丢了 o（客户端解析不出来）")

    # ── G615b ───────────────────────────────────────────────────────────────
    def test_g615b_batch_expands_sub_operations(self):
        """Case G615b BATCH 必须展开子操作：子 APPEND 按 父path/子path 分通道（RESTORE_6105）。"""
        first = _sse('{"p": "response", "o": "BATCH", "v": ['
                     '{"p": "fragments/-1/content", "o": "APPEND", "v": "前 ' + TOK[:5] + '"}]}')
        # 先只喂一帧（不是最终帧）：半截必须落在「父path/子path」通道上
        tr.restore_stream_chunk(first, SID, "g615b", content_type=CT, final=False)
        channel = "pov:response/fragments/-1/content"
        self.assertIn(channel, self.s.get("pending") or {},
                      "RESTORE_6105 子路径必须拼成 父path/子path（否则半截落在错通道、拼不回来）")
        self.assertNotIn("pov:fragments/-1/content", self.s.get("pending") or {},
                         "RESTORE_6105 子路径不得丢掉父前缀")
        self.assertEqual(self.s.get("pov_sticky", {}).get("g615b", {}).get("path"), "response",
                         "RESTORE_6105 顶层粘性该记父路径")
        out = self._feed([
            _sse('{"p": "response", "o": "BATCH", "v": ['
                 '{"p": "fragments/-1/content", "o": "APPEND", "v": "' + TOK[5:] + ' 后"}]}'),
            _sse("{}", event="finish"),
        ], "g615b")
        self.assertIn(ORIG, out, "RESTORE_6105 BATCH 子 APPEND 的跨帧占位符没拼回（两帧跨调用也要拼）")
        self.assertNotIn(_LB, out, "RESTORE_6105 输出里仍留着双左花括号")

    def test_g615b_batch_sub_set_drops_the_same_path_half(self):
        """Case G615b BATCH 里的子 SET 必须丢弃同路径半截，不得拼进新值（RESTORE_6105）。"""
        out = self._feed([
            _sse('{"p": "response", "o": "BATCH", "v": ['
                 '{"p": "fragments/-1/content", "o": "APPEND", "v": "旧 ' + TOK[:5] + '"}]}'),
            _sse('{"p": "response", "o": "BATCH", "v": ['
                 '{"p": "fragments/-1/content", "o": "SET", "v": "全新值"}]}'),
            _sse("{}", event="finish"),
        ], "g615b2")
        self.assertIn("全新值", out, "RESTORE_6105 子 SET 的新值必须完整下发")
        self.assertNotIn(TOK[:5], out, "RESTORE_6105 子 SET 之前的半截不得拼进新值")

    # ── G617b ───────────────────────────────────────────────────────────────
    def test_g617b_sticky_state_is_per_stream(self):
        """Case G617b 同一 sid 的两条流各自持有粘性：B 流不得继承 A 流的 p/o（RESTORE_6107）。"""
        path_a = "response/fragments/-1/content"
        # A 流：留下半截
        self._feed([_sse('{"p": "%s", "o": "APPEND", "v": "旧 ' % path_a + TOK[:5] + '"}')], "steam-A")
        # B 流：第一帧什么都没带 —— 不得继承 A 的 (APPEND, path)
        out = self._feed([_sse('{"v": "' + TOK[5:] + ' 新流"}'), _sse("{}", event="finish")], "stream-B")
        self.assertNotIn(ORIG, out, "RESTORE_6107 B 流继承了 A 流的粘性，半截被拼到了一起（跨流串字）")
        self.assertIn(TOK[5:], out, "RESTORE_6107 B 流没有粘性时该按兜底原样透传（本用例要的是不拼合）")
        buckets = self.s.get("pov_sticky") or {}
        self.assertIn("steam-A", buckets, "RESTORE_6107 粘性状态必须按流分桶")
        self.assertNotIn("stream-B", buckets, "RESTORE_6107 判不出 op/path 的流不该留下粘性桶")

    # ── EXEC ────────────────────────────────────────────────────────────────
    def test_exec_known_shapes_still_restore(self):
        """Case EXEC 已知形状（OpenAI 信封）行为不变：这条是最容易写坏别人的回归面。"""
        out = self._feed([
            _sse('{"choices":[{"delta":{"content":"电话 ' + TOK[:4] + '"}}]}'),
            _sse('{"choices":[{"delta":{"content":"' + TOK[4:] + '"}}]}'),
            _sse("[DONE]"),
        ], "exec")
        self.assertIn(ORIG, out, "EXEC OpenAI 信封的跨帧占位符必须仍然拼回")
        self.assertEqual(self._counter("unknown_envelope_frames") >= 0, True,
                         "EXEC 诊断出口必须可用")


if __name__ == "__main__":
    unittest.main()
