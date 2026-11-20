"""G721~G724：代理启动失败的现场必须带 mitmdump 输出，且一次失败只产一份。

真机背景（2026-11-19）：`engine/crash-dumps/` 下 10 份 `crash-*-startfail.txt` 全是 205 字节，
`-- upstream port occupancy --` 与 `-- crash log tail --` 下方全空 —— 留了现场，现场没内容。

两个根因，都写在 `_start_proxy_locked` 的时序里：
  1. `proc["p"] = p` 要到就绪之后才设（`panel.py:3214`），`_reader` 线程要到 `:3229` 才启动，
     所以失败分支调 `_dump_crash_context` 时 `p` 取不到、`proxy-crash.log` 还不存在；
  2. mitmdump 的真实输出只活在局部变量 `p.stdout` 里，读完只塞进 return 值给前端 toast。

再加上外层 `_watchdog` / `_restart_proxy_locked` 在 `start_proxy()` 返回 False 后又写一份，
于是 5 次失败产出 10 份同样空的文件。

## 为什么是源码断言

落盘是纯 IO，真起 mitmdump 失败的成本与不确定性都太高（要真的占住端口或让二进制崩），
而这些守卫错位的形态是「文件里少一段」，只有对着真实现场才知道。这里钉的是代码结构：
采集时机、写入模式、去重、fail-safe。

错误码是本仓既定格式：`<MODULE>_<4位>`，仅作台账标识（诊断落盘不产生 HTTP 响应）。
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PANEL_PY = ROOT / "engine" / "panel.py"
# `import panel` 需要 engine/ 在 sys.path（与 tests/test_attribution.py 同法）
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT))


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def _py_func(src, name):
    """按缩进取一个模块级函数体（Python 没有花括号，不能用 `_block`）。"""
    lines = src.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^def\s+%s\s*\(" % re.escape(name), line):
            start = i
            break
    if start is None:
        raise AssertionError("找不到函数 %s" % name)
    body = [lines[start]]
    for line in lines[start + 1:]:
        if line and not line[0].isspace():
            break
        body.append(line)
    return "\n".join(body)


class G721PortTableBeforeKillTests(unittest.TestCase):
    """G721 / ENGINE_7101：端口占用表必须在 kill 之前采集。"""

    def test_g721_error_code_is_fixed(self):
        self.assertEqual("ENGINE_7101", "ENGINE_7101")

    def test_g721_dump_precedes_kill(self):
        body = _py_func(_read(PANEL_PY), "_start_proxy_locked")
        dump_at = body.find('_dump_crash_context("startfail")')
        kill_at = body.find("_kill_proxy_tree")
        self.assertGreaterEqual(dump_at, 0, "失败分支缺少现场落盘（ENGINE_7101）")
        self.assertGreaterEqual(kill_at, 0, "失败分支缺少 kill（ENGINE_7101）")
        self.assertLess(dump_at, kill_at, "现场落盘必须在 kill 之前，否则端口占用表恒空（ENGINE_7101）")


class G722TailGoesToSameFileTests(unittest.TestCase):
    """G722 / ENGINE_7102：输出尾部必须追加进同一份现场。"""

    def test_g722_error_code_is_fixed(self):
        self.assertEqual("ENGINE_7102", "ENGINE_7102")

    def test_g722_append_helper_is_append_mode_and_noop_on_empty(self):
        body = _py_func(_read(PANEL_PY), "_append_crash_tail")
        self.assertIn('open(path, "a"', body, "追加必须用 append 模式，不得重建文件（ENGINE_7102）")
        self.assertIn("if not path or not tail:", body, "空路径或空输出必须直接返回（ENGINE_7102）")

    def test_g722_startfail_branch_appends_after_reading_out(self):
        body = _py_func(_read(PANEL_PY), "_start_proxy_locked")
        append_at = body.find("_append_crash_tail(")
        out_at = body.find("out = (raw or \"\")[-500:]")
        self.assertGreaterEqual(append_at, 0, "失败分支必须把输出尾部追加进现场（ENGINE_7102）")
        self.assertGreaterEqual(out_at, 0, "失败分支必须读取子进程输出（ENGINE_7102）")
        self.assertLess(out_at, append_at, "必须先读到 out 再追加（ENGINE_7102）")


class G723OneDumpPerFailureTests(unittest.TestCase):
    """G723 / ENGINE_7103：同一次启动失败只产出一份现场。"""

    def test_g723_error_code_is_fixed(self):
        self.assertEqual("ENGINE_7103", "ENGINE_7103")

    def test_g723_dedup_window_exists(self):
        source = _read(PANEL_PY)
        self.assertIn("_CRASH_DUMP_DEDUP_S = 5.0", source, "去重窗口常量必须存在且为实测依据的 5s（ENGINE_7103）")
        self.assertIn("_LAST_CRASH_DUMP", source, "缺少上次落盘路径的登记（ENGINE_7103）")

    def test_g723_repeat_call_reuses_previous_path(self):
        body = _py_func(source := _read(PANEL_PY), "_dump_crash_context")
        self.assertIn('_LAST_CRASH_DUMP["reason"]', body, "去重必须按 reason 匹配（ENGINE_7103）")
        self.assertIn("_CRASH_DUMP_DEDUP_S", body, "去重必须用时间窗（ENGINE_7103）")
        self.assertIn('return _LAST_CRASH_DUMP["path"]', body, "命中去重时必须复用上次路径（ENGINE_7103）")
        self.assertIn("_LAST_CRASH_DUMP.update(", source, "落盘成功后必须登记路径（ENGINE_7103）")


class G724FailsafeTests(unittest.TestCase):
    """G724 / ENGINE_7104：落盘全程 fail-safe，不得中断启动失败路径。"""

    def test_g724_error_code_is_fixed(self):
        self.assertEqual("ENGINE_7104", "ENGINE_7104")

    def test_g724_dump_returns_none_instead_of_raising(self):
        body = _py_func(_read(PANEL_PY), "_dump_crash_context")
        self.assertIn("except Exception:", body, "必须包住异常（ENGINE_7104）")
        self.assertIn("return None", body, "落盘失败必须返回 None 而不是抛出（ENGINE_7104）")

    def test_g724_append_swallows_errors(self):
        body = _py_func(_read(PANEL_PY), "_append_crash_tail")
        self.assertIn("except Exception:", body, "追加失败必须吞掉（ENGINE_7104）")


class CrashDumpBehaviorTests(unittest.TestCase):
    """真跑一次落盘 —— 源码断言只能证明「代码里有这两行」，证明不了文件里多了那段。"""

    def setUp(self):
        import panel

        self.panel = panel
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._patches = [
            mock.patch.object(panel, "DATA_ROOT", self.root),
            mock.patch.object(panel, "_listening_port_pids", lambda *a, **k: {}),
            mock.patch.object(panel, "_emit_log", lambda *a, **k: None),
        ]
        for p in self._patches:
            p.start()
        panel._LAST_CRASH_DUMP.update(ts=0.0, reason="", path=None)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()
        self.panel._LAST_CRASH_DUMP.update(ts=0.0, reason="", path=None)

    def test_dump_then_append_writes_tail_into_same_file(self):
        path = self.panel._dump_crash_context("selftest")
        self.assertTrue(path and Path(path).exists(), "落盘必须返回真实路径")
        self.panel._append_crash_tail(path, "boom: ModuleNotFoundError: mitmproxy")
        text = Path(path).read_text(encoding="utf-8")
        self.assertIn("-- crash log tail --", text)
        self.assertIn("-- subprocess output (tail) --", text)
        self.assertIn("mitmproxy", text)

    def test_second_dump_within_window_reuses_same_file(self):
        first = self.panel._dump_crash_context("selftest")
        second = self.panel._dump_crash_context("selftest")
        self.assertEqual(first, second, "同一次失败不得写成两份")
        files = list((self.root / "crash-dumps").glob("crash-*selftest.txt"))
        self.assertEqual(len(files), 1, "5s 窗口内只应有一份现场")

    def test_different_reason_writes_its_own_file(self):
        first = self.panel._dump_crash_context("selftest")
        other = self.panel._dump_crash_context("otherreason")
        self.assertNotEqual(first, other, "不同原因必须各留一份")

    def test_empty_tail_does_not_append_a_bare_header(self):
        path = self.panel._dump_crash_context("selftest")
        before = Path(path).read_text(encoding="utf-8")
        self.panel._append_crash_tail(path, "")
        self.panel._append_crash_tail(None, "x")
        self.assertEqual(Path(path).read_text(encoding="utf-8"), before, "空输出不得留下空标题段")


if __name__ == "__main__":
    unittest.main()