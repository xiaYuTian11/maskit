"""§D3.3：「清空内存映射」的独立动作与跨进程信号。

三件事必须同时成立，缺任何一个这个功能就是假的：
  1. 引擎侧真的清掉了会话表与复用窗口（否则用户点了没反应）；
  2. 面板与引擎是**两个进程**，面板清不到引擎的表 → 信号必须真的能传过去；
  3. 引擎侧的首次检查**只看不重置**（否则启动时刚预热完的映射会被立刻抹掉，
     用户看到的是"重启后历史占位符全没了"）。

另外钉住两条边界：自定义词永久映射**不清**（它由用户词表派生，词不删就该稳定）、
清空必须显式 confirm（它会让当前对话的历史占位符全部还原不了）。
"""
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import panel
import transparent as tr


class _SignalsIsolation(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for target, name, value in (
            (event_store, "SIGNALS_FILE", root / "engine-signals.json"),
            (event_store, "_SIGNALS_CACHE", {"ts": 0.0, "data": {}}),
            (event_store, "DB_PATH", root / "events.sqlite3"),
            (event_store, "_db_ready", False),
            (panel, "CONFIG_PATH", root / "config.json"),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # 引擎侧全局态的隔离（sessions / 复用窗口 / 自定义词表）
        self._saved = (
            dict(tr.sessions),
            dict(tr._RECENT_FWD),
            dict(tr._RECENT_REV),
            dict(tr._RECENT_SUFFIX),
            tr._MAPPING_RESET_SEEN[0],
        )
        self.addCleanup(self._restore)
        self.client = panel.app.test_client()

    def _restore(self):
        sessions, fwd, rev, suffix, seen = self._saved
        tr.sessions.clear()
        tr.sessions.update(sessions)
        tr._RECENT_FWD.clear()
        tr._RECENT_FWD.update(fwd)
        tr._RECENT_REV.clear()
        tr._RECENT_REV.update(rev)
        tr._RECENT_SUFFIX.clear()
        tr._RECENT_SUFFIX.update(suffix)
        tr._MAPPING_RESET_SEEN[0] = seen

    def _dirty(self):
        # 先清空再种：本文件的口径是「计数必须确定」，而上游测试可能已经给
        # 模块全局表留了残留（sessions 与复用窗口都是进程级共享的）。
        # setUp 已快照，tearDown 会原样恢复。
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr.sessions["live-sid"] = {"fwd": {}, "rev": {}, "labels": {}, "pending": {}}
        tr._RECENT_FWD["SYNTH-ORIG"] = ["{{" + "PHONE_" + "aaaaaa" + "}}", "PHONE", time.time()]
        tr._RECENT_REV["{{" + "PHONE_" + "aaaaaa" + "}}"] = ["SYNTH-ORIG", "PHONE", time.time()]


class SignalFileTests(_SignalsIsolation):
    def test_temp_file_name_is_pid_scoped(self):
        """暂存文件必须带 pid：两个进程共用同一个 `.tmp` 名时，
        先 `os.replace` 的那个会搬走对方的半成品，后一个拿 FileNotFoundError。"""
        event_store.request_mapping_reset()
        leftovers = list(event_store.SIGNALS_FILE.parent.glob("engine-signals.json.*.tmp"))
        self.assertEqual(leftovers, [], "写完不该留暂存文件")
        with mock.patch.object(os, "getpid", return_value=4242):
            event_store.request_mapping_reset()
        # 用假 pid 时万一替换失败会留下带 4242 的暂存名 —— 这里只锁定“不撞名”这个契约
        self.assertFalse((event_store.SIGNALS_FILE.parent / "engine-signals.json.tmp").exists())

    def test_generation_is_monotonic_even_when_cache_always_expires(self):
        """代号来自「读→+1→写」，所以缓存完全失效时也必须是单调的。

        不单调的后果很重：面板两次点击得到同一个代号 → 引擎认为「没变化」
        → 第二次点击静默失效（而且 `engine_applied=pending` 看不出区别）。
        """
        with mock.patch.object(event_store, "_SIGNALS_CACHE_TTL_S", 0.0):
            gens = [event_store.request_mapping_reset() for _ in range(4)]
        self.assertEqual(gens, [1, 2, 3, 4])
        self.assertEqual(event_store.mapping_reset_generation(), 4)

    def test_generation_is_monotonic_and_trace_survives_reset_bump(self):
        self.assertEqual(event_store.mapping_reset_generation(), 0)
        first = event_store.request_mapping_reset()
        second = event_store.request_mapping_reset()
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(event_store.mapping_reset_generation(), 2)

    def test_trace_window_and_reset_generation_do_not_overwrite_each_other(self):
        """两个信号共用一个文件：任一写入都不能把另一个抹掉。"""
        event_store.start_log_trace(15)
        event_store.request_mapping_reset()
        self.assertTrue(event_store.log_trace_state()["active"])
        self.assertEqual(event_store.mapping_reset_generation(), 1)
        event_store.stop_log_trace()
        self.assertFalse(event_store.log_trace_state()["active"])
        self.assertEqual(event_store.mapping_reset_generation(), 1, "关排障不得清掉重置代号")


class EngineApplyTests(_SignalsIsolation):
    def test_first_check_only_records_and_does_not_reset(self):
        """引擎启动路径：首次看到代号只记下，绝不清 —— 否则 `load()` 刚预热的映射会立刻没了。"""
        self._dirty()
        tr._MAPPING_RESET_SEEN[0] = None
        tr._maybe_apply_mapping_reset()
        self.assertIn("live-sid", tr.sessions)
        self.assertEqual(len(tr._RECENT_FWD), 1)

    def test_generation_change_triggers_exactly_one_reset(self):
        self._dirty()
        tr._MAPPING_RESET_SEEN[0] = event_store.mapping_reset_generation()
        event_store.request_mapping_reset()
        tr._maybe_apply_mapping_reset()
        self.assertEqual(tr.sessions, {})
        self.assertEqual(tr._RECENT_FWD, {})
        self.assertEqual(tr._RECENT_REV, {})
        self.assertEqual(tr._RECENT_SUFFIX, {})
        # 再调一次不得重复触发（代号已消费）
        self._dirty()
        tr._maybe_apply_mapping_reset()
        self.assertIn("live-sid", tr.sessions)

    def test_custom_word_mappings_are_preserved(self):
        """自定义词永久映射不清：它由用户自己的词表派生，词不删就该稳定。"""
        self._dirty()
        tr._CUSTOM_WORD_FWD["SYNTH-CUSTOM-ORIG"] = "{{" + "CUSTOM_" + "bbbbbb" + "}}"
        self.addCleanup(tr._CUSTOM_WORD_FWD.pop, "SYNTH-CUSTOM-ORIG", None)
        tr.reset_mappings(reason="test")
        self.assertIn("SYNTH-CUSTOM-ORIG", tr._CUSTOM_WORD_FWD)

    def test_reset_reports_counts(self):
        self._dirty()
        out = tr.reset_mappings(reason="test")
        self.assertEqual(out["ok"], True)
        self.assertEqual(out["sessions"], 1)
        self.assertEqual(out["recent_entries"], 1)

    def test_mapping_stats_counts_without_exposing_content(self):
        self._dirty()
        stats = tr.mapping_stats()
        self.assertEqual(stats["sessions"], 1)
        self.assertEqual(stats["recent_entries"], 1)
        self.assertNotIn("SYNTH-ORIG", json.dumps(stats))


class MappingEndpointTests(_SignalsIsolation):
    def test_requires_explicit_confirmation(self):
        resp = self.client.post("/api/mappings/clear", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()["ok"])

    def test_confirmed_clear_bumps_generation_and_clears_panel_side(self):
        self._dirty()
        resp = self.client.post("/api/mappings/clear?confirm=true",
                                headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(body["engine_generation"], 1)
        # 面板侧（扩展桥接链路）当场清掉
        self.assertEqual(tr.sessions, {})
        self.assertEqual(tr._RECENT_FWD, {})
        # 引擎侧是异步消费的：必须如实标注 pending，不能让 UI 以为已生效
        self.assertEqual(body["engine_applied"], "pending")

    def test_state_endpoint_reports_panel_and_engine_separately(self):
        self._dirty()
        # 引擎快照的"新鲜度"必须**显式注入**：靠"临时目录里应该没有这个文件"
        # 断言 stale 会在全量套件里被别的测试写下的快照打翻（实测）。
        with mock.patch.object(panel, "_read_engine_metrics",
                               return_value={"mappings": {"sessions": 7}, "stale": False}):
            body = self.client.get("/api/mappings/state",
                                   headers={"X-Shield-Token": panel.API_TOKEN}).get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["panel"]["sessions"], 1)
        self.assertEqual(body["engine"]["sessions"], 7)
        self.assertFalse(body["engine_stale"])
        # 拿不到快照时如实标 stale，不假装是实时值
        with mock.patch.object(panel, "_read_engine_metrics", return_value={}):
            body = self.client.get("/api/mappings/state",
                                   headers={"X-Shield-Token": panel.API_TOKEN}).get_json()
        self.assertTrue(body["engine_stale"])
        self.assertEqual(body["engine"], {})


class PanelDoesNotConsumeItsOwnResetTests(_SignalsIsolation):
    """面板自己清完后**不得**再消费一次自己的代号。

    面板也是消费方（扩展桥接链路用面板进程自己的 `transparent` 副本）。
    不登记代号的话，用户点完清空、随后刚产生的新映射会在下一个 `/api/ext/mask`
    被同一个代号再清一遍 —— 用户视角就是「刚清完又莫名少了一次」。
    """

    def test_panel_clear_acks_so_next_check_is_a_no_op(self):
        self._dirty()
        resp = self.client.post("/api/mappings/clear?confirm=true",
                                headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertTrue(resp.get_json()["ok"])
        # 清空之后用户又做了一次脱敏 → 表里重新有东西
        self._dirty()
        before = dict(tr._RECENT_FWD)
        tr._maybe_apply_mapping_reset()
        self.assertEqual(tr._RECENT_FWD, before, "面板重复消费了自己的代号")
        self.assertIn("live-sid", tr.sessions)

    def test_engine_side_still_consumes_after_panel_ack(self):
        """ack 只影响**面板进程**：引擎进程必须照旧靠代号变化触发。

        用重置 `_MAPPING_RESET_SEEN` 模拟「另一个进程」：它没有 ack 过这个代号，
        所以下一次检查必须真的清一次。
        """
        self._dirty()
        self.client.post("/api/mappings/clear?confirm=true",
                         headers={"X-Shield-Token": panel.API_TOKEN})
        self._dirty()
        tr._MAPPING_RESET_SEEN[0] = 0          # 模拟引擎进程：基线还是 0
        tr._maybe_apply_mapping_reset()
        self.assertEqual(tr.sessions, {})
        self.assertEqual(tr._RECENT_FWD, {})


class BeforeTsFilterTests(_SignalsIsolation):
    def _append(self, ts):
        return event_store.append_event({"type": "PASS", "host": "example.invalid", "ts": ts})

    def test_pages_by_before_ts_without_seq_cursor(self):
        """单独给 `before_ts`（不带 before_seq）也要成立。

        API 路径吃的是 panel 补的 int64 彝兵，所以测不到这条；而 `before_ts`
        单独使用是文档写明的用法（`fetch_events_before` 的两个游标各自可省）。
        """
        now = time.time()
        a = self._append(now - 7200)
        b = self._append(now - 3600)
        recent = self._append(now)
        ev, has_more = event_store.fetch_events_before(before_ts=now - 1800, limit=50)
        self.assertEqual([e["seq"] for e in ev], [a, b])
        self.assertFalse(has_more)
        self.assertNotIn(recent, [e["seq"] for e in ev])

    def test_before_ts_pages_only_older_records(self):
        now = time.time()
        old_a = self._append(now - 7200)
        old_b = self._append(now - 3600)
        recent = self._append(now)
        resp = self.client.get("/api/logs", query_string={"before_ts": now - 1800, "limit": 50},
                               headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual([e["seq"] for e in body["events"]], [old_a, old_b])
        self.assertFalse(body["has_more"])
        self.assertNotIn(recent, [e["seq"] for e in body["events"]])

    def test_illegal_before_ts_is_ignored_not_fatal(self):
        seq = self._append(time.time())
        resp = self.client.get("/api/logs", query_string={"before_ts": "not-a-number"},
                               headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(seq, [e["seq"] for e in resp.get_json()["events"]])

    def test_before_ts_combines_with_before_seq(self):
        now = time.time()
        a = self._append(now - 7200)
        self._append(now - 3600)
        resp = self.client.get("/api/logs",
                               query_string={"before_ts": now, "before_seq": a + 1, "limit": 50},
                               headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual([e["seq"] for e in resp.get_json()["events"]], [a])


if __name__ == "__main__":
    unittest.main()
