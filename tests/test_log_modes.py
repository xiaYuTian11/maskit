"""§D1/D2/D3：日志写入分级、限时排障、反向游标、导出一致性与动作分离。

测试样例里的“明文”一律用明显伪造的合成串（`SYNTH-*`），**不写**任何形如
占位符或真实 PII 的字面量：本机在脱敏网关之后，写在测试文件里的占位符字面量
会在落盘时被还原、读回时又被掩码（AGENTS.md §3.9），用合成串既避开这个坑，
也让断言只依赖“字段被投影掉”这一事实，而与具体内容无关。
"""
import json
from contextlib import closing
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import panel

ROOT = Path(__file__).resolve().parents[1]
SYNTH_PLAIN = "SYNTH-ORIGINAL-VALUE"


def _mask_record(**extra):
    rec = {
        "type": "MASK",
        "host": "api.example.invalid",
        "method": "POST",
        "path": "/v1/messages",
        "count": 2,
        "mask_ms": 12.5,
        "decision": "masked",
        "suffix_reused": True,
        "dialog": "SYNTH-DIALOG " + SYNTH_PLAIN,
        "dialog_req": "SYNTH-REQ " + SYNTH_PLAIN,
        "req_preview": "SYNTH-PREVIEW " + SYNTH_PLAIN,
        "msg": "SYNTH-MESSAGE " + SYNTH_PLAIN,
        "items": [{"label": "PHONE", "original": SYNTH_PLAIN,
                   "preview": "1" + "*" * 10, "digest": "abcdef"}],
    }
    rec.update(extra)
    return rec


class LogModeConfigTests(unittest.TestCase):
    """配置四处同源：模板 / 默认 / 归一化 / 非法值。"""

    def test_legacy_config_without_key_stays_detailed(self):
        """缺 key = 老配置，必须迁到 detailed，绝不 setdefault 成 summary。

        把升级用户的历史还原能力与词榜在升级里静默关掉，是 §D2 明确禁止的。
        """
        self.assertEqual(panel.normalize_config({})["log_mode"], "detailed")
        legacy = {"capture_mode": "reverse", "log_retention_days": 7}
        self.assertEqual(panel.normalize_config(legacy)["log_mode"], "detailed")

    def test_explicit_modes_survive_and_trace_is_not_persistable(self):
        self.assertEqual(panel.normalize_config({"log_mode": "summary"})["log_mode"], "summary")
        self.assertEqual(panel.normalize_config({"log_mode": "detailed"})["log_mode"], "detailed")
        # trace 是限时运行时状态（走 engine-signals.json），配置里出现它一律回落 detailed：
        # 与其它辅助配置“非法值静默回落默认”的既有口径一致（不是安全边界，
        # 能改配置文件的人本来就能直接写 detailed）。
        self.assertEqual(panel.normalize_config({"log_mode": "trace"})["log_mode"], "detailed")
        self.assertEqual(panel.normalize_config({"log_mode": "bogus"})["log_mode"], "detailed")

    def test_log_mode_is_a_legal_patch_key(self):
        """必须登记进 default_config，否则前端存不下去（patch 会 400）。"""
        self.assertIn("log_mode", panel.default_config())
        self.assertEqual(panel.default_config()["log_mode"], "detailed")

    def test_template_installs_minimal_mode_for_fresh_users(self):
        """新装走随包模板：模板写 summary，这就是“新安装默认最小记录”的落地方式。"""
        ex = json.loads((ROOT / "engine" / "config.example.json").read_text(encoding="utf-8"))
        self.assertEqual(ex["log_mode"], "summary")
        # 模板里的值经归一化后仍然合法（四处同源的最基本要求）
        self.assertEqual(panel.normalize_config({k: v for k, v in ex.items()})["log_mode"], "summary")


class LogModeProjectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.trace_file = root / "engine-signals.json"
        for target, name, value in (
            (event_store, "DB_PATH", root / "events.sqlite3"),
            (event_store, "_db_ready", False),
            (event_store, "SIGNALS_FILE", self.trace_file),
            (event_store, "_SIGNALS_CACHE", {"ts": 0.0, "data": {}}),
            (event_store, "LOG_MODE", event_store.LOG_MODE_DETAILED),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_detailed_keeps_comparison_ability(self):
        event_store.set_log_mode("detailed")
        seq = event_store.append_event(_mask_record())
        row = event_store.fetch_event_by_id(seq)
        self.assertEqual(row["items"][0]["original"], SYNTH_PLAIN)
        self.assertIn(SYNTH_PLAIN, row["dialog"])
        self.assertEqual(row["mask_ms"], 12.5)

    def test_summary_drops_every_body_carrier(self):
        event_store.set_log_mode("summary")
        seq = event_store.append_event(_mask_record())
        row = event_store.fetch_event_by_id(seq)
        for gone in ("dialog", "dialog_req", "req_preview", "msg"):
            self.assertNotIn(gone, row, f"{gone} 不得在最小模式下落盘")
        blob = json.dumps(row, ensure_ascii=False)
        self.assertNotIn(SYNTH_PLAIN, blob)
        # 结构性/统计字段照旧：最小模式只减正文，不减可观测性
        self.assertEqual(row["host"], "api.example.invalid")
        self.assertEqual(row["count"], 2)
        self.assertEqual(row["mask_ms"], 12.5)
        self.assertEqual(row["decision"], "masked")
        self.assertTrue(row["suffix_reused"])

    def test_summary_keeps_label_counts_only(self):
        """类别数量是保留的（§D1 明列），但每项只留 label，不留任何可还原/可识别片段。"""
        event_store.set_log_mode("summary")
        seq = event_store.append_event(_mask_record())
        row = event_store.fetch_event_by_id(seq)
        self.assertEqual(row["items"], [{"label": "PHONE"}])

    def test_summary_words_keep_label_distribution_without_words(self):
        """词榜在最小模式下只保留类别分布：word 固定 "?"，明文词绝不落盘。"""
        event_store.set_log_mode("summary")
        event_store.append_event(_mask_record())
        with closing(event_store._connect()) as conn:
            rows = conn.execute("SELECT label, word, cnt FROM daily_words").fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [("PHONE", "?")])

    def test_detailed_words_keep_user_opt_in_plaintext(self):
        event_store.set_log_mode("detailed")
        event_store.append_event(_mask_record())
        with closing(event_store._connect()) as conn:
            rows = conn.execute("SELECT label, word FROM daily_words").fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [("PHONE", SYNTH_PLAIN)])

    def test_trace_drops_plaintext_but_keeps_masked_fragments(self):
        event_store.set_log_mode("detailed")
        event_store.start_log_trace(15)
        long_dialog = "SYNTH-" + "x" * 3000
        seq = event_store.append_event(_mask_record(dialog=long_dialog))
        row = event_store.fetch_event_by_id(seq)
        self.assertNotIn("original", row["items"][0])
        self.assertEqual(row["items"][0]["preview"], "1" + "*" * 10)
        self.assertIn("SYNTH-", row["dialog"])
        self.assertLess(len(row["dialog"]), len(long_dialog))
        self.assertIn("已截断", row["dialog"])

    def test_trace_window_expires_and_manual_stop_restores_base_mode(self):
        event_store.set_log_mode("detailed")
        event_store.start_log_trace(15)
        self.assertEqual(event_store.effective_log_mode(), "trace")
        future = time.time() + 16 * 60
        self.assertFalse(event_store.log_trace_state(now=future)["active"])
        self.assertEqual(event_store.effective_log_mode(now=future), "detailed")
        event_store.stop_log_trace()
        self.assertEqual(event_store.effective_log_mode(), "detailed")

    def test_engine_startup_clears_trace_window(self):
        """trace 不跨重启：引擎 load() 必须清掉状态文件里的 trace 窗口。"""
        event_store.start_log_trace(15)
        self.assertTrue(event_store.log_trace_state()["active"])
        import transparent
        with mock.patch.object(transparent, "_maybe_reload"), \
                mock.patch.object(transparent, "_warmup_recent_from_db"), \
                mock.patch.object(transparent, "_prune_debug_logs"), \
                mock.patch.object(transparent, "_log"):
            transparent.load(None)
        self.assertFalse(event_store.log_trace_state()["active"])
        # 文件可以留着（同一文件里还有映射重置代号），但 trace 窗口必须归零
        self.assertEqual(float(event_store._read_signals().get("trace_until") or 0.0), 0.0)


class _ReverseCursorBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for target, name, value in (
            (event_store, "DB_PATH", root / "events.sqlite3"),
            (event_store, "_db_ready", False),
            (event_store, "SIGNALS_FILE", root / "engine-signals.json"),
            (event_store, "_SIGNALS_CACHE", {"ts": 0.0, "data": {}}),
            (panel, "CONFIG_PATH", root / "config.json"),
            (panel, "_last_log_prune", [float("inf")]),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = panel.app.test_client()
        self.ids = []

    def append(self, typ="MASK", ingress="proxy"):
        seq = event_store.append_event({
            "type": typ, "host": "example.invalid", "method": "POST",
            "ingress": ingress, "count": 1,
        })
        self.ids.append(seq)
        return seq

    def get(self, **params):
        response = self.client.get("/api/logs", query_string=params,
                                   headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(response.status_code, 200)
        return response.json


class ReverseCursorTests(_ReverseCursorBase):
    def test_reverse_cursor_walks_history_without_gaps_or_overlap(self):
        for _ in range(12):
            self.append()
        top = self.get(limit=5)
        self.assertEqual([e["seq"] for e in top["events"]], self.ids[-5:])
        self.assertFalse(top["has_more"])

        page1 = self.get(limit=5, before_seq=self.ids[-5])
        self.assertEqual([e["seq"] for e in page1["events"]], self.ids[-10:-5])
        self.assertTrue(page1["has_older"])
        self.assertEqual(page1["before_cursor"], self.ids[-10])

        page2 = self.get(limit=5, before_seq=page1["before_cursor"])
        self.assertEqual([e["seq"] for e in page2["events"]], self.ids[-12:-10])
        self.assertFalse(page2["has_older"], "已到最早一页")
        self.assertEqual(page2["before_cursor"], self.ids[0])

        seen = [e["seq"] for e in page1["events"]] + [e["seq"] for e in page2["events"]]
        self.assertEqual(len(seen), len(set(seen)), "反向翻页不得重复")
        self.assertEqual(sorted(seen, reverse=True), self.ids[-12:-5][::-1])

    def test_older_cursor_honours_the_same_filters(self):
        wanted = [self.append("BLOCK"), self.append("BLOCK")]
        self.append("MASK")
        page = self.get(limit=5, before_seq=2 ** 31, type="BLOCK")
        self.assertEqual([e["seq"] for e in page["events"]], wanted)
        self.assertFalse(page["has_older"])

    def test_empty_history_page_is_not_an_error(self):
        self.append()
        page = self.get(limit=5, before_seq=self.ids[0])
        self.assertEqual(page["events"], [])
        self.assertFalse(page["has_older"])

    def test_list_reports_effective_log_mode(self):
        self.append()
        payload = self.get(limit=5)
        self.assertEqual(payload["log_mode"], "detailed")
        self.assertEqual(payload["trace_until"], 0)


class ExportConsistencyTests(_ReverseCursorBase):
    def test_export_reports_truncation_and_applies_ingress(self):
        for _ in range(3):
            self.append(ingress="ext")
        for _ in range(2):
            self.append(ingress="proxy")
        resp = self.client.get(
            "/api/logs/export",
            query_string={"limit": 2, "ingress": "ext"},
            headers={"X-Shield-Token": panel.API_TOKEN},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["X-Maskit-Matched"], "3")
        self.assertEqual(resp.headers["X-Maskit-Exported"], "2")
        self.assertEqual(resp.headers["X-Maskit-Truncated"], "1")
        body = resp.get_json()
        self.assertEqual(body["ingress"], "ext")
        self.assertEqual({e["ingress"] for e in body["events"]}, {"ext"})
        self.assertEqual(body["count"], 2)
        self.assertTrue(body["truncated"])

    def test_export_without_truncation_flags_zero(self):
        self.append(ingress="ext")
        resp = self.client.get(
            "/api/logs/export",
            query_string={"limit": 50, "ingress": "ext"},
            headers={"X-Shield-Token": panel.API_TOKEN},
        )
        self.assertEqual(resp.headers["X-Maskit-Truncated"], "0")
        self.assertEqual(resp.headers["X-Maskit-Matched"], "1")


class StatsActionSeparationTests(_ReverseCursorBase):
    def test_clear_stats_removes_numbers_but_keeps_events_and_words(self):
        seq = self.append()
        with closing(event_store._connect()) as conn:
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM daily_stats").fetchone()[0], 0)
            words_before = conn.execute("SELECT COUNT(*) FROM daily_words").fetchone()[0]
        resp = self.client.post("/api/stats/clear", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])
        with closing(event_store._connect()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM daily_stats").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM daily_tokens").fetchone()[0], 0)
            # 清统计不动日志：事件与词级明细必须原样还在
            # （daily_words 属日志明细，归 clear_events 管，不归 clear_stats）
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM daily_words").fetchone()[0], words_before)
        self.assertIsNotNone(event_store.fetch_event_by_id(seq))

    def test_clear_logs_keeps_numeric_stats(self):
        self.append()
        resp = self.client.post("/api/logs/clear", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(resp.status_code, 200)
        with closing(event_store._connect()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            # 默认清日志保留数字统计（趋势图不因清日志归零）
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM daily_stats").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
