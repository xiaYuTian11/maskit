"""Log retention must survive the config -> panel -> SQLite path."""
from contextlib import closing
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import panel


class PanelRetentionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for target, name, value in (
            (panel, "CONFIG_PATH", root / "config.json"),
            (event_store, "DB_PATH", root / "events.sqlite3"),
            (event_store, "_db_ready", False),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        event_store.init_db()
        self.now = time.time()
        for age in (30, 1):
            ts = self.now - age * 86400
            event_store.append_event({"type": "PASS", "ts": ts, "host": "example.invalid"})
            self.assertTrue(event_store.append_audit_event({"signal_type": "TEST", "ts": ts}))

    def counts(self):
        with closing(sqlite3.connect(event_store.DB_PATH)) as conn:
            return tuple(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                         for table in ("events", "audit_events"))

    def save_retention(self, days):
        cfg = panel.default_config()
        cfg["log_retention_days"] = days
        panel.save_config(cfg)

    def test_unlimited_saved_config_keeps_both_event_tables(self):
        self.save_retention(0)
        result = panel.prune_event_log(now=self.now)
        self.assertEqual(result.get("retained"), "forever")
        self.assertEqual(self.counts(), (2, 2))

    def test_finite_retention_only_removes_expired_events(self):
        self.save_retention(7)
        result = panel.prune_event_log(now=self.now)
        self.assertEqual(result["removed"], 1)
        self.assertEqual(self.counts(), (1, 1))

    def test_invalid_retention_uses_default(self):
        self.save_retention("invalid")
        self.assertEqual(panel.load_config()["log_retention_days"], 7)
        panel.prune_event_log(now=self.now)
        self.assertEqual(self.counts(), (1, 1))

    def test_logs_endpoint_reports_zero_and_preserves_history(self):
        self.save_retention(0)
        with mock.patch.object(panel, "_last_log_prune", [0]), panel.app.test_client() as client:
            response = client.get("/api/logs", headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["retention_days"], 0)
        self.assertEqual(len(response.json["events"]), 2)
        self.assertEqual(self.counts(), (2, 2))
