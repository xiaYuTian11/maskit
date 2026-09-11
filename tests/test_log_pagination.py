"""A log poll must not skip the oldest unseen events when a page fills."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import panel


class LogPaginationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for target, name, value in (
            (event_store, "DB_PATH", root / "events.sqlite3"),
            (event_store, "_db_ready", False),
            (panel, "CONFIG_PATH", root / "config.json"),
            (panel, "_last_log_prune", [float("inf")]),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = panel.app.test_client()
        for _ in range(202):
            self.append()

    def append(self, typ="PASS"):
        return event_store.append_event({"type": typ, "host": "example.invalid", "method": "POST",
                                         "dialog": "synthetic detail", "count": 1})

    def get(self, **params):
        response = self.client.get("/api/logs", query_string=params,
                                   headers={"X-Shield-Token": panel.API_TOKEN})
        self.assertEqual(response.status_code, 200)
        return response.json

    def test_backlog_and_new_writes_are_returned_without_gaps(self):
        first = self.get(since=1, limit=200, slim=1)
        self.assertEqual([e["seq"] for e in first["events"]], list(range(2, 202)))
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_since"], 201)
        new_id = self.append()
        second = self.get(since=first["next_since"], limit=200)
        self.assertEqual([e["seq"] for e in second["events"]], [202, new_id])
        self.assertFalse(second["has_more"])
        self.assertTrue(all("dialog" not in e for e in first["events"]))

    def test_initial_snapshot_and_default_store_query_still_show_latest(self):
        first = self.get(limit=200)
        self.assertEqual([e["seq"] for e in first["events"]], list(range(3, 203)))
        self.assertFalse(first["has_more"])
        self.assertEqual(first["next_since"], 202)
        self.assertEqual([e["seq"] for e in event_store.fetch_events(limit=2)], [201, 202])

    def test_filters_are_applied_before_pagination(self):
        wanted = [self.append("MASK"), self.append("MASK")]
        self.append("PASS")
        first = self.get(since=1, limit=1, type="MASK", q="example.invalid")
        self.assertEqual([e["seq"] for e in first["events"]], wanted[:1])
        self.assertTrue(first["has_more"])
        second = self.get(since=first["next_since"], limit=1, type="MASK", q="example.invalid")
        self.assertEqual([e["seq"] for e in second["events"]], wanted[1:])
        self.assertFalse(second["has_more"])

    def test_empty_and_exactly_full_pages_do_not_claim_more_records(self):
        exact = self.get(since=2, limit=200)
        self.assertEqual(len(exact["events"]), 200)
        self.assertFalse(exact["has_more"])
        empty = self.get(since=exact["next_since"], limit=200)
        self.assertEqual(empty["events"], [])
        self.assertFalse(empty["has_more"])
        self.assertEqual(empty["next_since"], 202)
        # Oversized client limits must use the same cap for fetching and has_more.
        for _ in range(1000):
            self.append()
        capped = self.get(since=1, limit=5000)
        self.assertEqual(len(capped["events"]), 1000)
        self.assertTrue(capped["has_more"])
        self.assertEqual(capped["next_since"], 1001)
