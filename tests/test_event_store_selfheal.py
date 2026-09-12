"""事件库 schema 初始化与损坏自愈。

两条底线：
1) `_ensure_db()` 对**同一个路径只建一次表**（读路径以前每次查询都跑十几条
   CREATE TABLE/INDEX IF NOT EXISTS），但**换路径必须重建**（测试与「把数据目录
   指到别处」都会换路径，漏建表会变成 no such table）；
2) 文件真损坏时（不是锁竞争、不是路径不可写）不能只让面板永久 500，要挪走坏文件
   重建空库——且**绝不删除**旧文件。
"""
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store


class EnsureDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: self._cleanup(self.tmp))
        self.old_db = event_store.DB_PATH
        self.addCleanup(lambda: setattr(event_store, "DB_PATH", self.old_db))
        event_store.DB_PATH = self.tmp / "ev.sqlite3"
        event_store._reset_writer()

    @staticmethod
    def _cleanup(tmp):
        for p in list(tmp.glob("*")):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    def test_ddl_runs_once_per_path(self):
        calls = []
        real_init = event_store.init_db

        def counting_init():
            calls.append(1)
            return real_init()

        with mock.patch.object(event_store, "init_db", counting_init):
            for _ in range(5):
                event_store.fetch_events(limit=1)
        self.assertEqual(len(calls), 1, "同一路径只该建一次表")

    def test_switching_db_path_reinitializes(self):
        event_store.fetch_events(limit=1)  # 先把第一个路径标记为已初始化
        # 换路径但**不**调 _reset_writer（模拟生产里改数据目录）
        second = self.tmp / "second.sqlite3"
        event_store.DB_PATH = second
        events = event_store.fetch_events(limit=1)  # 必须自动重建，否则 no such table
        self.assertEqual(events, [])
        with sqlite3.connect(second) as conn:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("events", names)

    def test_corrupt_db_is_quarantined_and_recreated(self):
        event_store.DB_PATH.write_bytes(b"this is definitely not a sqlite database" * 4)
        event_store._reset_writer()
        events = event_store.fetch_events(limit=1)  # 不能抛
        self.assertEqual(events, [])
        quarantined = list(self.tmp.glob("ev.sqlite3.corrupt-*"))
        self.assertEqual(len(quarantined), 1, "坏文件必须留档，不能删除")
        self.assertGreater(quarantined[0].stat().st_size, 0)
        # 新库可用
        event_store.append_event({"ts": time.time(), "type": "MASK", "count": 1, "host": "h"})
        self.assertTrue(event_store.fetch_events(limit=5))

    def test_unwritable_path_is_not_quarantined(self):
        # 父目录不存在 → OperationalError（不是损坏）。绝不能把「打不开」当损坏处理：
        # 那会在路径写错时凭空建出 .corrupt-* 垃圾，还会让用户误以为数据坏了。
        event_store.DB_PATH = self.tmp / "no_such_dir" / "ev.sqlite3"
        event_store._reset_writer()
        with self.assertRaises(sqlite3.OperationalError):
            event_store.fetch_events(limit=1)
        self.assertEqual(list(self.tmp.glob("*.corrupt-*")), [])
        self.assertEqual(list((self.tmp / "no_such_dir").glob("*")) if (self.tmp / "no_such_dir").exists() else [], [])


class EventIndexTests(unittest.TestCase):
    """日志列表查询必须命中 `(type, id)` 索引。

    `fetch_events` 的形态是 `WHERE id > ? AND type = ? ORDER BY id [ASC|DESC] LIMIT n`
    —— 按 id 游标增量取某一类型。`id` 是 rowid，只有在 `(type, id)` 上才是可直接
    使用的范围约束；只有 `(type, ts)` 时会退化成「扫完整个类型段 → TEMP B-TREE 排序」
    （100 万行实测首屏 292ms → 6ms）。这里断言**查询计划**而不是耗时，避免用例在
    慢机器上偶发失败。
    """

    SQL = ("SELECT id, payload FROM events WHERE id > ? AND type = ? "
           "ORDER BY id DESC LIMIT ?")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: self._cleanup(self.tmp))
        self.old_db = event_store.DB_PATH
        self.addCleanup(lambda: setattr(event_store, "DB_PATH", self.old_db))
        event_store.DB_PATH = self.tmp / "ev.sqlite3"
        event_store._reset_writer()
        for i in range(300):
            event_store.append_event({"ts": 1000 + i, "type": ["MASK", "RESTORE"][i % 2],
                                      "count": 1, "host": "example.invalid"})

    @staticmethod
    def _cleanup(tmp):
        for p in list(tmp.glob("*")):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    def _plan(self):
        with event_store.closing(event_store._connect()) as conn:
            return [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + self.SQL,
                                                   (0, "MASK", 50))]

    def test_typed_list_query_uses_type_id_index(self):
        plan = self._plan()
        joined = "; ".join(plan)
        self.assertTrue(any("idx_events_type_id" in step for step in plan),
                        f"应按 (type, id) 走索引，实际计划：{joined}")
        self.assertFalse(any("TEMP B-TREE" in step for step in plan),
                         f"不该再为 ORDER BY 建临时排序树，实际计划：{joined}")

    def test_type_ts_index_is_kept_for_time_range_queries(self):
        # 按时间范围查（stats / fetch_restore_items）仍需要 (type, ts)；
        # 两个索引各管一种形态，别把后者当成冗余删掉。
        with event_store.closing(event_store._connect()) as conn:
            names = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("idx_events_type_ts", names)
        self.assertIn("idx_events_type_id", names)


if __name__ == "__main__":
    unittest.main()
