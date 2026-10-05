"""§G2/G3：复用与还原范围的**特征化**测试（先测再改）。

本文件不改变任何行为，只把现状钉住，好让「是否收窄恢复集合」「淘汰是否退化成
插入序」这类将来改动有一个可重跑的对比点：

  · G2：还原集合是**进程级复用表**，不是「本请求引用过的映射」——跨会话也能还原。
    这是现状，不是新增约束。若将来把恢复集合按入口/请求收窄，这里就是变更点
    （同时必须覆盖长对话、历史 token、凭据标签容错、panel fallback 与重启行为）。
  · G3：`suffix_reused` 与 `_prefix_payload` 的 `reuse_rate` 是验收指标
    （更完整的口径用例在 `tests/test_shield.py` 的 PrefixFidelity* 里）；
    命中即续期（`_touch_recent`）必须保持，否则活跃映射会被 24h TTL 误清。

样例原文用明显伪造的合成串；占位符一律**分片拼接**，不写占位符字面量
（AGENTS.md §3.9：本机网关会把写进文件的占位符字面量还原成真实值）。
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import transparent as tr

ORIG = "SYNTH-REUSE-VALUE-1"
TOKEN_PREFIX = "{{" + "PHONE_"


class _ReuseIsolation(unittest.TestCase):
    """全局复用表是进程共享的：用例前后必须快照/还原，避免污染其它用例。"""

    def setUp(self):
        tables = tr._tables()
        self._snap = (
            {k: list(v) for k, v in tables.fwd.items()},
            {k: list(v) for k, v in tables.rev.items()},
            dict(tables.suffix),
        )
        self._sids = ("scope-src", "scope-other", "scope-missing")
        self.addCleanup(self._restore)

    def _restore(self):
        tables = tr._tables()
        with tr._STATE_LOCK:
            tables.fwd.clear()
            tables.fwd.update(self._snap[0])
            tables.rev.clear()
            tables.rev.update(self._snap[1])
            tables.suffix.clear()
            tables.suffix.update(self._snap[2])
        for sid in self._sids:
            tr.sessions.pop(sid, None)

    def _register(self):
        fwd, labels = {}, {}
        tr._remember(fwd, labels, ORIG, "PHONE")
        return fwd[ORIG]


class RestoreScopeTests(_ReuseIsolation):
    def test_reuse_table_is_process_global_across_live_sessions(self):
        """G2 现状：在两个会话都活着的条件下，A 会话登记的占位符在 B 会话也能还原。

        正因为恢复集合是全进程共享的复用表（而不是「本请求引用过的映射」），
        「是否收窄到按入口/请求限定」才需要单独威胁建模与专项测试。
        """
        tr._new_session("scope-src")
        tr._new_session("scope-other")
        token = self._register()
        self.assertTrue(token.startswith(TOKEN_PREFIX))
        self.assertEqual(tr.restore(token, "scope-other", final=True), ORIG)
        self.assertIn(token, tr._tables().rev)

    def test_restore_without_a_live_session_is_refused(self):
        """无会话时**绝不**还原：否则任意自造 sid 都能借复用表还原占位符。

        这是与上一条配对的安全门（有会话才谈得上“范围有多宽”）。
        """
        token = self._register()
        self.assertEqual(tr.restore(token, "scope-missing", final=True), token)

    def test_unknown_placeholder_is_left_verbatim_and_never_guessed(self):
        """模型自造的占位符必须原样保留：表里没有它，还原它在信息论上就不可能。"""
        bogus = "{{" + "PHONE_" + "zzzzzz" + "}}"
        self.assertEqual(tr.restore(bogus, "scope-other", final=True), bogus)

    def test_hit_renews_timestamps_so_active_mappings_survive_ttl(self):
        """G3：命中即续期。只刷一个方向会让另一方向被 `_prune_recent` 连带清掉。"""
        token = self._register()
        tables = tr._tables()
        stale = time.time() - 10 * 24 * 3600
        tables.rev[token][2] = stale
        tables.fwd[ORIG][2] = stale
        now = time.time()
        tr._touch_recent(token, ORIG, now=now)
        self.assertEqual(tables.rev[token][2], now)
        self.assertEqual(tables.fwd[ORIG][2], now)


class PrefixMetricTests(unittest.TestCase):
    def test_prefix_metrics_expose_reuse_rate(self):
        """G3 验收指标存在且口径正确（分母是 rewritten，不是 masks）。"""
        payload = event_store._prefix_payload(3, 2, 1, 10, 2)
        self.assertEqual(payload["suffix_reused"], 1)
        self.assertEqual(payload["rewritten"], 2)
        self.assertAlmostEqual(payload["reuse_rate"], 0.5, places=4)

    def test_reuse_rate_is_none_without_rewrites(self):
        payload = event_store._prefix_payload(3, 0, 0, 0, 0)
        self.assertIsNone(payload["reuse_rate"],
                          "没签发过占位符时报 0% 是另一种含义（「查了但没命中」）")


if __name__ == "__main__":
    unittest.main()
