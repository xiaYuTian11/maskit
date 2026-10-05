"""批次 8（P0-1/P0-3/P0-4/P1-7/P0-2/P0-5）：CPU 配额感知、预算结算、切段与失败归因。

这些改动都长在**热路径的治理层**上，写错了不会报错，只会「静默地少扫」或
「静默地把责任判给错的一方」，所以每一条都要有独立的钉子：

  · `effective_cpu_count`  —— 容器 `--cpus=N` 下必须按配额算，不是按宿主核数；
  · `_bucket_settle`       —— 估高了退还、估低了**追缴**（旧口径只退不追，预算形同虚设）；
  · `skip_epoch`           —— 只统计「结果残缺」类原因（决定上游叶子缓存能否入库）；
  · `_long_seg_cuts`       —— 切点吸附到换行/句末，且每段长度上界恒为 `MAX_TEXT_CHARS`；
  · `warmup`               —— 幂等、失败不抛、模型不可用时不硬来；
  · `_ner_prefetch_newest_first` —— 逆序（最新优先）、降级即停、关掉开关即回旧行为；
  · `_flow_failure_owner`  —— 引擎/上游/客户端/DNS/代理五类归因，拿不准时归上游。
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import event_store
import ner_engine as ner
import transparent as tr


class EffectiveCpuCountTests(unittest.TestCase):
    """`effective_cpu_count`：亲和性掩码 ∩ cgroup 配额，至少 1。"""

    def _patch(self, quota, affinity):
        return (mock.patch.object(ner, "_cgroup_cpu_quota", lambda: quota),
                mock.patch.object(ner.os, "process_cpu_count", lambda: affinity,
                                  create=True))

    def test_cgroup_quota_caps_host_core_count(self):
        """16 核宿主上 `--cpus=2`：必须报 2（报 16 就会开 4 个 ONNX 线程把配额吃满）。"""
        q, a = self._patch(2.0, 16)
        with q, a:
            self.assertEqual(ner.effective_cpu_count(), 2)

    def test_affinity_is_honoured_when_no_quota(self):
        q, a = self._patch(None, 3)
        with q, a:
            self.assertEqual(ner.effective_cpu_count(), 3)

    def test_fractional_quota_rounds_up(self):
        """1.5 核向上取整成 2：向下取整会让 1.5 核的容器只开 1 线程，白丢半核。"""
        q, a = self._patch(1.5, 8)
        with q, a:
            self.assertEqual(ner.effective_cpu_count(), 2)

    def test_never_below_one(self):
        q, a = self._patch(0.1, 8)
        with q, a:
            self.assertEqual(ner.effective_cpu_count(), 1)

    def test_real_environment_is_sane(self):
        """真实环境里必须是个 ≥1 的整数（防止整条路径在容器里抛异常）。"""
        self.assertGreaterEqual(ner.effective_cpu_count(), 1)


class BucketSettlementTests(unittest.TestCase):
    """预算结算：`墙钟 × 线程数` 记 CPU 毫秒，估高了退、估低了追。"""

    def setUp(self):
        self.saved = ner._BUCKET["tokens"]
        self.addCleanup(self._restore)

    def _restore(self):
        ner._BUCKET["tokens"] = self.saved

    def test_over_estimate_is_refunded(self):
        ner._BUCKET["tokens"] = 100.0
        ner._bucket_settle(500.0, 100.0)
        self.assertEqual(ner._BUCKET["tokens"], 500.0)

    def test_refund_is_capped_at_capacity(self):
        ner._BUCKET["tokens"] = 100.0
        ner._bucket_settle(10 ** 9, 0.0)
        self.assertEqual(ner._BUCKET["tokens"], float(ner._NER_BUDGET_MS_PER_S))

    def test_under_estimate_is_charged_back(self):
        """旧口径只退不追：超支永远不记账，预算就不是 CPU 上限。"""
        ner._BUCKET["tokens"] = 100.0
        ner._bucket_settle(50.0, 550.0)
        self.assertEqual(ner._BUCKET["tokens"], -400.0)

    def test_debt_is_floored(self):
        ner._BUCKET["tokens"] = 0.0
        ner._bucket_settle(1.0, 10 ** 9)
        self.assertEqual(ner._BUCKET["tokens"], ner._BUCKET_DEBT_FLOOR)
        self.assertLess(ner._BUCKET_DEBT_FLOOR, 0.0)

    def test_cpu_threads_is_positive(self):
        self.assertGreaterEqual(ner._cpu_threads(), 1)

    def test_governor_status_declares_the_cpu_unit(self):
        """单位换了必须外发，否则面板上「12000 毫秒/秒」会被读成墙钟。"""
        g = ner.governor_status()
        self.assertEqual(g.get("budget_unit"), "cpu_ms_per_s")
        self.assertGreaterEqual(g.get("cpu_cores"), 1)
        self.assertGreaterEqual(g.get("cpu_threads"), 1)


class _NerSkipIsolation(unittest.TestCase):
    """`_note_skip` 会写线程本地的本轮跳过表与进程级的累计计数，两边都要还原。

    不还原的后果不是“测试自己脏”，而是**把别的用例测脏**：
    `request_skips() == {}` 是签名块豁免用例的断言，多出来的键会让它莫名其妙地红。
    """

    def setUp(self):
        # ⚠️ 必须**拷一份**：`_note_skip` 是就地改那个 dict 的，直接存引用的话
        # “快照”会跟着被测代码一起被污染，还原时又把污染装回去（实测踩过）。
        self._saved_skip_stats = dict(ner._SKIP_STATS)
        self._saved_skip_logged = set(ner._SKIP_LOGGED)
        cur = getattr(ner._local, "skips", None)
        self._saved_local_skips = dict(cur) if isinstance(cur, dict) else cur
        self.addCleanup(self._restore_skip_state)

    def _restore_skip_state(self):
        ner._SKIP_STATS.clear()
        ner._SKIP_STATS.update(self._saved_skip_stats)
        ner._SKIP_LOGGED.clear()
        ner._SKIP_LOGGED.update(self._saved_skip_logged)
        ner._local.skips = self._saved_local_skips


class SkipEpochTests(_NerSkipIsolation):
    """`skip_epoch`：只统计会让结果残缺的原因，供上游叶子缓存决定能否入库。"""

    def test_poison_reasons_bump_the_epoch(self):
        for key in ("global_throttled", "sem_timeout", "deadline", "cancelled",
                    "budget_exhausted", "infer_failed", "init_failed"):
            before = ner.skip_epoch()
            ner._note_skip(key)
            self.assertEqual(ner.skip_epoch(), before + 1, "%s 没有抬高代号" % key)

    def test_model_unavailable_is_not_poisoning(self):
        """模型缺失是进程级常量：此时 NER 不产生任何替换，规则结果是完整的。"""
        before = ner.skip_epoch()
        ner._note_skip("model_unavailable")
        self.assertEqual(ner.skip_epoch(), before)

    def test_poison_set_covers_every_known_reason(self):
        """新增降级原因时必须显式决定它算不算「残缺」（默认不算是危险的默认值）。"""
        self.assertIn("budget_exhausted", ner._CACHE_POISON_SKIPS)
        self.assertNotIn("model_unavailable", ner._CACHE_POISON_SKIPS)


class LongSegmentTests(unittest.TestCase):
    """长文本切段：吸附到换行/句末，段长上界恒为 `MAX_TEXT_CHARS`。"""

    def _segments(self, text):
        cuts = ner._long_seg_cuts(text) + [len(text)]
        prev, out = 0, []
        for c in cuts:
            start = 0 if prev == 0 else max(0, prev - ner._LONG_SEG_OVERLAP)
            out.append(text[start:c])
            prev = c
        return out

    def test_short_text_is_not_cut(self):
        self.assertEqual(ner._long_seg_cuts("短文本"), [])

    def test_every_segment_respects_the_char_cap(self):
        """段长超上限会让 `extract_entities` 对这一段再递归切一次（无限递归面）。"""
        for body in ("甲" * (ner.MAX_TEXT_CHARS * 3 + 7),
                     ("第%d行：某公司的联系人张三。\n" % 0).join(["x"] * 2000),
                     ("句子结束。 " * 5000)):
            segs = self._segments(body)
            self.assertGreater(len(segs), 1, "用例前提：应当被切开")
            for s in segs:
                self.assertLessEqual(len(s), ner.MAX_TEXT_CHARS,
                                     "段长 %d 超过上限" % len(s))

    def test_cut_snaps_to_a_boundary(self):
        """切点必须落在换行/句末之后（固定偏移会把实体劈成两半）。"""
        body = ("这是一个完整的句子。" * 300) + "尾巴" * 100
        for c in ner._long_seg_cuts(body):
            self.assertIn(body[c - 1], "\n。！？；",
                          "切点没有吸附到边界（前一字符是 %r）" % body[c - 1])

    def test_tail_append_does_not_move_existing_cuts(self):
        """客户端每轮重发整段历史：尾部追加不得移动已有切点（段级缓存的前提）。"""
        body = ("第%d行：某公司的联系人张三住在北京市朝阳区。\n" % 0).join(["y"] * 1500)
        before = ner._long_seg_cuts(body)
        after = ner._long_seg_cuts(body + "追加的一行内容。\n" + "z" * 3000)
        self.assertEqual(after[:len(before)], before, "尾部追加移动了已有切点")

    def test_segments_are_used_by_extract_long(self):
        """`_extract_long` 必须真的用这套切点，而不是自己另切一份。"""
        calls = []

        def fake(seg):
            calls.append(seg)
            return []

        body = "甲" * (ner.MAX_TEXT_CHARS * 2 + 500)
        with mock.patch.object(ner, "extract_entities", fake):
            ner._extract_long(body)
        self.assertGreater(len(calls), 1)
        self.assertEqual(calls, self._segments(body), "分段结果与切点不一致")


class WarmupTests(_NerSkipIsolation):
    """启动预热：幂等、失败不抛、模型不可用时不硬来。"""

    def setUp(self):
        super().setUp()          # `_warn_once` 会写进程级跳过计数，同样要还原
        self.saved = ner._WARMED
        ner._WARMED = False
        self.addCleanup(self._restore)

    def _restore(self):
        ner._WARMED = self.saved

    def test_missing_model_returns_false_without_loading(self):
        with mock.patch.object(ner, "is_ner_available", lambda: False), \
             mock.patch.object(ner, "_init_ner") as init:
            self.assertFalse(ner.warmup())
        init.assert_not_called()

    def test_success_runs_once_and_is_idempotent(self):
        saved = ner._INITIALIZED
        self.addCleanup(setattr, ner, "_INITIALIZED", saved)

        def init():
            ner._INITIALIZED = True
            return True

        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "_init_ner", side_effect=init), \
             mock.patch.object(ner, "_decode_chunks", return_value=([], True)) as dec:
            self.assertTrue(ner.warmup())
            self.assertTrue(ner.warmup())
        self.assertEqual(dec.call_count, 1, "预热跑了不止一次")

    def test_inference_failure_does_not_raise(self):
        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "_init_ner", return_value=True), \
             mock.patch.object(ner, "_decode_chunks", side_effect=RuntimeError("boom")):
            self.assertTrue(ner.warmup(), "预热失败不该把异常抛出去")


class NerPrefetchTests(_NerSkipIsolation):
    """NER 预取：最新消息优先（P0-2）。"""

    def setUp(self):
        super().setUp()          # ⚠️ 必须调：否则跳过计数不会被还原（实测把别的用例测脏）
        self.saved = (tr.NER_ENABLED, tr._NER_PREFETCH_SHARE, tr._NER_PREFETCH_LEAVES)
        self.addCleanup(self._restore)

    def _restore(self):
        (tr.NER_ENABLED, tr._NER_PREFETCH_SHARE, tr._NER_PREFETCH_LEAVES) = self.saved
    def test_disabled_when_ner_is_off(self):
        tr.NER_ENABLED = False
        with mock.patch.object(ner, "extract_entities") as ex:
            self.assertEqual(tr._ner_prefetch_newest_first({"a": "有汉字"}, 1.0), 0)
        ex.assert_not_called()

    def test_share_zero_restores_old_behaviour(self):
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.0
        with mock.patch.object(ner, "extract_entities") as ex:
            self.assertEqual(tr._ner_prefetch_newest_first({"a": "有汉字"}, 1.0), 0)
        ex.assert_not_called()

    def test_prefetches_newest_first(self):
        """顺序必须是**逆序**：正序会让最老的历史先吃光预算，最新那条永远轮不到。"""
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.5
        tr._NER_PREFETCH_LEAVES = 16
        body = {"messages": [{"content": "第%d条有汉字" % i} for i in range(5)]}
        seen = []
        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "extract_entities",
                               side_effect=lambda t: seen.append(t) or []):
            n = tr._ner_prefetch_newest_first(body, 1.0)
        self.assertEqual(n, 5)
        self.assertEqual(seen, ["第%d条有汉字" % i for i in reversed(range(5))],
                         "预取顺序不是「最新优先」")

    def test_stops_as_soon_as_something_degrades(self):
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.5
        tr._NER_PREFETCH_LEAVES = 16
        body = {"messages": [{"content": "第%d条有汉字" % i} for i in range(5)]}
        calls = []

        def fake(text):
            calls.append(text)
            if len(calls) == 2:
                ner._note_skip("budget_exhausted")
            return []

        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "extract_entities", side_effect=fake):
            n = tr._ner_prefetch_newest_first(body, 1.0)
        self.assertEqual(n, 2, "降级之后还继续白烧时间")

    def test_short_and_oversized_leaves_are_skipped(self):
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.5
        tr._NER_PREFETCH_LEAVES = 16
        body = {"a": "短", "b": "有汉字的内容", "c": "汉" * (tr._NER_PREFETCH_MAX_CHARS + 1)}
        seen = []
        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "extract_entities",
                               side_effect=lambda t: seen.append(t) or []):
            tr._ner_prefetch_newest_first(body, 1.0)
        self.assertEqual(seen, ["有汉字的内容"])

    def test_collector_walks_dicts_and_lists(self):
        out = []
        tr._collect_leaf_texts({"a": ["有汉字一", {"b": "有汉字二"}], "c": 3}, out, 10)
        self.assertEqual(out, ["有汉字一", "有汉字二"])

    def test_collector_stops_at_the_same_depth_as_mask_tree(self):
        """深度上限与 `_mask_tree` 同口径：超深 body 由 `_mask_tree` fail-closed 阻断，
        预取不必先在它上面把递归跑到 Python 栈底（再撞同一个墙）。
        """
        deep = "有汉字的叶子"
        for _ in range(tr._MASK_MAX_DEPTH + 5):
            deep = {"k": deep}
        out = []
        tr._collect_leaf_texts(deep, out, 10)          # 不得抛 RecursionError
        self.assertEqual(out, [])
        shallow = {"k": {"k": "有汉字的叶子"}}
        out2 = []
        tr._collect_leaf_texts(shallow, out2, 10)
        self.assertEqual(out2, ["有汉字的叶子"], "正常深度不能被上限误伤")

    def test_degradation_during_prefetch_is_not_charged_to_the_request(self):
        """预取的降级是**推测性**的：不能进请求级跳过记录。

        判据取 `request_skips()` —— 那正是严格模式（`ner_require_complete`）的阻断
        依据。漏了隔离会把「其实完整扫完」的请求 503 掉，而且事件/导出里会多一条
        已被推翻的降级原因。进程级计数相反：**必须照常涨**，设置页与自检靠它看到
        「预取确实降级过」。
        """
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.5
        before = dict(ner.status().get("skips") or {})
        ner.begin_budget(5)
        try:
            with mock.patch.object(ner, "is_ner_available", lambda: True), \
                 mock.patch.object(ner, "extract_entities",
                                   side_effect=lambda t: ner._note_skip("sem_timeout") or []):
                tr._ner_prefetch_newest_first({"a": "有汉字的内容"}, 1.0)
            self.assertEqual(ner.request_skips(), {},
                             "预取的降级被记进了本请求，严格模式会据此误 503")
        finally:
            ner.end_budget()
        after = dict(ner.status().get("skips") or {})
        self.assertGreater(after.get("sem_timeout", 0),
                           before.get("sem_timeout", 0),
                           "进程级计数被一并隔离了：设置页将看不到预取的降级")

    def test_failure_is_logged_once_and_still_returns_zero(self):
        """吞异常 ≠ 无声无息：首次意外要留一行日志，之后不刷屏。

        这条路径**不**往 NER 跳过记账里写：那是严格模式的阻断判据，而「预取没跑」
        不等于「本次检测不完整」（正常遍历仍会扫）。
        """
        tr.NER_ENABLED = True
        tr._NER_PREFETCH_SHARE = 0.5
        saved = tr._NER_PREFETCH_WARNED[0]
        tr._NER_PREFETCH_WARNED[0] = False
        self.addCleanup(lambda: tr._NER_PREFETCH_WARNED.__setitem__(0, saved))
        logged = []
        with mock.patch.object(ner, "is_ner_available", lambda: True), \
             mock.patch.object(ner, "extract_entities",
                               side_effect=RuntimeError("boom")), \
             mock.patch.object(tr, "_log", lambda m="", *a, **k: logged.append(m)):
            self.assertEqual(tr._ner_prefetch_newest_first({"a": "有汉字的内容"}, 1.0), 0)
            self.assertEqual(tr._ner_prefetch_newest_first({"a": "有汉字的内容"}, 1.0), 0)
        self.assertEqual(len(logged), 1, "首次告警必须留下，且只留一次")
        self.assertIn("预取", logged[0])


class BudgetDefaultTests(unittest.TestCase):
    """预算默认容量 = 「NER 线程池最多能吃的 CPU」的 75%，**不是**「核数 × 750」。

    旧口径按**墙钟**计费，容量 `并发 × 750` 对应的实际 CPU 是 `并发 × 线程数 × 750`；
    改成 CPU 毫秒后不换算，16 核机器上的允许量会平白翻倍（2 核上则是减半），
    与「注释里那句把 3/4 个核留给推理」对不上。
    """

    def test_default_is_a_faithful_translation_of_the_old_wall_clock_value(self):
        if (os.environ.get("MASKIT_NER_BUDGET") or "").strip():
            self.skipTest("MASKIT_NER_BUDGET 已覆盖，本用例只校验默认换算")
        expected = max(50, int(ner._NER_CONCURRENCY * ner._intra_threads() * 1000 * 0.75))
        self.assertEqual(ner._NER_BUDGET_MS_PER_S, expected)
        self.assertLessEqual(ner._NER_BUDGET_MS_PER_S,
                             ner._NER_CONCURRENCY * ner._intra_threads() * 1000,
                             "预算不得超过线程池实际的 CPU 上限")


class FailureOwnerTests(unittest.TestCase):
    """P0-5：失败归因必须能把「引擎 / 上游 / 客户端 / DNS / 出口代理」分开。"""

    @staticmethod
    def _flow(raw_error="", metadata=None, response=None):
        return SimpleNamespace(error=raw_error, metadata=dict(metadata or {}),
                               response=response)

    def test_client_disconnect(self):
        self.assertEqual(tr._flow_failure_owner(self._flow(), "Client disconnected"),
                         "client")
        self.assertEqual(
            tr._flow_failure_owner(self._flow(), "EOF occurred in violation of protocol"),
            "client")

    def test_dns_failure(self):
        self.assertEqual(tr._flow_failure_owner(self._flow(), "getaddrinfo failed"), "dns")
        self.assertEqual(
            tr._flow_failure_owner(self._flow(), "Temporary failure in name resolution"),
            "dns")

    def test_egress_proxy_is_called_out(self):
        flow = self._flow("Connection refused", {"shield_via_proxy": True})
        self.assertEqual(tr._flow_failure_owner(flow, ""), "proxy")

    def test_engine_when_masking_never_finished(self):
        flow = self._flow("TimeoutError", {"session_id": "s1"})
        self.assertEqual(tr._flow_failure_owner(flow, ""), "engine")

    def test_upstream_when_masking_completed(self):
        flow = self._flow("TimeoutError", {"session_id": "s1",
                                           "shield_mask_done_at": 1.0})
        self.assertEqual(tr._flow_failure_owner(flow, ""), "upstream")

    def test_plain_passthrough_timeout_is_not_blamed_on_the_engine(self):
        """没走过脱敏链路的请求（非匹配域名透传）超时，不能算成引擎问题。"""
        flow = self._flow("TimeoutError", {})
        self.assertEqual(tr._flow_failure_owner(flow, ""), "upstream")

    def test_owner_is_always_a_known_label(self):
        for flow, raw in ((self._flow(""), ""), (self._flow("x", {}), "")):
            self.assertIn(tr._flow_failure_owner(flow, raw), tr._FAILURE_OWNERS)

    def test_error_type_is_structured(self):
        self.assertEqual(tr._flow_error_type(self._flow(RuntimeError("x"))), "RuntimeError")
        self.assertEqual(tr._flow_error_type(self._flow(None)), "")


class FailureOwnerEventTests(unittest.TestCase):
    """归因字段必须真的进事件、且能活过最小模式投影（否则面板看不到）。"""

    def test_fields_survive_summary_projection(self):
        for key in ("failure_owner", "error_type"):
            self.assertIn(key, event_store._SUMMARY_KEEP_FIELDS)

    def test_error_event_carries_the_owner(self):
        events = []
        flow = SimpleNamespace(
            error=RuntimeError("Client disconnected"),
            metadata={"session_id": "s-err", "transport": {}},
            request=SimpleNamespace(host="h", method="POST", path="/v1/chat",
                                    pretty_host="h"),
            response=None, _shield_mask_cancel=None,
        )
        with mock.patch.object(tr, "_emit", lambda *a, **k: events.append(k)), \
             mock.patch.object(tr, "_dispose_stream", lambda *a, **k: None), \
             mock.patch.object(tr, "_transport_event", lambda *a, **k: None), \
             mock.patch.object(tr, "_safe_transport_snapshot", lambda *a: {}), \
             mock.patch.object(tr, "_aux_token", lambda *a: None), \
             mock.patch.object(tr, "_aux_abandon", lambda *a: None), \
             mock.patch.object(tr, "_drop", lambda *a, **k: None):
            tr.error(flow)
        self.assertTrue(events, "error() 没有落任何事件")
        self.assertEqual(events[0].get("failure_owner"), "client")
        self.assertEqual(events[0].get("error_type"), "RuntimeError")


if __name__ == "__main__":
    unittest.main()
