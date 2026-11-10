"""G611~G613：复用表的「最近使用」语义。

真机背景（2026-11-10，同一会话不同轮次）：810 条消息的一轮只要 0.58 s
（NER miss=2），而 663 条消息的一轮要 19.5 s（NER miss=657）、636 条的一轮 27.6 s。
同一会话、更大体量反而更快 —— 说明不是文本必然变化，而是命中状态成批翻转。

根因在 `_leaf_cache_lookup`：命中只校验 token 还活着，**不刷新 ts**；而
`_prune_recent_locked` 按 ts 排序淘汰、TTL 判定也用同一个 ts。于是「每轮都在用、
但每轮都走叶子缓存」的 token 时间戳停在最后一次冷跑，被同会话新签的几百个 token
推开；一个 token 消失，所有引用它的叶子整叶失效 → 全量重扫 + 重跑 NER → 撞 10 s
单请求预算。

三条守卫：
  G611 命中必须给两个方向都续期（只刷 REV 不够：淘汰是按 FWD 的 ts 扫的）
  G612 治失效不得顺手放宽上界（原文驻留窗口是 SECURITY.md 的契约）
  G613 miss 必须能归因到四类，且诊断不得改变任何输出

用例全部关掉 NER：测的是复用表与叶子缓存的失效语义，与模型无关。
"""

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import transparent as tr


def _phone(i=0):
    """显然伪造的样例号码（尾段按序号变化，不做真实号段）。"""
    return "138" + "%08d" % i


def _placeholder(label, suffix):
    """占位符字面量一律片段拼接（整串写进文件可能被网关还原）。"""
    return "{" * 2 + label + "_" + suffix + "}" * 2


class _RecentLruBase(unittest.TestCase):
    """与 `tests/test_leaf_cache.py` 同款隔离：不动真实数据目录、不串全局表。"""

    def setUp(self):
        self._saved_globals = (tr.NER_ENABLED, tr.BUILTIN_RULES, tr._RECENT_MAX)
        tr.NER_ENABLED = False
        self.addCleanup(self._restore_globals)

        self._saved_tables = (dict(tr.sessions), dict(tr._RECENT_FWD),
                              dict(tr._RECENT_REV), dict(tr._RECENT_SUFFIX))
        self.addCleanup(self._restore_tables)
        tr.sessions.clear()
        tr._RECENT_FWD.clear()
        tr._RECENT_REV.clear()
        tr._RECENT_SUFFIX.clear()
        tr._known_reset_for_tests()

        tr._recent_in_use_clear()
        self.addCleanup(tr._recent_in_use_clear)

        self._saved_cache_ok = tr._LEAF_CACHE_OK[0]
        tr._LEAF_CACHE_OK[0] = True
        tr._leaf_cache_clear()
        tr._LEAF_CACHE_STATS.update(
            hit=0, miss=0, verify=0, poison=0,
            miss_token_gone=0, miss_identity=0, miss_gen=0, miss_scope=0,
        )
        self.addCleanup(self._restore_cache)

    def _restore_globals(self):
        tr.NER_ENABLED, tr.BUILTIN_RULES, tr._RECENT_MAX = self._saved_globals

    def _restore_tables(self):
        sessions, fwd, rev, suffix = self._saved_tables
        tr.sessions.clear()
        tr.sessions.update(sessions)
        tr._RECENT_FWD.clear()
        tr._RECENT_FWD.update(fwd)
        tr._RECENT_REV.clear()
        tr._RECENT_REV.update(rev)
        tr._RECENT_SUFFIX.clear()
        tr._RECENT_SUFFIX.update(suffix)

    def _restore_cache(self):
        tr._LEAF_CACHE_OK[0] = self._saved_cache_ok
        tr._leaf_cache_clear()

    def _cold_run(self, text, sid):
        """跑一次冷脱敏并返回（原文 → token）里唯一那条记录。"""
        tr.mask(text, sid)
        self.assertEqual(len(tr._RECENT_FWD), 1, "用例前提：这段文本只应产生一个占位符")
        orig, rec = next(iter(tr._RECENT_FWD.items()))
        return orig, rec[0]


class G611HitRefreshesTimestampsTests(_RecentLruBase):
    """G611 / CACHE_6101：叶子缓存命中必须给 token 续期。

    只刷 REV 不算通过：`_prune_recent_locked` 是按 FWD 的 ts 排序删除的
    （`sorted(evictable, key=lambda kv: kv[1][2])`），只刷 REV 照样被连带删 ——
    2026-10 在 restore 侧踩过同一条。
    """

    ERROR_CODE = "CACHE_6101"

    def test_g611_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "CACHE_6101")

    def test_g611_leaf_cache_hit_refreshes_both_directions(self):
        text = "联系人手机 %s" % _phone(21)
        orig, tok = self._cold_run(text, "hit-1")
        self.assertIn(tok, tr._RECENT_REV, "用例前提：冷跑应登记 REV")

        stale = time.time() - 3600          # 一小时前：远早于 24h TTL，仍可命中
        tr._RECENT_FWD[orig][2] = stale
        tr._RECENT_REV[tok][2] = stale

        hit_before = tr._LEAF_CACHE_STATS["hit"]
        tr.mask(text, "hit-2")               # 新 sid、同一段原文 → 走叶子缓存命中
        self.assertGreater(tr._LEAF_CACHE_STATS["hit"], hit_before,
                           "用例前提：第二次必须真的命中叶子缓存（否则没走到续期那条路）")

        self.assertGreater(tr._RECENT_FWD[orig][2], stale,
                           "叶子缓存命中没有给 FWD 续期：活跃映射会被当成最老淘汰")
        self.assertGreater(tr._RECENT_REV[tok][2], stale,
                           "叶子缓存命中没有给 REV 续期：还原侧映射照样会过期")

    def test_g611_failed_verification_is_not_refreshed(self):
        """校验失败的条目不得续期，否则挂着一张已失效映射的表项永不淘汰。"""
        text = "联系人手机 %s" % _phone(22)
        orig, tok = self._cold_run(text, "stale-1")
        stale = time.time() - 3600
        tr._RECENT_FWD[orig][2] = stale
        tr._RECENT_REV[tok][2] = stale
        # 让校验失败：把 FWD 指向另一个 token。
        # 必须直接调 `_leaf_cache_lookup`：走 `tr.mask` 会先冷跑一遍，`_recall_token`
        # 的命中路径本来就会续期，把「校验失败」与「冷跑续期」两件事混在一起。
        tr._RECENT_FWD[orig][0] = _placeholder("ID", "zzzzzz")

        got = tr._leaf_cache_lookup(text, "stale-2")
        self.assertIsNone(got, "用例前提：校验必须失败")
        self.assertEqual(tr._RECENT_FWD[orig][2], stale,
                         "校验失败的条目被续期了：失效映射会永久驻留")
        self.assertEqual(tr._RECENT_REV[tok][2], stale,
                         "校验失败的条目被续期了：失效映射会永久驻留")


class G612EvictionSemanticsTests(_RecentLruBase):
    """G612 / CACHE_6102：容量与 TTL 的上界不得被顺手放宽。"""

    ERROR_CODE = "CACHE_6102"

    def test_g612_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "CACHE_6102")

    def test_g612_capacity_is_the_agreed_value(self):
        self.assertEqual(self._saved_globals[2], 32768,
                         "复用表容量应为 32768（长会话几十轮就会顶到 8000）")

    def test_g612_ttl_contract_unchanged(self):
        self.assertEqual(tr._recent_ttl(), max(tr.RECENT_TTL, tr.SESSION_TTL),
                         "TTL 口径被改动：原文驻留窗口是 SECURITY.md 写明的契约")

    def test_g612_eviction_prefers_entries_not_in_use(self):
        """本请求复用的映射优先保留；未被复用的按 ts 最老删。

        淘汰必须区分两类：① 本请求复用的（历史叶子，重签会让同一实体在上下文里
        出现两个占位符）；② 本请求刚签发的（丢掉重签即可）。只按 ts 排会把历史
        永远排最前 —— 请求里历史在前、新增在后（2026-11-10 实测 r1 hit 0 / miss 100）。
        """
        now = time.time()
        for i in range(5):
            orig = "示例值-" + "abcdef"[i]
            tok = _placeholder("ID", "suf" + "abcdef"[i])
            tr._RECENT_FWD[orig] = [tok, "ID", now - (50 - i * 10)]
            tr._RECENT_REV[tok] = [orig, "ID", now - (50 - i * 10)]
        touched = "示例值-" + "a"                 # 最老，但在本请求里被复用
        tr._recent_in_use_add(_placeholder("ID", "sufa"))

        with mock.patch.object(tr, "_RECENT_MAX", 3):
            tr._prune_recent_locked(now)

        self.assertIn(touched, tr._RECENT_FWD,
                      "本请求复用的映射被淘汰：下次重发同一段历史会整叶重算")
        self.assertEqual(len(tr._RECENT_FWD), 3, "超容量清理没有把表压回上限")

    def test_g612_all_in_use_still_capped(self):
        """保护名单不能变成「永不淘汰」：全在用也必须压回上限。"""
        now = time.time()
        for i in range(5):
            orig = "示例值-" + "abcde"[i]
            tok = _placeholder("ID", "all" + "abcde"[i])
            tr._RECENT_FWD[orig] = [tok, "ID", now - (50 - i * 10)]
            tr._RECENT_REV[tok] = [orig, "ID", now - (50 - i * 10)]
            tr._recent_in_use_add(tok)

        with mock.patch.object(tr, "_RECENT_MAX", 3):
            tr._prune_recent_locked(now)

        self.assertEqual(len(tr._RECENT_FWD), 3,
                         "全部在用时表没有被压回上限：淘汰退化成了事实无界")

    def test_g612_long_conversation_survives_capacity_pressure(self):
        """端到端：容量压力下重发整段历史必须继续命中。

        真机形态（2026-11-10）：历史 100 条 + 每轮新增 60 条，容量压到 120。
        修复前实测 r1/r2 都是 hit 0 / miss 100（`miss_token_gone=200`），
        真机上对应的就是 19~28 秒的整段重扫。
        """
        hist = ["历史第 %d 条：手机 138%08d" % (i, i) for i in range(100)]
        with mock.patch.object(tr, "_RECENT_MAX", 120):
            tr._recent_in_use_clear()
            for i, t in enumerate(hist):
                tr.mask(t, "boot-%d" % i)
            for r in range(2):
                tr._recent_in_use_clear()          # 请求边界
                m0 = tr._LEAF_CACHE_STATS["miss"]
                for i, t in enumerate(hist):
                    tr.mask(t, "r%d-%d" % (r, i))
                self.assertEqual(
                    tr._LEAF_CACHE_STATS["miss"] - m0, 0,
                    "第 %d 轮重发历史出现 miss：整段历史被重扫 + 重跑语义识别" % r)
                for i in range(60):
                    tr.mask("第%d轮新增 %d：手机 139%06d%02d" % (r, i, i, r),
                            "n%d-%d" % (r, i))

    def test_g612_expired_entries_still_pruned(self):
        now = time.time()
        orig = "示例值-expired"
        tok = _placeholder("ID", "oldold")
        tr._RECENT_FWD[orig] = [tok, "ID", now - tr._recent_ttl() - 60]
        tr._RECENT_REV[tok] = [orig, "ID", now - tr._recent_ttl() - 60]
        tr._prune_recent_locked(now)
        self.assertNotIn(orig, tr._RECENT_FWD, "过期条目没有被 TTL 清掉")
        self.assertNotIn(tok, tr._RECENT_REV, "过期 token 的 REV 成了孤儿")


class G613MissReasonAttributionTests(_RecentLruBase):
    """G613 / CACHE_6103：四类 miss 必须分开计数，否则「为什么慢」永远查不出来。"""

    ERROR_CODE = "CACHE_6103"

    def test_g613_error_code_literal(self):
        self.assertEqual(self.ERROR_CODE, "CACHE_6103")

    def _store(self, text, sid="owner", dependent=False, owner="owner"):
        """造一条叶子缓存条目（不经 mask：要精确控制 tokens 清单）。"""
        orig = "示例原文-" + text
        tok = _placeholder("ID", "aaaa" + text[:2])
        tr._RECENT_FWD[orig] = [tok, "ID", time.time()]
        tr._RECENT_REV[tok] = [orig, "ID", time.time()]
        tokens = [(tok, "ID", tr._orig_digest(orig))]
        tr._leaf_cache_store(text, "脱敏后-" + text, tokens,
                             dependent=dependent, owner_sid=owner)
        return orig, tok

    def _stats(self):
        return dict(tr._LEAF_CACHE_STATS)

    def test_g613_token_gone(self):
        orig, tok = self._store("gone")
        before = self._stats()
        tr._RECENT_REV.pop(tok)
        tr._leaf_cache_lookup("gone", "owner")
        after = self._stats()
        self.assertEqual(after["miss_token_gone"] - before["miss_token_gone"], 1)
        self.assertEqual(after["miss"] - before["miss"], 1)

    def test_g613_identity_changed(self):
        orig, tok = self._store("ident")
        before = self._stats()
        tr._RECENT_FWD[orig][0] = _placeholder("ID", "bbbbbb")
        tr._leaf_cache_lookup("ident", "owner")
        after = self._stats()
        self.assertEqual(after["miss_identity"] - before["miss_identity"], 1)
        self.assertEqual(after["miss"] - before["miss"], 1)

    def test_g613_generation_bumped(self):
        orig, tok = self._store("gen")
        before = self._stats()
        tr._leaf_cache_bump()
        tr._leaf_cache_lookup("gen", "owner")
        after = self._stats()
        self.assertEqual(after["miss_gen"] - before["miss_gen"], 1)
        self.assertEqual(after["miss"] - before["miss"], 1)

    def test_g613_scope_restricted(self):
        orig, tok = self._store("scope", sid="A", dependent=True, owner="A")
        before = self._stats()
        tr._leaf_cache_lookup("scope", "B")
        after = self._stats()
        self.assertEqual(after["miss_scope"] - before["miss_scope"], 1)
        self.assertEqual(after["miss"] - before["miss"], 1)

    def test_g613_stats_surface_exposes_four_keys(self):
        stats = tr._leaf_cache_stats()
        for key in ("miss_token_gone", "miss_identity", "miss_gen", "miss_scope"):
            self.assertIn(key, stats, "诊断键没有外发：面板与自检看不到 miss 归因")


if __name__ == "__main__":
    unittest.main()
